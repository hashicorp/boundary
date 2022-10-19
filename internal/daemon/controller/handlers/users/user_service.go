package users

import (
	"context"
	"fmt"

	"github.com/hashicorp/boundary/globals"
	"github.com/hashicorp/boundary/internal/auth/oidc"
	"github.com/hashicorp/boundary/internal/daemon/controller/auth"
	"github.com/hashicorp/boundary/internal/daemon/controller/common"
	"github.com/hashicorp/boundary/internal/daemon/controller/common/scopeids"
	"github.com/hashicorp/boundary/internal/daemon/controller/handlers"
	"github.com/hashicorp/boundary/internal/errors"
	pbs "github.com/hashicorp/boundary/internal/gen/controller/api/services"
	"github.com/hashicorp/boundary/internal/iam"
	"github.com/hashicorp/boundary/internal/iam/store"
	"github.com/hashicorp/boundary/internal/intglobals"
	"github.com/hashicorp/boundary/internal/perms"
	"github.com/hashicorp/boundary/internal/requests"
	"github.com/hashicorp/boundary/internal/types/action"
	"github.com/hashicorp/boundary/internal/types/resource"
	"github.com/hashicorp/boundary/internal/types/scope"
	pb "github.com/hashicorp/boundary/sdk/pbs/controller/api/resources/users"
	"github.com/hashicorp/go-secure-stdlib/strutil"
	"google.golang.org/grpc/codes"
	"google.golang.org/protobuf/types/known/wrapperspb"
)

var (
	maskManager handlers.MaskManager

	// IdActions contains the set of actions that can be performed on
	// individual resources
	IdActions = action.ActionSet{
		action.NoOp,
		action.Read,
		action.Update,
		action.Delete,
		action.AddAccounts,
		action.SetAccounts,
		action.RemoveAccounts,
	}

	// CollectionActions contains the set of actions that can be performed on
	// this collection
	CollectionActions = action.ActionSet{
		action.Create,
		action.List,
	}
)

func init() {
	var err error
	if maskManager, err = handlers.NewMaskManager(handlers.MaskDestination{&store.User{}}, handlers.MaskSource{&pb.User{}}); err != nil {
		panic(err)
	}
}

// Service handles request as described by the pbs.UserServiceServer interface.
type Service struct {
	pbs.UnsafeUserServiceServer

	repoFn common.IamRepoFactory
}

var _ pbs.UserServiceServer = (*Service)(nil)

// NewService returns a user service which handles user related requests to boundary.
func NewService(repo common.IamRepoFactory) (Service, error) {
	const op = "users.NewService"
	if repo == nil {
		return Service{}, errors.NewDeprecated(errors.InvalidParameter, op, "missing iam repository")
	}
	return Service{repoFn: repo}, nil
}

// ListUsers implements the interface pbs.UserServiceServer.
func (s Service) ListUsers(ctx context.Context, req *pbs.ListUsersRequest) (*pbs.ListUsersResponse, error) {
	if err := validateListRequest(req); err != nil {
		return nil, err
	}
	authResults := s.authResult(ctx, req.GetScopeId(), action.List)
	if authResults.Error != nil {
		// If it's forbidden, and it's a recursive request, and they're
		// successfully authenticated but just not authorized, keep going as we
		// may have authorization on downstream scopes. Or, if they've not
		// authenticated, still process in case u_anon has permissions.
		if (authResults.Error == handlers.ForbiddenError() || authResults.Error == handlers.UnauthenticatedError()) &&
			req.GetRecursive() &&
			authResults.AuthenticationFinished {
		} else {
			return nil, authResults.Error
		}
	}

	scopeIds, scopeInfoMap, err := scopeids.GetListingScopeIds(
		ctx, s.repoFn, authResults, req.GetScopeId(), resource.User, req.GetRecursive())
	if err != nil {
		return nil, err
	}
	// If no scopes match, return an empty response
	if len(scopeIds) == 0 {
		return &pbs.ListUsersResponse{}, nil
	}

	ul, err := s.listFromRepo(ctx, scopeIds)
	if err != nil {
		return nil, err
	}
	if len(ul) == 0 {
		return &pbs.ListUsersResponse{}, nil
	}

	filter, err := handlers.NewFilter(req.GetFilter())
	if err != nil {
		return nil, err
	}
	finalItems := make([]*pb.User, 0, len(ul))
	res := perms.Resource{
		Type: resource.User,
	}
	for _, item := range ul {
		res.Id = item.GetPublicId()
		res.ScopeId = item.GetScopeId()
		authorizedActions := authResults.FetchActionSetForId(ctx, item.GetPublicId(), IdActions, auth.WithResource(&res)).Strings()
		if len(authorizedActions) == 0 {
			continue
		}

		outputFields := authResults.FetchOutputFields(res, action.List).SelfOrDefaults(authResults.UserData.User.Id)
		outputOpts := make([]handlers.Option, 0, 3)
		outputOpts = append(outputOpts, handlers.WithOutputFields(&outputFields))
		if outputFields.Has(globals.ScopeField) {
			outputOpts = append(outputOpts, handlers.WithScope(scopeInfoMap[item.GetScopeId()]))
		}
		if outputFields.Has(globals.AuthorizedActionsField) {
			outputOpts = append(outputOpts, handlers.WithAuthorizedActions(authorizedActions))
		}

		item, err := toProto(ctx, item, nil, outputOpts...)
		if err != nil {
			return nil, err
		}

		if filter.Match(item) {
			finalItems = append(finalItems, item)
		}
	}
	return &pbs.ListUsersResponse{Items: finalItems}, nil
}

// GetUsers implements the interface pbs.UserServiceServer.
func (s Service) GetUser(ctx context.Context, req *pbs.GetUserRequest) (*pbs.GetUserResponse, error) {
	const op = "users.(Service).GetUser"

	if err := validateGetRequest(req); err != nil {
		return nil, err
	}
	authResults := s.authResult(ctx, req.GetId(), action.Read)
	if authResults.Error != nil {
		return nil, authResults.Error
	}
	u, accts, err := s.getFromRepo(ctx, req.GetId())
	if err != nil {
		return nil, err
	}

	outputFields, ok := requests.OutputFields(ctx)
	if !ok {
		return nil, errors.New(ctx, errors.Internal, op, "no request context found")
	}

	outputOpts := make([]handlers.Option, 0, 3)
	outputOpts = append(outputOpts, handlers.WithOutputFields(&outputFields))
	if outputFields.Has(globals.ScopeField) {
		outputOpts = append(outputOpts, handlers.WithScope(authResults.Scope))
	}
	if outputFields.Has(globals.AuthorizedActionsField) {
		outputOpts = append(outputOpts, handlers.WithAuthorizedActions(authResults.FetchActionSetForId(ctx, u.GetPublicId(), IdActions).Strings()))
	}

	item, err := toProto(ctx, u, accts, outputOpts...)
	if err != nil {
		return nil, err
	}

	return &pbs.GetUserResponse{Item: item}, nil
}

// CreateUser implements the interface pbs.UserServiceServer.
func (s Service) CreateUser(ctx context.Context, req *pbs.CreateUserRequest) (*pbs.CreateUserResponse, error) {
	const op = "users.(Service).CreateUser"

	if err := validateCreateRequest(req); err != nil {
		return nil, err
	}
	authResults := s.authResult(ctx, req.GetItem().GetScopeId(), action.Create)
	if authResults.Error != nil {
		return nil, authResults.Error
	}
	u, err := s.createInRepo(ctx, authResults.Scope.GetId(), req.GetItem())
	if err != nil {
		return nil, err
	}

	outputFields, ok := requests.OutputFields(ctx)
	if !ok {
		return nil, errors.New(ctx, errors.Internal, op, "no request context found")
	}

	outputOpts := make([]handlers.Option, 0, 3)
	outputOpts = append(outputOpts, handlers.WithOutputFields(&outputFields))
	if outputFields.Has(globals.ScopeField) {
		outputOpts = append(outputOpts, handlers.WithScope(authResults.Scope))
	}
	if outputFields.Has(globals.AuthorizedActionsField) {
		outputOpts = append(outputOpts, handlers.WithAuthorizedActions(authResults.FetchActionSetForId(ctx, u.GetPublicId(), IdActions).Strings()))
	}

	item, err := toProto(ctx, u, nil, outputOpts...)
	if err != nil {
		return nil, err
	}
	return &pbs.CreateUserResponse{Item: item, Uri: fmt.Sprintf("users/%s", item.GetId())}, nil
}

// UpdateUser implements the interface pbs.UserServiceServer.
func (s Service) UpdateUser(ctx context.Context, req *pbs.UpdateUserRequest) (*pbs.UpdateUserResponse, error) {
	const op = "users.(Service).UpdateUser"

	if err := validateUpdateRequest(req); err != nil {
		return nil, err
	}
	authResults := s.authResult(ctx, req.GetId(), action.Update)
	if authResults.Error != nil {
		return nil, authResults.Error
	}
	u, accts, err := s.updateInRepo(ctx, authResults.Scope.GetId(), req.GetId(), req.GetUpdateMask().GetPaths(), req.GetItem())
	if err != nil {
		return nil, err
	}

	outputFields, ok := requests.OutputFields(ctx)
	if !ok {
		return nil, errors.New(ctx, errors.Internal, op, "no request context found")
	}

	outputOpts := make([]handlers.Option, 0, 3)
	outputOpts = append(outputOpts, handlers.WithOutputFields(&outputFields))
	if outputFields.Has(globals.ScopeField) {
		outputOpts = append(outputOpts, handlers.WithScope(authResults.Scope))
	}
	if outputFields.Has(globals.AuthorizedActionsField) {
		outputOpts = append(outputOpts, handlers.WithAuthorizedActions(authResults.FetchActionSetForId(ctx, u.GetPublicId(), IdActions).Strings()))
	}

	item, err := toProto(ctx, u, accts, outputOpts...)
	if err != nil {
		return nil, err
	}

	return &pbs.UpdateUserResponse{Item: item}, nil
}

// DeleteUser implements the interface pbs.UserServiceServer.
func (s Service) DeleteUser(ctx context.Context, req *pbs.DeleteUserRequest) (*pbs.DeleteUserResponse, error) {
	if err := validateDeleteRequest(req); err != nil {
		return nil, err
	}
	authResults := s.authResult(ctx, req.GetId(), action.Delete)
	if authResults.Error != nil {
		return nil, authResults.Error
	}
	_, err := s.deleteFromRepo(ctx, req.GetId())
	if err != nil {
		return nil, err
	}
	return nil, nil
}

// AddUserAccounts implements the interface pbs.GroupServiceServer.
func (s Service) AddUserAccounts(ctx context.Context, req *pbs.AddUserAccountsRequest) (*pbs.AddUserAccountsResponse, error) {
	const op = "users.(Service).AddUserAccounts"

	if err := validateAddUserAccountsRequest(req); err != nil {
		return nil, err
	}
	authResults := s.authResult(ctx, req.GetId(), action.AddAccounts)
	if authResults.Error != nil {
		return nil, authResults.Error
	}
	u, accts, err := s.addInRepo(ctx, req.GetId(), req.GetAccountIds(), req.GetVersion())
	if err != nil {
		return nil, err
	}

	outputFields, ok := requests.OutputFields(ctx)
	if !ok {
		return nil, errors.New(ctx, errors.Internal, op, "no request context found")
	}

	outputOpts := make([]handlers.Option, 0, 3)
	outputOpts = append(outputOpts, handlers.WithOutputFields(&outputFields))
	if outputFields.Has(globals.ScopeField) {
		outputOpts = append(outputOpts, handlers.WithScope(authResults.Scope))
	}
	if outputFields.Has(globals.AuthorizedActionsField) {
		outputOpts = append(outputOpts, handlers.WithAuthorizedActions(authResults.FetchActionSetForId(ctx, u.GetPublicId(), IdActions).Strings()))
	}

	item, err := toProto(ctx, u, accts, outputOpts...)
	if err != nil {
		return nil, err
	}

	return &pbs.AddUserAccountsResponse{Item: item}, nil
}

// SetUserAccounts implements the interface pbs.GroupServiceServer.
func (s Service) SetUserAccounts(ctx context.Context, req *pbs.SetUserAccountsRequest) (*pbs.SetUserAccountsResponse, error) {
	const op = "users.(Service).SetUserAccounts"

	if err := validateSetUserAccountsRequest(req); err != nil {
		return nil, err
	}
	authResults := s.authResult(ctx, req.GetId(), action.SetAccounts)
	if authResults.Error != nil {
		return nil, authResults.Error
	}
	u, accts, err := s.setInRepo(ctx, req.GetId(), req.GetAccountIds(), req.GetVersion())
	if err != nil {
		return nil, err
	}

	outputFields, ok := requests.OutputFields(ctx)
	if !ok {
		return nil, errors.New(ctx, errors.Internal, op, "no request context found")
	}

	outputOpts := make([]handlers.Option, 0, 3)
	outputOpts = append(outputOpts, handlers.WithOutputFields(&outputFields))
	if outputFields.Has(globals.ScopeField) {
		outputOpts = append(outputOpts, handlers.WithScope(authResults.Scope))
	}
	if outputFields.Has(globals.AuthorizedActionsField) {
		outputOpts = append(outputOpts, handlers.WithAuthorizedActions(authResults.FetchActionSetForId(ctx, u.GetPublicId(), IdActions).Strings()))
	}

	item, err := toProto(ctx, u, accts, outputOpts...)
	if err != nil {
		return nil, err
	}

	return &pbs.SetUserAccountsResponse{Item: item}, nil
}

// RemoveUserAccounts implements the interface pbs.GroupServiceServer.
func (s Service) RemoveUserAccounts(ctx context.Context, req *pbs.RemoveUserAccountsRequest) (*pbs.RemoveUserAccountsResponse, error) {
	const op = "users.(Service).RemoveUserAccounts"

	if err := validateRemoveUserAccountsRequest(req); err != nil {
		return nil, err
	}
	authResults := s.authResult(ctx, req.GetId(), action.RemoveAccounts)
	if authResults.Error != nil {
		return nil, authResults.Error
	}
	u, accts, err := s.removeInRepo(ctx, req.GetId(), req.GetAccountIds(), req.GetVersion())
	if err != nil {
		return nil, err
	}

	outputFields, ok := requests.OutputFields(ctx)
	if !ok {
		return nil, errors.New(ctx, errors.Internal, op, "no request context found")
	}

	outputOpts := make([]handlers.Option, 0, 3)
	outputOpts = append(outputOpts, handlers.WithOutputFields(&outputFields))
	if outputFields.Has(globals.ScopeField) {
		outputOpts = append(outputOpts, handlers.WithScope(authResults.Scope))
	}
	if outputFields.Has(globals.AuthorizedActionsField) {
		outputOpts = append(outputOpts, handlers.WithAuthorizedActions(authResults.FetchActionSetForId(ctx, u.GetPublicId(), IdActions).Strings()))
	}

	item, err := toProto(ctx, u, accts, outputOpts...)
	if err != nil {
		return nil, err
	}

	return &pbs.RemoveUserAccountsResponse{Item: item}, nil
}

func (s Service) getFromRepo(ctx context.Context, id string) (*iam.User, []string, error) {
	repo, err := s.repoFn()
	if err != nil {
		return nil, nil, err
	}
	u, accts, err := repo.LookupUser(ctx, id)
	if err != nil {
		if errors.IsNotFoundError(err) {
			return nil, nil, handlers.NotFoundErrorf("User %q doesn't exist.", id)
		}
		return nil, nil, err
	}
	if u == nil {
		return nil, nil, handlers.NotFoundErrorf("User %q doesn't exist.", id)
	}
	return u, accts, nil
}

func (s Service) createInRepo(ctx context.Context, orgId string, item *pb.User) (*iam.User, error) {
	const op = "users.(Service).createInRepo"
	var opts []iam.Option
	if item.GetName() != nil {
		opts = append(opts, iam.WithName(item.GetName().GetValue()))
	}
	if item.GetDescription() != nil {
		opts = append(opts, iam.WithDescription(item.GetDescription().GetValue()))
	}
	u, err := iam.NewUser(orgId, opts...)
	if err != nil {
		return nil, handlers.ApiErrorWithCodeAndMessage(codes.Internal, "Unable to build user for creation: %v.", err)
	}
	repo, err := s.repoFn()
	if err != nil {
		return nil, err
	}
	out, err := repo.CreateUser(ctx, u)
	if err != nil {
		return nil, errors.Wrap(ctx, err, op, errors.WithMsg("unable to create user"))
	}
	if out == nil {
		return nil, handlers.ApiErrorWithCodeAndMessage(codes.Internal, "Unable to create user but no error returned from repository.")
	}
	return out, nil
}

func (s Service) updateInRepo(ctx context.Context, orgId, id string, mask []string, item *pb.User) (*iam.User, []string, error) {
	const op = "users.(Service).updateInRepo"
	var opts []iam.Option
	if desc := item.GetDescription(); desc != nil {
		opts = append(opts, iam.WithDescription(desc.GetValue()))
	}
	if name := item.GetName(); name != nil {
		opts = append(opts, iam.WithName(name.GetValue()))
	}
	version := item.GetVersion()
	u, err := iam.NewUser(orgId, opts...)
	if err != nil {
		return nil, nil, handlers.ApiErrorWithCodeAndMessage(codes.Internal, "Unable to build user for update: %v.", err)
	}
	u.PublicId = id
	dbMask := maskManager.Translate(mask)
	if len(dbMask) == 0 {
		return nil, nil, handlers.InvalidArgumentErrorf("No valid fields included in the update mask.", map[string]string{"update_mask": "No valid fields provided in the update mask."})
	}
	repo, err := s.repoFn()
	if err != nil {
		return nil, nil, err
	}
	out, accts, rowsUpdated, err := repo.UpdateUser(ctx, u, version, dbMask)
	if err != nil {
		return nil, nil, errors.Wrap(ctx, err, op, errors.WithMsg("unable to update user"))
	}
	if rowsUpdated == 0 {
		return nil, nil, handlers.NotFoundErrorf("User %q doesn't exist or incorrect version provided.", id)
	}
	return out, accts, nil
}

func (s Service) deleteFromRepo(ctx context.Context, id string) (bool, error) {
	const op = "users.(Service).deleteFromRepo"
	repo, err := s.repoFn()
	if err != nil {
		return false, err
	}
	rows, err := repo.DeleteUser(ctx, id)
	if err != nil {
		if errors.IsNotFoundError(err) {
			return false, nil
		}
		return false, errors.Wrap(ctx, err, op, errors.WithMsg("unable to delete user"))
	}
	return rows > 0, nil
}

func (s Service) listFromRepo(ctx context.Context, scopeIds []string) ([]*iam.User, error) {
	repo, err := s.repoFn()
	if err != nil {
		return nil, err
	}
	ul, err := repo.ListUsers(ctx, scopeIds)
	if err != nil {
		return nil, err
	}
	return ul, nil
}

func (s Service) addInRepo(ctx context.Context, userId string, accountIds []string, version uint32) (*iam.User, []string, error) {
	const op = "users.(Service).addInRepo"
	repo, err := s.repoFn()
	if err != nil {
		return nil, nil, err
	}
	_, err = repo.AddUserAccounts(ctx, userId, version, strutil.RemoveDuplicates(accountIds, false))
	if err != nil {
		return nil, nil, handlers.ApiErrorWithCodeAndMessage(codes.Internal, "Unable to add accounts to user: %v.", err)
	}
	out, accts, err := repo.LookupUser(ctx, userId)
	if err != nil {
		return nil, nil, errors.Wrap(ctx, err, op, errors.WithMsg("unable to look up user after adding accounts"))
	}
	if out == nil {
		return nil, nil, handlers.ApiErrorWithCodeAndMessage(codes.Internal, "Unable to lookup user after adding accounts to it.")
	}
	return out, accts, nil
}

func (s Service) setInRepo(ctx context.Context, userId string, accountIds []string, version uint32) (*iam.User, []string, error) {
	const op = "users.(Service).setInRepo"
	repo, err := s.repoFn()
	if err != nil {
		return nil, nil, err
	}
	_, err = repo.SetUserAccounts(ctx, userId, version, strutil.RemoveDuplicates(accountIds, false))
	if err != nil {
		return nil, nil, handlers.ApiErrorWithCodeAndMessage(codes.Internal, "Unable to set accounts for the user: %v.", err)
	}
	out, accts, err := repo.LookupUser(ctx, userId)
	if err != nil {
		return nil, nil, errors.Wrap(ctx, err, op, errors.WithMsg("unable to look up user after setting accounts"))
	}
	if out == nil {
		return nil, nil, handlers.ApiErrorWithCodeAndMessage(codes.Internal, "Unable to lookup user after setting accounts for it.")
	}
	return out, accts, nil
}

func (s Service) removeInRepo(ctx context.Context, userId string, accountIds []string, version uint32) (*iam.User, []string, error) {
	const op = "users.(Service).removeInRepo"
	repo, err := s.repoFn()
	if err != nil {
		return nil, nil, err
	}
	_, err = repo.DeleteUserAccounts(ctx, userId, version, strutil.RemoveDuplicates(accountIds, false))
	if err != nil {
		return nil, nil, handlers.ApiErrorWithCodeAndMessage(codes.Internal, "Unable to remove accounts from user: %v.", err)
	}
	out, accts, err := repo.LookupUser(ctx, userId)
	if err != nil {
		return nil, nil, errors.Wrap(ctx, err, op, errors.WithMsg("unable to look up user after removing accounts"))
	}
	if out == nil {
		return nil, nil, handlers.ApiErrorWithCodeAndMessage(codes.Internal, "Unable to lookup user after removing accounts from it.")
	}
	return out, accts, nil
}

func (s Service) authResult(ctx context.Context, id string, a action.Type) auth.VerifyResults {
	res := auth.VerifyResults{}
	repo, err := s.repoFn()
	if err != nil {
		res.Error = err
		return res
	}

	var parentId string
	opts := []auth.Option{auth.WithType(resource.User), auth.WithAction(a)}
	switch a {
	case action.List, action.Create:
		parentId = id
		scp, err := repo.LookupScope(ctx, parentId)
		if err != nil {
			res.Error = err
			return res
		}
		if scp == nil {
			res.Error = handlers.NotFoundError()
			return res
		}
	default:
		u, _, err := repo.LookupUser(ctx, id)
		if err != nil {
			res.Error = err
			return res
		}
		if u == nil {
			res.Error = handlers.NotFoundError()
			return res
		}
		parentId = u.GetScopeId()
		opts = append(opts, auth.WithId(id))
	}
	opts = append(opts, auth.WithScopeId(parentId))
	return auth.Verify(ctx, opts...)
}

func toProto(ctx context.Context, in *iam.User, accts []string, opt ...handlers.Option) (*pb.User, error) {
	opts := handlers.GetOpts(opt...)
	if opts.WithOutputFields == nil {
		return nil, handlers.ApiErrorWithCodeAndMessage(codes.Internal, "output fields not found when building user proto")
	}
	outputFields := *opts.WithOutputFields

	out := pb.User{}
	if outputFields.Has(globals.IdField) {
		out.Id = in.GetPublicId()
	}
	if outputFields.Has(globals.ScopeIdField) {
		out.ScopeId = in.GetScopeId()
	}
	if outputFields.Has(globals.DescriptionField) && in.GetDescription() != "" {
		out.Description = wrapperspb.String(in.GetDescription())
	}
	if outputFields.Has(globals.NameField) && in.GetName() != "" {
		out.Name = wrapperspb.String(in.GetName())
	}
	if outputFields.Has(globals.CreatedTimeField) {
		out.CreatedTime = in.GetCreateTime().GetTimestamp()
	}
	if outputFields.Has(globals.UpdatedTimeField) {
		out.UpdatedTime = in.GetUpdateTime().GetTimestamp()
	}
	if outputFields.Has(globals.VersionField) {
		out.Version = in.GetVersion()
	}
	if outputFields.Has(globals.AccountIdsField) {
		out.AccountIds = accts
	}
	if outputFields.Has(globals.PrimaryAccountIdField) {
		out.PrimaryAccountId = in.GetPrimaryAccountId()
	}
	if outputFields.Has(globals.LoginNameField) {
		out.LoginName = in.GetLoginName()
	}
	if outputFields.Has(globals.FullNameField) {
		out.FullName = in.GetFullName()
	}
	if outputFields.Has(globals.EmailField) {
		out.Email = in.GetEmail()
	}
	if outputFields.Has(globals.ScopeField) {
		out.Scope = opts.WithScope
	}
	if outputFields.Has(globals.AuthorizedActionsField) {
		out.AuthorizedActions = opts.WithAuthorizedActions
	}
	if outputFields.Has(globals.AccountsField) {
		for _, a := range accts {
			out.Accounts = append(out.Accounts, &pb.Account{
				Id: a,
				// TODO: Update this when an account can be associated with a user from a different scope.
				ScopeId: in.GetScopeId(),
			})
		}
	}
	return &out, nil
}

// A validateX method should exist for each method above.  These methods do not make calls to any backing service but enforce
// requirements on the structure of the request.  They verify that:
//   - The path passed in is correctly formatted
//   - All required parameters are set
//   - There are no conflicting parameters provided
func validateGetRequest(req *pbs.GetUserRequest) error {
	return handlers.ValidateGetRequest(handlers.NoopValidatorFn, req, iam.UserPrefix)
}

func validateCreateRequest(req *pbs.CreateUserRequest) error {
	return handlers.ValidateCreateRequest(req.GetItem(), func() map[string]string {
		badFields := map[string]string{}
		if !handlers.ValidId(handlers.Id(req.GetItem().GetScopeId()), scope.Org.Prefix()) &&
			scope.Global.String() != req.GetItem().GetScopeId() {
			badFields["scope_id"] = "Must be 'global' or a valid org scope id."
		}
		return badFields
	})
}

func validateUpdateRequest(req *pbs.UpdateUserRequest) error {
	return handlers.ValidateUpdateRequest(req, req.GetItem(), handlers.NoopValidatorFn, iam.UserPrefix)
}

func validateDeleteRequest(req *pbs.DeleteUserRequest) error {
	return handlers.ValidateDeleteRequest(handlers.NoopValidatorFn, req, iam.UserPrefix)
}

func validateListRequest(req *pbs.ListUsersRequest) error {
	badFields := map[string]string{}
	if !handlers.ValidId(handlers.Id(req.GetScopeId()), scope.Org.Prefix()) &&
		req.GetScopeId() != scope.Global.String() {
		badFields["scope_id"] = "Must be 'global' or a valid org scope id when listing."
	}
	if _, err := handlers.NewFilter(req.GetFilter()); err != nil {
		badFields["filter"] = fmt.Sprintf("This field could not be parsed. %v", err)
	}
	if len(badFields) > 0 {
		return handlers.InvalidArgumentErrorf("Improperly formatted identifier.", badFields)
	}
	return nil
}

func validateAddUserAccountsRequest(req *pbs.AddUserAccountsRequest) error {
	badFields := map[string]string{}
	if !handlers.ValidId(handlers.Id(req.GetId()), iam.UserPrefix) {
		badFields["id"] = "Incorrectly formatted identifier."
	}
	if req.GetVersion() == 0 {
		badFields["version"] = "Required field."
	}
	if len(req.GetAccountIds()) == 0 {
		badFields["account_ids"] = "Must be non-empty."
	}
	for _, a := range req.GetAccountIds() {
		// TODO: Increase the type of auth accounts that can be added to a user.
		if !handlers.ValidId(handlers.Id(a),
			intglobals.OldPasswordAccountPrefix,
			intglobals.NewPasswordAccountPrefix,
			oidc.AccountPrefix,
		) {
			badFields["account_ids"] = "Values must be valid account ids."
			break
		}
	}
	if len(badFields) > 0 {
		return handlers.InvalidArgumentErrorf("Errors in provided fields.", badFields)
	}
	return nil
}

func validateSetUserAccountsRequest(req *pbs.SetUserAccountsRequest) error {
	badFields := map[string]string{}
	if !handlers.ValidId(handlers.Id(req.GetId()), iam.UserPrefix) {
		badFields["id"] = "Incorrectly formatted identifier."
	}
	if req.GetVersion() == 0 {
		badFields["version"] = "Required field."
	}
	for _, a := range req.GetAccountIds() {
		// TODO: Increase the type of auth accounts that can be added to a user.
		if !handlers.ValidId(handlers.Id(a),
			intglobals.OldPasswordAccountPrefix,
			intglobals.NewPasswordAccountPrefix,
			oidc.AccountPrefix,
		) {
			badFields["account_ids"] = "Values must be valid account ids."
			break
		}
	}
	if len(badFields) > 0 {
		return handlers.InvalidArgumentErrorf("Errors in provided fields.", badFields)
	}
	return nil
}

func validateRemoveUserAccountsRequest(req *pbs.RemoveUserAccountsRequest) error {
	badFields := map[string]string{}
	if !handlers.ValidId(handlers.Id(req.GetId()), iam.UserPrefix) {
		badFields["id"] = "Incorrectly formatted identifier."
	}
	if req.GetVersion() == 0 {
		badFields["version"] = "Required field."
	}
	if len(req.GetAccountIds()) == 0 {
		badFields["account_ids"] = "Must be non-empty."
	}
	for _, a := range req.GetAccountIds() {
		// TODO: Increase the type of auth accounts that can be added to a user.
		if !handlers.ValidId(handlers.Id(a),
			intglobals.OldPasswordAccountPrefix,
			intglobals.NewPasswordAccountPrefix,
			oidc.AccountPrefix,
		) {
			badFields["account_ids"] = "Values must be valid account ids."
			break
		}
	}
	if len(badFields) > 0 {
		return handlers.InvalidArgumentErrorf("Errors in provided fields.", badFields)
	}
	return nil
}
