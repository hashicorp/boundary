package roles

import (
	"context"
	"fmt"

	"github.com/hashicorp/boundary/globals"
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
	pb "github.com/hashicorp/boundary/sdk/pbs/controller/api/resources/roles"
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
		action.AddPrincipals,
		action.SetPrincipals,
		action.RemovePrincipals,
		action.AddGrants,
		action.SetGrants,
		action.RemoveGrants,
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
	if maskManager, err = handlers.NewMaskManager(handlers.MaskDestination{&store.Role{}}, handlers.MaskSource{&pb.Role{}}); err != nil {
		panic(err)
	}
}

// Service handles request as described by the pbs.RoleServiceServer interface.
type Service struct {
	pbs.UnsafeRoleServiceServer

	repoFn common.IamRepoFactory
}

var _ pbs.RoleServiceServer = (*Service)(nil)

// NewService returns a role service which handles role related requests to boundary.
func NewService(repo common.IamRepoFactory) (Service, error) {
	const op = "roles.NewService"
	if repo == nil {
		return Service{}, errors.NewDeprecated(errors.InvalidParameter, op, "missing iam repository")
	}
	return Service{repoFn: repo}, nil
}

// ListRoles implements the interface pbs.RoleServiceServer.
func (s Service) ListRoles(ctx context.Context, req *pbs.ListRolesRequest) (*pbs.ListRolesResponse, error) {
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
		ctx, s.repoFn, authResults, req.GetScopeId(), resource.Role, req.GetRecursive())
	if err != nil {
		return nil, err
	}
	// If no scopes match, return an empty response
	if len(scopeIds) == 0 {
		return &pbs.ListRolesResponse{}, nil
	}

	items, err := s.listFromRepo(ctx, scopeIds)
	if err != nil {
		return nil, err
	}
	if len(items) == 0 {
		return &pbs.ListRolesResponse{}, nil
	}

	filter, err := handlers.NewFilter(req.GetFilter())
	if err != nil {
		return nil, err
	}
	finalItems := make([]*pb.Role, 0, len(items))
	res := perms.Resource{
		Type: resource.Role,
	}
	for _, item := range items {
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

		item, err := toProto(ctx, item, nil, nil, outputOpts...)
		if err != nil {
			return nil, err
		}

		if filter.Match(item) {
			finalItems = append(finalItems, item)
		}
	}
	return &pbs.ListRolesResponse{Items: finalItems}, nil
}

// GetRoles implements the interface pbs.RoleServiceServer.
func (s Service) GetRole(ctx context.Context, req *pbs.GetRoleRequest) (*pbs.GetRoleResponse, error) {
	const op = "roles.(Service).GetRole"

	if err := validateGetRequest(req); err != nil {
		return nil, err
	}
	authResults := s.authResult(ctx, req.GetId(), action.Read)
	if authResults.Error != nil {
		return nil, authResults.Error
	}
	r, prs, rgs, err := s.getFromRepo(ctx, req.GetId())
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
		outputOpts = append(outputOpts, handlers.WithAuthorizedActions(authResults.FetchActionSetForId(ctx, r.GetPublicId(), IdActions).Strings()))
	}

	item, err := toProto(ctx, r, prs, rgs, outputOpts...)
	if err != nil {
		return nil, err
	}

	return &pbs.GetRoleResponse{Item: item}, nil
}

// CreateRole implements the interface pbs.RoleServiceServer.
func (s Service) CreateRole(ctx context.Context, req *pbs.CreateRoleRequest) (*pbs.CreateRoleResponse, error) {
	const op = "roles.(Service).CreateRole"

	if err := validateCreateRequest(req); err != nil {
		return nil, err
	}
	authResults := s.authResult(ctx, req.GetItem().GetScopeId(), action.Create)
	if authResults.Error != nil {
		return nil, authResults.Error
	}
	r, err := s.createInRepo(ctx, authResults.Scope.GetId(), req.GetItem())
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
		outputOpts = append(outputOpts, handlers.WithAuthorizedActions(authResults.FetchActionSetForId(ctx, r.GetPublicId(), IdActions).Strings()))
	}

	item, err := toProto(ctx, r, nil, nil, outputOpts...)
	if err != nil {
		return nil, err
	}

	return &pbs.CreateRoleResponse{Item: item, Uri: fmt.Sprintf("roles/%s", item.GetId())}, nil
}

// UpdateRole implements the interface pbs.RoleServiceServer.
func (s Service) UpdateRole(ctx context.Context, req *pbs.UpdateRoleRequest) (*pbs.UpdateRoleResponse, error) {
	const op = "roles.(Service).UpdateRole"

	if err := validateUpdateRequest(req); err != nil {
		return nil, err
	}
	authResults := s.authResult(ctx, req.GetId(), action.Update)
	if authResults.Error != nil {
		return nil, authResults.Error
	}
	r, prs, rgs, err := s.updateInRepo(ctx, authResults.Scope.GetId(), req.GetId(), req.GetUpdateMask().GetPaths(), req.GetItem())
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
		outputOpts = append(outputOpts, handlers.WithAuthorizedActions(authResults.FetchActionSetForId(ctx, r.GetPublicId(), IdActions).Strings()))
	}

	item, err := toProto(ctx, r, prs, rgs, outputOpts...)
	if err != nil {
		return nil, err
	}

	return &pbs.UpdateRoleResponse{Item: item}, nil
}

// DeleteRole implements the interface pbs.RoleServiceServer.
func (s Service) DeleteRole(ctx context.Context, req *pbs.DeleteRoleRequest) (*pbs.DeleteRoleResponse, error) {
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

// AddRolePrincipals implements the interface pbs.RoleServiceServer.
func (s Service) AddRolePrincipals(ctx context.Context, req *pbs.AddRolePrincipalsRequest) (*pbs.AddRolePrincipalsResponse, error) {
	const op = "roles.(Service).AddRolePrincipals"

	if err := validateAddRolePrincipalsRequest(req); err != nil {
		return nil, err
	}
	authResults := s.authResult(ctx, req.GetId(), action.AddPrincipals)
	if authResults.Error != nil {
		return nil, authResults.Error
	}
	r, prs, rgs, err := s.addPrinciplesInRepo(ctx, req.GetId(), req.GetPrincipalIds(), req.GetVersion())
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
		outputOpts = append(outputOpts, handlers.WithAuthorizedActions(authResults.FetchActionSetForId(ctx, r.GetPublicId(), IdActions).Strings()))
	}

	item, err := toProto(ctx, r, prs, rgs, outputOpts...)
	if err != nil {
		return nil, err
	}

	return &pbs.AddRolePrincipalsResponse{Item: item}, nil
}

// SetRolePrincipals implements the interface pbs.RoleServiceServer.
func (s Service) SetRolePrincipals(ctx context.Context, req *pbs.SetRolePrincipalsRequest) (*pbs.SetRolePrincipalsResponse, error) {
	const op = "roles.(Service).SetRolePrincipals"

	if err := validateSetRolePrincipalsRequest(req); err != nil {
		return nil, err
	}
	authResults := s.authResult(ctx, req.GetId(), action.SetPrincipals)
	if authResults.Error != nil {
		return nil, authResults.Error
	}
	r, prs, rgs, err := s.setPrinciplesInRepo(ctx, req.GetId(), req.GetPrincipalIds(), req.GetVersion())
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
		outputOpts = append(outputOpts, handlers.WithAuthorizedActions(authResults.FetchActionSetForId(ctx, r.GetPublicId(), IdActions).Strings()))
	}

	item, err := toProto(ctx, r, prs, rgs, outputOpts...)
	if err != nil {
		return nil, err
	}

	return &pbs.SetRolePrincipalsResponse{Item: item}, nil
}

// RemoveRolePrincipals implements the interface pbs.RoleServiceServer.
func (s Service) RemoveRolePrincipals(ctx context.Context, req *pbs.RemoveRolePrincipalsRequest) (*pbs.RemoveRolePrincipalsResponse, error) {
	const op = "roles.(Service).RemoveRolePrincipals"

	if err := validateRemoveRolePrincipalsRequest(req); err != nil {
		return nil, err
	}
	authResults := s.authResult(ctx, req.GetId(), action.RemovePrincipals)
	if authResults.Error != nil {
		return nil, authResults.Error
	}
	r, prs, rgs, err := s.removePrinciplesInRepo(ctx, req.GetId(), req.GetPrincipalIds(), req.GetVersion())
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
		outputOpts = append(outputOpts, handlers.WithAuthorizedActions(authResults.FetchActionSetForId(ctx, r.GetPublicId(), IdActions).Strings()))
	}

	item, err := toProto(ctx, r, prs, rgs, outputOpts...)
	if err != nil {
		return nil, err
	}

	return &pbs.RemoveRolePrincipalsResponse{Item: item}, nil
}

// AddRoleGrants implements the interface pbs.RoleServiceServer.
func (s Service) AddRoleGrants(ctx context.Context, req *pbs.AddRoleGrantsRequest) (*pbs.AddRoleGrantsResponse, error) {
	const op = "roles.(Service).AddRoleGrants"

	if err := validateAddRoleGrantsRequest(req); err != nil {
		return nil, err
	}
	authResults := s.authResult(ctx, req.GetId(), action.AddGrants)
	if authResults.Error != nil {
		return nil, authResults.Error
	}
	r, prs, rgs, err := s.addGrantsInRepo(ctx, req.GetId(), req.GetGrantStrings(), req.GetVersion())
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
		outputOpts = append(outputOpts, handlers.WithAuthorizedActions(authResults.FetchActionSetForId(ctx, r.GetPublicId(), IdActions).Strings()))
	}

	item, err := toProto(ctx, r, prs, rgs, outputOpts...)
	if err != nil {
		return nil, err
	}

	return &pbs.AddRoleGrantsResponse{Item: item}, nil
}

// SetRoleGrants implements the interface pbs.RoleServiceServer.
func (s Service) SetRoleGrants(ctx context.Context, req *pbs.SetRoleGrantsRequest) (*pbs.SetRoleGrantsResponse, error) {
	const op = "roles.(Service).SetRoleGrants"

	if err := validateSetRoleGrantsRequest(req); err != nil {
		return nil, err
	}
	authResults := s.authResult(ctx, req.GetId(), action.SetGrants)
	if authResults.Error != nil {
		return nil, authResults.Error
	}
	r, prs, rgs, err := s.setGrantsInRepo(ctx, req.GetId(), req.GetGrantStrings(), req.GetVersion())
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
		outputOpts = append(outputOpts, handlers.WithAuthorizedActions(authResults.FetchActionSetForId(ctx, r.GetPublicId(), IdActions).Strings()))
	}

	item, err := toProto(ctx, r, prs, rgs, outputOpts...)
	if err != nil {
		return nil, err
	}

	return &pbs.SetRoleGrantsResponse{Item: item}, nil
}

// RemoveRoleGrants implements the interface pbs.RoleServiceServer.
func (s Service) RemoveRoleGrants(ctx context.Context, req *pbs.RemoveRoleGrantsRequest) (*pbs.RemoveRoleGrantsResponse, error) {
	const op = "roles.(Service).RemoveRoleGrants"

	if err := validateRemoveRoleGrantsRequest(req); err != nil {
		return nil, err
	}
	authResults := s.authResult(ctx, req.GetId(), action.RemoveGrants)
	if authResults.Error != nil {
		return nil, authResults.Error
	}
	r, prs, rgs, err := s.removeGrantsInRepo(ctx, req.GetId(), req.GetGrantStrings(), req.GetVersion())
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
		outputOpts = append(outputOpts, handlers.WithAuthorizedActions(authResults.FetchActionSetForId(ctx, r.GetPublicId(), IdActions).Strings()))
	}

	item, err := toProto(ctx, r, prs, rgs, outputOpts...)
	if err != nil {
		return nil, err
	}

	return &pbs.RemoveRoleGrantsResponse{Item: item}, nil
}

func (s Service) getFromRepo(ctx context.Context, id string) (*iam.Role, []*iam.PrincipalRole, []*iam.RoleGrant, error) {
	repo, err := s.repoFn()
	if err != nil {
		return nil, nil, nil, err
	}
	out, pr, roleGrants, err := repo.LookupRole(ctx, id)
	if err != nil {
		if errors.IsNotFoundError(err) {
			return nil, nil, nil, handlers.NotFoundErrorf("Role %q doesn't exist.", id)
		}
		return nil, nil, nil, err
	}
	if out == nil {
		return nil, nil, nil, handlers.NotFoundErrorf("Role %q doesn't exist.", id)
	}
	return out, pr, roleGrants, nil
}

func (s Service) createInRepo(ctx context.Context, scopeId string, item *pb.Role) (*iam.Role, error) {
	const op = "roles.(Service).createInRepo"
	var opts []iam.Option
	if item.GetName() != nil {
		opts = append(opts, iam.WithName(item.GetName().GetValue()))
	}
	if item.GetDescription() != nil {
		opts = append(opts, iam.WithDescription(item.GetDescription().GetValue()))
	}
	if item.GetGrantScopeId() != nil {
		opts = append(opts, iam.WithGrantScopeId(item.GetGrantScopeId().GetValue()))
	}
	u, err := iam.NewRole(scopeId, opts...)
	if err != nil {
		return nil, handlers.ApiErrorWithCodeAndMessage(codes.Internal, "Unable to build role for creation: %v.", err)
	}
	repo, err := s.repoFn()
	if err != nil {
		return nil, err
	}
	out, err := repo.CreateRole(ctx, u)
	if err != nil {
		return nil, errors.Wrap(ctx, err, op)
	}
	if out == nil {
		return nil, handlers.ApiErrorWithCodeAndMessage(codes.Internal, "Unable to create role but no error returned from repository.")
	}
	return out, nil
}

func (s Service) updateInRepo(ctx context.Context, scopeId, id string, mask []string, item *pb.Role) (*iam.Role, []*iam.PrincipalRole, []*iam.RoleGrant, error) {
	const op = "roles.(Service).updateInRepo"
	var opts []iam.Option
	if desc := item.GetDescription(); desc != nil {
		opts = append(opts, iam.WithDescription(desc.GetValue()))
	}
	if name := item.GetName(); name != nil {
		opts = append(opts, iam.WithName(name.GetValue()))
	}
	if grantScopeId := item.GetGrantScopeId(); grantScopeId != nil {
		opts = append(opts, iam.WithGrantScopeId(grantScopeId.GetValue()))
	}
	version := item.GetVersion()

	u, err := iam.NewRole(scopeId, opts...)
	if err != nil {
		return nil, nil, nil, handlers.ApiErrorWithCodeAndMessage(codes.Internal, "Unable to build role for update: %v.", err)
	}
	u.PublicId = id
	dbMask := maskManager.Translate(mask)
	if len(dbMask) == 0 {
		return nil, nil, nil, handlers.InvalidArgumentErrorf("No valid fields included in the update mask.", map[string]string{"update_mask": "No valid fields provided in the update mask."})
	}
	repo, err := s.repoFn()
	if err != nil {
		return nil, nil, nil, err
	}
	out, pr, gr, rowsUpdated, err := repo.UpdateRole(ctx, u, version, dbMask)
	if err != nil {
		return nil, nil, nil, errors.Wrap(ctx, err, op)
	}
	if rowsUpdated == 0 {
		return nil, nil, nil, handlers.NotFoundErrorf("Role %q doesn't exist or incorrect version provided.", id)
	}
	return out, pr, gr, nil
}

func (s Service) deleteFromRepo(ctx context.Context, id string) (bool, error) {
	const op = "roles.(Service).deleteFromRepo"
	repo, err := s.repoFn()
	if err != nil {
		return false, err
	}
	rows, err := repo.DeleteRole(ctx, id)
	if err != nil {
		if errors.IsNotFoundError(err) {
			return false, nil
		}
		return false, errors.Wrap(ctx, err, op, errors.WithMsg("unable to delete role"))
	}
	return rows > 0, nil
}

func (s Service) listFromRepo(ctx context.Context, scopeIds []string) ([]*iam.Role, error) {
	repo, err := s.repoFn()
	if err != nil {
		return nil, err
	}
	rl, err := repo.ListRoles(ctx, scopeIds)
	if err != nil {
		return nil, err
	}
	return rl, nil
}

func (s Service) addPrinciplesInRepo(ctx context.Context, roleId string, principalIds []string, version uint32) (*iam.Role, []*iam.PrincipalRole, []*iam.RoleGrant, error) {
	const op = "roles.(Service).addPrincpleInRepo"
	repo, err := s.repoFn()
	if err != nil {
		return nil, nil, nil, err
	}
	_, err = repo.AddPrincipalRoles(ctx, roleId, version, strutil.RemoveDuplicates(principalIds, false))
	if err != nil {
		// TODO: Figure out a way to surface more helpful error info beyond the Internal error.
		return nil, nil, nil, handlers.ApiErrorWithCodeAndMessage(codes.Internal, "Unable to add principals to role: %v.", err)
	}
	out, pr, roleGrants, err := repo.LookupRole(ctx, roleId)
	if err != nil {
		return nil, nil, nil, errors.Wrap(ctx, err, op, errors.WithMsg("unable to look up role after adding principals"))
	}
	if out == nil {
		return nil, nil, nil, handlers.ApiErrorWithCodeAndMessage(codes.Internal, "Unable to lookup role after adding principals to it.")
	}
	return out, pr, roleGrants, nil
}

func (s Service) setPrinciplesInRepo(ctx context.Context, roleId string, principalIds []string, version uint32) (*iam.Role, []*iam.PrincipalRole, []*iam.RoleGrant, error) {
	const op = "roles.(Service).setPrinciplesInRepo"
	repo, err := s.repoFn()
	if err != nil {
		return nil, nil, nil, err
	}
	_, _, err = repo.SetPrincipalRoles(ctx, roleId, version, strutil.RemoveDuplicates(principalIds, false))
	if err != nil {
		// TODO: Figure out a way to surface more helpful error info beyond the Internal error.
		return nil, nil, nil, handlers.ApiErrorWithCodeAndMessage(codes.Internal, "Unable to set principals on role: %v.", err)
	}
	out, pr, roleGrants, err := repo.LookupRole(ctx, roleId)
	if err != nil {
		return nil, nil, nil, errors.Wrap(ctx, err, op, errors.WithMsg("unable to look up role after setting principals"))
	}
	if out == nil {
		return nil, nil, nil, handlers.ApiErrorWithCodeAndMessage(codes.Internal, "Unable to lookup role after setting principals for it.")
	}
	return out, pr, roleGrants, nil
}

func (s Service) removePrinciplesInRepo(ctx context.Context, roleId string, principalIds []string, version uint32) (*iam.Role, []*iam.PrincipalRole, []*iam.RoleGrant, error) {
	const op = "roles.(Service).removePrinciplesInRepo"
	repo, err := s.repoFn()
	if err != nil {
		return nil, nil, nil, err
	}
	_, err = repo.DeletePrincipalRoles(ctx, roleId, version, strutil.RemoveDuplicates(principalIds, false))
	if err != nil {
		// TODO: Figure out a way to surface more helpful error info beyond the Internal error.
		return nil, nil, nil, handlers.ApiErrorWithCodeAndMessage(codes.Internal, "Unable to remove principals from role: %v.", err)
	}
	out, pr, roleGrants, err := repo.LookupRole(ctx, roleId)
	if err != nil {
		return nil, nil, nil, errors.Wrap(ctx, err, op, errors.WithMsg("unable to look up role after removing principals"))
	}
	if out == nil {
		return nil, nil, nil, handlers.ApiErrorWithCodeAndMessage(codes.Internal, "Unable to lookup role after removing principals from it.")
	}
	return out, pr, roleGrants, nil
}

func (s Service) addGrantsInRepo(ctx context.Context, roleId string, grants []string, version uint32) (*iam.Role, []*iam.PrincipalRole, []*iam.RoleGrant, error) {
	const op = "service.(Service).addGrantsInRepo"
	repo, err := s.repoFn()
	if err != nil {
		return nil, nil, nil, err
	}
	_, err = repo.AddRoleGrants(ctx, roleId, version, strutil.RemoveDuplicates(grants, false))
	if err != nil {
		// TODO: Figure out a way to surface more helpful error info beyond the Internal error.
		return nil, nil, nil, handlers.ApiErrorWithCodeAndMessage(codes.Internal, "Unable to add grants to role: %v.", err)
	}
	out, pr, roleGrants, err := repo.LookupRole(ctx, roleId)
	if err != nil {
		return nil, nil, nil, errors.Wrap(ctx, err, op, errors.WithMsg("unable to look up role after adding grants"))
	}
	if out == nil {
		return nil, nil, nil, handlers.ApiErrorWithCodeAndMessage(codes.Internal, "Unable to lookup role after adding grants to it.")
	}
	return out, pr, roleGrants, nil
}

func (s Service) setGrantsInRepo(ctx context.Context, roleId string, grants []string, version uint32) (*iam.Role, []*iam.PrincipalRole, []*iam.RoleGrant, error) {
	const op = "roles.(Service).setGrantsInRepo"
	repo, err := s.repoFn()
	if err != nil {
		return nil, nil, nil, err
	}
	// If no grant was provided, we clear the grants.
	if grants == nil {
		grants = []string{}
	}
	_, _, err = repo.SetRoleGrants(ctx, roleId, version, strutil.RemoveDuplicates(grants, false))
	if err != nil {
		// TODO: Figure out a way to surface more helpful error info beyond the Internal error.
		return nil, nil, nil, handlers.ApiErrorWithCodeAndMessage(codes.Internal, "Unable to set grants on role: %v.", err)
	}
	out, pr, roleGrants, err := repo.LookupRole(ctx, roleId)
	if err != nil {
		return nil, nil, nil, errors.Wrap(ctx, err, op, errors.WithMsg("unable to look up role after setting grants"))
	}
	if out == nil {
		return nil, nil, nil, handlers.ApiErrorWithCodeAndMessage(codes.Internal, "Unable to lookup role after setting grants on it.")
	}
	return out, pr, roleGrants, nil
}

func (s Service) removeGrantsInRepo(ctx context.Context, roleId string, grants []string, version uint32) (*iam.Role, []*iam.PrincipalRole, []*iam.RoleGrant, error) {
	const op = "roles.(Service).removeGrantsInRepo"
	repo, err := s.repoFn()
	if err != nil {
		return nil, nil, nil, err
	}
	_, err = repo.DeleteRoleGrants(ctx, roleId, version, strutil.RemoveDuplicates(grants, false))
	if err != nil {
		// TODO: Figure out a way to surface more helpful error info beyond the Internal error.
		return nil, nil, nil, handlers.ApiErrorWithCodeAndMessage(codes.Internal, "Unable to remove grants from role: %v", err)
	}
	out, pr, roleGrants, err := repo.LookupRole(ctx, roleId)
	if err != nil {
		return nil, nil, nil, errors.Wrap(ctx, err, op, errors.WithMsg("uable to look up role after removing grant"))
	}
	if out == nil {
		return nil, nil, nil, handlers.ApiErrorWithCodeAndMessage(codes.Internal, "Unable to lookup role after removing grants from it.")
	}
	return out, pr, roleGrants, nil
}

func (s Service) authResult(ctx context.Context, id string, a action.Type) auth.VerifyResults {
	res := auth.VerifyResults{}
	repo, err := s.repoFn()
	if err != nil {
		res.Error = err
		return res
	}

	var parentId string
	opts := []auth.Option{auth.WithType(resource.Role), auth.WithAction(a)}
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
		r, _, _, err := repo.LookupRole(ctx, id)
		if err != nil {
			res.Error = err
			return res
		}
		if r == nil {
			res.Error = handlers.NotFoundError()
			return res
		}
		parentId = r.GetScopeId()
		opts = append(opts, auth.WithId(id))
	}
	opts = append(opts, auth.WithScopeId(parentId))
	return auth.Verify(ctx, opts...)
}

func toProto(ctx context.Context, in *iam.Role, principals []*iam.PrincipalRole, grants []*iam.RoleGrant, opt ...handlers.Option) (*pb.Role, error) {
	opts := handlers.GetOpts(opt...)
	if opts.WithOutputFields == nil {
		return nil, handlers.ApiErrorWithCodeAndMessage(codes.Internal, "output fields not found when building role proto")
	}
	outputFields := *opts.WithOutputFields

	out := pb.Role{}
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
	if outputFields.Has(globals.ScopeField) {
		out.Scope = opts.WithScope
	}
	if outputFields.Has(globals.AuthorizedActionsField) {
		out.AuthorizedActions = opts.WithAuthorizedActions
	}
	if outputFields.Has(globals.GrantScopeIdField) && in.GetGrantScopeId() != "" {
		out.GrantScopeId = &wrapperspb.StringValue{Value: in.GetGrantScopeId()}
	}
	if outputFields.Has(globals.PrincipalIdsField) {
		for _, p := range principals {
			out.PrincipalIds = append(out.PrincipalIds, p.GetPrincipalId())
		}
	}
	if outputFields.Has(globals.PrincipalsField) {
		for _, p := range principals {
			principal := &pb.Principal{
				Id:      p.GetPrincipalId(),
				Type:    p.GetType(),
				ScopeId: p.GetPrincipalScopeId(),
			}
			out.Principals = append(out.Principals, principal)
		}
	}
	if outputFields.Has(globals.GrantStringsField) {
		for _, g := range grants {
			out.GrantStrings = append(out.GrantStrings, g.GetRawGrant())
		}
	}
	if outputFields.Has(globals.GrantsField) {
		for _, g := range grants {
			parsed, err := perms.Parse(in.GetGrantScopeId(), g.GetRawGrant())
			if err != nil {
				// This should never happen as we validate on the way in, but let's
				// return what we can since we are still returning the raw grant
				out.Grants = append(out.Grants, &pb.Grant{
					Raw:       g.GetRawGrant(),
					Canonical: "<parse_error>",
					Json:      nil,
				})
			} else {
				_, actions := parsed.Actions()
				out.Grants = append(out.Grants, &pb.Grant{
					Raw:       g.GetRawGrant(),
					Canonical: g.GetCanonicalGrant(),
					Json: &pb.GrantJson{
						Id:      parsed.Id(),
						Type:    parsed.Type().String(),
						Actions: actions,
					},
				})
			}
		}
	}

	return &out, nil
}

// A validateX method should exist for each method above.  These methods do not make calls to any backing service but enforce
// requirements on the structure of the request.  They verify that:
//   - The path passed in is correctly formatted
//   - All required parameters are set
//   - There are no conflicting parameters provided
func validateGetRequest(req *pbs.GetRoleRequest) error {
	return handlers.ValidateGetRequest(handlers.NoopValidatorFn, req, iam.RolePrefix)
}

func validateCreateRequest(req *pbs.CreateRoleRequest) error {
	return handlers.ValidateCreateRequest(req.GetItem(), func() map[string]string {
		badFields := map[string]string{}
		item := req.GetItem()
		if !handlers.ValidId(handlers.Id(item.GetScopeId()), scope.Org.Prefix()) &&
			!handlers.ValidId(handlers.Id(item.GetScopeId()), scope.Project.Prefix()) &&
			scope.Global.String() != item.GetScopeId() {
			badFields["scope_id"] = "This field is missing or improperly formatted."
		}
		if item.GetGrantScopeId() != nil && handlers.ValidId(handlers.Id(item.GetScopeId()), scope.Project.Prefix()) {
			if item.GetGrantScopeId().GetValue() != item.GetScopeId() {
				badFields["grant_scope_id"] = "When the role is in a project scope this value must be that project's scope ID."
			}
		}
		if item.GetPrincipals() != nil {
			badFields["principals"] = "This is a read only field."
		}
		if item.GetGrants() != nil {
			badFields["grant_strings"] = "This is a read only field."
		}
		return badFields
	})
}

func validateUpdateRequest(req *pbs.UpdateRoleRequest) error {
	return handlers.ValidateUpdateRequest(req, req.GetItem(), func() map[string]string {
		badFields := map[string]string{}
		if req.GetItem().GetPrincipalIds() != nil {
			badFields["principal_ids"] = "This is a read only field and cannot be specified in an update request."
		}
		if req.GetItem().GetPrincipals() != nil {
			badFields["principals"] = "This is a read only field and cannot be specified in an update request."
		}
		if req.GetItem().GetGrants() != nil {
			badFields["grants"] = "This is a read only field and cannot be specified in an update request."
		}
		if req.GetItem().GetGrantStrings() != nil {
			badFields["grant_strings"] = "This is a read only field and cannot be specified in an update request."
		}
		if req.GetItem().GetGrantScopeId() != nil && handlers.ValidId(handlers.Id(req.GetItem().GetScopeId()), scope.Project.Prefix()) {
			if req.GetItem().GetGrantScopeId().GetValue() != req.GetItem().GetScopeId() {
				badFields["grant_scope_id"] = "When the role is in a project scope this value must be that project's scope ID"
			}
		}
		return badFields
	}, iam.RolePrefix)
}

func validateDeleteRequest(req *pbs.DeleteRoleRequest) error {
	return handlers.ValidateDeleteRequest(func() map[string]string {
		return nil
	}, req, iam.RolePrefix)
}

func validateListRequest(req *pbs.ListRolesRequest) error {
	badFields := map[string]string{}
	if !handlers.ValidId(handlers.Id(req.GetScopeId()), scope.Org.Prefix()) &&
		!handlers.ValidId(handlers.Id(req.GetScopeId()), scope.Project.Prefix()) &&
		req.GetScopeId() != scope.Global.String() {
		badFields["scope_id"] = "Improperly formatted field."
	}
	if _, err := handlers.NewFilter(req.GetFilter()); err != nil {
		badFields["filter"] = fmt.Sprintf("This field could not be parsed. %v", err)
	}
	if len(badFields) > 0 {
		return handlers.InvalidArgumentErrorf("Improperly formatted identifier.", badFields)
	}
	return nil
}

func validateAddRolePrincipalsRequest(req *pbs.AddRolePrincipalsRequest) error {
	badFields := map[string]string{}
	if !handlers.ValidId(handlers.Id(req.GetId()), iam.RolePrefix) {
		badFields["id"] = "Incorrectly formatted identifier."
	}
	if req.GetVersion() == 0 {
		badFields["version"] = "Required field."
	}
	if len(req.GetPrincipalIds()) == 0 {
		badFields["principal_ids"] = "Must be non-empty."
	}
	for _, id := range req.GetPrincipalIds() {
		if !handlers.ValidId(handlers.Id(id), iam.GroupPrefix) &&
			!handlers.ValidId(handlers.Id(id), iam.UserPrefix) &&
			!handlers.ValidId(handlers.Id(id), intglobals.OidcManagedGroupPrefix) {
			badFields["principal_ids"] = "Must only have valid user, group, and/or managed group ids."
			break
		}
		if id == "u_recovery" {
			badFields["principal_ids"] = "u_recovery cannot be assigned to a role"
			break
		}
	}
	if len(badFields) > 0 {
		return handlers.InvalidArgumentErrorf("Errors in provided fields.", badFields)
	}
	return nil
}

func validateSetRolePrincipalsRequest(req *pbs.SetRolePrincipalsRequest) error {
	badFields := map[string]string{}
	if !handlers.ValidId(handlers.Id(req.GetId()), iam.RolePrefix) {
		badFields["id"] = "Incorrectly formatted identifier."
	}
	if req.GetVersion() == 0 {
		badFields["version"] = "Required field."
	}
	for _, id := range req.GetPrincipalIds() {
		if !handlers.ValidId(handlers.Id(id), iam.GroupPrefix) &&
			!handlers.ValidId(handlers.Id(id), iam.UserPrefix) &&
			!handlers.ValidId(handlers.Id(id), intglobals.OidcManagedGroupPrefix) {
			badFields["principal_ids"] = "Must only have valid user, group, and/or managed group ids."
			break
		}
		if id == "u_recovery" {
			badFields["principal_ids"] = "u_recovery cannot be assigned to a role"
			break
		}
	}
	if len(badFields) > 0 {
		return handlers.InvalidArgumentErrorf("Errors in provided fields.", badFields)
	}
	return nil
}

func validateRemoveRolePrincipalsRequest(req *pbs.RemoveRolePrincipalsRequest) error {
	badFields := map[string]string{}
	if !handlers.ValidId(handlers.Id(req.GetId()), iam.RolePrefix) {
		badFields["id"] = "Incorrectly formatted identifier."
	}
	if req.GetVersion() == 0 {
		badFields["version"] = "Required field."
	}
	if len(req.GetPrincipalIds()) == 0 {
		badFields["principal_ids"] = "Must be non-empty."
	}
	for _, id := range req.GetPrincipalIds() {
		if !handlers.ValidId(handlers.Id(id), iam.GroupPrefix) &&
			!handlers.ValidId(handlers.Id(id), iam.UserPrefix) &&
			!handlers.ValidId(handlers.Id(id), intglobals.OidcManagedGroupPrefix) {
			badFields["principal_ids"] = "Must only have valid user, group, and/or managed group ids."
			break
		}
	}
	if len(badFields) > 0 {
		return handlers.InvalidArgumentErrorf("Errors in provided fields.", badFields)
	}
	return nil
}

func validateAddRoleGrantsRequest(req *pbs.AddRoleGrantsRequest) error {
	badFields := map[string]string{}
	if !handlers.ValidId(handlers.Id(req.GetId()), iam.RolePrefix) {
		badFields["id"] = "Incorrectly formatted identifier."
	}
	if req.GetVersion() == 0 {
		badFields["version"] = "Required field."
	}
	if len(req.GetGrantStrings()) == 0 {
		badFields["grant_strings"] = "Must be non-empty."
	}
	for _, v := range req.GetGrantStrings() {
		if len(v) == 0 {
			badFields["grant_strings"] = "Grant strings must not be empty."
			break
		}
		grant, err := perms.Parse("p_anything", v)
		if err != nil {
			badFields["grant_strings"] = fmt.Sprintf("Improperly formatted grant %q.", v)
			break
		}
		_, actStrs := grant.Actions()
		for _, actStr := range actStrs {
			if depAct := action.DeprecatedMap[actStr]; depAct != action.Unknown {
				badFields["grant_strings"] = fmt.Sprintf("Action %q has been deprecated and is not allowed to be set in grants. Use %q instead.", actStr, depAct.String())
			}
		}
	}
	if len(badFields) > 0 {
		return handlers.InvalidArgumentErrorf("Errors in provided fields.", badFields)
	}
	return nil
}

func validateSetRoleGrantsRequest(req *pbs.SetRoleGrantsRequest) error {
	badFields := map[string]string{}
	if !handlers.ValidId(handlers.Id(req.GetId()), iam.RolePrefix) {
		badFields["id"] = "Incorrectly formatted identifier."
	}
	if req.GetVersion() == 0 {
		badFields["version"] = "Required field."
	}
	for _, v := range req.GetGrantStrings() {
		if len(v) == 0 {
			badFields["grant_strings"] = "Grant strings must not be empty."
			break
		}
		grant, err := perms.Parse("p_anything", v)
		if err != nil {
			badFields["grant_strings"] = fmt.Sprintf("Improperly formatted grant %q.", v)
			break
		}
		_, actStrs := grant.Actions()
		for _, actStr := range actStrs {
			if depAct := action.DeprecatedMap[actStr]; depAct != action.Unknown {
				badFields["grant_strings"] = fmt.Sprintf("Action %q has been deprecated and is not allowed to be set in grants. Use %q instead.", actStr, depAct.String())
			}
		}
	}
	if len(badFields) > 0 {
		return handlers.InvalidArgumentErrorf("Errors in provided fields.", badFields)
	}
	return nil
}

func validateRemoveRoleGrantsRequest(req *pbs.RemoveRoleGrantsRequest) error {
	badFields := map[string]string{}
	if !handlers.ValidId(handlers.Id(req.GetId()), iam.RolePrefix) {
		badFields["id"] = "Incorrectly formatted identifier."
	}
	if req.GetVersion() == 0 {
		badFields["version"] = "Required field."
	}
	if len(req.GetGrantStrings()) == 0 {
		badFields["grant_strings"] = "Must be non-empty."
	}
	for _, v := range req.GetGrantStrings() {
		if len(v) == 0 {
			badFields["grant_strings"] = "Grant strings must not be empty."
			break
		}
		if _, err := perms.Parse("p_anything", v); err != nil {
			badFields["grant_strings"] = fmt.Sprintf("Improperly formatted grant %q.", v)
			break
		}
		// NOTE: we don't do a deprecation check here because it's fine to allow people to remove deprecated grants.
	}
	if len(badFields) > 0 {
		return handlers.InvalidArgumentErrorf("Errors in provided fields.", badFields)
	}
	return nil
}
