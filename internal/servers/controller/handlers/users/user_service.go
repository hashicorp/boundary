package users

import (
	"context"
	"errors"
	"fmt"

	"github.com/hashicorp/boundary/internal/auth"
	"github.com/hashicorp/boundary/internal/auth/password"
	"github.com/hashicorp/boundary/internal/db"
	pb "github.com/hashicorp/boundary/internal/gen/controller/api/resources/users"
	pbs "github.com/hashicorp/boundary/internal/gen/controller/api/services"
	"github.com/hashicorp/boundary/internal/iam"
	"github.com/hashicorp/boundary/internal/iam/store"
	"github.com/hashicorp/boundary/internal/servers/controller/common"
	"github.com/hashicorp/boundary/internal/servers/controller/handlers"
	"github.com/hashicorp/boundary/internal/types/action"
	"github.com/hashicorp/boundary/internal/types/resource"
	"github.com/hashicorp/boundary/internal/types/scope"
	"github.com/hashicorp/boundary/sdk/strutil"
	"google.golang.org/grpc/codes"
	"google.golang.org/protobuf/types/known/wrapperspb"
)

var (
	maskManager handlers.MaskManager
)

func init() {
	var err error
	if maskManager, err = handlers.NewMaskManager(&store.User{}, &pb.User{}); err != nil {
		panic(err)
	}
}

// Service handles request as described by the pbs.UserServiceServer interface.
type Service struct {
	repoFn common.IamRepoFactory
}

// NewService returns a user service which handles user related requests to boundary.
func NewService(repo common.IamRepoFactory) (Service, error) {
	if repo == nil {
		return Service{}, fmt.Errorf("nil iam repository provided")
	}
	return Service{repoFn: repo}, nil
}

var _ pbs.UserServiceServer = Service{}

// ListUsers implements the interface pbs.UserServiceServer.
func (s Service) ListUsers(ctx context.Context, req *pbs.ListUsersRequest) (*pbs.ListUsersResponse, error) {
	if err := validateListRequest(req); err != nil {
		return nil, err
	}
	authResults := s.authResult(ctx, req.GetScopeId(), action.List)
	if authResults.Error != nil {
		return nil, authResults.Error
	}
	ul, err := s.listFromRepo(ctx, req.GetScopeId())
	if err != nil {
		return nil, err
	}
	for _, item := range ul {
		item.Scope = authResults.Scope
	}
	return &pbs.ListUsersResponse{Items: ul}, nil
}

// GetUsers implements the interface pbs.UserServiceServer.
func (s Service) GetUser(ctx context.Context, req *pbs.GetUserRequest) (*pbs.GetUserResponse, error) {
	if err := validateGetRequest(req); err != nil {
		return nil, err
	}
	authResults := s.authResult(ctx, req.GetId(), action.Read)
	if authResults.Error != nil {
		return nil, authResults.Error
	}
	u, err := s.getFromRepo(ctx, req.GetId())
	if err != nil {
		return nil, err
	}
	u.Scope = authResults.Scope
	return &pbs.GetUserResponse{Item: u}, nil
}

// CreateUser implements the interface pbs.UserServiceServer.
func (s Service) CreateUser(ctx context.Context, req *pbs.CreateUserRequest) (*pbs.CreateUserResponse, error) {
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
	u.Scope = authResults.Scope
	return &pbs.CreateUserResponse{Item: u, Uri: fmt.Sprintf("users/%s", u.GetId())}, nil
}

// UpdateUser implements the interface pbs.UserServiceServer.
func (s Service) UpdateUser(ctx context.Context, req *pbs.UpdateUserRequest) (*pbs.UpdateUserResponse, error) {
	if err := validateUpdateRequest(req); err != nil {
		return nil, err
	}
	authResults := s.authResult(ctx, req.GetId(), action.Update)
	if authResults.Error != nil {
		return nil, authResults.Error
	}
	u, err := s.updateInRepo(ctx, authResults.Scope.GetId(), req.GetId(), req.GetUpdateMask().GetPaths(), req.GetItem())
	if err != nil {
		return nil, err
	}
	u.Scope = authResults.Scope
	return &pbs.UpdateUserResponse{Item: u}, nil
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
	if err := validateAddUserAccountsRequest(req); err != nil {
		return nil, err
	}
	authResults := s.authResult(ctx, req.GetId(), action.AddAccounts)
	if authResults.Error != nil {
		return nil, authResults.Error
	}
	u, err := s.addInRepo(ctx, req.GetId(), req.GetAccountIds(), req.GetVersion())
	if err != nil {
		return nil, err
	}
	u.Scope = authResults.Scope
	return &pbs.AddUserAccountsResponse{Item: u}, nil
}

// SetUserAccounts implements the interface pbs.GroupServiceServer.
func (s Service) SetUserAccounts(ctx context.Context, req *pbs.SetUserAccountsRequest) (*pbs.SetUserAccountsResponse, error) {
	if err := validateSetUserAccountsRequest(req); err != nil {
		return nil, err
	}
	authResults := s.authResult(ctx, req.GetId(), action.SetAccounts)
	if authResults.Error != nil {
		return nil, authResults.Error
	}
	u, err := s.setInRepo(ctx, req.GetId(), req.GetAccountIds(), req.GetVersion())
	if err != nil {
		return nil, err
	}
	u.Scope = authResults.Scope
	return &pbs.SetUserAccountsResponse{Item: u}, nil
}

// RemoveUserAccounts implements the interface pbs.GroupServiceServer.
func (s Service) RemoveUserAccounts(ctx context.Context, req *pbs.RemoveUserAccountsRequest) (*pbs.RemoveUserAccountsResponse, error) {
	if err := validateRemoveUserAccountsRequest(req); err != nil {
		return nil, err
	}
	authResults := s.authResult(ctx, req.GetId(), action.RemoveAccounts)
	if authResults.Error != nil {
		return nil, authResults.Error
	}
	u, err := s.removeInRepo(ctx, req.GetId(), req.GetAccountIds(), req.GetVersion())
	if err != nil {
		return nil, err
	}
	u.Scope = authResults.Scope
	return &pbs.RemoveUserAccountsResponse{Item: u}, nil
}

func (s Service) getFromRepo(ctx context.Context, id string) (*pb.User, error) {
	repo, err := s.repoFn()
	if err != nil {
		return nil, err
	}
	u, accts, err := repo.LookupUser(ctx, id)
	if err != nil {
		if errors.Is(err, db.ErrRecordNotFound) {
			return nil, handlers.NotFoundErrorf("User %q doesn't exist.", id)
		}
		return nil, err
	}
	if u == nil {
		return nil, handlers.NotFoundErrorf("User %q doesn't exist.", id)
	}
	return toProto(u, accts), nil
}

func (s Service) createInRepo(ctx context.Context, orgId string, item *pb.User) (*pb.User, error) {
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
		return nil, fmt.Errorf("unable to create user: %w", err)
	}
	if out == nil {
		return nil, handlers.ApiErrorWithCodeAndMessage(codes.Internal, "Unable to create user but no error returned from repository.")
	}
	return toProto(out, nil), nil
}

func (s Service) updateInRepo(ctx context.Context, orgId, id string, mask []string, item *pb.User) (*pb.User, error) {
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
		return nil, handlers.ApiErrorWithCodeAndMessage(codes.Internal, "Unable to build user for update: %v.", err)
	}
	u.PublicId = id
	dbMask := maskManager.Translate(mask)
	if len(dbMask) == 0 {
		return nil, handlers.InvalidArgumentErrorf("No valid fields included in the update mask.", map[string]string{"update_mask": "No valid fields provided in the update mask."})
	}
	repo, err := s.repoFn()
	if err != nil {
		return nil, err
	}
	out, accts, rowsUpdated, err := repo.UpdateUser(ctx, u, version, dbMask)
	if err != nil {
		return nil, fmt.Errorf("unable to update user: %w", err)
	}
	if rowsUpdated == 0 {
		return nil, handlers.NotFoundErrorf("User %q doesn't exist or incorrect version provided.", id)
	}
	return toProto(out, accts), nil
}

func (s Service) deleteFromRepo(ctx context.Context, id string) (bool, error) {
	repo, err := s.repoFn()
	if err != nil {
		return false, err
	}
	rows, err := repo.DeleteUser(ctx, id)
	if err != nil {
		if errors.Is(err, db.ErrRecordNotFound) {
			return false, nil
		}
		return false, fmt.Errorf("unable to delete user: %w", err)
	}
	return rows > 0, nil
}

func (s Service) listFromRepo(ctx context.Context, orgId string) ([]*pb.User, error) {
	repo, err := s.repoFn()
	if err != nil {
		return nil, err
	}
	ul, err := repo.ListUsers(ctx, orgId)
	if err != nil {
		return nil, err
	}
	var outUl []*pb.User
	for _, u := range ul {
		outUl = append(outUl, toProto(u, nil))
	}
	return outUl, nil
}

func (s Service) addInRepo(ctx context.Context, userId string, accountIds []string, version uint32) (*pb.User, error) {
	repo, err := s.repoFn()
	if err != nil {
		return nil, err
	}
	_, err = repo.AddUserAccounts(ctx, userId, version, strutil.RemoveDuplicates(accountIds, false))
	if err != nil {
		return nil, handlers.ApiErrorWithCodeAndMessage(codes.Internal, "Unable to add accounts to user: %v.", err)
	}
	out, accts, err := repo.LookupUser(ctx, userId)
	if err != nil {
		return nil, fmt.Errorf("unable to look up user after adding accounts: %w", err)
	}
	if out == nil {
		return nil, handlers.ApiErrorWithCodeAndMessage(codes.Internal, "Unable to lookup user after adding accounts to it.")
	}
	return toProto(out, accts), nil
}

func (s Service) setInRepo(ctx context.Context, userId string, accountIds []string, version uint32) (*pb.User, error) {
	repo, err := s.repoFn()
	if err != nil {
		return nil, err
	}
	_, err = repo.SetUserAccounts(ctx, userId, version, strutil.RemoveDuplicates(accountIds, false))
	if err != nil {
		return nil, handlers.ApiErrorWithCodeAndMessage(codes.Internal, "Unable to set accounts for the user: %v.", err)
	}
	out, accts, err := repo.LookupUser(ctx, userId)
	if err != nil {
		return nil, fmt.Errorf("unable to look up user after setting accounts: %w", err)
	}
	if out == nil {
		return nil, handlers.ApiErrorWithCodeAndMessage(codes.Internal, "Unable to lookup user after setting accounts for it.")
	}
	return toProto(out, accts), nil
}

func (s Service) removeInRepo(ctx context.Context, userId string, accountIds []string, version uint32) (*pb.User, error) {
	repo, err := s.repoFn()
	if err != nil {
		return nil, err
	}
	_, err = repo.DeleteUserAccounts(ctx, userId, version, strutil.RemoveDuplicates(accountIds, false))
	if err != nil {
		return nil, handlers.ApiErrorWithCodeAndMessage(codes.Internal, "Unable to remove accounts from user: %v.", err)
	}
	out, accts, err := repo.LookupUser(ctx, userId)
	if err != nil {
		return nil, fmt.Errorf("unable to look up user after removing accounts: %w", err)
	}
	if out == nil {
		return nil, handlers.ApiErrorWithCodeAndMessage(codes.Internal, "Unable to lookup user after removing accounts from it.")
	}
	return toProto(out, accts), nil
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

func toProto(in *iam.User, accts []string) *pb.User {
	out := pb.User{
		Id:          in.GetPublicId(),
		ScopeId:     in.GetScopeId(),
		CreatedTime: in.GetCreateTime().GetTimestamp(),
		UpdatedTime: in.GetUpdateTime().GetTimestamp(),
		Version:     in.GetVersion(),
		AccountIds:  accts,
	}
	if in.GetDescription() != "" {
		out.Description = &wrapperspb.StringValue{Value: in.GetDescription()}
	}
	if in.GetName() != "" {
		out.Name = &wrapperspb.StringValue{Value: in.GetName()}
	}
	for _, a := range accts {
		out.Accounts = append(out.Accounts, &pb.Account{
			Id: a,
			// TODO: Update this when an account can be associated with a user from a different scope.
			ScopeId: in.GetScopeId(),
		})
	}
	return &out
}

// A validateX method should exist for each method above.  These methods do not make calls to any backing service but enforce
// requirements on the structure of the request.  They verify that:
//  * The path passed in is correctly formatted
//  * All required parameters are set
//  * There are no conflicting parameters provided
func validateGetRequest(req *pbs.GetUserRequest) error {
	return handlers.ValidateGetRequest(iam.UserPrefix, req, handlers.NoopValidatorFn)
}

func validateCreateRequest(req *pbs.CreateUserRequest) error {
	return handlers.ValidateCreateRequest(req.GetItem(), func() map[string]string {
		badFields := map[string]string{}
		if !handlers.ValidId(scope.Org.Prefix(), req.GetItem().GetScopeId()) &&
			scope.Global.String() != req.GetItem().GetScopeId() {
			badFields["scope_id"] = "This field is missing or improperly formatted."
		}
		return badFields
	})
}

func validateUpdateRequest(req *pbs.UpdateUserRequest) error {
	return handlers.ValidateUpdateRequest(iam.UserPrefix, req, req.GetItem(), handlers.NoopValidatorFn)
}

func validateDeleteRequest(req *pbs.DeleteUserRequest) error {
	return handlers.ValidateDeleteRequest(iam.UserPrefix, req, handlers.NoopValidatorFn)
}

func validateListRequest(req *pbs.ListUsersRequest) error {
	badFields := map[string]string{}
	if !handlers.ValidId(scope.Org.Prefix(), req.GetScopeId()) &&
		req.GetScopeId() != scope.Global.String() {
		badFields["scope_id"] = "Invalidly formatted required identifer."
	}
	if len(badFields) > 0 {
		return handlers.InvalidArgumentErrorf("Improperly formatted identifier.", badFields)
	}
	return nil
}

func validateAddUserAccountsRequest(req *pbs.AddUserAccountsRequest) error {
	badFields := map[string]string{}
	if !handlers.ValidId(iam.UserPrefix, req.GetId()) {
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
		if !handlers.ValidId(password.AccountPrefix, a) {
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
	if !handlers.ValidId(iam.UserPrefix, req.GetId()) {
		badFields["id"] = "Incorrectly formatted identifier."
	}
	if req.GetVersion() == 0 {
		badFields["version"] = "Required field."
	}
	for _, a := range req.GetAccountIds() {
		// TODO: Increase the type of auth accounts that can be added to a user.
		if !handlers.ValidId(password.AccountPrefix, a) {
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
	if !handlers.ValidId(iam.UserPrefix, req.GetId()) {
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
		if !handlers.ValidId(password.AccountPrefix, a) {
			badFields["account_ids"] = "Values must be valid account ids."
			break
		}
	}
	if len(badFields) > 0 {
		return handlers.InvalidArgumentErrorf("Errors in provided fields.", badFields)
	}
	return nil
}
