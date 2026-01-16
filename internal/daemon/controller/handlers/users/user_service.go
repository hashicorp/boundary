// Copyright IBM Corp. 2020, 2025
// SPDX-License-Identifier: BUSL-1.1

package users

import (
	"context"
	"fmt"

	"github.com/hashicorp/boundary/globals"
	talias "github.com/hashicorp/boundary/internal/alias/target"
	"github.com/hashicorp/boundary/internal/daemon/controller/auth"
	"github.com/hashicorp/boundary/internal/daemon/controller/common"
	"github.com/hashicorp/boundary/internal/daemon/controller/common/scopeids"
	"github.com/hashicorp/boundary/internal/daemon/controller/handlers"
	"github.com/hashicorp/boundary/internal/daemon/controller/handlers/targets"
	"github.com/hashicorp/boundary/internal/errors"
	pbs "github.com/hashicorp/boundary/internal/gen/controller/api/services"
	"github.com/hashicorp/boundary/internal/iam"
	"github.com/hashicorp/boundary/internal/iam/store"
	"github.com/hashicorp/boundary/internal/listtoken"
	"github.com/hashicorp/boundary/internal/pagination"
	"github.com/hashicorp/boundary/internal/perms"
	"github.com/hashicorp/boundary/internal/requests"
	"github.com/hashicorp/boundary/internal/types/action"
	"github.com/hashicorp/boundary/internal/types/resource"
	"github.com/hashicorp/boundary/internal/types/scope"
	aliaspb "github.com/hashicorp/boundary/sdk/pbs/controller/api/resources/aliases"
	"github.com/hashicorp/boundary/sdk/pbs/controller/api/resources/scopes"
	pb "github.com/hashicorp/boundary/sdk/pbs/controller/api/resources/users"
	"github.com/hashicorp/go-secure-stdlib/strutil"
	"google.golang.org/grpc/codes"
	"google.golang.org/protobuf/types/known/wrapperspb"
)

var (
	maskManager handlers.MaskManager

	// IdActions contains the set of actions that can be performed on
	// individual resources
	IdActions = action.NewActionSet(
		action.NoOp,
		action.Read,
		action.Update,
		action.Delete,
		action.AddAccounts,
		action.SetAccounts,
		action.RemoveAccounts,
		action.ListResolvableAliases,
	)

	// CollectionActions contains the set of actions that can be performed on
	// this collection
	CollectionActions = action.NewActionSet(
		action.Create,
		action.List,
	)
)

func init() {
	var err error
	if maskManager, err = handlers.NewMaskManager(
		context.Background(),
		handlers.MaskDestination{&store.User{}},
		handlers.MaskSource{&pb.User{}},
	); err != nil {
		panic(err)
	}
	// TODO: refactor to remove IdActions and CollectionActions package variables
	action.RegisterResource(resource.User, IdActions, CollectionActions)
}

// Service handles request as described by the pbs.UserServiceServer interface.
type Service struct {
	pbs.UnsafeUserServiceServer

	repoFn      common.IamRepoFactory
	aliasRepoFn common.TargetAliasRepoFactory
	maxPageSize uint
}

var _ pbs.UserServiceServer = (*Service)(nil)

// NewService returns a user service which handles user related requests to boundary.
func NewService(ctx context.Context, repo common.IamRepoFactory, aliasRepoFn common.TargetAliasRepoFactory, maxPageSize uint) (Service, error) {
	const op = "users.NewService"
	switch {
	case repo == nil:
		return Service{}, errors.New(ctx, errors.InvalidParameter, op, "missing iam repository")
	case aliasRepoFn == nil:
		return Service{}, errors.New(ctx, errors.InvalidParameter, op, "missing alias repository")
	}
	if maxPageSize == 0 {
		maxPageSize = uint(globals.DefaultMaxPageSize)
	}
	return Service{repoFn: repo, aliasRepoFn: aliasRepoFn, maxPageSize: maxPageSize}, nil
}

// ListUsers implements the interface pbs.UserServiceServer.
func (s Service) ListUsers(ctx context.Context, req *pbs.ListUsersRequest) (*pbs.ListUsersResponse, error) {
	const op = "users.(Service).ListUsers"
	if err := validateListRequest(ctx, req); err != nil {
		return nil, err
	}
	authResults := s.authResult(ctx, req.GetScopeId(), action.List, req.GetRecursive())
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

	pageSize := int(s.maxPageSize)
	// Use the requested page size only if it is smaller than
	// the configured max.
	if req.GetPageSize() != 0 && uint(req.GetPageSize()) < s.maxPageSize {
		pageSize = int(req.GetPageSize())
	}

	var filterItemFn func(ctx context.Context, item *iam.User) (bool, error)
	switch {
	case req.GetFilter() != "":
		// Only use a filter if we need to
		filter, err := handlers.NewFilter(ctx, req.GetFilter())
		if err != nil {
			return nil, err
		}
		filterItemFn = func(ctx context.Context, item *iam.User) (bool, error) {
			outputOpts, ok := newOutputOpts(ctx, item, scopeInfoMap, authResults)
			if !ok {
				return false, nil
			}
			pbItem, err := toProto(ctx, item, nil, outputOpts...)
			if err != nil {
				return false, err
			}
			return filter.Match(pbItem), nil
		}
	default:
		filterItemFn = func(ctx context.Context, item *iam.User) (bool, error) {
			return true, nil
		}
	}

	grantsHash, err := authResults.GrantsHash(ctx)
	if err != nil {
		return nil, errors.Wrap(ctx, err, op)
	}

	repo, err := s.repoFn()
	if err != nil {
		return nil, errors.Wrap(ctx, err, op)
	}
	var listResp *pagination.ListResponse[*iam.User]
	var sortBy string
	if req.GetListToken() == "" {
		sortBy = "created_time"
		listResp, err = iam.ListUsers(ctx, grantsHash, pageSize, filterItemFn, repo, scopeIds)
		if err != nil {
			return nil, err
		}
	} else {
		listToken, err := handlers.ParseListToken(ctx, req.GetListToken(), resource.User, grantsHash)
		if err != nil {
			return nil, err
		}
		switch st := listToken.Subtype.(type) {
		case *listtoken.PaginationToken:
			sortBy = "created_time"
			listResp, err = iam.ListUsersPage(ctx, grantsHash, pageSize, filterItemFn, listToken, repo, scopeIds)
			if err != nil {
				return nil, err
			}
		case *listtoken.StartRefreshToken:
			sortBy = "updated_time"
			listResp, err = iam.ListUsersRefresh(ctx, grantsHash, pageSize, filterItemFn, listToken, repo, scopeIds)
			if err != nil {
				return nil, err
			}
		case *listtoken.RefreshToken:
			sortBy = "updated_time"
			listResp, err = iam.ListUsersRefreshPage(ctx, grantsHash, pageSize, filterItemFn, listToken, repo, scopeIds)
			if err != nil {
				return nil, err
			}
		default:
			return nil, handlers.ApiErrorWithCodeAndMessage(codes.InvalidArgument, "unexpected list token subtype: %T", st)
		}
	}

	finalItems := make([]*pb.User, 0, len(listResp.Items))
	for _, item := range listResp.Items {
		outputOpts, ok := newOutputOpts(ctx, item, scopeInfoMap, authResults)
		if !ok {
			continue
		}
		item, err := toProto(ctx, item, nil, outputOpts...)
		if err != nil {
			return nil, errors.Wrap(ctx, err, op)
		}
		finalItems = append(finalItems, item)
	}
	respType := "delta"
	if listResp.CompleteListing {
		respType = "complete"
	}
	resp := &pbs.ListUsersResponse{
		Items:        finalItems,
		EstItemCount: uint32(listResp.EstimatedItemCount),
		RemovedIds:   listResp.DeletedIds,
		ResponseType: respType,
		SortBy:       sortBy,
		SortDir:      "desc",
	}
	if listResp.ListToken != nil {
		resp.ListToken, err = handlers.MarshalListToken(ctx, listResp.ListToken, pbs.ResourceType_RESOURCE_TYPE_USER)
		if err != nil {
			return nil, err
		}
	}
	return resp, nil
}

// GetUsers implements the interface pbs.UserServiceServer.
func (s Service) GetUser(ctx context.Context, req *pbs.GetUserRequest) (*pbs.GetUserResponse, error) {
	const op = "users.(Service).GetUser"

	if err := validateGetRequest(req); err != nil {
		return nil, err
	}
	authResults := s.authResult(ctx, req.GetId(), action.Read, false)
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
	outputOpts = append(outputOpts, handlers.WithOutputFields(outputFields))
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
	authResults := s.authResult(ctx, req.GetItem().GetScopeId(), action.Create, false)
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
	outputOpts = append(outputOpts, handlers.WithOutputFields(outputFields))
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
	authResults := s.authResult(ctx, req.GetId(), action.Update, false)
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
	outputOpts = append(outputOpts, handlers.WithOutputFields(outputFields))
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
	authResults := s.authResult(ctx, req.GetId(), action.Delete, false)
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
	authResults := s.authResult(ctx, req.GetId(), action.AddAccounts, false)
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
	outputOpts = append(outputOpts, handlers.WithOutputFields(outputFields))
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
	authResults := s.authResult(ctx, req.GetId(), action.SetAccounts, false)
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
	outputOpts = append(outputOpts, handlers.WithOutputFields(outputFields))
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
	authResults := s.authResult(ctx, req.GetId(), action.RemoveAccounts, false)
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
	outputOpts = append(outputOpts, handlers.WithOutputFields(outputFields))
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

// ListResolvableAliases implements the interface pbs.AliasServiceServer.
func (s Service) ListResolvableAliases(ctx context.Context, req *pbs.ListResolvableAliasesRequest) (*pbs.ListResolvableAliasesResponse, error) {
	const op = "users.(Service).ListResolvableAliases"
	if err := validateListResolvableAliasesRequest(req); err != nil {
		return nil, err
	}

	authResults := s.authResult(ctx, req.GetId(), action.ListResolvableAliases, false)
	if authResults.Error != nil {
		return nil, authResults.Error
	}

	outputFields, ok := requests.OutputFields(ctx)
	if !ok {
		return nil, errors.New(ctx, errors.Internal, op, "no request context found")
	}

	// fetch ACL and grantsHash for target resource so we can resolve ListResolvableAliasesPermissions
	// because permissions in authResults only contains permissions relevant to resource.User
	acl, grantsHash, err := s.aclAndGrantHashForUser(ctx, req.GetId(), []resource.Type{resource.Target})
	if err != nil {
		return nil, errors.Wrap(ctx, err, op, errors.WithoutEvent())
	}

	permissions := acl.ListResolvableAliasesPermissions(resource.Target, targets.IdActions)

	if len(permissions) == 0 {
		// if there are no permitted targets then there will be no aliases that
		// can resolve to them.
		return &pbs.ListResolvableAliasesResponse{
			ResponseType: "complete",
			SortBy:       "created_time",
			SortDir:      "desc",
		}, nil
	}

	pageSize := int(s.maxPageSize)
	// Use the requested page size only if it is smaller than
	// the configured max.
	if req.GetPageSize() != 0 && uint(req.GetPageSize()) < s.maxPageSize {
		pageSize = int(req.GetPageSize())
	}

	repo, err := s.aliasRepoFn()
	if err != nil {
		return nil, errors.Wrap(ctx, err, op)
	}
	var listResp *pagination.ListResponse[*talias.Alias]
	var sortBy string
	if req.GetListToken() == "" {
		sortBy = "created_time"
		listResp, err = talias.ListResolvableAliases(ctx, grantsHash, pageSize, repo, permissions)
		if err != nil {
			return nil, err
		}
	} else {
		listToken, err := handlers.ParseListToken(ctx, req.GetListToken(), resource.Alias, grantsHash)
		if err != nil {
			return nil, err
		}
		switch st := listToken.Subtype.(type) {
		case *listtoken.PaginationToken:
			sortBy = "created_time"
			listResp, err = talias.ListResolvableAliasesPage(ctx, grantsHash, pageSize, listToken, repo, permissions)
			if err != nil {
				return nil, err
			}
		case *listtoken.StartRefreshToken:
			sortBy = "updated_time"
			listResp, err = talias.ListResolvableAliasesRefresh(ctx, grantsHash, pageSize, listToken, repo, permissions)
			if err != nil {
				return nil, err
			}
		case *listtoken.RefreshToken:
			sortBy = "updated_time"
			listResp, err = talias.ListResolvableAliasesRefreshPage(ctx, grantsHash, pageSize, listToken, repo, permissions)
			if err != nil {
				return nil, err
			}
		default:
			return nil, handlers.ApiErrorWithCodeAndMessage(codes.InvalidArgument, "unexpected list token subtype: %T", st)
		}
	}

	finalItems := make([]*aliaspb.Alias, 0, len(listResp.Items))
	for _, item := range listResp.Items {
		item, err := toResolvableAliasProto(item, handlers.WithOutputFields(outputFields))
		if err != nil {
			return nil, errors.Wrap(ctx, err, op)
		}
		finalItems = append(finalItems, item)
	}
	respType := "delta"
	if listResp.CompleteListing {
		respType = "complete"
	}
	resp := &pbs.ListResolvableAliasesResponse{
		Items:        finalItems,
		EstItemCount: uint32(listResp.EstimatedItemCount),
		RemovedIds:   listResp.DeletedIds,
		ResponseType: respType,
		SortBy:       sortBy,
		SortDir:      "desc",
	}
	if listResp.ListToken != nil {
		resp.ListToken, err = handlers.MarshalListToken(ctx, listResp.ListToken, pbs.ResourceType_RESOURCE_TYPE_ALIAS)
		if err != nil {
			return nil, err
		}
	}
	return resp, nil
}

// aclAndGrantHashForUser returns an ACL from the grants provided to the user and
// the hash of those grants.
func (s Service) aclAndGrantHashForUser(ctx context.Context, userId string, resourceType []resource.Type) (perms.ACL, []byte, error) {
	const op = "users.(Service).aclAndGrantHashForUser"
	iamRepo, err := s.repoFn()
	if err != nil {
		return perms.ACL{}, nil, errors.Wrap(ctx, err, op, errors.WithoutEvent())
	}
	// Need to resolve all possible permissions for a user on a specific resource type because this request
	// does not have a request scope. A user may be associated with a role at a higher-level scope
	// (e.g. user in an org can be a principal of a role in the global scope) so we always have to
	// look up the user's grants as if the request is a global-scoped to resolve the user's
	// full permissions tree
	grantTuples, err := iamRepo.GrantsForUser(ctx, userId, resourceType, globals.GlobalPrefix, iam.WithRecursive(true))
	if err != nil {
		return perms.ACL{}, nil, errors.Wrap(ctx, err, op, errors.WithoutEvent())
	}
	hash, err := grantTuples.GrantHash(ctx)
	if err != nil {
		return perms.ACL{}, nil, errors.Wrap(ctx, err, op, errors.WithoutEvent())
	}
	parsedGrants := make([]perms.Grant, 0, len(grantTuples))
	// Note: Below, we always skip validation so that we don't error on formats
	// that we've since restricted, e.g. "ids=foo;actions=create,read". These
	// will simply not have an effect.
	for _, tuple := range grantTuples {
		permsOpts := []perms.Option{
			perms.WithUserId(userId),
			perms.WithSkipFinalValidation(true),
		}
		parsed, err := perms.Parse(
			ctx,
			tuple,
			permsOpts...)
		if err != nil {
			return perms.ACL{}, nil, errors.Wrap(ctx, err, op)
		}
		parsedGrants = append(parsedGrants, parsed)
	}
	return perms.NewACL(parsedGrants...), hash, nil
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
	u, err := iam.NewUser(ctx, orgId, opts...)
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
	u, err := iam.NewUser(ctx, orgId, opts...)
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

func (s Service) authResult(ctx context.Context, id string, a action.Type, isRecursive bool) auth.VerifyResults {
	res := auth.VerifyResults{}
	repo, err := s.repoFn()
	if err != nil {
		res.Error = err
		return res
	}

	var parentId string
	opts := []auth.Option{auth.WithAction(a), auth.WithRecursive(isRecursive)}
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
	return auth.Verify(ctx, resource.User, opts...)
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

// toResolvableAliasProto converts *talias.Alias to *aliaspb.Alias only including fields specified in output_fields.
// These fields are not included in the result set: Name, Description, Version
func toResolvableAliasProto(a *talias.Alias, opt ...handlers.Option) (*aliaspb.Alias, error) {
	opts := handlers.GetOpts(opt...)
	if opts.WithOutputFields == nil {
		return nil, handlers.ApiErrorWithCodeAndMessage(codes.Internal, "output fields not found when building user proto")
	}
	outputFields := *opts.WithOutputFields

	pbItem := &aliaspb.Alias{}
	if a == nil {
		return pbItem, nil
	}
	if outputFields.Has(globals.IdField) {
		pbItem.Id = a.GetPublicId()
	}
	if outputFields.Has(globals.CreatedTimeField) {
		pbItem.CreatedTime = a.GetCreateTime().GetTimestamp()
	}
	if outputFields.Has(globals.UpdatedTimeField) {
		pbItem.UpdatedTime = a.GetUpdateTime().GetTimestamp()
	}
	if outputFields.Has(globals.ValueField) {
		pbItem.Value = a.GetValue()
	}
	if outputFields.Has(globals.DestinationIdField) && a.GetDestinationId() != "" {
		pbItem.DestinationId = wrapperspb.String(a.GetDestinationId())
	}
	if outputFields.Has(globals.TypeField) {
		pbItem.Type = "target"
	}
	return pbItem, nil
}

// A validateX method should exist for each method above.  These methods do not make calls to any backing service but enforce
// requirements on the structure of the request.  They verify that:
//   - The path passed in is correctly formatted
//   - All required parameters are set
//   - There are no conflicting parameters provided
func validateGetRequest(req *pbs.GetUserRequest) error {
	return handlers.ValidateGetRequest(handlers.NoopValidatorFn, req, globals.UserPrefix)
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
	return handlers.ValidateUpdateRequest(req, req.GetItem(), handlers.NoopValidatorFn, globals.UserPrefix)
}

func validateDeleteRequest(req *pbs.DeleteUserRequest) error {
	return handlers.ValidateDeleteRequest(handlers.NoopValidatorFn, req, globals.UserPrefix)
}

func validateListRequest(ctx context.Context, req *pbs.ListUsersRequest) error {
	badFields := map[string]string{}
	if !handlers.ValidId(handlers.Id(req.GetScopeId()), scope.Org.Prefix()) &&
		req.GetScopeId() != scope.Global.String() {
		badFields["scope_id"] = "Must be 'global' or a valid org scope id when listing."
	}
	if _, err := handlers.NewFilter(ctx, req.GetFilter()); err != nil {
		badFields["filter"] = fmt.Sprintf("This field could not be parsed. %v", err)
	}
	if len(badFields) > 0 {
		return handlers.InvalidArgumentErrorf("Improperly formatted identifier.", badFields)
	}
	return nil
}

func validateAddUserAccountsRequest(req *pbs.AddUserAccountsRequest) error {
	badFields := map[string]string{}
	if !handlers.ValidId(handlers.Id(req.GetId()), globals.UserPrefix) {
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
			globals.PasswordAccountPreviousPrefix,
			globals.PasswordAccountPrefix,
			globals.OidcAccountPrefix,
			globals.LdapAccountPrefix,
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
	if !handlers.ValidId(handlers.Id(req.GetId()), globals.UserPrefix) {
		badFields["id"] = "Incorrectly formatted identifier."
	}
	if req.GetVersion() == 0 {
		badFields["version"] = "Required field."
	}
	for _, a := range req.GetAccountIds() {
		// TODO: Increase the type of auth accounts that can be added to a user.
		if !handlers.ValidId(handlers.Id(a),
			globals.PasswordAccountPreviousPrefix,
			globals.PasswordAccountPrefix,
			globals.OidcAccountPrefix,
			globals.LdapAccountPrefix,
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
	if !handlers.ValidId(handlers.Id(req.GetId()), globals.UserPrefix) {
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
			globals.PasswordAccountPreviousPrefix,
			globals.PasswordAccountPrefix,
			globals.OidcAccountPrefix,
			globals.LdapAccountPrefix,
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

func validateListResolvableAliasesRequest(req *pbs.ListResolvableAliasesRequest) error {
	badFields := map[string]string{}
	if !handlers.ValidId(handlers.Id(req.GetId()), globals.UserPrefix) {
		badFields[globals.IdField] = "Incorrectly formatted identifier."
	}
	if req.GetId() == globals.RecoveryUserId {
		badFields["principal_ids"] = "Cannot list resolvable aliases for the recovery user."
	}
	if len(badFields) > 0 {
		return handlers.InvalidArgumentErrorf("Errors in provided fields.", badFields)
	}
	return nil
}

func newOutputOpts(ctx context.Context, item *iam.User, scopeInfoMap map[string]*scopes.ScopeInfo, authResults auth.VerifyResults) ([]handlers.Option, bool) {
	res := perms.Resource{
		Type: resource.User,
	}
	res.Id = item.GetPublicId()
	res.ScopeId = item.GetScopeId()
	res.ParentScopeId = scopeInfoMap[item.GetScopeId()].GetParentScopeId()
	authorizedActions := authResults.FetchActionSetForId(ctx, item.GetPublicId(), IdActions, auth.WithResource(&res))
	if len(authorizedActions) == 0 {
		return nil, false
	}

	outputFields := authResults.FetchOutputFields(res, action.List).SelfOrDefaults(authResults.UserId)
	outputOpts := make([]handlers.Option, 0, 3)
	outputOpts = append(outputOpts, handlers.WithOutputFields(outputFields))
	if outputFields.Has(globals.ScopeField) {
		outputOpts = append(outputOpts, handlers.WithScope(scopeInfoMap[item.GetScopeId()]))
	}
	if outputFields.Has(globals.AuthorizedActionsField) {
		outputOpts = append(outputOpts, handlers.WithAuthorizedActions(authorizedActions.Strings()))
	}
	return outputOpts, true
}
