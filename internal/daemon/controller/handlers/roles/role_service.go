// Copyright IBM Corp. 2020, 2025
// SPDX-License-Identifier: BUSL-1.1

package roles

import (
	"context"
	"fmt"
	"sort"
	"strings"

	"github.com/hashicorp/boundary/globals"
	"github.com/hashicorp/boundary/internal/daemon/controller/auth"
	"github.com/hashicorp/boundary/internal/daemon/controller/common"
	"github.com/hashicorp/boundary/internal/daemon/controller/common/scopeids"
	"github.com/hashicorp/boundary/internal/daemon/controller/handlers"
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
	pb "github.com/hashicorp/boundary/sdk/pbs/controller/api/resources/roles"
	"github.com/hashicorp/boundary/sdk/pbs/controller/api/resources/scopes"
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
		action.AddPrincipals,
		action.SetPrincipals,
		action.RemovePrincipals,
		action.AddGrants,
		action.SetGrants,
		action.RemoveGrants,
		action.AddGrantScopes,
		action.SetGrantScopes,
		action.RemoveGrantScopes,
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
		handlers.MaskDestination{&store.Role{}},
		handlers.MaskSource{&pb.Role{}},
	); err != nil {
		panic(err)
	}

	// TODO: refactor to remove IdActions and CollectionActions package variables
	action.RegisterResource(resource.Role, IdActions, CollectionActions)
}

// Service handles request as described by the pbs.RoleServiceServer interface.
type Service struct {
	pbs.UnsafeRoleServiceServer

	repoFn      common.IamRepoFactory
	maxPageSize uint
}

var _ pbs.RoleServiceServer = (*Service)(nil)

// NewService returns a role service which handles role related requests to boundary.
func NewService(ctx context.Context, repo common.IamRepoFactory, maxPageSize uint) (Service, error) {
	const op = "roles.NewService"
	if repo == nil {
		return Service{}, errors.New(ctx, errors.InvalidParameter, op, "missing iam repository")
	}
	if maxPageSize == 0 {
		maxPageSize = uint(globals.DefaultMaxPageSize)
	}
	return Service{repoFn: repo, maxPageSize: maxPageSize}, nil
}

// ListRoles implements the interface pbs.RoleServiceServer.
func (s Service) ListRoles(ctx context.Context, req *pbs.ListRolesRequest) (*pbs.ListRolesResponse, error) {
	const op = "roles.(Service).ListRoles"

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
		ctx, s.repoFn, authResults, req.GetScopeId(), resource.Role, req.GetRecursive())
	if err != nil {
		return nil, err
	}

	pageSize := int(s.maxPageSize)
	// Use the requested page size only if it is smaller than
	// the configured max.
	if req.GetPageSize() != 0 && uint(req.GetPageSize()) < s.maxPageSize {
		pageSize = int(req.GetPageSize())
	}

	var filterItemFn func(ctx context.Context, item *iam.Role) (bool, error)
	switch {
	case req.GetFilter() != "":
		// Only use a filter if we need to
		filter, err := handlers.NewFilter(ctx, req.GetFilter())
		if err != nil {
			return nil, err
		}
		filterItemFn = func(ctx context.Context, item *iam.Role) (bool, error) {
			outputOpts, ok := newOutputOpts(ctx, item, scopeInfoMap, authResults)
			if !ok {
				return false, nil
			}
			pbItem, err := toProto(ctx, item, nil, nil, nil, outputOpts...)
			if err != nil {
				return false, err
			}
			return filter.Match(pbItem), nil
		}
	default:
		filterItemFn = func(ctx context.Context, item *iam.Role) (bool, error) {
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

	var listResp *pagination.ListResponse[*iam.Role]
	var sortBy string
	if req.GetListToken() == "" {
		sortBy = "created_time"
		listResp, err = iam.ListRoles(ctx, grantsHash, pageSize, filterItemFn, repo, scopeIds)
		if err != nil {
			return nil, err
		}
	} else {
		listToken, err := handlers.ParseListToken(ctx, req.GetListToken(), resource.Role, grantsHash)
		if err != nil {
			return nil, err
		}
		switch st := listToken.Subtype.(type) {
		case *listtoken.PaginationToken:
			sortBy = "created_time"
			listResp, err = iam.ListRolesPage(ctx, grantsHash, pageSize, filterItemFn, listToken, repo, scopeIds)
			if err != nil {
				return nil, err
			}
		case *listtoken.StartRefreshToken:
			sortBy = "updated_time"
			listResp, err = iam.ListRolesRefresh(ctx, grantsHash, pageSize, filterItemFn, listToken, repo, scopeIds)
			if err != nil {
				return nil, err
			}
		case *listtoken.RefreshToken:
			sortBy = "updated_time"
			listResp, err = iam.ListRolesRefreshPage(ctx, grantsHash, pageSize, filterItemFn, listToken, repo, scopeIds)
			if err != nil {
				return nil, err
			}
		default:
			return nil, handlers.ApiErrorWithCodeAndMessage(codes.InvalidArgument, "unexpected list token subtype: %T", st)
		}
	}

	finalItems := make([]*pb.Role, 0, len(listResp.Items))
	for _, item := range listResp.Items {
		outputOpts, ok := newOutputOpts(ctx, item, scopeInfoMap, authResults)
		if !ok {
			continue
		}
		item, err := toProto(ctx, item, nil, nil, item.GrantScopes, outputOpts...)
		if err != nil {
			return nil, errors.Wrap(ctx, err, op)
		}
		finalItems = append(finalItems, item)
	}
	respType := "delta"
	if listResp.CompleteListing {
		respType = "complete"
	}
	resp := &pbs.ListRolesResponse{
		Items:        finalItems,
		EstItemCount: uint32(listResp.EstimatedItemCount),
		RemovedIds:   listResp.DeletedIds,
		ResponseType: respType,
		SortBy:       sortBy,
		SortDir:      "desc",
	}

	if listResp.ListToken != nil {
		resp.ListToken, err = handlers.MarshalListToken(ctx, listResp.ListToken, pbs.ResourceType_RESOURCE_TYPE_ROLE)
		if err != nil {
			return nil, err
		}
	}
	return resp, nil
}

// GetRoles implements the interface pbs.RoleServiceServer.
func (s Service) GetRole(ctx context.Context, req *pbs.GetRoleRequest) (*pbs.GetRoleResponse, error) {
	const op = "roles.(Service).GetRole"

	if err := validateGetRequest(req); err != nil {
		return nil, err
	}
	authResults := s.authResult(ctx, req.GetId(), action.Read, false)
	if authResults.Error != nil {
		return nil, authResults.Error
	}
	r, prs, rgs, grantScopes, err := s.getFromRepo(ctx, req.GetId())
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
		outputOpts = append(outputOpts, handlers.WithAuthorizedActions(authResults.FetchActionSetForId(ctx, r.GetPublicId(), IdActions).Strings()))
	}

	item, err := toProto(ctx, r, prs, rgs, grantScopes, outputOpts...)
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
	authResults := s.authResult(ctx, req.GetItem().GetScopeId(), action.Create, false)
	if authResults.Error != nil {
		return nil, authResults.Error
	}
	r, prs, rgs, grantScopes, err := s.createInRepo(ctx, authResults.Scope.GetId(), req.GetItem())
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
		outputOpts = append(outputOpts, handlers.WithAuthorizedActions(authResults.FetchActionSetForId(ctx, r.GetPublicId(), IdActions).Strings()))
	}

	item, err := toProto(ctx, r, prs, rgs, grantScopes, outputOpts...)
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
	authResults := s.authResult(ctx, req.GetId(), action.Update, false)
	if authResults.Error != nil {
		return nil, authResults.Error
	}
	r, prs, rgs, grantScopes, err := s.updateInRepo(ctx, authResults.Scope.GetId(), req.GetId(), req.GetUpdateMask().GetPaths(), req.GetItem())
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
		outputOpts = append(outputOpts, handlers.WithAuthorizedActions(authResults.FetchActionSetForId(ctx, r.GetPublicId(), IdActions).Strings()))
	}

	item, err := toProto(ctx, r, prs, rgs, grantScopes, outputOpts...)
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

// AddRolePrincipals implements the interface pbs.RoleServiceServer.
func (s Service) AddRolePrincipals(ctx context.Context, req *pbs.AddRolePrincipalsRequest) (*pbs.AddRolePrincipalsResponse, error) {
	const op = "roles.(Service).AddRolePrincipals"

	if err := validateAddRolePrincipalsRequest(req); err != nil {
		return nil, err
	}
	authResults := s.authResult(ctx, req.GetId(), action.AddPrincipals, false)
	if authResults.Error != nil {
		return nil, authResults.Error
	}
	r, prs, rgs, grantScopes, err := s.addPrincipalsInRepo(ctx, req.GetId(), req.GetPrincipalIds(), req.GetVersion())
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
		outputOpts = append(outputOpts, handlers.WithAuthorizedActions(authResults.FetchActionSetForId(ctx, r.GetPublicId(), IdActions).Strings()))
	}

	item, err := toProto(ctx, r, prs, rgs, grantScopes, outputOpts...)
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
	authResults := s.authResult(ctx, req.GetId(), action.SetPrincipals, false)
	if authResults.Error != nil {
		return nil, authResults.Error
	}
	r, prs, rgs, grantScopes, err := s.setPrincipalsInRepo(ctx, req.GetId(), req.GetPrincipalIds(), req.GetVersion())
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
		outputOpts = append(outputOpts, handlers.WithAuthorizedActions(authResults.FetchActionSetForId(ctx, r.GetPublicId(), IdActions).Strings()))
	}

	item, err := toProto(ctx, r, prs, rgs, grantScopes, outputOpts...)
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
	authResults := s.authResult(ctx, req.GetId(), action.RemovePrincipals, false)
	if authResults.Error != nil {
		return nil, authResults.Error
	}
	r, prs, rgs, grantScopes, err := s.removePrincipalsInRepo(ctx, req.GetId(), req.GetPrincipalIds(), req.GetVersion())
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
		outputOpts = append(outputOpts, handlers.WithAuthorizedActions(authResults.FetchActionSetForId(ctx, r.GetPublicId(), IdActions).Strings()))
	}

	item, err := toProto(ctx, r, prs, rgs, grantScopes, outputOpts...)
	if err != nil {
		return nil, err
	}

	return &pbs.RemoveRolePrincipalsResponse{Item: item}, nil
}

// AddRoleGrants implements the interface pbs.RoleServiceServer.
func (s Service) AddRoleGrants(ctx context.Context, req *pbs.AddRoleGrantsRequest) (*pbs.AddRoleGrantsResponse, error) {
	const op = "roles.(Service).AddRoleGrants"

	if err := validateAddRoleGrantsRequest(ctx, req); err != nil {
		return nil, err
	}
	authResults := s.authResult(ctx, req.GetId(), action.AddGrants, false)
	if authResults.Error != nil {
		return nil, authResults.Error
	}
	r, prs, rgs, grantScopes, err := s.addGrantsInRepo(ctx, req.GetId(), req.GetGrantStrings(), req.GetVersion())
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
		outputOpts = append(outputOpts, handlers.WithAuthorizedActions(authResults.FetchActionSetForId(ctx, r.GetPublicId(), IdActions).Strings()))
	}

	item, err := toProto(ctx, r, prs, rgs, grantScopes, outputOpts...)
	if err != nil {
		return nil, err
	}

	return &pbs.AddRoleGrantsResponse{Item: item}, nil
}

// SetRoleGrants implements the interface pbs.RoleServiceServer.
func (s Service) SetRoleGrants(ctx context.Context, req *pbs.SetRoleGrantsRequest) (*pbs.SetRoleGrantsResponse, error) {
	const op = "roles.(Service).SetRoleGrants"

	if err := validateSetRoleGrantsRequest(ctx, req); err != nil {
		return nil, err
	}
	authResults := s.authResult(ctx, req.GetId(), action.SetGrants, false)
	if authResults.Error != nil {
		return nil, authResults.Error
	}
	r, prs, rgs, grantScopes, err := s.setGrantsInRepo(ctx, req.GetId(), req.GetGrantStrings(), req.GetVersion())
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
		outputOpts = append(outputOpts, handlers.WithAuthorizedActions(authResults.FetchActionSetForId(ctx, r.GetPublicId(), IdActions).Strings()))
	}

	item, err := toProto(ctx, r, prs, rgs, grantScopes, outputOpts...)
	if err != nil {
		return nil, err
	}

	return &pbs.SetRoleGrantsResponse{Item: item}, nil
}

// RemoveRoleGrants implements the interface pbs.RoleServiceServer.
func (s Service) RemoveRoleGrants(ctx context.Context, req *pbs.RemoveRoleGrantsRequest) (*pbs.RemoveRoleGrantsResponse, error) {
	const op = "roles.(Service).RemoveRoleGrants"

	if err := validateRemoveRoleGrantsRequest(ctx, req); err != nil {
		return nil, err
	}
	authResults := s.authResult(ctx, req.GetId(), action.RemoveGrants, false)
	if authResults.Error != nil {
		return nil, authResults.Error
	}
	r, prs, rgs, grantScopes, err := s.removeGrantsInRepo(ctx, req.GetId(), req.GetGrantStrings(), req.GetVersion())
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
		outputOpts = append(outputOpts, handlers.WithAuthorizedActions(authResults.FetchActionSetForId(ctx, r.GetPublicId(), IdActions).Strings()))
	}

	item, err := toProto(ctx, r, prs, rgs, grantScopes, outputOpts...)
	if err != nil {
		return nil, err
	}

	return &pbs.RemoveRoleGrantsResponse{Item: item}, nil
}

// AddRoleGrantScopes implements the interface pbs.RoleServiceServer.
func (s Service) AddRoleGrantScopes(ctx context.Context, req *pbs.AddRoleGrantScopesRequest) (*pbs.AddRoleGrantScopesResponse, error) {
	const op = "roles.(Service).AddRoleGrantScopes"

	if err := validateRoleGrantScopesRequest(ctx, req); err != nil {
		return nil, err
	}
	authResults := s.authResult(ctx, req.GetId(), action.AddGrantScopes, false)
	if authResults.Error != nil {
		return nil, authResults.Error
	}

	r, prs, rgs, grantScopes, err := s.addGrantScopesInRepo(ctx, req)
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
		outputOpts = append(outputOpts, handlers.WithAuthorizedActions(authResults.FetchActionSetForId(ctx, r.GetPublicId(), IdActions).Strings()))
	}

	item, err := toProto(ctx, r, prs, rgs, grantScopes, outputOpts...)
	if err != nil {
		return nil, err
	}

	return &pbs.AddRoleGrantScopesResponse{Item: item}, nil
}

// SetRoleGrantScopes implements the interface pbs.RoleServiceServer.
func (s Service) SetRoleGrantScopes(ctx context.Context, req *pbs.SetRoleGrantScopesRequest) (*pbs.SetRoleGrantScopesResponse, error) {
	const op = "roles.(Service).SetRoleGrantScopes"

	if err := validateRoleGrantScopesRequest(ctx, req); err != nil {
		return nil, err
	}
	authResults := s.authResult(ctx, req.GetId(), action.SetGrantScopes, false)
	if authResults.Error != nil {
		return nil, authResults.Error
	}

	r, prs, rgs, grantScopes, err := s.setGrantScopesInRepo(ctx, req)
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
		outputOpts = append(outputOpts, handlers.WithAuthorizedActions(authResults.FetchActionSetForId(ctx, r.GetPublicId(), IdActions).Strings()))
	}

	item, err := toProto(ctx, r, prs, rgs, grantScopes, outputOpts...)
	if err != nil {
		return nil, err
	}

	return &pbs.SetRoleGrantScopesResponse{Item: item}, nil
}

// RemoveRoleGrantScopes implements the interface pbs.RoleServiceServer.
func (s Service) RemoveRoleGrantScopes(ctx context.Context, req *pbs.RemoveRoleGrantScopesRequest) (*pbs.RemoveRoleGrantScopesResponse, error) {
	const op = "roles.(Service).RemoveRoleGrantScopes"

	if err := validateRoleGrantScopesRequest(ctx, req); err != nil {
		return nil, err
	}
	authResults := s.authResult(ctx, req.GetId(), action.RemoveGrants, false)
	if authResults.Error != nil {
		return nil, authResults.Error
	}

	r, prs, rgs, grantScopes, err := s.removeGrantScopesInRepo(ctx, req)
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
		outputOpts = append(outputOpts, handlers.WithAuthorizedActions(authResults.FetchActionSetForId(ctx, r.GetPublicId(), IdActions).Strings()))
	}

	item, err := toProto(ctx, r, prs, rgs, grantScopes, outputOpts...)
	if err != nil {
		return nil, err
	}

	return &pbs.RemoveRoleGrantScopesResponse{Item: item}, nil
}

func (s Service) getFromRepo(ctx context.Context, id string) (*iam.Role, []*iam.PrincipalRole, []*iam.RoleGrant, []*iam.RoleGrantScope, error) {
	repo, err := s.repoFn()
	if err != nil {
		return nil, nil, nil, nil, err
	}
	out, pr, roleGrants, roleGrantScopes, err := repo.LookupRole(ctx, id)
	if err != nil {
		if errors.IsNotFoundError(err) {
			return nil, nil, nil, nil, handlers.NotFoundErrorf("Role %q doesn't exist.", id)
		}
		return nil, nil, nil, nil, err
	}
	if out == nil {
		return nil, nil, nil, nil, handlers.NotFoundErrorf("Role %q doesn't exist.", id)
	}
	return out, pr, roleGrants, roleGrantScopes, nil
}

func (s Service) createInRepo(ctx context.Context, scopeId string, item *pb.Role) (*iam.Role, []*iam.PrincipalRole, []*iam.RoleGrant, []*iam.RoleGrantScope, error) {
	const op = "roles.(Service).createInRepo"
	var opts []iam.Option
	if item.GetName() != nil {
		opts = append(opts, iam.WithName(item.GetName().GetValue()))
	}
	if item.GetDescription() != nil {
		opts = append(opts, iam.WithDescription(item.GetDescription().GetValue()))
	}
	u, err := iam.NewRole(ctx, scopeId, opts...)
	if err != nil {
		return nil, nil, nil, nil, handlers.ApiErrorWithCodeAndMessage(codes.Internal, "Unable to build role for creation: %v.", err)
	}
	repo, err := s.repoFn()
	if err != nil {
		return nil, nil, nil, nil, err
	}
	out, pr, roleGrants, roleGrantScopes, err := repo.CreateRole(ctx, u, opts...)
	if err != nil {
		return nil, nil, nil, nil, errors.Wrap(ctx, err, op)
	}
	if out == nil {
		return nil, nil, nil, nil, handlers.ApiErrorWithCodeAndMessage(codes.Internal, "Unable to create role but no error returned from repository.")
	}
	return out, pr, roleGrants, roleGrantScopes, nil
}

func (s Service) updateInRepo(ctx context.Context, scopeId, id string, mask []string, item *pb.Role) (*iam.Role, []*iam.PrincipalRole, []*iam.RoleGrant, []*iam.RoleGrantScope, error) {
	const op = "roles.(Service).updateInRepo"
	var opts []iam.Option
	if desc := item.GetDescription(); desc != nil {
		opts = append(opts, iam.WithDescription(desc.GetValue()))
	}
	if name := item.GetName(); name != nil {
		opts = append(opts, iam.WithName(name.GetValue()))
	}
	version := item.GetVersion()

	u, err := iam.NewRole(ctx, scopeId, opts...)
	if err != nil {
		return nil, nil, nil, nil, handlers.ApiErrorWithCodeAndMessage(codes.Internal, "Unable to build role for update: %v.", err)
	}
	u.PublicId = id

	repo, err := s.repoFn()
	if err != nil {
		return nil, nil, nil, nil, err
	}

	dbMask := maskManager.Translate(mask)
	if len(dbMask) == 0 {
		return nil, nil, nil, nil, handlers.InvalidArgumentErrorf("No valid fields provided in the update mask.", map[string]string{"update_mask": "No valid fields provided in the update mask."})
	}

	out, pr, gr, grantScopes, rowsUpdated, err := repo.UpdateRole(ctx, u, version, dbMask, opts...)
	if err != nil {
		return nil, nil, nil, nil, errors.Wrap(ctx, err, op)
	}
	// This is slightly problematic but it's a very unlikely error case and when
	// we remove the ability to update grant scope ID via here in 0.17 it will
	// go away.
	if rowsUpdated == 0 {
		return nil, nil, nil, nil, handlers.NotFoundErrorf("Role %q doesn't exist or incorrect version provided.", id)
	}
	return out, pr, gr, grantScopes, nil
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

func (s Service) addPrincipalsInRepo(ctx context.Context, roleId string, principalIds []string, version uint32) (*iam.Role, []*iam.PrincipalRole, []*iam.RoleGrant, []*iam.RoleGrantScope, error) {
	const op = "roles.(Service).addPrincpleInRepo"
	repo, err := s.repoFn()
	if err != nil {
		return nil, nil, nil, nil, err
	}
	_, err = repo.AddPrincipalRoles(ctx, roleId, version, strutil.RemoveDuplicates(principalIds, false))
	if err != nil {
		// TODO: Figure out a way to surface more helpful error info beyond the Internal error.
		return nil, nil, nil, nil, handlers.ApiErrorWithCodeAndMessage(codes.Internal, "Unable to add principals to role: %v.", err)
	}
	out, pr, roleGrants, grantScopes, err := repo.LookupRole(ctx, roleId)
	if err != nil {
		return nil, nil, nil, nil, errors.Wrap(ctx, err, op, errors.WithMsg("unable to look up role after adding principals"))
	}
	if out == nil {
		return nil, nil, nil, nil, handlers.ApiErrorWithCodeAndMessage(codes.Internal, "Unable to lookup role after adding principals to it.")
	}
	return out, pr, roleGrants, grantScopes, nil
}

func (s Service) setPrincipalsInRepo(ctx context.Context, roleId string, principalIds []string, version uint32) (*iam.Role, []*iam.PrincipalRole, []*iam.RoleGrant, []*iam.RoleGrantScope, error) {
	const op = "roles.(Service).setPrincipalsInRepo"
	repo, err := s.repoFn()
	if err != nil {
		return nil, nil, nil, nil, err
	}
	_, _, err = repo.SetPrincipalRoles(ctx, roleId, version, strutil.RemoveDuplicates(principalIds, false))
	if err != nil {
		// TODO: Figure out a way to surface more helpful error info beyond the Internal error.
		return nil, nil, nil, nil, handlers.ApiErrorWithCodeAndMessage(codes.Internal, "Unable to set principals on role: %v.", err)
	}
	out, pr, roleGrants, grantScopes, err := repo.LookupRole(ctx, roleId)
	if err != nil {
		return nil, nil, nil, nil, errors.Wrap(ctx, err, op, errors.WithMsg("unable to look up role after setting principals"))
	}
	if out == nil {
		return nil, nil, nil, nil, handlers.ApiErrorWithCodeAndMessage(codes.Internal, "Unable to lookup role after setting principals for it.")
	}
	return out, pr, roleGrants, grantScopes, nil
}

func (s Service) removePrincipalsInRepo(ctx context.Context, roleId string, principalIds []string, version uint32) (*iam.Role, []*iam.PrincipalRole, []*iam.RoleGrant, []*iam.RoleGrantScope, error) {
	const op = "roles.(Service).removePrincipalsInRepo"
	repo, err := s.repoFn()
	if err != nil {
		return nil, nil, nil, nil, err
	}
	_, err = repo.DeletePrincipalRoles(ctx, roleId, version, strutil.RemoveDuplicates(principalIds, false))
	if err != nil {
		// TODO: Figure out a way to surface more helpful error info beyond the Internal error.
		return nil, nil, nil, nil, handlers.ApiErrorWithCodeAndMessage(codes.Internal, "Unable to remove principals from role: %v.", err)
	}
	out, pr, roleGrants, grantScopes, err := repo.LookupRole(ctx, roleId)
	if err != nil {
		return nil, nil, nil, nil, errors.Wrap(ctx, err, op, errors.WithMsg("unable to look up role after removing principals"))
	}
	if out == nil {
		return nil, nil, nil, nil, handlers.ApiErrorWithCodeAndMessage(codes.Internal, "Unable to lookup role after removing principals from it.")
	}
	return out, pr, roleGrants, grantScopes, nil
}

func (s Service) addGrantsInRepo(ctx context.Context, roleId string, grants []string, version uint32) (*iam.Role, []*iam.PrincipalRole, []*iam.RoleGrant, []*iam.RoleGrantScope, error) {
	const op = "service.(Service).addGrantsInRepo"
	repo, err := s.repoFn()
	if err != nil {
		return nil, nil, nil, nil, err
	}
	_, err = repo.AddRoleGrants(ctx, roleId, version, strutil.RemoveDuplicates(grants, false))
	if err != nil {
		// TODO: Figure out a way to surface more helpful error info beyond the Internal error.
		return nil, nil, nil, nil, handlers.ApiErrorWithCodeAndMessage(codes.Internal, "Unable to add grants to role: %v.", err)
	}
	out, pr, roleGrants, grantScopes, err := repo.LookupRole(ctx, roleId)
	if err != nil {
		return nil, nil, nil, nil, errors.Wrap(ctx, err, op, errors.WithMsg("unable to look up role after adding grants"))
	}
	if out == nil {
		return nil, nil, nil, nil, handlers.ApiErrorWithCodeAndMessage(codes.Internal, "Unable to lookup role after adding grants to it.")
	}
	return out, pr, roleGrants, grantScopes, nil
}

func (s Service) setGrantsInRepo(ctx context.Context, roleId string, grants []string, version uint32) (*iam.Role, []*iam.PrincipalRole, []*iam.RoleGrant, []*iam.RoleGrantScope, error) {
	const op = "roles.(Service).setGrantsInRepo"
	repo, err := s.repoFn()
	if err != nil {
		return nil, nil, nil, nil, err
	}
	// If no grant was provided, we clear the grants.
	if grants == nil {
		grants = []string{}
	}
	_, _, err = repo.SetRoleGrants(ctx, roleId, version, strutil.RemoveDuplicates(grants, false))
	if err != nil {
		// TODO: Figure out a way to surface more helpful error info beyond the Internal error.
		return nil, nil, nil, nil, handlers.ApiErrorWithCodeAndMessage(codes.Internal, "Unable to set grants on role: %v.", err)
	}
	out, pr, roleGrants, grantScopes, err := repo.LookupRole(ctx, roleId)
	if err != nil {
		return nil, nil, nil, nil, errors.Wrap(ctx, err, op, errors.WithMsg("unable to look up role after setting grants"))
	}
	if out == nil {
		return nil, nil, nil, nil, handlers.ApiErrorWithCodeAndMessage(codes.Internal, "Unable to lookup role after setting grants on it.")
	}
	return out, pr, roleGrants, grantScopes, nil
}

func (s Service) removeGrantsInRepo(ctx context.Context, roleId string, grants []string, version uint32) (*iam.Role, []*iam.PrincipalRole, []*iam.RoleGrant, []*iam.RoleGrantScope, error) {
	const op = "roles.(Service).removeGrantsInRepo"
	repo, err := s.repoFn()
	if err != nil {
		return nil, nil, nil, nil, err
	}
	_, err = repo.DeleteRoleGrants(ctx, roleId, version, strutil.RemoveDuplicates(grants, false))
	if err != nil {
		// TODO: Figure out a way to surface more helpful error info beyond the Internal error.
		return nil, nil, nil, nil, handlers.ApiErrorWithCodeAndMessage(codes.Internal, "Unable to remove grants from role: %v", err)
	}
	out, pr, roleGrants, grantScopes, err := repo.LookupRole(ctx, roleId)
	if err != nil {
		return nil, nil, nil, nil, errors.Wrap(ctx, err, op, errors.WithMsg("uable to look up role after removing grant"))
	}
	if out == nil {
		return nil, nil, nil, nil, handlers.ApiErrorWithCodeAndMessage(codes.Internal, "Unable to lookup role after removing grants from it.")
	}
	return out, pr, roleGrants, grantScopes, nil
}

func (s Service) addGrantScopesInRepo(ctx context.Context, req grantScopeRequest) (*iam.Role, []*iam.PrincipalRole, []*iam.RoleGrant, []*iam.RoleGrantScope, error) {
	const op = "service.(Service).addGrantScopesInRepo"
	repo, err := s.repoFn()
	if err != nil {
		return nil, nil, nil, nil, err
	}

	deduped := strutil.RemoveDuplicates(req.GetGrantScopeIds(), false)

	if err := validateAndCleanRoleGrantScopesHierarchy(ctx, repo, req.GetId(), deduped); err != nil {
		return nil, nil, nil, nil, err
	}

	_, err = repo.AddRoleGrantScopes(ctx, req.GetId(), req.GetVersion(), deduped)
	if err != nil {
		// TODO: Figure out a way to surface more helpful error info beyond the Internal error.
		return nil, nil, nil, nil, handlers.ApiErrorWithCodeAndMessage(codes.Internal, "Unable to add grant scopes to role: %v.", err)
	}
	out, pr, roleGrants, grantScopes, err := repo.LookupRole(ctx, req.GetId())
	if err != nil {
		return nil, nil, nil, nil, errors.Wrap(ctx, err, op, errors.WithMsg("unable to look up role after adding grant scopes"))
	}
	if out == nil {
		return nil, nil, nil, nil, handlers.ApiErrorWithCodeAndMessage(codes.Internal, "Unable to lookup role after adding grant scopes to it.")
	}
	return out, pr, roleGrants, grantScopes, nil
}

func (s Service) setGrantScopesInRepo(ctx context.Context, req grantScopeRequest) (*iam.Role, []*iam.PrincipalRole, []*iam.RoleGrant, []*iam.RoleGrantScope, error) {
	const op = "service.(Service).setGrantScopesInRepo"
	repo, err := s.repoFn()
	if err != nil {
		return nil, nil, nil, nil, err
	}

	deduped := strutil.RemoveDuplicates(req.GetGrantScopeIds(), false)

	if err := validateAndCleanRoleGrantScopesHierarchy(ctx, repo, req.GetId(), deduped); err != nil {
		return nil, nil, nil, nil, err
	}

	_, _, err = repo.SetRoleGrantScopes(ctx, req.GetId(), req.GetVersion(), deduped)
	if err != nil {
		// TODO: Figure out a way to surface more helpful error info beyond the Internal error.
		return nil, nil, nil, nil, handlers.ApiErrorWithCodeAndMessage(codes.Internal, "Unable to set grant scopes on role: %v.", err)
	}
	out, pr, roleGrants, grantScopes, err := repo.LookupRole(ctx, req.GetId())
	if err != nil {
		return nil, nil, nil, nil, errors.Wrap(ctx, err, op, errors.WithMsg("unable to look up role after setting grant scopes"))
	}
	if out == nil {
		return nil, nil, nil, nil, handlers.ApiErrorWithCodeAndMessage(codes.Internal, "Unable to lookup role after setting grant scopes to it.")
	}
	return out, pr, roleGrants, grantScopes, nil
}

func (s Service) removeGrantScopesInRepo(ctx context.Context, req grantScopeRequest) (*iam.Role, []*iam.PrincipalRole, []*iam.RoleGrant, []*iam.RoleGrantScope, error) {
	const op = "service.(Service).setGrantScopesInRepo"
	repo, err := s.repoFn()
	if err != nil {
		return nil, nil, nil, nil, err
	}
	_, err = repo.DeleteRoleGrantScopes(ctx, req.GetId(), req.GetVersion(), strutil.RemoveDuplicates(req.GetGrantScopeIds(), false))
	if err != nil {
		// TODO: Figure out a way to surface more helpful error info beyond the Internal error.
		return nil, nil, nil, nil, handlers.ApiErrorWithCodeAndMessage(codes.Internal, "Unable to remove grant scopes from role: %v.", err)
	}
	out, pr, roleGrants, grantScopes, err := repo.LookupRole(ctx, req.GetId())
	if err != nil {
		return nil, nil, nil, nil, errors.Wrap(ctx, err, op, errors.WithMsg("unable to look up role after removing grant scopes"))
	}
	if out == nil {
		return nil, nil, nil, nil, handlers.ApiErrorWithCodeAndMessage(codes.Internal, "Unable to lookup role after removing grant scopes to it.")
	}
	return out, pr, roleGrants, grantScopes, nil
}

func (s Service) authResult(ctx context.Context, id string, a action.Type, isResursive bool) auth.VerifyResults {
	res := auth.VerifyResults{}
	repo, err := s.repoFn()
	if err != nil {
		res.Error = err
		return res
	}

	var parentId string
	opts := []auth.Option{auth.WithAction(a), auth.WithRecursive(isResursive)}
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
		r, _, _, _, err := repo.LookupRole(ctx, id)
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
	return auth.Verify(ctx, resource.Role, opts...)
}

func toProto(ctx context.Context, in *iam.Role, principals []*iam.PrincipalRole, grants []*iam.RoleGrant, grantScopes []*iam.RoleGrantScope, opt ...handlers.Option) (*pb.Role, error) {
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
	if outputFields.Has(globals.PrincipalIdsField) {
		for _, p := range principals {
			out.PrincipalIds = append(out.PrincipalIds, p.GetPrincipalId())
		}
	}
	if outputFields.Has(globals.GrantScopeIdsField) {
		for _, gs := range grantScopes {
			out.GrantScopeIds = append(out.GrantScopeIds, gs.GetScopeIdOrSpecial())
		}
		sort.Strings(out.GrantScopeIds)
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
			parsed, err := perms.Parse(ctx, perms.GrantTuple{RoleScopeId: in.GetPublicId(), GrantScopeId: in.GetScopeId(), Grant: g.GetRawGrant()})
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
						Ids:     parsed.Ids(),
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
	return handlers.ValidateGetRequest(handlers.NoopValidatorFn, req, globals.RolePrefix)
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
		return badFields
	}, globals.RolePrefix)
}

func validateDeleteRequest(req *pbs.DeleteRoleRequest) error {
	return handlers.ValidateDeleteRequest(func() map[string]string {
		return nil
	}, req, globals.RolePrefix)
}

func validateListRequest(ctx context.Context, req *pbs.ListRolesRequest) error {
	badFields := map[string]string{}
	if !handlers.ValidId(handlers.Id(req.GetScopeId()), scope.Org.Prefix()) &&
		!handlers.ValidId(handlers.Id(req.GetScopeId()), scope.Project.Prefix()) &&
		req.GetScopeId() != scope.Global.String() {
		badFields["scope_id"] = "Improperly formatted field."
	}
	if _, err := handlers.NewFilter(ctx, req.GetFilter()); err != nil {
		badFields["filter"] = fmt.Sprintf("This field could not be parsed. %v", err)
	}
	if len(badFields) > 0 {
		return handlers.InvalidArgumentErrorf("Improperly formatted identifier.", badFields)
	}
	return nil
}

func validateAddRolePrincipalsRequest(req *pbs.AddRolePrincipalsRequest) error {
	badFields := map[string]string{}
	if !handlers.ValidId(handlers.Id(req.GetId()), globals.RolePrefix) {
		badFields["id"] = "Incorrectly formatted identifier."
	}
	if req.GetVersion() == 0 {
		badFields["version"] = "Required field."
	}
	if len(req.GetPrincipalIds()) == 0 {
		badFields["principal_ids"] = "Must be non-empty."
	}
	for _, id := range req.GetPrincipalIds() {
		if !handlers.ValidId(handlers.Id(id), globals.GroupPrefix) &&
			!handlers.ValidId(handlers.Id(id), globals.UserPrefix) &&
			!handlers.ValidId(handlers.Id(id), globals.OidcManagedGroupPrefix) &&
			!handlers.ValidId(handlers.Id(id), globals.LdapManagedGroupPrefix) {
			badFields["principal_ids"] = "Must only have valid user, group, and/or managed group ids."
			break
		}
		if id == globals.RecoveryUserId {
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
	if !handlers.ValidId(handlers.Id(req.GetId()), globals.RolePrefix) {
		badFields["id"] = "Incorrectly formatted identifier."
	}
	if req.GetVersion() == 0 {
		badFields["version"] = "Required field."
	}
	for _, id := range req.GetPrincipalIds() {
		if !handlers.ValidId(handlers.Id(id), globals.GroupPrefix) &&
			!handlers.ValidId(handlers.Id(id), globals.UserPrefix) &&
			!handlers.ValidId(handlers.Id(id), globals.OidcManagedGroupPrefix) &&
			!handlers.ValidId(handlers.Id(id), globals.LdapManagedGroupPrefix) {
			badFields["principal_ids"] = "Must only have valid user, group, and/or managed group ids."
			break
		}
		if id == globals.RecoveryUserId {
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
	if !handlers.ValidId(handlers.Id(req.GetId()), globals.RolePrefix) {
		badFields["id"] = "Incorrectly formatted identifier."
	}
	if req.GetVersion() == 0 {
		badFields["version"] = "Required field."
	}
	if len(req.GetPrincipalIds()) == 0 {
		badFields["principal_ids"] = "Must be non-empty."
	}
	for _, id := range req.GetPrincipalIds() {
		if !handlers.ValidId(handlers.Id(id), globals.GroupPrefix) &&
			!handlers.ValidId(handlers.Id(id), globals.UserPrefix) &&
			!handlers.ValidId(handlers.Id(id), globals.OidcManagedGroupPrefix) &&
			!handlers.ValidId(handlers.Id(id), globals.LdapManagedGroupPrefix) {
			badFields["principal_ids"] = "Must only have valid user, group, and/or managed group ids."
			break
		}
	}
	if len(badFields) > 0 {
		return handlers.InvalidArgumentErrorf("Errors in provided fields.", badFields)
	}
	return nil
}

func validateAddRoleGrantsRequest(ctx context.Context, req *pbs.AddRoleGrantsRequest) error {
	badFields := map[string]string{}
	if !handlers.ValidId(handlers.Id(req.GetId()), globals.RolePrefix) {
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
		grant, err := perms.Parse(ctx, perms.GrantTuple{RoleScopeId: req.GetId(), GrantScopeId: "p_anything", Grant: v})
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
		switch {
		case grant.Id() == "":
			// Nothing
		default:
			badFields["grant_strings"] = fmt.Sprintf("Grant %q uses the %q field which is no longer supported. Please use %q instead.", v, "id", "ids")
		}
	}
	if len(badFields) > 0 {
		return handlers.InvalidArgumentErrorf("Errors in provided fields.", badFields)
	}
	return nil
}

func validateSetRoleGrantsRequest(ctx context.Context, req *pbs.SetRoleGrantsRequest) error {
	badFields := map[string]string{}
	if !handlers.ValidId(handlers.Id(req.GetId()), globals.RolePrefix) {
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
		grant, err := perms.Parse(ctx, perms.GrantTuple{RoleScopeId: req.GetId(), GrantScopeId: "p_anything", Grant: v})
		if err != nil {
			badFields["grant_strings"] = fmt.Sprintf("Improperly formatted grant %q: %s.", v, err.Error())
			break
		}
		_, actStrs := grant.Actions()
		for _, actStr := range actStrs {
			if depAct := action.DeprecatedMap[actStr]; depAct != action.Unknown {
				badFields["grant_strings"] = fmt.Sprintf("Action %q has been deprecated and is not allowed to be set in grants. Use %q instead.", actStr, depAct.String())
			}
		}
		switch {
		case grant.Id() == "":
			// Nothing
		default:
			badFields["grant_strings"] = fmt.Sprintf("Grant %q uses the %q field which is no longer supported. Please use %q instead.", v, "id", "ids")
		}
	}
	if len(badFields) > 0 {
		return handlers.InvalidArgumentErrorf("Errors in provided fields.", badFields)
	}
	return nil
}

func validateRemoveRoleGrantsRequest(ctx context.Context, req *pbs.RemoveRoleGrantsRequest) error {
	badFields := map[string]string{}
	if !handlers.ValidId(handlers.Id(req.GetId()), globals.RolePrefix) {
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
		if _, err := perms.Parse(ctx, perms.GrantTuple{RoleScopeId: req.GetId(), GrantScopeId: "p_anything", Grant: v}); err != nil {
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

// grantScopeRequest allows us to reuse a few request types in a common way for
// grant scope add/set/remove operations
type grantScopeRequest interface {
	GetId() string
	GetVersion() uint32
	GetGrantScopeIds() []string
}

func validateRoleGrantScopesRequest(ctx context.Context, req grantScopeRequest) error {
	badFields := map[string]string{}
	if !handlers.ValidId(handlers.Id(req.GetId()), globals.RolePrefix) {
		badFields["id"] = "Incorrectly formatted identifier."
	}
	if req.GetVersion() == 0 {
		badFields["version"] = "Required field."
	}
	if len(req.GetGrantScopeIds()) == 0 {
		// This is actually okay for Set because they could be setting to null,
		// e.g. removing all grant scope ids
		if _, ok := req.(*pbs.SetRoleGrantScopesRequest); !ok {
			badFields["grant_scope_ids"] = "Must be non-empty."
		}
	}
	for _, v := range req.GetGrantScopeIds() {
		if len(v) == 0 {
			badFields["grant_scope_ids"] = "Grant scope IDs must not be empty."
			break
		}
		switch {
		case v == scope.Global.String(),
			v == globals.GrantScopeThis,
			v == globals.GrantScopeChildren,
			v == globals.GrantScopeDescendants:
		case globals.ResourceInfoFromPrefix(v).Type == resource.Scope:
			if !handlers.ValidId(handlers.Id(v), globals.ProjectPrefix) &&
				!handlers.ValidId(handlers.Id(v), globals.OrgPrefix) {
				badFields["grant_scope_ids"] = fmt.Sprintf("Incorrectly formatted identifier %q.", v)
				break
			}
		default:
			badFields["grant_scope_ids"] = fmt.Sprintf("Unknown value %q.", v)
			break
		}
	}
	if len(badFields) > 0 {
		return handlers.InvalidArgumentErrorf("Errors in provided fields.", badFields)
	}
	return nil
}

// validateAndCleanRoleGrantScopesHierarchy is the companion to the domain-side logic to
// validate scopes. It doesn't do all of the same checking but will allow for
// better error messages when possible. We perform this check after
// authentication to limit the possibility of an anonymous user causing DB load
// due to this lookup, which is not a cheap one.
// This function also converts grant scope that is the role's scope ID to 'this'
// by mutating grantScopes input
func validateAndCleanRoleGrantScopesHierarchy(ctx context.Context, repo *iam.Repository, roleId string, grantScopes []string) error {
	const op = "service.(Service).validateAndCleanRoleGrantScopesHierarchy"
	// We want to ensure that the values being passed in make sense to whatever
	// extent we can right now, so we can provide nice errors back instead of DB
	// errors.
	role, _, _, _, err := repo.LookupRole(ctx, roleId)
	if err != nil {
		return errors.Wrap(ctx, err, op)
	}
	switch {
	case role.ScopeId == scope.Global.String():
		for i, grantScope := range grantScopes {
			if grantScope == scope.Global.String() {
				grantScopes[i] = globals.GrantScopeThis
			}
		}
	case strings.HasPrefix(role.ScopeId, scope.Project.Prefix()):
		// In this case only "this" or the same project scope is allowed
		for i, grantScope := range grantScopes {
			switch grantScope {
			case globals.GrantScopeThis:
			case role.ScopeId:
				grantScopes[i] = globals.GrantScopeThis
			default:
				return handlers.InvalidArgumentErrorf(
					"Invalid grant scope.",
					map[string]string{
						"grant_scope_ids": `Project scopes can only have their own scope ID or "this" as a grant scope ID.`,
					})
			}
		}
	case strings.HasPrefix(role.ScopeId, scope.Org.Prefix()):
		// Orgs can have "this", its own scope, a project scope, or "children"
		for i, grantScope := range grantScopes {
			switch {
			case grantScope == role.ScopeId:
				grantScopes[i] = globals.GrantScopeThis
			case grantScope == globals.GrantScopeThis,
				grantScope == globals.GrantScopeChildren,
				strings.HasPrefix(grantScope, scope.Project.Prefix()):
			default:
				return handlers.InvalidArgumentErrorf(
					"Invalid grant scope.",
					map[string]string{
						"grant_scope_ids": fmt.Sprintf("Grant scope ID %q is not valid to set on an organization role.", grantScope),
					})
			}
		}
	default:
		// Should never happen
		return handlers.InvalidArgumentErrorf(
			"Improperly formatted identifier.",
			map[string]string{
				"grant_scope_ids": `Unknown scope prefix type.`,
			})
	}
	return nil
}

func newOutputOpts(ctx context.Context, item *iam.Role, scopeInfoMap map[string]*scopes.ScopeInfo, authResults auth.VerifyResults) ([]handlers.Option, bool) {
	res := perms.Resource{
		Type: resource.Role,
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
