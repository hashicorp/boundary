// Copyright IBM Corp. 2020, 2025
// SPDX-License-Identifier: BUSL-1.1

package managed_groups

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/hashicorp/boundary/globals"
	"github.com/hashicorp/boundary/internal/auth"
	"github.com/hashicorp/boundary/internal/auth/ldap"
	ldapstore "github.com/hashicorp/boundary/internal/auth/ldap/store"
	"github.com/hashicorp/boundary/internal/auth/oidc"
	oidcstore "github.com/hashicorp/boundary/internal/auth/oidc/store"
	requestauth "github.com/hashicorp/boundary/internal/daemon/controller/auth"
	"github.com/hashicorp/boundary/internal/daemon/controller/common"
	"github.com/hashicorp/boundary/internal/daemon/controller/handlers"
	"github.com/hashicorp/boundary/internal/errors"
	pbs "github.com/hashicorp/boundary/internal/gen/controller/api/services"
	"github.com/hashicorp/boundary/internal/listtoken"
	"github.com/hashicorp/boundary/internal/pagination"
	"github.com/hashicorp/boundary/internal/perms"
	"github.com/hashicorp/boundary/internal/requests"
	"github.com/hashicorp/boundary/internal/types/action"
	"github.com/hashicorp/boundary/internal/types/resource"
	"github.com/hashicorp/boundary/internal/types/subtypes"
	pb "github.com/hashicorp/boundary/sdk/pbs/controller/api/resources/managedgroups"
	"github.com/hashicorp/go-bexpr"
	"golang.org/x/exp/maps"
	"google.golang.org/grpc/codes"
	"google.golang.org/protobuf/types/known/wrapperspb"
)

const (
	// oidc field names
	attrFilterField     = "attributes.filter"
	attrGroupNamesField = "attributes.group_names"

	domain = "auth"
)

var (
	oidcMaskManager handlers.MaskManager
	ldapMaskManager handlers.MaskManager

	// IdActions contains the set of actions that can be performed on
	// individual resources
	IdActions = map[globals.Subtype]action.ActionSet{
		oidc.Subtype: action.NewActionSet(
			action.NoOp,
			action.Read,
			action.Update,
			action.Delete,
		),
		ldap.Subtype: action.NewActionSet(
			action.NoOp,
			action.Read,
			action.Update,
			action.Delete,
		),
	}

	// CollectionActions contains the set of actions that can be performed on
	// this collection
	CollectionActions = action.NewActionSet(
		action.Create,
		action.List,
	)
)

func init() {
	var err error
	if oidcMaskManager, err = handlers.NewMaskManager(
		context.Background(),
		handlers.MaskDestination{&oidcstore.ManagedGroup{}},
		handlers.MaskSource{&pb.ManagedGroup{}, &pb.OidcManagedGroupAttributes{}},
	); err != nil {
		panic(err)
	}
	if ldapMaskManager, err = handlers.NewMaskManager(
		context.Background(),
		handlers.MaskDestination{&ldapstore.ManagedGroup{}},
		handlers.MaskSource{&pb.ManagedGroup{}, &pb.LdapManagedGroupAttributes{}},
	); err != nil {
		panic(err)
	}

	// TODO: refactor to remove IdActions and CollectionActions package variables
	action.RegisterResource(resource.ManagedGroup, action.Union(maps.Values(IdActions)...), CollectionActions)
}

// Service handles request as described by the pbs.ManagedGroupServiceServer interface.
type Service struct {
	pbs.UnsafeManagedGroupServiceServer

	oidcRepoFn  common.OidcAuthRepoFactory
	ldapRepoFn  common.LdapAuthRepoFactory
	maxPageSize uint
}

var _ pbs.ManagedGroupServiceServer = (*Service)(nil)

// NewService returns a managed group service which handles managed group related requests to boundary.
func NewService(ctx context.Context, oidcRepo common.OidcAuthRepoFactory, ldapRepo common.LdapAuthRepoFactory, maxPageSize uint) (Service, error) {
	const op = "managed_groups.NewService"
	switch {
	case oidcRepo == nil:
		return Service{}, errors.New(ctx, errors.InvalidParameter, op, "missing oidc repository provided")
	case ldapRepo == nil:
		return Service{}, errors.New(ctx, errors.InvalidParameter, op, "missing ldap repository provided")
	}
	if maxPageSize == 0 {
		maxPageSize = uint(globals.DefaultMaxPageSize)
	}
	return Service{oidcRepoFn: oidcRepo, ldapRepoFn: ldapRepo, maxPageSize: maxPageSize}, nil
}

// ListManagedGroups implements the interface pbs.ManagedGroupsServiceServer.
func (s Service) ListManagedGroups(ctx context.Context, req *pbs.ListManagedGroupsRequest) (*pbs.ListManagedGroupsResponse, error) {
	const op = "managed_groups.(Service).ListManagedGroups"
	if err := validateListRequest(ctx, req); err != nil {
		return nil, errors.Wrap(ctx, err, op)
	}
	_, authResults := s.parentAndAuthResult(ctx, req.GetAuthMethodId(), action.List, false)
	if authResults.Error != nil {
		return nil, authResults.Error
	}

	authMethodId := req.GetAuthMethodId()
	pageSize := int(s.maxPageSize)
	// Use the requested page size only if it is smaller than
	// the configured max.
	if req.GetPageSize() != 0 && uint(req.GetPageSize()) < s.maxPageSize {
		pageSize = int(req.GetPageSize())
	}

	var filterItemFn func(ctx context.Context, item auth.ManagedGroup) (bool, error)
	switch {
	case req.GetFilter() != "":
		// Only use a filter if we need to
		filter, err := handlers.NewFilter(ctx, req.GetFilter())
		if err != nil {
			return nil, err
		}
		// TODO: replace the need for this function with some way to convert the `filter`
		// to a domain type. This would allow filtering to happen in the domain, and we could
		// remove this callback altogether.
		filterItemFn = func(ctx context.Context, item auth.ManagedGroup) (bool, error) {
			outputOpts, ok := newOutputOpts(ctx, item, authMethodId, authResults)
			if !ok {
				return false, nil
			}
			pbItem, err := toProto(ctx, item, outputOpts...)
			if err != nil {
				return false, err
			}

			filterable, err := subtypes.Filterable(ctx, pbItem)
			if err != nil {
				return false, err
			}
			return filter.Match(filterable), nil
		}
	default:
		filterItemFn = func(ctx context.Context, item auth.ManagedGroup) (bool, error) {
			return true, nil
		}
	}

	grantsHash, err := authResults.GrantsHash(ctx)
	if err != nil {
		return nil, err
	}

	var listResp *pagination.ListResponse[auth.ManagedGroup]
	var sortBy string
	switch globals.ResourceInfoFromPrefix(authMethodId).Subtype {
	case ldap.Subtype:
		repo, err := s.ldapRepoFn()
		if err != nil {
			return nil, errors.Wrap(ctx, err, op)
		}
		if req.GetListToken() == "" {
			sortBy = "created_time"
			listResp, err = ldap.ListManagedGroups(ctx, grantsHash, pageSize, filterItemFn, repo, authMethodId)
			if err != nil {
				return nil, err
			}
		} else {
			listToken, err := handlers.ParseListToken(ctx, req.GetListToken(), resource.ManagedGroup, grantsHash)
			if err != nil {
				return nil, err
			}
			switch st := listToken.Subtype.(type) {
			case *listtoken.PaginationToken:
				sortBy = "created_time"
				listResp, err = ldap.ListManagedGroupsPage(ctx, grantsHash, pageSize, filterItemFn, listToken, repo, authMethodId)
				if err != nil {
					return nil, err
				}
			case *listtoken.StartRefreshToken:
				sortBy = "updated_time"
				listResp, err = ldap.ListManagedGroupsRefresh(ctx, grantsHash, pageSize, filterItemFn, listToken, repo, authMethodId)
				if err != nil {
					return nil, err
				}
			case *listtoken.RefreshToken:
				sortBy = "updated_time"
				listResp, err = ldap.ListManagedGroupsRefreshPage(ctx, grantsHash, pageSize, filterItemFn, listToken, repo, authMethodId)
				if err != nil {
					return nil, err
				}
			default:
				return nil, handlers.ApiErrorWithCodeAndMessage(codes.InvalidArgument, "unexpected list token subtype: %T", st)
			}
		}
	case oidc.Subtype:
		repo, err := s.oidcRepoFn()
		if err != nil {
			return nil, errors.Wrap(ctx, err, op)
		}
		if req.GetListToken() == "" {
			sortBy = "created_time"
			listResp, err = oidc.ListManagedGroups(ctx, grantsHash, pageSize, filterItemFn, repo, authMethodId)
			if err != nil {
				return nil, err
			}
		} else {
			listToken, err := handlers.ParseListToken(ctx, req.GetListToken(), resource.ManagedGroup, grantsHash)
			if err != nil {
				return nil, err
			}
			switch st := listToken.Subtype.(type) {
			case *listtoken.PaginationToken:
				sortBy = "created_time"
				listResp, err = oidc.ListManagedGroupsPage(ctx, grantsHash, pageSize, filterItemFn, listToken, repo, authMethodId)
				if err != nil {
					return nil, err
				}
			case *listtoken.StartRefreshToken:
				sortBy = "updated_time"
				listResp, err = oidc.ListManagedGroupsRefresh(ctx, grantsHash, pageSize, filterItemFn, listToken, repo, authMethodId)
				if err != nil {
					return nil, err
				}
			case *listtoken.RefreshToken:
				sortBy = "updated_time"
				listResp, err = oidc.ListManagedGroupsRefreshPage(ctx, grantsHash, pageSize, filterItemFn, listToken, repo, authMethodId)
				if err != nil {
					return nil, err
				}
			default:
				return nil, handlers.ApiErrorWithCodeAndMessage(codes.InvalidArgument, "unexpected list token subtype: %T", st)
			}
		}
	default:
		return nil, handlers.ApiErrorWithCodeAndMessage(codes.InvalidArgument, "unknown auth method type for id: %s", authMethodId)
	}

	finalItems := make([]*pb.ManagedGroup, 0, len(listResp.Items))
	for _, item := range listResp.Items {
		outputOpts, ok := newOutputOpts(ctx, item, authMethodId, authResults)
		if !ok {
			continue
		}
		pbItem, err := toProto(ctx, item, outputOpts...)
		if err != nil {
			continue
		}
		finalItems = append(finalItems, pbItem)
	}
	respType := "delta"
	if listResp.CompleteListing {
		respType = "complete"
	}
	resp := &pbs.ListManagedGroupsResponse{
		Items:        finalItems,
		EstItemCount: uint32(listResp.EstimatedItemCount),
		RemovedIds:   listResp.DeletedIds,
		ResponseType: respType,
		SortBy:       sortBy,
		SortDir:      "desc",
	}

	if listResp.ListToken != nil {
		resp.ListToken, err = handlers.MarshalListToken(ctx, listResp.ListToken, pbs.ResourceType_RESOURCE_TYPE_MANAGED_GROUP)
		if err != nil {
			return nil, err
		}
	}

	return resp, nil
}

// GetManagedGroup implements the interface pbs.ManagedGroupServiceServer.
func (s Service) GetManagedGroup(ctx context.Context, req *pbs.GetManagedGroupRequest) (*pbs.GetManagedGroupResponse, error) {
	const op = "managed_groups.(Service).GetManagedGroup"

	if err := validateGetRequest(ctx, req); err != nil {
		return nil, err
	}

	_, authResults := s.parentAndAuthResult(ctx, req.GetId(), action.Read, false)
	if authResults.Error != nil {
		return nil, authResults.Error
	}
	mg, memberIds, err := s.getFromRepo(ctx, req.GetId())
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
		outputOpts = append(outputOpts, handlers.WithAuthorizedActions(authResults.FetchActionSetForId(ctx, mg.GetPublicId(), IdActions[globals.ResourceInfoFromPrefix(mg.GetPublicId()).Subtype]).Strings()))
	}
	if outputFields.Has(globals.MemberIdsField) {
		outputOpts = append(outputOpts, handlers.WithMemberIds(memberIds))
	}

	item, err := toProto(ctx, mg, outputOpts...)
	if err != nil {
		return nil, err
	}

	return &pbs.GetManagedGroupResponse{Item: item}, nil
}

// CreateManagedGroup implements the interface pbs.ManagedGroupServiceServer.
func (s Service) CreateManagedGroup(ctx context.Context, req *pbs.CreateManagedGroupRequest) (*pbs.CreateManagedGroupResponse, error) {
	const op = "managed_groups.(Service).CreateManagedGroup"

	if err := validateCreateRequest(ctx, req); err != nil {
		return nil, err
	}

	authMeth, authResults := s.parentAndAuthResult(ctx, req.GetItem().GetAuthMethodId(), action.Create, false)
	if authResults.Error != nil {
		return nil, authResults.Error
	}
	mg, err := s.createInRepo(ctx, authMeth, req.GetItem())
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
		outputOpts = append(outputOpts, handlers.WithAuthorizedActions(authResults.FetchActionSetForId(ctx, mg.GetPublicId(), IdActions[globals.ResourceInfoFromPrefix(mg.GetPublicId()).Subtype]).Strings()))
	}

	item, err := toProto(ctx, mg, outputOpts...)
	if err != nil {
		return nil, err
	}

	return &pbs.CreateManagedGroupResponse{Item: item, Uri: fmt.Sprintf("managed-groups/%s", item.GetId())}, nil
}

// UpdateManagedGroup implements the interface pbs.ManagedGroupServiceServer.
func (s Service) UpdateManagedGroup(ctx context.Context, req *pbs.UpdateManagedGroupRequest) (*pbs.UpdateManagedGroupResponse, error) {
	const op = "managed_groups.(Service).UpdateManagedGroup"

	if err := validateUpdateRequest(ctx, req); err != nil {
		return nil, err
	}

	authMeth, authResults := s.parentAndAuthResult(ctx, req.GetId(), action.Update, false)
	if authResults.Error != nil {
		return nil, authResults.Error
	}
	mg, err := s.updateInRepo(ctx, authResults.Scope.GetId(), authMeth.GetPublicId(), req)
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
		outputOpts = append(outputOpts, handlers.WithAuthorizedActions(authResults.FetchActionSetForId(ctx, mg.GetPublicId(), IdActions[globals.ResourceInfoFromPrefix(mg.GetPublicId()).Subtype]).Strings()))
	}

	item, err := toProto(ctx, mg, outputOpts...)
	if err != nil {
		return nil, err
	}

	return &pbs.UpdateManagedGroupResponse{Item: item}, nil
}

// DeleteManagedGroup implements the interface pbs.ManagedGroupServiceServer.
func (s Service) DeleteManagedGroup(ctx context.Context, req *pbs.DeleteManagedGroupRequest) (*pbs.DeleteManagedGroupResponse, error) {
	if err := validateDeleteRequest(ctx, req); err != nil {
		return nil, err
	}
	_, authResults := s.parentAndAuthResult(ctx, req.GetId(), action.Delete, false)
	if authResults.Error != nil {
		return nil, authResults.Error
	}
	_, err := s.deleteFromRepo(ctx, authResults.Scope.GetId(), req.GetId())
	if err != nil {
		return nil, err
	}
	return nil, nil
}

func (s Service) getFromRepo(ctx context.Context, id string) (auth.ManagedGroup, []string, error) {
	var out auth.ManagedGroup
	var memberIds []string
	switch globals.ResourceInfoFromPrefix(id).Subtype {
	case oidc.Subtype:
		repo, err := s.oidcRepoFn()
		if err != nil {
			return nil, nil, err
		}
		mg, err := repo.LookupManagedGroup(ctx, id)
		if err != nil {
			if errors.IsNotFoundError(err) {
				return nil, nil, handlers.NotFoundErrorf("ManagedGroup %q doesn't exist.", id)
			}
			return nil, nil, err
		}
		ids, err := repo.ListManagedGroupMembershipsByGroup(ctx, mg.GetPublicId(), oidc.WithLimit(-1))
		if err != nil {
			return nil, nil, err
		}
		if len(ids) > 0 {
			memberIds = make([]string, len(ids))
			for i, v := range ids {
				memberIds[i] = v.MemberId
			}
		}
		out = mg
	case ldap.Subtype:
		repo, err := s.ldapRepoFn()
		if err != nil {
			return nil, nil, err
		}
		mg, err := repo.LookupManagedGroup(ctx, id)
		if err != nil {
			if errors.IsNotFoundError(err) {
				return nil, nil, handlers.NotFoundErrorf("LDAP ManagedGroup %q doesn't exist.", id)
			}
			return nil, nil, err
		}
		ids, err := repo.ListManagedGroupMembershipsByGroup(ctx, mg.GetPublicId(), ldap.WithLimit(ctx, -1))
		if err != nil {
			return nil, nil, err
		}
		if len(ids) > 0 {
			memberIds = make([]string, len(ids))
			for i, v := range ids {
				memberIds[i] = v.MemberId
			}
		}
		out = mg
	default:
		return nil, nil, handlers.NotFoundErrorf("Unrecognized id.")
	}
	return out, memberIds, nil
}

func (s Service) createOidcInRepo(ctx context.Context, am auth.AuthMethod, item *pb.ManagedGroup) (*oidc.ManagedGroup, error) {
	const op = "managed_groups.(Service).createOidcInRepo"
	if item == nil {
		return nil, errors.New(ctx, errors.InvalidParameter, op, "missing item")
	}
	var opts []oidc.Option
	if item.GetName() != nil {
		opts = append(opts, oidc.WithName(item.GetName().GetValue()))
	}
	if item.GetDescription() != nil {
		opts = append(opts, oidc.WithDescription(item.GetDescription().GetValue()))
	}
	attrs := item.GetOidcManagedGroupAttributes()
	mg, err := oidc.NewManagedGroup(ctx, am.GetPublicId(), attrs.GetFilter(), opts...)
	if err != nil {
		return nil, handlers.ApiErrorWithCodeAndMessage(codes.Internal, "Unable to build managed group for creation: %v.", err)
	}
	repo, err := s.oidcRepoFn()
	if err != nil {
		return nil, err
	}

	out, err := repo.CreateManagedGroup(ctx, am.GetScopeId(), mg)
	if err != nil {
		return nil, errors.Wrap(ctx, err, op, errors.WithMsg("unable to create managed group"))
	}
	if out == nil {
		return nil, handlers.ApiErrorWithCodeAndMessage(codes.Internal, "Unable to create managed group but no error returned from repository.")
	}
	return out, nil
}

func (s Service) createLdapInRepo(ctx context.Context, am auth.AuthMethod, item *pb.ManagedGroup) (*ldap.ManagedGroup, error) {
	const op = "managed_groups.(Service).createLdapInRepo"
	if item == nil {
		return nil, errors.New(ctx, errors.InvalidParameter, op, "missing item")
	}
	var opts []ldap.Option
	if item.GetName() != nil {
		opts = append(opts, ldap.WithName(ctx, item.GetName().GetValue()))
	}
	if item.GetDescription() != nil {
		opts = append(opts, ldap.WithDescription(ctx, item.GetDescription().GetValue()))
	}
	attrs := item.GetLdapManagedGroupAttributes()
	mg, err := ldap.NewManagedGroup(ctx, am.GetPublicId(), attrs.GetGroupNames(), opts...)
	if err != nil {
		return nil, handlers.ApiErrorWithCodeAndMessage(codes.Internal, "Unable to build managed group for creation: %v.", err)
	}
	repo, err := s.ldapRepoFn()
	if err != nil {
		return nil, err
	}

	out, err := repo.CreateManagedGroup(ctx, am.GetScopeId(), mg)
	if err != nil {
		return nil, errors.Wrap(ctx, err, op, errors.WithMsg("unable to create managed group"))
	}
	if out == nil {
		return nil, handlers.ApiErrorWithCodeAndMessage(codes.Internal, "Unable to create managed group but no error returned from repository.")
	}
	return out, nil
}

func (s Service) createInRepo(ctx context.Context, am auth.AuthMethod, item *pb.ManagedGroup) (auth.ManagedGroup, error) {
	const op = "managed_groups.(Service).createInRepo"
	if item == nil {
		return nil, errors.New(ctx, errors.InvalidParameter, op, "missing item")
	}
	var out auth.ManagedGroup
	switch globals.ResourceInfoFromPrefix(am.GetPublicId()).Subtype {
	case oidc.Subtype:
		am, err := s.createOidcInRepo(ctx, am, item)
		if err != nil {
			return nil, errors.Wrap(ctx, err, op)
		}
		if am == nil {
			return nil, handlers.ApiErrorWithCodeAndMessage(codes.Internal, "Unable to create managed group but no error returned from repository.")
		}
		out = am
	case ldap.Subtype:
		am, err := s.createLdapInRepo(ctx, am, item)
		if err != nil {
			return nil, errors.Wrap(ctx, err, op)
		}
		if am == nil {
			return nil, handlers.ApiErrorWithCodeAndMessage(codes.Internal, "Unable to create ldap managed group but no error returned from repository.")
		}
		out = am
	}
	return out, nil
}

func (s Service) updateOidcInRepo(ctx context.Context, scopeId, amId, id string, mask []string, item *pb.ManagedGroup) (*oidc.ManagedGroup, error) {
	const op = "managed_groups.(Service).updateOidcInRepo"
	if item == nil {
		return nil, errors.New(ctx, errors.InvalidParameter, op, "nil managed group.")
	}
	mg := oidc.AllocManagedGroup()
	mg.PublicId = id
	if item.GetName() != nil {
		mg.Name = item.GetName().GetValue()
	}
	if item.GetDescription() != nil {
		mg.Description = item.GetDescription().GetValue()
	}
	// Set this regardless; it'll only take effect if the masks contain the value
	mg.Filter = item.GetOidcManagedGroupAttributes().GetFilter()

	version := item.GetVersion()

	dbMask := oidcMaskManager.Translate(mask)
	if len(dbMask) == 0 {
		return nil, handlers.InvalidArgumentErrorf("No valid fields included in the update mask.", map[string]string{"update_mask": "No valid fields provided in the update mask."})
	}
	repo, err := s.oidcRepoFn()
	if err != nil {
		return nil, errors.Wrap(ctx, err, op)
	}
	out, rowsUpdated, err := repo.UpdateManagedGroup(ctx, scopeId, mg, version, dbMask)
	if err != nil {
		return nil, errors.Wrap(ctx, err, op, errors.WithMsg("unable to update managed group"))
	}
	if rowsUpdated == 0 {
		return nil, handlers.NotFoundErrorf("Managed Group %q doesn't exist or incorrect version provided.", id)
	}
	return out, nil
}

func (s Service) updateLdapInRepo(ctx context.Context, scopeId, amId, id string, mask []string, item *pb.ManagedGroup) (*ldap.ManagedGroup, error) {
	const op = "managed_groups.(Service).updateLdapInRepo"
	if item == nil {
		return nil, errors.New(ctx, errors.InvalidParameter, op, "nil managed group.")
	}
	mg := ldap.AllocManagedGroup()
	mg.PublicId = id
	if item.GetName() != nil {
		mg.Name = item.GetName().GetValue()
	}
	if item.GetDescription() != nil {
		mg.Description = item.GetDescription().GetValue()
	}
	// Set this regardless; it'll only take effect if the masks contain the value
	encodedGroupNames, err := json.Marshal(item.GetLdapManagedGroupAttributes().GetGroupNames())
	if err != nil {
		return nil, errors.Wrap(ctx, err, op, errors.WithMsg("unable to encode group names"))
	}
	mg.GroupNames = string(encodedGroupNames)

	version := item.GetVersion()

	dbMask := ldapMaskManager.Translate(mask)
	if len(dbMask) == 0 {
		return nil, handlers.InvalidArgumentErrorf("No valid fields included in the update mask.", map[string]string{"update_mask": "No valid fields provided in the update mask."})
	}
	repo, err := s.ldapRepoFn()
	if err != nil {
		return nil, errors.Wrap(ctx, err, op)
	}
	out, rowsUpdated, err := repo.UpdateManagedGroup(ctx, scopeId, mg, version, dbMask)
	if err != nil {
		return nil, errors.Wrap(ctx, err, op, errors.WithMsg("unable to update managed group"))
	}
	if rowsUpdated == 0 {
		return nil, handlers.NotFoundErrorf("Managed Group %q doesn't exist or incorrect version provided.", id)
	}
	return out, nil
}

func (s Service) updateInRepo(ctx context.Context, scopeId, authMethodId string, req *pbs.UpdateManagedGroupRequest) (auth.ManagedGroup, error) {
	const op = "managed_groups.(Service).updateInRepo"
	var out auth.ManagedGroup
	switch globals.ResourceInfoFromPrefix(req.GetId()).Subtype {
	case oidc.Subtype:
		mg, err := s.updateOidcInRepo(ctx, scopeId, authMethodId, req.GetId(), req.GetUpdateMask().GetPaths(), req.GetItem())
		if err != nil {
			return nil, errors.Wrap(ctx, err, op)
		}
		if mg == nil {
			return nil, handlers.ApiErrorWithCodeAndMessage(codes.Internal, "Unable to update managed group but no error returned from repository.")
		}
		out = mg
	case ldap.Subtype:
		mg, err := s.updateLdapInRepo(ctx, scopeId, authMethodId, req.GetId(), req.GetUpdateMask().GetPaths(), req.GetItem())
		if err != nil {
			return nil, errors.Wrap(ctx, err, op)
		}
		if mg == nil {
			return nil, handlers.ApiErrorWithCodeAndMessage(codes.Internal, "Unable to update managed group but no error returned from repository.")
		}
		out = mg
	}
	return out, nil
}

func (s Service) deleteFromRepo(ctx context.Context, scopeId, id string) (bool, error) {
	const op = "managed_groups.(Service).deleteFromRepo"
	var rows int
	var err error
	switch globals.ResourceInfoFromPrefix(id).Subtype {
	case oidc.Subtype:
		repo, iErr := s.oidcRepoFn()
		if iErr != nil {
			return false, iErr
		}
		rows, err = repo.DeleteManagedGroup(ctx, scopeId, id)
	case ldap.Subtype:
		repo, iErr := s.ldapRepoFn()
		if iErr != nil {
			return false, iErr
		}
		rows, err = repo.DeleteManagedGroup(ctx, scopeId, id)
	}
	if err != nil {
		if errors.IsNotFoundError(err) {
			return false, nil
		}
		return false, errors.Wrap(ctx, err, op)
	}
	return rows > 0, nil
}

func (s Service) parentAndAuthResult(ctx context.Context, id string, a action.Type, isRecursive bool) (auth.AuthMethod, requestauth.VerifyResults) {
	const op = "managed_groups.(Service)."
	res := requestauth.VerifyResults{}
	oidcRepo, err := s.oidcRepoFn()
	if err != nil {
		res.Error = err
		return nil, res
	}
	ldapRepo, err := s.ldapRepoFn()
	if err != nil {
		res.Error = err
		return nil, res
	}

	var parentId string
	opts := []requestauth.Option{requestauth.WithAction(a), requestauth.WithRecursive(isRecursive)}
	switch a {
	case action.List, action.Create:
		parentId = id
	default:
		switch globals.ResourceInfoFromPrefix(id).Subtype {
		case oidc.Subtype:
			grp, err := oidcRepo.LookupManagedGroup(ctx, id)
			if err != nil {
				res.Error = err
				return nil, res
			}
			if grp == nil {
				res.Error = handlers.NotFoundError()
				return nil, res
			}
			parentId = grp.GetAuthMethodId()
		case ldap.Subtype:
			grp, err := ldapRepo.LookupManagedGroup(ctx, id)
			if err != nil {
				res.Error = err
				return nil, res
			}
			if grp == nil {
				res.Error = handlers.NotFoundError()
				return nil, res
			}
			parentId = grp.GetAuthMethodId()
		default:
			res.Error = errors.New(ctx, errors.InvalidPublicId, op, "unrecognized managed group subtype")
			return nil, res
		}
		opts = append(opts, requestauth.WithId(id))
	}

	var authMeth auth.AuthMethod
	switch globals.ResourceInfoFromPrefix(parentId).Subtype {
	case oidc.Subtype:
		am, err := oidcRepo.LookupAuthMethod(ctx, parentId)
		if err != nil {
			res.Error = err
			return nil, res
		}
		if am == nil {
			res.Error = handlers.NotFoundError()
			return nil, res
		}
		authMeth = am
		opts = append(opts, requestauth.WithScopeId(am.GetScopeId()))
	case ldap.Subtype:
		am, err := ldapRepo.LookupAuthMethod(ctx, parentId)
		if err != nil {
			res.Error = err
			return nil, res
		}
		if am == nil {
			res.Error = handlers.NotFoundError()
			return nil, res
		}
		authMeth = am
		opts = append(opts, requestauth.WithScopeId(am.GetScopeId()))
	default:
		res.Error = errors.New(ctx, errors.InvalidPublicId, op, "unrecognized auth method subtype")
		return nil, res
	}
	opts = append(opts, requestauth.WithPin(parentId))
	return authMeth, requestauth.Verify(ctx, resource.ManagedGroup, opts...)
}

func toProto(ctx context.Context, in auth.ManagedGroup, opt ...handlers.Option) (*pb.ManagedGroup, error) {
	opts := handlers.GetOpts(opt...)
	if opts.WithOutputFields == nil {
		return nil, handlers.ApiErrorWithCodeAndMessage(codes.Internal, "output fields not found when building managed group proto")
	}
	outputFields := *opts.WithOutputFields

	out := pb.ManagedGroup{}
	if outputFields.Has(globals.IdField) {
		out.Id = in.GetPublicId()
	}
	if outputFields.Has(globals.AuthMethodIdField) {
		out.AuthMethodId = in.GetAuthMethodId()
	}
	if outputFields.Has(globals.DescriptionField) && in.GetDescription() != "" {
		out.Description = &wrapperspb.StringValue{Value: in.GetDescription()}
	}
	if outputFields.Has(globals.NameField) && in.GetName() != "" {
		out.Name = &wrapperspb.StringValue{Value: in.GetName()}
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
	if outputFields.Has(globals.MemberIdsField) {
		out.MemberIds = opts.WithMemberIds
	}
	switch i := in.(type) {
	case *oidc.ManagedGroup:
		if outputFields.Has(globals.TypeField) {
			out.Type = oidc.Subtype.String()
		}
		if !outputFields.Has(globals.AttributesField) {
			break
		}
		attrs := &pb.OidcManagedGroupAttributes{
			Filter: i.GetFilter(),
		}
		out.Attrs = &pb.ManagedGroup_OidcManagedGroupAttributes{
			OidcManagedGroupAttributes: attrs,
		}
	case *ldap.ManagedGroup:
		if outputFields.Has(globals.TypeField) {
			out.Type = ldap.Subtype.String()
		}
		if !outputFields.Has(globals.AttributesField) {
			break
		}

		var grpNames []string
		if err := json.Unmarshal([]byte(i.GetGroupNames()), &grpNames); err != nil {
			return nil, handlers.ApiErrorWithCodeAndMessage(codes.Internal, "unable to unmarshal group names")
		}

		attrs := &pb.LdapManagedGroupAttributes{
			GroupNames: grpNames,
		}
		out.Attrs = &pb.ManagedGroup_LdapManagedGroupAttributes{
			LdapManagedGroupAttributes: attrs,
		}
	}
	return &out, nil
}

// A validateX method should exist for each method above.  These methods do not make calls to any backing service but enforce
// requirements on the structure of the request.  They verify that:
//   - The path passed in is correctly formatted
//   - All required parameters are set
//   - There are no conflicting parameters provided
func validateGetRequest(ctx context.Context, req *pbs.GetManagedGroupRequest) error {
	const op = "managed_groups.validateGetRequest"
	if req == nil {
		return errors.New(ctx, errors.InvalidParameter, op, "nil request")
	}
	return handlers.ValidateGetRequest(handlers.NoopValidatorFn, req, globals.OidcManagedGroupPrefix, globals.LdapManagedGroupPrefix)
}

func validateCreateRequest(ctx context.Context, req *pbs.CreateManagedGroupRequest) error {
	const op = "managed_groups.validateCreateRequest"
	if req == nil {
		return errors.New(ctx, errors.InvalidParameter, op, "nil request")
	}
	return handlers.ValidateCreateRequest(req.GetItem(), func() map[string]string {
		badFields := map[string]string{}
		if req.GetItem().GetAuthMethodId() == "" {
			badFields[globals.AuthMethodIdField] = "This field is required."
		}
		switch globals.ResourceInfoFromPrefix(req.GetItem().GetAuthMethodId()).Subtype {
		case oidc.Subtype:
			if req.GetItem().GetType() != "" && req.GetItem().GetType() != oidc.Subtype.String() {
				badFields[globals.TypeField] = "Doesn't match the parent resource's type."
			}
			attrs := req.GetItem().GetOidcManagedGroupAttributes()
			if attrs == nil {
				badFields[globals.AttributesField] = "Attribute fields is required."
			} else {
				if attrs.Filter == "" {
					badFields[attrFilterField] = "This field is required."
				} else {
					if _, err := bexpr.CreateEvaluator(attrs.Filter); err != nil {
						badFields[attrFilterField] = fmt.Sprintf("Error evaluating submitted filter expression: %v.", err)
					}
				}
			}
		case ldap.Subtype:
			if req.GetItem().GetType() != "" && req.GetItem().GetType() != ldap.Subtype.String() {
				badFields[globals.TypeField] = "Doesn't match the parent resource's type."
			}
			attrs := req.GetItem().GetLdapManagedGroupAttributes()
			if attrs == nil {
				badFields[globals.AttributesField] = "Attribute fields is required."
			} else {
				if len(attrs.GroupNames) == 0 {
					badFields[attrGroupNamesField] = "This field is required."
				}
			}
		default:
			badFields[globals.AuthMethodIdField] = "Unknown auth method type from ID."
		}
		return badFields
	})
}

func validateUpdateRequest(ctx context.Context, req *pbs.UpdateManagedGroupRequest) error {
	const op = "managed_groups.validateUpdateRequest"
	if req == nil {
		return errors.New(ctx, errors.InvalidParameter, op, "nil request")
	}
	return handlers.ValidateUpdateRequest(req, req.GetItem(), func() map[string]string {
		badFields := map[string]string{}
		switch globals.ResourceInfoFromPrefix(req.GetId()).Subtype {
		case oidc.Subtype:
			if req.GetItem().GetType() != "" && req.GetItem().GetType() != oidc.Subtype.String() {
				badFields[globals.TypeField] = "Cannot modify the resource type."
			}
			attrs := req.GetItem().GetOidcManagedGroupAttributes()
			if handlers.MaskContains(req.GetUpdateMask().GetPaths(), attrFilterField) {
				switch {
				case attrs == nil:
					badFields["attributes"] = "Attributes field not supplied request"
				default:
					if attrs.Filter == "" {
						badFields[attrFilterField] = "Field cannot be empty."
					} else {
						if _, err := bexpr.CreateEvaluator(attrs.Filter); err != nil {
							badFields[attrFilterField] = fmt.Sprintf("Error evaluating submitted filter expression: %v.", err)
						}
					}
				}
			}
		case ldap.Subtype:
			if req.GetItem().GetType() != "" && req.GetItem().GetType() != ldap.Subtype.String() {
				badFields[globals.TypeField] = "Cannot modify the resource type."
			}
			attrs := req.GetItem().GetLdapManagedGroupAttributes()
			if handlers.MaskContains(req.GetUpdateMask().GetPaths(), attrGroupNamesField) {
				if len(attrs.GroupNames) == 0 {
					badFields[attrFilterField] = "Field cannot be empty."
				}
			}
		default:
			badFields[globals.IdField] = "Unrecognized resource type."
		}
		return badFields
	}, globals.OidcManagedGroupPrefix, globals.LdapManagedGroupPrefix)
}

func validateDeleteRequest(ctx context.Context, req *pbs.DeleteManagedGroupRequest) error {
	const op = "managed_groups.validateDeleteRequest"
	if req == nil {
		return errors.New(ctx, errors.InvalidParameter, op, "nil request")
	}
	return handlers.ValidateDeleteRequest(handlers.NoopValidatorFn, req, globals.OidcManagedGroupPrefix, globals.LdapManagedGroupPrefix)
}

func validateListRequest(ctx context.Context, req *pbs.ListManagedGroupsRequest) error {
	const op = "managed_groups.validateListRequest"
	if req == nil {
		return errors.New(ctx, errors.InvalidParameter, op, "nil request")
	}
	badFields := map[string]string{}
	if !handlers.ValidId(handlers.Id(req.GetAuthMethodId()), globals.OidcAuthMethodPrefix, globals.LdapAuthMethodPrefix) {
		badFields[globals.AuthMethodIdField] = "Invalid formatted identifier."
	}
	if _, err := handlers.NewFilter(ctx, req.GetFilter()); err != nil {
		badFields[globals.FilterField] = fmt.Sprintf("This field could not be parsed. %v", err)
	}
	if len(badFields) > 0 {
		return handlers.InvalidArgumentErrorf("Error in provided request.", badFields)
	}
	return nil
}

func newOutputOpts(ctx context.Context, item auth.ManagedGroup, authMethodId string, authResults requestauth.VerifyResults) ([]handlers.Option, bool) {
	res := perms.Resource{
		ScopeId:       authResults.Scope.Id,
		ParentScopeId: authResults.Scope.ParentScopeId,
		Type:          resource.ManagedGroup,
		Pin:           authMethodId,
	}
	res.Id = item.GetPublicId()
	authorizedActions := authResults.FetchActionSetForId(ctx, item.GetPublicId(), IdActions[globals.ResourceInfoFromPrefix(item.GetPublicId()).Subtype], requestauth.WithResource(&res)).Strings()
	if len(authorizedActions) == 0 {
		return nil, false
	}

	outputFields := authResults.FetchOutputFields(res, action.List).SelfOrDefaults(authResults.UserId)
	outputOpts := make([]handlers.Option, 0, 3)
	outputOpts = append(outputOpts, handlers.WithOutputFields(outputFields))
	if outputFields.Has(globals.ScopeField) {
		outputOpts = append(outputOpts, handlers.WithScope(authResults.Scope))
	}
	if outputFields.Has(globals.AuthorizedActionsField) {
		outputOpts = append(outputOpts, handlers.WithAuthorizedActions(authorizedActions))
	}
	return outputOpts, true
}
