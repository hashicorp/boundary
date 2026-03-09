// Copyright IBM Corp. 2020, 2025
// SPDX-License-Identifier: BUSL-1.1

package groups

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
	"github.com/hashicorp/boundary/internal/listtoken"
	"github.com/hashicorp/boundary/internal/pagination"
	"github.com/hashicorp/boundary/internal/perms"
	"github.com/hashicorp/boundary/internal/requests"
	"github.com/hashicorp/boundary/internal/types/action"
	"github.com/hashicorp/boundary/internal/types/resource"
	"github.com/hashicorp/boundary/internal/types/scope"
	pb "github.com/hashicorp/boundary/sdk/pbs/controller/api/resources/groups"
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
		action.AddMembers,
		action.SetMembers,
		action.RemoveMembers,
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
		handlers.MaskDestination{&store.Group{}},
		handlers.MaskSource{&pb.Group{}},
	); err != nil {
		panic(err)
	}

	// TODO: refactor to remove IdActionsMap and CollectionActions package variables
	action.RegisterResource(resource.Group, IdActions, CollectionActions)
}

// Service handles request as described by the pbs.GroupServiceServer interface.
type Service struct {
	pbs.UnsafeGroupServiceServer

	repoFn      common.IamRepoFactory
	maxPageSize uint
}

var _ pbs.GroupServiceServer = (*Service)(nil)

// NewService returns a group service which handles group related requests to boundary.
func NewService(ctx context.Context, repo common.IamRepoFactory, maxPageSize uint) (Service, error) {
	const op = "groups.NewService"
	if repo == nil {
		return Service{}, errors.New(ctx, errors.InvalidParameter, op, "missing iam repository")
	}
	if maxPageSize == 0 {
		maxPageSize = uint(globals.DefaultMaxPageSize)
	}
	return Service{repoFn: repo, maxPageSize: maxPageSize}, nil
}

// ListGroups implements the interface pbs.GroupServiceServer.
func (s Service) ListGroups(ctx context.Context, req *pbs.ListGroupsRequest) (*pbs.ListGroupsResponse, error) {
	const op = "groups.(Service).ListGroups"
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
		ctx, s.repoFn, authResults, req.GetScopeId(), resource.Group, req.GetRecursive())
	if err != nil {
		return nil, err
	}

	pageSize := int(s.maxPageSize)
	// Use the requested page size only if it is smaller than
	// the configured max.
	if req.GetPageSize() != 0 && uint(req.GetPageSize()) < s.maxPageSize {
		pageSize = int(req.GetPageSize())
	}

	var filterItemFn func(ctx context.Context, item *iam.Group) (bool, error)
	switch {
	case req.GetFilter() != "":
		// Only use a filter if we need to
		filter, err := handlers.NewFilter(ctx, req.GetFilter())
		if err != nil {
			return nil, err
		}
		filterItemFn = func(ctx context.Context, item *iam.Group) (bool, error) {
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
		filterItemFn = func(ctx context.Context, item *iam.Group) (bool, error) {
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
	var listResp *pagination.ListResponse[*iam.Group]
	var sortBy string
	if req.GetListToken() == "" {
		sortBy = "created_time"
		listResp, err = iam.ListGroups(ctx, grantsHash, pageSize, filterItemFn, repo, scopeIds)
		if err != nil {
			return nil, err
		}
	} else {
		listToken, err := handlers.ParseListToken(ctx, req.GetListToken(), resource.Group, grantsHash)
		if err != nil {
			return nil, err
		}
		switch st := listToken.Subtype.(type) {
		case *listtoken.PaginationToken:
			sortBy = "created_time"
			listResp, err = iam.ListGroupsPage(ctx, grantsHash, pageSize, filterItemFn, listToken, repo, scopeIds)
			if err != nil {
				return nil, err
			}
		case *listtoken.StartRefreshToken:
			sortBy = "updated_time"
			listResp, err = iam.ListGroupsRefresh(ctx, grantsHash, pageSize, filterItemFn, listToken, repo, scopeIds)
			if err != nil {
				return nil, err
			}
		case *listtoken.RefreshToken:
			sortBy = "updated_time"
			listResp, err = iam.ListGroupsRefreshPage(ctx, grantsHash, pageSize, filterItemFn, listToken, repo, scopeIds)
			if err != nil {
				return nil, err
			}
		default:
			return nil, handlers.ApiErrorWithCodeAndMessage(codes.InvalidArgument, "unexpected list token subtype: %T", st)
		}
	}

	finalItems := make([]*pb.Group, 0, len(listResp.Items))
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
	resp := &pbs.ListGroupsResponse{
		Items:        finalItems,
		EstItemCount: uint32(listResp.EstimatedItemCount),
		RemovedIds:   listResp.DeletedIds,
		ResponseType: respType,
		SortBy:       sortBy,
		SortDir:      "desc",
	}
	if listResp.ListToken != nil {
		resp.ListToken, err = handlers.MarshalListToken(ctx, listResp.ListToken, pbs.ResourceType_RESOURCE_TYPE_GROUP)
		if err != nil {
			return nil, err
		}
	}
	return resp, nil
}

// GetGroups implements the interface pbs.GroupServiceServer.
func (s Service) GetGroup(ctx context.Context, req *pbs.GetGroupRequest) (*pbs.GetGroupResponse, error) {
	const op = "groups.(Service).GetGroup"

	if err := validateGetRequest(req); err != nil {
		return nil, err
	}
	authResults := s.authResult(ctx, req.GetId(), action.Read, false)
	if authResults.Error != nil {
		return nil, authResults.Error
	}
	u, members, err := s.getFromRepo(ctx, req.GetId())
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

	item, err := toProto(ctx, u, members, outputOpts...)
	if err != nil {
		return nil, err
	}

	return &pbs.GetGroupResponse{Item: item}, nil
}

// CreateGroup implements the interface pbs.GroupServiceServer.
func (s Service) CreateGroup(ctx context.Context, req *pbs.CreateGroupRequest) (*pbs.CreateGroupResponse, error) {
	const op = "groups.(Service).CreateGroup"

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

	return &pbs.CreateGroupResponse{Item: item, Uri: fmt.Sprintf("groups/%s", item.GetId())}, nil
}

// UpdateGroup implements the interface pbs.GroupServiceServer.
func (s Service) UpdateGroup(ctx context.Context, req *pbs.UpdateGroupRequest) (*pbs.UpdateGroupResponse, error) {
	const op = "groups.(Service).UpdateGroup"

	if err := validateUpdateRequest(req); err != nil {
		return nil, err
	}
	authResults := s.authResult(ctx, req.GetId(), action.Update, false)
	if authResults.Error != nil {
		return nil, authResults.Error
	}
	u, members, err := s.updateInRepo(ctx, authResults.Scope.GetId(), req.GetId(), req.GetUpdateMask().GetPaths(), req.GetItem())
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

	item, err := toProto(ctx, u, members, outputOpts...)
	if err != nil {
		return nil, err
	}

	return &pbs.UpdateGroupResponse{Item: item}, nil
}

// DeleteGroup implements the interface pbs.GroupServiceServer.
func (s Service) DeleteGroup(ctx context.Context, req *pbs.DeleteGroupRequest) (*pbs.DeleteGroupResponse, error) {
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

// AddGroupMembers implements the interface pbs.GroupServiceServer.
func (s Service) AddGroupMembers(ctx context.Context, req *pbs.AddGroupMembersRequest) (*pbs.AddGroupMembersResponse, error) {
	const op = "groups.(Service).AddGroupMembers"

	if err := validateAddGroupMembersRequest(req); err != nil {
		return nil, err
	}
	authResults := s.authResult(ctx, req.GetId(), action.AddMembers, false)
	if authResults.Error != nil {
		return nil, authResults.Error
	}
	g, members, err := s.addMembersInRepo(ctx, req.GetId(), req.GetMemberIds(), req.GetVersion())
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
		outputOpts = append(outputOpts, handlers.WithAuthorizedActions(authResults.FetchActionSetForId(ctx, g.GetPublicId(), IdActions).Strings()))
	}

	item, err := toProto(ctx, g, members, outputOpts...)
	if err != nil {
		return nil, err
	}

	return &pbs.AddGroupMembersResponse{Item: item}, nil
}

// SetGroupMembers implements the interface pbs.GroupServiceServer.
func (s Service) SetGroupMembers(ctx context.Context, req *pbs.SetGroupMembersRequest) (*pbs.SetGroupMembersResponse, error) {
	const op = "groups.(Service).SetGroupMembers"

	if err := validateSetGroupMembersRequest(req); err != nil {
		return nil, err
	}
	authResults := s.authResult(ctx, req.GetId(), action.SetMembers, false)
	if authResults.Error != nil {
		return nil, authResults.Error
	}
	g, members, err := s.setMembersInRepo(ctx, req.GetId(), req.GetMemberIds(), req.GetVersion())
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
		outputOpts = append(outputOpts, handlers.WithAuthorizedActions(authResults.FetchActionSetForId(ctx, g.GetPublicId(), IdActions).Strings()))
	}

	item, err := toProto(ctx, g, members, outputOpts...)
	if err != nil {
		return nil, err
	}

	return &pbs.SetGroupMembersResponse{Item: item}, nil
}

// RemoveGroupMembers implements the interface pbs.GroupServiceServer.
func (s Service) RemoveGroupMembers(ctx context.Context, req *pbs.RemoveGroupMembersRequest) (*pbs.RemoveGroupMembersResponse, error) {
	const op = "groups.(Service).RemoveGroupMembers"

	if err := validateRemoveGroupMembersRequest(req); err != nil {
		return nil, err
	}
	authResults := s.authResult(ctx, req.GetId(), action.RemoveMembers, false)
	if authResults.Error != nil {
		return nil, authResults.Error
	}
	g, members, err := s.removeMembersInRepo(ctx, req.GetId(), req.GetMemberIds(), req.GetVersion())
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
		outputOpts = append(outputOpts, handlers.WithAuthorizedActions(authResults.FetchActionSetForId(ctx, g.GetPublicId(), IdActions).Strings()))
	}

	item, err := toProto(ctx, g, members, outputOpts...)
	if err != nil {
		return nil, err
	}

	return &pbs.RemoveGroupMembersResponse{Item: item}, nil
}

func (s Service) getFromRepo(ctx context.Context, id string) (*iam.Group, []*iam.GroupMember, error) {
	const op = "groups.(Service).getFromRepo"
	repo, err := s.repoFn()
	if err != nil {
		return nil, nil, errors.Wrap(ctx, err, op)
	}
	g, m, err := repo.LookupGroup(ctx, id)
	if err != nil && !errors.IsNotFoundError(err) {
		return nil, nil, errors.Wrap(ctx, err, op)
	}
	if g == nil {
		return nil, nil, errors.New(ctx, errors.InvalidParameter, op, fmt.Sprintf("group %q not found", id))
	}
	return g, m, err
}

func (s Service) createInRepo(ctx context.Context, scopeId string, item *pb.Group) (*iam.Group, error) {
	const op = "groups.(Service).createInRepo"
	var opts []iam.Option
	if item.GetName() != nil {
		opts = append(opts, iam.WithName(item.GetName().GetValue()))
	}
	if item.GetDescription() != nil {
		opts = append(opts, iam.WithDescription(item.GetDescription().GetValue()))
	}
	u, err := iam.NewGroup(ctx, scopeId, opts...)
	if err != nil {
		return nil, handlers.ApiErrorWithCodeAndMessage(codes.Internal, "Unable to build group for creation: %v.", err)
	}
	repo, err := s.repoFn()
	if err != nil {
		return nil, errors.Wrap(ctx, err, op)
	}
	out, err := repo.CreateGroup(ctx, u)
	if err != nil {
		return nil, errors.Wrap(ctx, err, op)
	}
	if out == nil {
		return nil, handlers.ApiErrorWithCodeAndMessage(codes.Internal, "Unable to create group but no error returned from repository.")
	}
	return out, nil
}

func (s Service) updateInRepo(ctx context.Context, scopeId, id string, mask []string, item *pb.Group) (*iam.Group, []*iam.GroupMember, error) {
	const op = "groups.(Service).updateInRepo"
	var opts []iam.Option
	if desc := item.GetDescription(); desc != nil {
		opts = append(opts, iam.WithDescription(desc.GetValue()))
	}
	if name := item.GetName(); name != nil {
		opts = append(opts, iam.WithName(name.GetValue()))
	}
	version := item.GetVersion()
	g, err := iam.NewGroup(ctx, scopeId, opts...)
	if err != nil {
		return nil, nil, handlers.ApiErrorWithCodeAndMessage(codes.Internal, "Unable to build group for update: %v.", err)
	}
	g.PublicId = id
	dbMask := maskManager.Translate(mask)
	if len(dbMask) == 0 {
		return nil, nil, handlers.InvalidArgumentErrorf("No valid fields included in the update mask.", map[string]string{"update_mask": "No valid fields provided in the update mask."})
	}
	repo, err := s.repoFn()
	if err != nil {
		return nil, nil, errors.Wrap(ctx, err, op)
	}
	out, m, rowsUpdated, err := repo.UpdateGroup(ctx, g, version, dbMask)
	if err != nil {
		return nil, nil, errors.Wrap(ctx, err, op)
	}
	if rowsUpdated == 0 {
		return nil, nil, handlers.NotFoundErrorf("Group %q doesn't exist or incorrect version provided.", id)
	}
	return out, m, nil
}

func (s Service) deleteFromRepo(ctx context.Context, id string) (bool, error) {
	const op = "groups.(Service).deleteFromRepo"
	repo, err := s.repoFn()
	if err != nil {
		return false, err
	}
	rows, err := repo.DeleteGroup(ctx, id)
	if err != nil {
		if errors.IsNotFoundError(err) {
			return false, nil
		}
		return false, errors.Wrap(ctx, err, op, errors.WithMsg("unable to delete group"))
	}
	return rows > 0, nil
}

func (s Service) addMembersInRepo(ctx context.Context, groupId string, userIds []string, version uint32) (*iam.Group, []*iam.GroupMember, error) {
	const op = "groups.(Service).addMembersInRepo"
	repo, err := s.repoFn()
	if err != nil {
		return nil, nil, errors.Wrap(ctx, err, op)
	}
	_, err = repo.AddGroupMembers(ctx, groupId, version, strutil.RemoveDuplicates(userIds, false))
	if err != nil {
		// TODO: Figure out a way to surface more helpful error info beyond the Internal error.
		return nil, nil, handlers.ApiErrorWithCodeAndMessage(codes.Internal, "Unable to add members to group: %v.", err)
	}
	out, m, err := repo.LookupGroup(ctx, groupId)
	if err != nil {
		return nil, nil, errors.Wrap(ctx, err, op, errors.WithMsg("unable to look up group after adding memebers"))
	}
	if out == nil {
		return nil, nil, handlers.ApiErrorWithCodeAndMessage(codes.Internal, "Unable to lookup group after adding member to it.")
	}
	return out, m, nil
}

func (s Service) setMembersInRepo(ctx context.Context, groupId string, userIds []string, version uint32) (*iam.Group, []*iam.GroupMember, error) {
	const op = "groups.(Service).setMembersInRepo"
	repo, err := s.repoFn()
	if err != nil {
		return nil, nil, errors.Wrap(ctx, err, op)
	}
	_, _, err = repo.SetGroupMembers(ctx, groupId, version, strutil.RemoveDuplicates(userIds, false))
	if err != nil {
		// TODO: Figure out a way to surface more helpful error info beyond the Internal error.
		return nil, nil, handlers.ApiErrorWithCodeAndMessage(codes.Internal, "Unable to set members on group: %v.", err)
	}
	out, m, err := repo.LookupGroup(ctx, groupId)
	if err != nil {
		return nil, nil, errors.Wrap(ctx, err, op, errors.WithMsg("unable to look up group after setting members"))
	}
	if out == nil {
		return nil, nil, handlers.ApiErrorWithCodeAndMessage(codes.Internal, "Unable to lookup group after setting members for it.")
	}
	return out, m, nil
}

func (s Service) removeMembersInRepo(ctx context.Context, groupId string, userIds []string, version uint32) (*iam.Group, []*iam.GroupMember, error) {
	const op = "groups.(Service).removeMembersInRepo"
	repo, err := s.repoFn()
	if err != nil {
		return nil, nil, errors.Wrap(ctx, err, op)
	}
	_, err = repo.DeleteGroupMembers(ctx, groupId, version, strutil.RemoveDuplicates(userIds, false))
	if err != nil {
		// TODO: Figure out a way to surface more helpful error info beyond the Internal error.
		return nil, nil, handlers.ApiErrorWithCodeAndMessage(codes.Internal, "Unable to remove members from group: %v.", err)
	}
	out, m, err := repo.LookupGroup(ctx, groupId)
	if err != nil {
		return nil, nil, errors.Wrap(ctx, err, op, errors.WithMsg("unable to look up group after removing members"))
	}
	if out == nil {
		return nil, nil, handlers.ApiErrorWithCodeAndMessage(codes.Internal, "Unable to lookup group after removing members from it.")
	}
	return out, m, nil
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
		grp, _, err := repo.LookupGroup(ctx, id)
		if err != nil {
			res.Error = err
			return res
		}
		if grp == nil {
			res.Error = handlers.NotFoundError()
			return res
		}
		parentId = grp.GetScopeId()
		opts = append(opts, auth.WithId(id))
	}
	opts = append(opts, auth.WithScopeId(parentId))
	return auth.Verify(ctx, resource.Group, opts...)
}

func toProto(ctx context.Context, in *iam.Group, members []*iam.GroupMember, opt ...handlers.Option) (*pb.Group, error) {
	opts := handlers.GetOpts(opt...)
	if opts.WithOutputFields == nil {
		return nil, handlers.ApiErrorWithCodeAndMessage(codes.Internal, "output fields not found when building group proto")
	}
	outputFields := *opts.WithOutputFields

	out := pb.Group{}
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
	if outputFields.Has(globals.MemberIdsField) {
		for _, m := range members {
			out.MemberIds = append(out.MemberIds, m.GetMemberId())
		}
	}
	if outputFields.Has(globals.MembersField) {
		for _, m := range members {
			out.Members = append(out.Members, &pb.Member{
				Id:      m.GetMemberId(),
				ScopeId: m.GetMemberScopeId(),
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
func validateGetRequest(req *pbs.GetGroupRequest) error {
	return handlers.ValidateGetRequest(handlers.NoopValidatorFn, req, globals.GroupPrefix)
}

func validateCreateRequest(req *pbs.CreateGroupRequest) error {
	return handlers.ValidateCreateRequest(req.GetItem(), func() map[string]string {
		badFields := map[string]string{}
		if !handlers.ValidId(handlers.Id(req.GetItem().GetScopeId()), scope.Org.Prefix()) &&
			!handlers.ValidId(handlers.Id(req.GetItem().GetScopeId()), scope.Project.Prefix()) &&
			scope.Global.String() != req.GetItem().GetScopeId() {
			badFields["scope_id"] = "This field is missing or improperly formatted."
		}
		return badFields
	})
}

func validateUpdateRequest(req *pbs.UpdateGroupRequest) error {
	return handlers.ValidateUpdateRequest(req, req.GetItem(), handlers.NoopValidatorFn, globals.GroupPrefix)
}

func validateDeleteRequest(req *pbs.DeleteGroupRequest) error {
	return handlers.ValidateDeleteRequest(handlers.NoopValidatorFn, req, globals.GroupPrefix)
}

func validateListRequest(ctx context.Context, req *pbs.ListGroupsRequest) error {
	badFields := map[string]string{}
	if !handlers.ValidId(handlers.Id(req.GetScopeId()), scope.Org.Prefix()) &&
		!handlers.ValidId(handlers.Id(req.GetScopeId()), scope.Project.Prefix()) &&
		req.GetScopeId() != scope.Global.String() {
		badFields["scope_id"] = "Incorrectly formatted identifier."
	}
	if _, err := handlers.NewFilter(ctx, req.GetFilter()); err != nil {
		badFields["filter"] = fmt.Sprintf("This field could not be parsed. %v", err)
	}
	if len(badFields) > 0 {
		return handlers.InvalidArgumentErrorf("Improperly formatted identifier.", badFields)
	}
	return nil
}

func validateAddGroupMembersRequest(req *pbs.AddGroupMembersRequest) error {
	badFields := map[string]string{}
	if !handlers.ValidId(handlers.Id(req.GetId()), globals.GroupPrefix) {
		badFields["id"] = "Incorrectly formatted identifier."
	}
	if req.GetVersion() == 0 {
		badFields["version"] = "Required field."
	}
	if len(req.GetMemberIds()) == 0 {
		badFields["member_ids"] = "Must be non-empty."
	}
	for _, id := range req.GetMemberIds() {
		if !handlers.ValidId(handlers.Id(id), globals.UserPrefix) {
			badFields["member_ids"] = fmt.Sprintf("Must only contain valid user ids but found %q.", id)
			break
		}
		if id == globals.RecoveryUserId {
			badFields["member_ids"] = "u_recovery cannot be assigned to a group."
			break
		}
	}
	if len(badFields) > 0 {
		return handlers.InvalidArgumentErrorf("Errors in provided fields.", badFields)
	}
	return nil
}

func validateSetGroupMembersRequest(req *pbs.SetGroupMembersRequest) error {
	badFields := map[string]string{}
	if !handlers.ValidId(handlers.Id(req.GetId()), globals.GroupPrefix) {
		badFields["id"] = "Incorrectly formatted identifier."
	}
	if req.GetVersion() == 0 {
		badFields["version"] = "Required field."
	}
	for _, id := range req.GetMemberIds() {
		if !handlers.ValidId(handlers.Id(id), globals.UserPrefix) {
			badFields["member_ids"] = fmt.Sprintf("Must only contain valid user ids but found %q.", id)
			break
		}
		if id == globals.RecoveryUserId {
			badFields["member_ids"] = "u_recovery cannot be assigned to a group."
			break
		}
	}
	if len(badFields) > 0 {
		return handlers.InvalidArgumentErrorf("Errors in provided fields.", badFields)
	}
	return nil
}

func validateRemoveGroupMembersRequest(req *pbs.RemoveGroupMembersRequest) error {
	badFields := map[string]string{}
	if !handlers.ValidId(handlers.Id(req.GetId()), globals.GroupPrefix) {
		badFields["id"] = "Incorrectly formatted identifier."
	}
	if req.GetVersion() == 0 {
		badFields["version"] = "Required field."
	}
	if len(req.GetMemberIds()) == 0 {
		badFields["member_ids"] = "Must be non-empty."
	}
	for _, id := range req.GetMemberIds() {
		if !handlers.ValidId(handlers.Id(id), globals.UserPrefix) {
			badFields["member_ids"] = fmt.Sprintf("Must only contain valid user ids but found %q.", id)
			break
		}
	}
	if len(badFields) > 0 {
		return handlers.InvalidArgumentErrorf("Errors in provided fields.", badFields)
	}
	return nil
}

func newOutputOpts(ctx context.Context, item *iam.Group, scopeInfoMap map[string]*scopes.ScopeInfo, authResults auth.VerifyResults) ([]handlers.Option, bool) {
	res := perms.Resource{
		Type: resource.Group,
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
