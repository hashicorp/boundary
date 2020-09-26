package groups

import (
	"context"
	"errors"
	"fmt"

	"github.com/hashicorp/boundary/internal/auth"
	"github.com/hashicorp/boundary/internal/db"
	pb "github.com/hashicorp/boundary/internal/gen/controller/api/resources/groups"
	pbs "github.com/hashicorp/boundary/internal/gen/controller/api/services"
	"github.com/hashicorp/boundary/internal/iam"
	"github.com/hashicorp/boundary/internal/iam/store"
	"github.com/hashicorp/boundary/internal/servers/controller/common"
	"github.com/hashicorp/boundary/internal/servers/controller/handlers"
	"github.com/hashicorp/boundary/internal/types/action"
	"github.com/hashicorp/boundary/internal/types/resource"
	"github.com/hashicorp/boundary/internal/types/scope"
	"google.golang.org/grpc/codes"
	"google.golang.org/protobuf/types/known/wrapperspb"
)

var (
	maskManager handlers.MaskManager
)

func init() {
	var err error
	if maskManager, err = handlers.NewMaskManager(&store.Group{}, &pb.Group{}); err != nil {
		panic(err)
	}
}

// Service handles request as described by the pbs.GroupServiceServer interface.
type Service struct {
	repoFn common.IamRepoFactory
}

// NewService returns a group service which handles group related requests to boundary.
func NewService(repo common.IamRepoFactory) (Service, error) {
	if repo == nil {
		return Service{}, fmt.Errorf("nil iam repository provided")
	}
	return Service{repoFn: repo}, nil
}

var _ pbs.GroupServiceServer = Service{}

// ListGroups implements the interface pbs.GroupServiceServer.
func (s Service) ListGroups(ctx context.Context, req *pbs.ListGroupsRequest) (*pbs.ListGroupsResponse, error) {
	if err := validateListRequest(req); err != nil {
		return nil, err
	}
	authResults := s.authResult(ctx, req.GetScopeId(), action.List)
	if authResults.Error != nil {
		return nil, authResults.Error
	}
	gl, err := s.listFromRepo(ctx, req.GetScopeId())
	if err != nil {
		return nil, err
	}
	for _, item := range gl {
		item.Scope = authResults.Scope
	}
	return &pbs.ListGroupsResponse{Items: gl}, nil
}

// GetGroups implements the interface pbs.GroupServiceServer.
func (s Service) GetGroup(ctx context.Context, req *pbs.GetGroupRequest) (*pbs.GetGroupResponse, error) {
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
	return &pbs.GetGroupResponse{Item: u}, nil
}

// CreateGroup implements the interface pbs.GroupServiceServer.
func (s Service) CreateGroup(ctx context.Context, req *pbs.CreateGroupRequest) (*pbs.CreateGroupResponse, error) {
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
	return &pbs.CreateGroupResponse{Item: u, Uri: fmt.Sprintf("groups/%s", u.GetId())}, nil
}

// UpdateGroup implements the interface pbs.GroupServiceServer.
func (s Service) UpdateGroup(ctx context.Context, req *pbs.UpdateGroupRequest) (*pbs.UpdateGroupResponse, error) {
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
	return &pbs.UpdateGroupResponse{Item: u}, nil
}

// DeleteGroup implements the interface pbs.GroupServiceServer.
func (s Service) DeleteGroup(ctx context.Context, req *pbs.DeleteGroupRequest) (*pbs.DeleteGroupResponse, error) {
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
	return &pbs.DeleteGroupResponse{}, nil
}

// AddGroupMembers implements the interface pbs.GroupServiceServer.
func (s Service) AddGroupMembers(ctx context.Context, req *pbs.AddGroupMembersRequest) (*pbs.AddGroupMembersResponse, error) {
	if err := validateAddGroupMembersRequest(req); err != nil {
		return nil, err
	}
	authResults := s.authResult(ctx, req.GetId(), action.AddMembers)
	if authResults.Error != nil {
		return nil, authResults.Error
	}
	g, err := s.addMembersInRepo(ctx, req.GetId(), req.GetMemberIds(), req.GetVersion())
	if err != nil {
		return nil, err
	}
	g.Scope = authResults.Scope
	return &pbs.AddGroupMembersResponse{Item: g}, nil
}

// SetGroupMembers implements the interface pbs.GroupServiceServer.
func (s Service) SetGroupMembers(ctx context.Context, req *pbs.SetGroupMembersRequest) (*pbs.SetGroupMembersResponse, error) {
	if err := validateSetGroupMembersRequest(req); err != nil {
		return nil, err
	}
	authResults := s.authResult(ctx, req.GetId(), action.SetMembers)
	if authResults.Error != nil {
		return nil, authResults.Error
	}
	g, err := s.setMembersInRepo(ctx, req.GetId(), req.GetMemberIds(), req.GetVersion())
	if err != nil {
		return nil, err
	}
	g.Scope = authResults.Scope
	return &pbs.SetGroupMembersResponse{Item: g}, nil
}

// RemoveGroupMembers implements the interface pbs.GroupServiceServer.
func (s Service) RemoveGroupMembers(ctx context.Context, req *pbs.RemoveGroupMembersRequest) (*pbs.RemoveGroupMembersResponse, error) {
	if err := validateRemoveGroupMembersRequest(req); err != nil {
		return nil, err
	}
	authResults := s.authResult(ctx, req.GetId(), action.RemoveMembers)
	if authResults.Error != nil {
		return nil, authResults.Error
	}
	g, err := s.removeMembersInRepo(ctx, req.GetId(), req.GetMemberIds(), req.GetVersion())
	if err != nil {
		return nil, err
	}
	g.Scope = authResults.Scope
	return &pbs.RemoveGroupMembersResponse{Item: g}, nil
}

func (s Service) getFromRepo(ctx context.Context, id string) (*pb.Group, error) {
	repo, err := s.repoFn()
	if err != nil {
		return nil, err
	}
	g, m, err := repo.LookupGroup(ctx, id)
	if err != nil {
		if errors.Is(err, db.ErrRecordNotFound) {
			return nil, handlers.NotFoundErrorf("Group %q doesn't exist.", id)
		}
		return nil, fmt.Errorf("unable to get group: %w", err)
	}
	if g == nil {
		return nil, handlers.NotFoundErrorf("Group %q doesn't exist.", id)
	}
	return toProto(g, m), nil
}

func (s Service) createInRepo(ctx context.Context, scopeId string, item *pb.Group) (*pb.Group, error) {
	var opts []iam.Option
	if item.GetName() != nil {
		opts = append(opts, iam.WithName(item.GetName().GetValue()))
	}
	if item.GetDescription() != nil {
		opts = append(opts, iam.WithDescription(item.GetDescription().GetValue()))
	}
	u, err := iam.NewGroup(scopeId, opts...)
	if err != nil {
		return nil, handlers.ApiErrorWithCodeAndMessage(codes.Internal, "Unable to build group for creation: %v.", err)
	}
	repo, err := s.repoFn()
	if err != nil {
		return nil, err
	}
	out, err := repo.CreateGroup(ctx, u)
	if err != nil {
		return nil, fmt.Errorf("unable to create group: %w", err)
	}
	if out == nil {
		return nil, handlers.ApiErrorWithCodeAndMessage(codes.Internal, "Unable to create group but no error returned from repository.")
	}
	return toProto(out, nil), nil
}

func (s Service) updateInRepo(ctx context.Context, scopeId, id string, mask []string, item *pb.Group) (*pb.Group, error) {
	var opts []iam.Option
	if desc := item.GetDescription(); desc != nil {
		opts = append(opts, iam.WithDescription(desc.GetValue()))
	}
	if name := item.GetName(); name != nil {
		opts = append(opts, iam.WithName(name.GetValue()))
	}
	version := item.GetVersion()
	g, err := iam.NewGroup(scopeId, opts...)
	if err != nil {
		return nil, handlers.ApiErrorWithCodeAndMessage(codes.Internal, "Unable to build group for update: %v.", err)
	}
	g.PublicId = id
	dbMask := maskManager.Translate(mask)
	if len(dbMask) == 0 {
		return nil, handlers.InvalidArgumentErrorf("No valid fields included in the update mask.", map[string]string{"update_mask": "No valid fields provided in the update mask."})
	}
	repo, err := s.repoFn()
	if err != nil {
		return nil, err
	}
	out, m, rowsUpdated, err := repo.UpdateGroup(ctx, g, version, dbMask)
	if err != nil {
		return nil, fmt.Errorf("unable to update group: %w", err)
	}
	if rowsUpdated == 0 {
		return nil, handlers.NotFoundErrorf("Group %q doesn't exist or incorrect version provided.", id)
	}
	return toProto(out, m), nil
}

func (s Service) deleteFromRepo(ctx context.Context, id string) (bool, error) {
	repo, err := s.repoFn()
	if err != nil {
		return false, err
	}
	rows, err := repo.DeleteGroup(ctx, id)
	if err != nil {
		if errors.Is(err, db.ErrRecordNotFound) {
			return false, nil
		}
		return false, fmt.Errorf("unable to delete group: %w", err)
	}
	return rows > 0, nil
}

func (s Service) listFromRepo(ctx context.Context, scopeId string) ([]*pb.Group, error) {
	repo, err := s.repoFn()
	if err != nil {
		return nil, err
	}
	gl, err := repo.ListGroups(ctx, scopeId)
	if err != nil {
		return nil, fmt.Errorf("unable to list groups: %w", err)
	}
	var outGl []*pb.Group
	for _, g := range gl {
		outGl = append(outGl, toProto(g, nil))
	}
	return outGl, nil
}

func (s Service) addMembersInRepo(ctx context.Context, groupId string, userIds []string, version uint32) (*pb.Group, error) {
	repo, err := s.repoFn()
	if err != nil {
		return nil, err
	}
	_, err = repo.AddGroupMembers(ctx, groupId, version, userIds)
	if err != nil {
		// TODO: Figure out a way to surface more helpful error info beyond the Internal error.
		return nil, handlers.ApiErrorWithCodeAndMessage(codes.Internal, "Unable to add members to group: %v.", err)
	}
	out, m, err := repo.LookupGroup(ctx, groupId)
	if err != nil {
		return nil, fmt.Errorf("unable to look up group after adding members: %w", err)
	}
	if out == nil {
		return nil, handlers.ApiErrorWithCodeAndMessage(codes.Internal, "Unable to lookup group after adding member to it.")
	}
	return toProto(out, m), nil
}

func (s Service) setMembersInRepo(ctx context.Context, groupId string, userIds []string, version uint32) (*pb.Group, error) {
	repo, err := s.repoFn()
	if err != nil {
		return nil, err
	}
	_, _, err = repo.SetGroupMembers(ctx, groupId, version, userIds)
	if err != nil {
		// TODO: Figure out a way to surface more helpful error info beyond the Internal error.
		return nil, handlers.ApiErrorWithCodeAndMessage(codes.Internal, "Unable to set members on group: %v.", err)
	}
	out, m, err := repo.LookupGroup(ctx, groupId)
	if err != nil {
		return nil, fmt.Errorf("unable to look up group after setting members: %w", err)
	}
	if out == nil {
		return nil, handlers.ApiErrorWithCodeAndMessage(codes.Internal, "Unable to lookup group after setting members for it.")
	}
	return toProto(out, m), nil
}

func (s Service) removeMembersInRepo(ctx context.Context, groupId string, userIds []string, version uint32) (*pb.Group, error) {
	repo, err := s.repoFn()
	if err != nil {
		return nil, err
	}
	_, err = repo.DeleteGroupMembers(ctx, groupId, version, userIds)
	if err != nil {
		// TODO: Figure out a way to surface more helpful error info beyond the Internal error.
		return nil, handlers.ApiErrorWithCodeAndMessage(codes.Internal, "Unable to remove members from group: %v.", err)
	}
	out, m, err := repo.LookupGroup(ctx, groupId)
	if err != nil {
		return nil, fmt.Errorf("unable to look up group after removing members: %w", err)
	}
	if out == nil {
		return nil, handlers.ApiErrorWithCodeAndMessage(codes.Internal, "Unable to lookup group after removing members from it.")
	}
	return toProto(out, m), nil
}

func (s Service) authResult(ctx context.Context, id string, a action.Type) auth.VerifyResults {
	res := auth.VerifyResults{}
	repo, err := s.repoFn()
	if err != nil {
		res.Error = err
		return res
	}

	var parentId string
	opts := []auth.Option{auth.WithType(resource.Group), auth.WithAction(a)}
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
	return auth.Verify(ctx, opts...)
}

func toProto(in *iam.Group, members []*iam.GroupMember) *pb.Group {
	out := pb.Group{
		Id:          in.GetPublicId(),
		ScopeId:     in.GetScopeId(),
		CreatedTime: in.GetCreateTime().GetTimestamp(),
		UpdatedTime: in.GetUpdateTime().GetTimestamp(),
		Version:     in.Version,
	}
	if in.GetDescription() != "" {
		out.Description = &wrapperspb.StringValue{Value: in.GetDescription()}
	}
	if in.GetName() != "" {
		out.Name = &wrapperspb.StringValue{Value: in.GetName()}
	}
	for _, m := range members {
		out.MemberIds = append(out.MemberIds, m.GetMemberId())
		out.Members = append(out.Members, &pb.Member{
			Id:      m.GetMemberId(),
			ScopeId: m.GetMemberScopeId(),
		})
	}
	return &out
}

// A validateX method should exist for each method above.  These methods do not make calls to any backing service but enforce
// requirements on the structure of the request.  They verify that:
//  * The path passed in is correctly formatted
//  * All required parameters are set
//  * There are no conflicting parameters provided
func validateGetRequest(req *pbs.GetGroupRequest) error {
	return handlers.ValidateGetRequest(iam.GroupPrefix, req, handlers.NoopValidatorFn)
}

func validateCreateRequest(req *pbs.CreateGroupRequest) error {
	return handlers.ValidateCreateRequest(req.GetItem(), func() map[string]string {
		badFields := map[string]string{}
		if !handlers.ValidId(scope.Org.Prefix(), req.GetItem().GetScopeId()) &&
			!handlers.ValidId(scope.Project.Prefix(), req.GetItem().GetScopeId()) &&
			scope.Global.String() != req.GetItem().GetScopeId() {
			badFields["scope_id"] = "This field is missing or improperly formatted."
		}
		return badFields
	})
}

func validateUpdateRequest(req *pbs.UpdateGroupRequest) error {
	return handlers.ValidateUpdateRequest(iam.GroupPrefix, req, req.GetItem(), handlers.NoopValidatorFn)
}

func validateDeleteRequest(req *pbs.DeleteGroupRequest) error {
	return handlers.ValidateDeleteRequest(iam.GroupPrefix, req, handlers.NoopValidatorFn)
}

func validateListRequest(req *pbs.ListGroupsRequest) error {
	badFields := map[string]string{}
	if !handlers.ValidId(scope.Org.Prefix(), req.GetScopeId()) &&
		!handlers.ValidId(scope.Project.Prefix(), req.GetScopeId()) &&
		req.GetScopeId() != scope.Global.String() {
		badFields["scope_id"] = "Incorrectly formatted identifier."
	}
	if len(badFields) > 0 {
		return handlers.InvalidArgumentErrorf("Improperly formatted identifier.", badFields)
	}
	return nil
}

func validateAddGroupMembersRequest(req *pbs.AddGroupMembersRequest) error {
	badFields := map[string]string{}
	if !handlers.ValidId(iam.GroupPrefix, req.GetId()) {
		badFields["id"] = "Incorrectly formatted identifier."
	}
	if req.GetVersion() == 0 {
		badFields["version"] = "Required field."
	}
	if len(req.GetMemberIds()) == 0 {
		badFields["member_ids"] = "Must be non-empty."
	}
	for _, id := range req.GetMemberIds() {
		if id == "u_recovery" {
			badFields["member_ids"] = "u_recovery cannot be assigned to a group"
		}
	}
	if len(badFields) > 0 {
		return handlers.InvalidArgumentErrorf("Errors in provided fields.", badFields)
	}
	return nil
}

func validateSetGroupMembersRequest(req *pbs.SetGroupMembersRequest) error {
	badFields := map[string]string{}
	if !handlers.ValidId(iam.GroupPrefix, req.GetId()) {
		badFields["id"] = "Incorrectly formatted identifier."
	}
	if req.GetVersion() == 0 {
		badFields["version"] = "Required field."
	}
	for _, id := range req.GetMemberIds() {
		if id == "u_recovery" {
			badFields["member_ids"] = "u_recovery cannot be assigned to a group"
		}
	}
	if len(badFields) > 0 {
		return handlers.InvalidArgumentErrorf("Errors in provided fields.", badFields)
	}
	return nil
}

func validateRemoveGroupMembersRequest(req *pbs.RemoveGroupMembersRequest) error {
	badFields := map[string]string{}
	if !handlers.ValidId(iam.GroupPrefix, req.GetId()) {
		badFields["id"] = "Incorrectly formatted identifier."
	}
	if req.GetVersion() == 0 {
		badFields["version"] = "Required field."
	}
	if len(req.GetMemberIds()) == 0 {
		badFields["member_ids"] = "Must be non-empty."
	}
	if len(badFields) > 0 {
		return handlers.InvalidArgumentErrorf("Errors in provided fields.", badFields)
	}
	return nil
}
