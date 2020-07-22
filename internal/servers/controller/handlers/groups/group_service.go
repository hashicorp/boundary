package groups

import (
	"context"
	"errors"
	"fmt"
	"regexp"
	"strings"

	"github.com/hashicorp/watchtower/internal/auth"
	"github.com/hashicorp/watchtower/internal/db"
	pb "github.com/hashicorp/watchtower/internal/gen/controller/api/resources/groups"
	pbs "github.com/hashicorp/watchtower/internal/gen/controller/api/services"
	"github.com/hashicorp/watchtower/internal/iam"
	"github.com/hashicorp/watchtower/internal/iam/store"
	"github.com/hashicorp/watchtower/internal/servers/controller/handlers"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/wrapperspb"
)

var (
	maskManager handlers.MaskManager
	reInvalidID = regexp.MustCompile("[^A-Za-z0-9]")
)

func init() {
	var err error
	if maskManager, err = handlers.NewMaskManager(&pb.Group{}, &store.Group{}); err != nil {
		panic(err)
	}
}

// Service handles request as described by the pbs.GroupServiceServer interface.
type Service struct {
	repoFn func() (*iam.Repository, error)
}

// NewService returns a group service which handles group related requests to watchtower.
func NewService(repo func() (*iam.Repository, error)) (Service, error) {
	if repo == nil {
		return Service{}, fmt.Errorf("nil iam repository provided")
	}
	return Service{repoFn: repo}, nil
}

var _ pbs.GroupServiceServer = Service{}

// ListGroups implements the interface pbs.GroupServiceServer.
func (s Service) ListGroups(ctx context.Context, req *pbs.ListGroupsRequest) (*pbs.ListGroupsResponse, error) {
	authResults := auth.Verify(ctx)
	if !authResults.Valid {
		return nil, handlers.ForbiddenError()
	}
	if err := validateListRequest(req); err != nil {
		return nil, err
	}
	gl, err := s.listFromRepo(ctx, authResults.Scope.GetId())
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
	authResults := auth.Verify(ctx)
	if !authResults.Valid {
		return nil, handlers.ForbiddenError()
	}
	if err := validateGetRequest(req); err != nil {
		return nil, err
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
	authResults := auth.Verify(ctx)
	if !authResults.Valid {
		return nil, handlers.ForbiddenError()
	}
	if err := validateCreateRequest(req); err != nil {
		return nil, err
	}
	u, err := s.createInRepo(ctx, authResults.Scope.GetId(), req.GetItem())
	if err != nil {
		return nil, err
	}
	u.Scope = authResults.Scope
	return &pbs.CreateGroupResponse{Item: u, Uri: fmt.Sprintf("scopes/%s/groups/%s", authResults.Scope.GetId(), u.GetId())}, nil
}

// UpdateGroup implements the interface pbs.GroupServiceServer.
func (s Service) UpdateGroup(ctx context.Context, req *pbs.UpdateGroupRequest) (*pbs.UpdateGroupResponse, error) {
	authResults := auth.Verify(ctx)
	if !authResults.Valid {
		return nil, handlers.ForbiddenError()
	}
	if err := validateUpdateRequest(req); err != nil {
		return nil, err
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
	authResults := auth.Verify(ctx)
	if !authResults.Valid {
		return nil, handlers.ForbiddenError()
	}
	if err := validateDeleteRequest(req); err != nil {
		return nil, err
	}
	existed, err := s.deleteFromRepo(ctx, req.GetId())
	if err != nil {
		return nil, err
	}
	return &pbs.DeleteGroupResponse{Existed: existed}, nil
}

// AddGroupMembers implements the interface pbs.GroupServiceServer.
func (s Service) AddGroupMembers(ctx context.Context, req *pbs.AddGroupMembersRequest) (*pbs.AddGroupMembersResponse, error) {
	auth := handlers.ToTokenMetadata(ctx)
	_ = auth
	if err := validateAddGroupMembersRequest(req); err != nil {
		return nil, err
	}
	g, err := s.addMembersInRepo(ctx, req.GetGroupId(), req.GetMemberIds(), req.GetVersion().GetValue())
	if err != nil {
		return nil, err
	}
	return &pbs.AddGroupMembersResponse{Item: g}, nil
}

// SetGroupMembers implements the interface pbs.GroupServiceServer.
func (s Service) SetGroupMembers(ctx context.Context, req *pbs.SetGroupMembersRequest) (*pbs.SetGroupMembersResponse, error) {
	auth := handlers.ToTokenMetadata(ctx)
	_ = auth
	if err := validateSetGroupMembersRequest(req); err != nil {
		return nil, err
	}
	g, err := s.setMembersInRepo(ctx, req.GetGroupId(), req.GetMemberIds(), req.GetVersion().GetValue())
	if err != nil {
		return nil, err
	}
	return &pbs.SetGroupMembersResponse{Item: g}, nil
}

// RemoveGroupMembers implements the interface pbs.GroupServiceServer.
func (s Service) RemoveGroupMembers(ctx context.Context, req *pbs.RemoveGroupMembersRequest) (*pbs.RemoveGroupMembersResponse, error) {
	auth := handlers.ToTokenMetadata(ctx)
	_ = auth
	if err := validateRemoveGroupMembersRequest(req); err != nil {
		return nil, err
	}
	g, err := s.removeMembersInRepo(ctx, req.GetGroupId(), req.GetMemberIds(), req.GetVersion().GetValue())
	if err != nil {
		return nil, err
	}
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
		return nil, err
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
		return nil, status.Errorf(codes.Internal, "Unable to build group for creation: %v.", err)
	}
	repo, err := s.repoFn()
	if err != nil {
		return nil, err
	}
	out, err := repo.CreateGroup(ctx, u)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "Unable to create group: %v.", err)
	}
	if out == nil {
		return nil, status.Error(codes.Internal, "Unable to create group but no error returned from repository.")
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
	u, err := iam.NewGroup(scopeId, opts...)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "Unable to build group for update: %v.", err)
	}
	u.PublicId = id
	dbMask := maskManager.Translate(mask)
	if len(dbMask) == 0 {
		return nil, handlers.InvalidArgumentErrorf("No valid fields included in the update mask.", map[string]string{"update_mask": "No valid paths provided in the update mask."})
	}
	repo, err := s.repoFn()
	if err != nil {
		return nil, err
	}
	out, m, rowsUpdated, err := repo.UpdateGroup(ctx, u, dbMask)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "Unable to update group: %v.", err)
	}
	if rowsUpdated == 0 {
		return nil, handlers.NotFoundErrorf("Group %q doesn't exist.", id)
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
		return false, status.Errorf(codes.Internal, "Unable to delete group: %v.", err)
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
		return nil, err
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
		return nil, status.Errorf(codes.Internal, "Unable to add members to group: %v.", err)
	}
	out, m, err := repo.LookupGroup(ctx, groupId)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "Unable to look up group: %v.", err)
	}
	if out == nil {
		return nil, status.Error(codes.Internal, "Unable to lookup group after adding member to it.")
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
		return nil, status.Errorf(codes.Internal, "Unable to set members on group: %v.", err)
	}
	out, m, err := repo.LookupGroup(ctx, groupId)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "Unable to look up group: %v.", err)
	}
	if out == nil {
		return nil, status.Error(codes.Internal, "Unable to lookup group after setting members for it.")
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
		return nil, status.Errorf(codes.Internal, "Unable to remove members from group: %v.", err)
	}
	out, m, err := repo.LookupGroup(ctx, groupId)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "Unable to look up group: %v.", err)
	}
	if out == nil {
		return nil, status.Error(codes.Internal, "Unable to lookup group after removing members from it.")
	}
	return toProto(out, m), nil
}

func toProto(in *iam.Group, members []*iam.GroupMember) *pb.Group {
	out := pb.Group{
		Id:          in.GetPublicId(),
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
			Type:    m.GetType(),
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
	badFields := map[string]string{}
	if !validId(req.GetId(), iam.GroupPrefix+"_") {
		badFields["id"] = "Invalid formatted group id."
	}
	if len(badFields) > 0 {
		return handlers.InvalidArgumentErrorf("Improperly formatted identifier.", badFields)
	}
	return nil
}

func validateCreateRequest(req *pbs.CreateGroupRequest) error {
	badFields := map[string]string{}
	item := req.GetItem()
	if item.GetId() != "" {
		badFields["id"] = "This is a read only field."
	}
	if item.GetCreatedTime() != nil {
		badFields["created_time"] = "This is a read only field."
	}
	if item.GetUpdatedTime() != nil {
		badFields["updated_time"] = "This is a read only field."
	}
	if len(badFields) > 0 {
		return handlers.InvalidArgumentErrorf("Argument errors found in the request.", badFields)
	}
	return nil
}

func validateUpdateRequest(req *pbs.UpdateGroupRequest) error {
	badFields := map[string]string{}
	if !validId(req.GetId(), iam.GroupPrefix+"_") {
		badFields["group_id"] = "Improperly formatted path identifier."
	}
	if req.GetUpdateMask() == nil {
		badFields["update_mask"] = "UpdateMask not provided but is required to update a group."
	}

	item := req.GetItem()
	if item == nil {
		// It is legitimate for no item to be specified in an update request as it indicates all fields provided in
		// the mask will be marked as unset.
		return nil
	}
	if item.GetId() != "" {
		badFields["id"] = "This is a read only field and cannot be specified in an update request."
	}
	if item.GetCreatedTime() != nil {
		badFields["created_time"] = "This is a read only field and cannot be specified in an update request."
	}
	if item.GetUpdatedTime() != nil {
		badFields["updated_time"] = "This is a read only field and cannot be specified in an update request."
	}
	if len(badFields) > 0 {
		return handlers.InvalidArgumentErrorf("Errors in provided fields.", badFields)
	}

	return nil
}

func validateDeleteRequest(req *pbs.DeleteGroupRequest) error {
	badFields := map[string]string{}
	if !validId(req.GetId(), iam.GroupPrefix+"_") {
		badFields["id"] = "Incorrectly formatted identifier."
	}
	if len(badFields) > 0 {
		return handlers.InvalidArgumentErrorf("Errors in provided fields.", badFields)
	}
	return nil
}

func validateListRequest(req *pbs.ListGroupsRequest) error {
	badFields := map[string]string{}
	if len(badFields) > 0 {
		return handlers.InvalidArgumentErrorf("Improperly formatted identifier.", badFields)
	}
	return nil
}

func validateAddGroupMembersRequest(req *pbs.AddGroupMembersRequest) error {
	badFields := validateAncestors(req)
	if !validId(req.GetGroupId(), iam.GroupPrefix+"_") {
		badFields["id"] = "Incorrectly formatted identifier."
	}
	if req.GetVersion() == nil {
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

func validateSetGroupMembersRequest(req *pbs.SetGroupMembersRequest) error {
	badFields := validateAncestors(req)
	if !validId(req.GetGroupId(), iam.GroupPrefix+"_") {
		badFields["id"] = "Incorrectly formatted identifier."
	}
	if req.GetVersion() == nil {
		badFields["version"] = "Required field."
	}
	if len(badFields) > 0 {
		return handlers.InvalidArgumentErrorf("Errors in provided fields.", badFields)
	}
	return nil
}

func validateRemoveGroupMembersRequest(req *pbs.RemoveGroupMembersRequest) error {
	badFields := validateAncestors(req)
	if !validId(req.GetGroupId(), iam.GroupPrefix+"_") {
		badFields["id"] = "Incorrectly formatted identifier."
	}
	if req.GetVersion() == nil {
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

func validId(id, prefix string) bool {
	if !strings.HasPrefix(id, prefix) {
		return false
	}
	id = strings.TrimPrefix(id, prefix)
	return !reInvalidID.Match([]byte(id))
}
