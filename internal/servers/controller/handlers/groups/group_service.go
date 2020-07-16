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
	"github.com/hashicorp/watchtower/internal/servers/controller/handlers"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/wrapperspb"
)

var (
	reInvalidID = regexp.MustCompile("[^A-Za-z0-9]")
	// TODO(ICU-28): Find a way to auto update these names and enforce the mappings between wire and storage.
	wireToStorageMask = map[string]string{
		"name":        "Name",
		"description": "Description",
	}
)

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
	_, scopeInfo, valid := auth.Verify(ctx)
	if !valid {
		return nil, handlers.ForbiddenError()
	}
	if err := validateListRequest(req); err != nil {
		return nil, err
	}
	gl, err := s.listFromRepo(ctx, scopeInfo.GetId())
	if err != nil {
		return nil, err
	}
	return &pbs.ListGroupsResponse{Items: gl}, nil
}

// GetGroups implements the interface pbs.GroupServiceServer.
func (s Service) GetGroup(ctx context.Context, req *pbs.GetGroupRequest) (*pbs.GetGroupResponse, error) {
	_, _, valid := auth.Verify(ctx)
	if !valid {
		return nil, handlers.ForbiddenError()
	}
	if err := validateGetRequest(req); err != nil {
		return nil, err
	}
	u, err := s.getFromRepo(ctx, req.GetId())
	if err != nil {
		return nil, err
	}
	return &pbs.GetGroupResponse{Item: u}, nil
}

// CreateGroup implements the interface pbs.GroupServiceServer.
func (s Service) CreateGroup(ctx context.Context, req *pbs.CreateGroupRequest) (*pbs.CreateGroupResponse, error) {
	_, scopeInfo, valid := auth.Verify(ctx)
	if !valid {
		return nil, handlers.ForbiddenError()
	}
	if err := validateCreateRequest(req); err != nil {
		return nil, err
	}
	u, err := s.createInRepo(ctx, scopeInfo.GetId(), req.GetItem())
	if err != nil {
		return nil, err
	}
	return &pbs.CreateGroupResponse{Item: u, Uri: fmt.Sprintf("scopes/%s/groups/%s", scopeInfo.GetId(), u.GetId())}, nil
}

// UpdateGroup implements the interface pbs.GroupServiceServer.
func (s Service) UpdateGroup(ctx context.Context, req *pbs.UpdateGroupRequest) (*pbs.UpdateGroupResponse, error) {
	_, scopeInfo, valid := auth.Verify(ctx)
	if !valid {
		return nil, handlers.ForbiddenError()
	}
	if err := validateUpdateRequest(req); err != nil {
		return nil, err
	}
	u, err := s.updateInRepo(ctx, scopeInfo.GetId(), req.GetId(), req.GetUpdateMask().GetPaths(), req.GetItem())
	if err != nil {
		return nil, err
	}
	return &pbs.UpdateGroupResponse{Item: u}, nil
}

// DeleteGroup implements the interface pbs.GroupServiceServer.
func (s Service) DeleteGroup(ctx context.Context, req *pbs.DeleteGroupRequest) (*pbs.DeleteGroupResponse, error) {
	_, _, valid := auth.Verify(ctx)
	if !valid {
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

func (s Service) getFromRepo(ctx context.Context, id string) (*pb.Group, error) {
	repo, err := s.repoFn()
	if err != nil {
		return nil, err
	}
	u, err := repo.LookupGroup(ctx, id)
	if err != nil {
		if errors.Is(err, db.ErrRecordNotFound) {
			return nil, handlers.NotFoundErrorf("Group %q doesn't exist.", id)
		}
		return nil, err
	}
	if u == nil {
		return nil, handlers.NotFoundErrorf("Group %q doesn't exist.", id)
	}
	return toProto(u), nil
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
	return toProto(out), nil
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
	dbMask, err := toDbUpdateMask(mask)
	if err != nil {
		return nil, err
	}
	if len(dbMask) == 0 {
		return nil, handlers.InvalidArgumentErrorf("No valid fields included in the update mask.", map[string]string{"update_mask": "No valid paths provided in the update mask."})
	}
	repo, err := s.repoFn()
	if err != nil {
		return nil, err
	}
	out, rowsUpdated, err := repo.UpdateGroup(ctx, u, dbMask)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "Unable to update group: %v.", err)
	}
	if rowsUpdated == 0 {
		return nil, handlers.NotFoundErrorf("Group %q doesn't exist.", id)
	}
	return toProto(out), nil
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
		outGl = append(outGl, toProto(g))
	}
	return outGl, nil
}

// toDbUpdateMask converts the wire format's FieldMask into a list of strings containing FieldMask paths used
func toDbUpdateMask(paths []string) ([]string, error) {
	var dbPaths []string
	var invalid []string
	for _, p := range paths {
		for _, f := range strings.Split(p, ",") {
			if dbField, ok := wireToStorageMask[strings.TrimSpace(f)]; ok {
				dbPaths = append(dbPaths, dbField)
			} else {
				invalid = append(invalid, f)
			}
		}
	}
	if len(invalid) > 0 {
		return nil, handlers.InvalidArgumentErrorf(fmt.Sprintf("Invalid fields passed in update_update mask: %v.", invalid), map[string]string{"update_mask": fmt.Sprintf("Unknown paths provided in update mask: %q", strings.Join(invalid, ","))})
	}
	return dbPaths, nil
}

func toProto(in *iam.Group) *pb.Group {
	out := pb.Group{
		Id:          in.GetPublicId(),
		CreatedTime: in.GetCreateTime().GetTimestamp(),
		UpdatedTime: in.GetUpdateTime().GetTimestamp(),
	}
	if in.GetDescription() != "" {
		out.Description = &wrapperspb.StringValue{Value: in.GetDescription()}
	}
	if in.GetName() != "" {
		out.Name = &wrapperspb.StringValue{Value: in.GetName()}
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

func validId(id, prefix string) bool {
	if !strings.HasPrefix(id, prefix) {
		return false
	}
	id = strings.TrimPrefix(id, prefix)
	return !reInvalidID.Match([]byte(id))
}
