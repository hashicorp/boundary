package users

import (
	"context"
	"errors"
	"fmt"
	"regexp"
	"strings"

	"github.com/hashicorp/watchtower/internal/db"
	pb "github.com/hashicorp/watchtower/internal/gen/controller/api/resources/users"
	pbs "github.com/hashicorp/watchtower/internal/gen/controller/api/services"
	"github.com/hashicorp/watchtower/internal/iam"
	"github.com/hashicorp/watchtower/internal/servers/controller/handlers"
	"github.com/hashicorp/watchtower/internal/types/scope"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/wrapperspb"
)

const orgIdFieldName = "org_id"

var (
	reInvalidID = regexp.MustCompile("[^A-Za-z0-9]")
	// TODO(ICU-28): Find a way to auto update these names and enforce the mappings between wire and storage.
	wireToStorageMask = map[string]string{
		"name":        "Name",
		"description": "Description",
	}
)

// Service handles request as described by the pbs.UserServiceServer interface.
type Service struct {
	repoFn func() (*iam.Repository, error)
}

// NewService returns a user service which handles user related requests to watchtower.
func NewService(repo func() (*iam.Repository, error)) (Service, error) {
	if repo == nil {
		return Service{}, fmt.Errorf("nil iam repostiroy provided")
	}
	return Service{repoFn: repo}, nil
}

var _ pbs.UserServiceServer = Service{}

// CreateUser is not yet implemented but will implement the interface pbs.UserServiceServer.
func (s Service) ListUsers(context.Context, *pbs.ListUsersRequest) (*pbs.ListUsersResponse, error) {
	return nil, status.Error(codes.Unimplemented, "List not enabled for this resource.")
}

// GetUsers implements the interface pbs.UserServiceServer.
func (s Service) GetUser(ctx context.Context, req *pbs.GetUserRequest) (*pbs.GetUserResponse, error) {
	auth := handlers.ToTokenMetadata(ctx)
	_ = auth
	if err := validateGetRequest(req); err != nil {
		return nil, err
	}
	u, err := s.getFromRepo(ctx, req.GetId())
	if err != nil {
		return nil, err
	}
	return &pbs.GetUserResponse{Item: u}, nil
}

// CreateUser implements the interface pbs.UserServiceServer.
func (s Service) CreateUser(ctx context.Context, req *pbs.CreateUserRequest) (*pbs.CreateUserResponse, error) {
	auth := handlers.ToTokenMetadata(ctx)
	_ = auth
	if err := validateCreateRequest(req); err != nil {
		return nil, err
	}
	u, err := s.createInRepo(ctx, req.GetOrgId(), req.GetItem())
	if err != nil {
		return nil, err
	}
	return &pbs.CreateUserResponse{Item: u, Uri: fmt.Sprintf("orgs/%s/users/%s", req.GetOrgId(), u.GetId())}, nil
}

// UpdateUser implements the interface pbs.UserServiceServer.
func (s Service) UpdateUser(ctx context.Context, req *pbs.UpdateUserRequest) (*pbs.UpdateUserResponse, error) {
	auth := handlers.ToTokenMetadata(ctx)
	_ = auth
	if err := validateUpdateRequest(req); err != nil {
		return nil, err
	}
	u, err := s.updateInRepo(ctx, req.GetOrgId(), req.GetId(), req.GetUpdateMask().GetPaths(), req.GetItem())
	if err != nil {
		return nil, err
	}
	return &pbs.UpdateUserResponse{Item: u}, nil
}

// DeleteUser implements the interface pbs.UserServiceServer.
func (s Service) DeleteUser(ctx context.Context, req *pbs.DeleteUserRequest) (*pbs.DeleteUserResponse, error) {
	auth := handlers.ToTokenMetadata(ctx)
	_ = auth
	if err := validateDeleteRequest(req); err != nil {
		return nil, err
	}
	existed, err := s.deleteFromRepo(ctx, req.GetId())
	if err != nil {
		return nil, err
	}
	return &pbs.DeleteUserResponse{Existed: existed}, nil
}

func (s Service) getFromRepo(ctx context.Context, id string) (*pb.User, error) {
	repo, err := s.repoFn()
	if err != nil {
		return nil, err
	}
	u, err := repo.LookupUser(ctx, id)
	if err != nil {
		if errors.Is(err, db.ErrRecordNotFound) {
			return nil, handlers.NotFoundErrorf("User %q doesn't exist.", id)
		}
		return nil, err
	}
	if u == nil {
		return nil, handlers.NotFoundErrorf("User %q doesn't exist.", id)
	}
	return toProto(u), nil
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
		return nil, status.Errorf(codes.Internal, "Unable to build user for creation: %v.", err)
	}
	repo, err := s.repoFn()
	if err != nil {
		return nil, err
	}
	out, err := repo.CreateUser(ctx, u)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "Unable to create user: %v.", err)
	}
	if out == nil {
		return nil, status.Error(codes.Internal, "Unable to create user but no error returned from repository.")
	}
	return toProto(out), nil
}

func (s Service) updateInRepo(ctx context.Context, orgId, id string, mask []string, item *pb.User) (*pb.User, error) {
	var opts []iam.Option
	if desc := item.GetDescription(); desc != nil {
		opts = append(opts, iam.WithDescription(desc.GetValue()))
	}
	if name := item.GetName(); name != nil {
		opts = append(opts, iam.WithName(name.GetValue()))
	}
	u, err := iam.NewUser(orgId, opts...)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "Unable to build user for update: %v.", err)
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
	out, rowsUpdated, err := repo.UpdateUser(ctx, u, dbMask)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "Unable to update user: %v.", err)
	}
	if rowsUpdated == 0 {
		return nil, handlers.NotFoundErrorf("User %q doesn't exist.", id)
	}
	return toProto(out), nil
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
		return false, status.Errorf(codes.Internal, "Unable to delete user: %v.", err)
	}
	return rows > 0, nil
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

func toProto(in *iam.User) *pb.User {
	out := pb.User{
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
func validateGetRequest(req *pbs.GetUserRequest) error {
	badFields := validateAncestors(req)
	if !validId(req.GetId(), iam.UserPrefix+"_") {
		badFields["id"] = "Invalid formatted user id."
	}
	if len(badFields) > 0 {
		return handlers.InvalidArgumentErrorf("Improperly formatted identifier.", badFields)
	}
	return nil
}

func validateCreateRequest(req *pbs.CreateUserRequest) error {
	badFields := validateAncestors(req)
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

func validateUpdateRequest(req *pbs.UpdateUserRequest) error {
	badFields := validateAncestors(req)
	if !validId(req.GetId(), iam.UserPrefix+"_") {
		badFields["user_id"] = "Improperly formatted path identifier."
	}
	if req.GetUpdateMask() == nil {
		badFields["update_mask"] = "UpdateMask not provided but is required to update a user."
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

func validateDeleteRequest(req *pbs.DeleteUserRequest) error {
	badFields := validateAncestors(req)
	if !validId(req.GetId(), iam.UserPrefix+"_") {
		badFields["id"] = "Incorrectly formatted identifier."
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

type ancestorProvider interface {
	GetOrgId() string
}

// validateAncestors verifies that the ancestors of this call are properly set and provided.
func validateAncestors(r ancestorProvider) map[string]string {
	if r.GetOrgId() == "" {
		return map[string]string{orgIdFieldName: "Missing organization id."}
	}
	if !validId(r.GetOrgId(), scope.Organization.Prefix()+"_") {
		return map[string]string{orgIdFieldName: "Improperly formatted identifier."}
	}
	return map[string]string{}
}
