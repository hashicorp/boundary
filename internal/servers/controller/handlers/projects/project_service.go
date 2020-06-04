package projects

import (
	"context"
	"fmt"
	"regexp"
	"strings"

	"github.com/grpc-ecosystem/grpc-gateway/runtime"
	pb "github.com/hashicorp/watchtower/internal/gen/controller/api/resources/scopes"
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

type Service struct {
	repo *iam.Repository
}

func NewService(repo *iam.Repository) (Service, error) {
	if repo == nil {
		return Service{}, fmt.Errorf("nil iam repostiroy provided")
	}
	return Service{repo: repo}, nil
}

var _ pbs.ProjectServiceServer = Service{}

func (s Service) ListProjects(ctx context.Context, req *pbs.ListProjectsRequest) (*pbs.ListProjectsResponse, error) {
	return nil, status.Error(codes.Unimplemented, "List not enabled for this resource.")
}

func (s Service) GetProject(ctx context.Context, req *pbs.GetProjectRequest) (*pbs.GetProjectResponse, error) {
	if err := validateGetRequest(req); err != nil {
		return nil, err
	}
	p, err := s.getFromRepo(ctx, req.GetId())
	if err != nil {
		return nil, err
	}
	return &pbs.GetProjectResponse{Item: p}, nil
}

func (s Service) CreateProject(ctx context.Context, req *pbs.CreateProjectRequest) (*pbs.CreateProjectResponse, error) {
	if err := validateCreateRequest(req); err != nil {
		return nil, err
	}
	p, err := s.createInRepo(ctx, req.GetOrgId(), req.GetItem())
	if err != nil {
		return nil, err
	}
	return &pbs.CreateProjectResponse{Item: p, Uri: fmt.Sprintf("orgs/%s/projects/%s", req.GetOrgId(), p.GetId())}, nil
}

func (s Service) UpdateProject(ctx context.Context, req *pbs.UpdateProjectRequest) (*pbs.UpdateProjectResponse, error) {
	if err := validateUpdateRequest(req); err != nil {
		return nil, err
	}
	p, err := s.updateInRepo(ctx, req.GetOrgId(), req.GetId(), req.GetUpdateMask().GetPaths(), req.GetItem())
	if err != nil {
		return nil, err
	}
	return &pbs.UpdateProjectResponse{Item: p}, nil
}

func (s Service) DeleteProject(ctx context.Context, req *pbs.DeleteProjectRequest) (*pbs.DeleteProjectResponse, error) {
	if err := validateDeleteRequest(req); err != nil {
		return nil, err
	}
	existed, err := s.deleteFromRepo(ctx, req.GetId())
	if err != nil {
		return nil, err
	}
	return &pbs.DeleteProjectResponse{Existed: existed}, nil
}

func (s Service) getFromRepo(ctx context.Context, id string) (*pb.Project, error) {
	p, err := s.repo.LookupScope(ctx, id)
	if err != nil {
		return nil, err
	}
	if p == nil {
		return nil, handlers.NotFoundErrorf("Project %q doesn't exist.", id)
	}
	return toProto(p), nil
}

func (s Service) createInRepo(ctx context.Context, orgID string, item *pb.Project) (*pb.Project, error) {
	var opts []iam.Option
	if item.GetName() != nil {
		opts = append(opts, iam.WithName(item.GetName().GetValue()))
	}
	if item.GetDescription() != nil {
		opts = append(opts, iam.WithDescription(item.GetDescription().GetValue()))
	}
	p, err := iam.NewProject(orgID, opts...)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "Unable to build project for creation: %v.", err)
	}
	out, err := s.repo.CreateScope(ctx, p)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "Unable to create project: %v.", err)
	}
	if out == nil {
		return nil, status.Error(codes.Internal, "Unable to create project but no error returned from repository.")
	}
	return toProto(out), nil
}

func (s Service) updateInRepo(ctx context.Context, orgID, projId string, mask []string, item *pb.Project) (*pb.Project, error) {
	var opts []iam.Option
	if desc := item.GetDescription(); desc != nil {
		opts = append(opts, iam.WithDescription(desc.GetValue()))
	}
	if name := item.GetName(); name != nil {
		opts = append(opts, iam.WithName(name.GetValue()))
	}
	p, err := iam.NewProject(orgID, opts...)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "Unable to build project for update: %v.", err)
	}
	p.PublicId = projId
	dbMask, err := toDbUpdateMask(mask)
	if err != nil {
		return nil, err
	}
	if len(dbMask) == 0 {
		return nil, handlers.InvalidArgumentErrorf("No valid fields included in the update mask.", []string{"update_mask"})
	}
	out, rowsUpdated, err := s.repo.UpdateScope(ctx, p, dbMask)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "Unable to update project: %v.", err)
	}
	if rowsUpdated == 0 {
		return nil, handlers.NotFoundErrorf("Project %q doesn't exist.", projId)
	}
	return toProto(out), nil
}

func (s Service) deleteFromRepo(ctx context.Context, projId string) (bool, error) {
	rows, err := s.repo.DeleteScope(ctx, projId)
	if err != nil {
		return false, status.Errorf(codes.Internal, "Unable to delete project: %v.", err)
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
		return nil, handlers.InvalidArgumentErrorf(fmt.Sprintf("Invalid fields passed in update_update mask: %v.", invalid), []string{"update_mask"})
	}
	return dbPaths, nil
}

func toProto(in *iam.Scope) *pb.Project {
	out := pb.Project{Id: in.GetPublicId()}
	if in.GetDescription() != "" {
		out.Description = &wrapperspb.StringValue{Value: in.GetDescription()}
	}
	if in.GetName() != "" {
		out.Name = &wrapperspb.StringValue{Value: in.GetName()}
	}
	out.CreatedTime = in.GetCreateTime().GetTimestamp()
	out.UpdatedTime = in.GetUpdateTime().GetTimestamp()
	return &out
}

// A validateX method should exist for each method above.  These methods do not make calls to any backing service but enforce
// requirements on the structure of the request.  They verify that:
//  * The path passed in is correctly formatted
//  * All required parameters are set
//  * There are no conflicting parameters provided
// TODO: Populate the error in a way to allow it to be converted to the previously described error format and include all invalid fields instead of just the most recent.
func validateGetRequest(req *pbs.GetProjectRequest) error {
	if err := validateAncestors(req); err != nil {
		return err
	}
	if !validId(req.GetId(), iam.ProjectScope.Prefix()+"_") {
		return handlers.InvalidArgumentErrorf("Improperly formatted identifier.", []string{"id"})
	}
	return nil
}

func validateCreateRequest(req *pbs.CreateProjectRequest) error {
	if err := validateAncestors(req); err != nil {
		return err
	}
	item := req.GetItem()
	if item == nil {
		return handlers.InvalidArgumentErrorf("A project's fields must be set to something.", []string{"item"})
	}
	var immutableFieldsSet []string
	if item.GetId() != "" {
		immutableFieldsSet = append(immutableFieldsSet, "id")
	}
	if item.GetCreatedTime() != nil {
		immutableFieldsSet = append(immutableFieldsSet, "created_time")
	}
	if item.GetUpdatedTime() != nil {
		immutableFieldsSet = append(immutableFieldsSet, "updated_time")
	}
	if len(immutableFieldsSet) > 0 {
		return handlers.InvalidArgumentErrorf("Cannot specify read only fields at creation time.", immutableFieldsSet)
	}
	return nil
}

func validateUpdateRequest(req *pbs.UpdateProjectRequest) error {
	if err := validateAncestors(req); err != nil {
		return err
	}
	if !validId(req.GetId(), iam.ProjectScope.Prefix()+"_") {
		return handlers.InvalidArgumentErrorf("Improperly formatted identifier.", []string{"id"})
	}

	if req.GetUpdateMask() == nil {
		return handlers.InvalidArgumentErrorf("UpdateMask not provided but is required to update a project.", []string{"update_mask"})
	}

	item := req.GetItem()
	if item == nil {
		// It is legitimate for no item to be specified in an update request as it indicates all fields provided in
		// the mask will be marked as unset.
		return nil
	}
	if item.GetId() != "" && item.GetId() != req.GetId() {
		return handlers.InvalidArgumentErrorf("Id in provided item and url do not match.", []string{"id"})
	}
	var immutableFieldsSet []string
	if item.GetId() != "" {
		immutableFieldsSet = append(immutableFieldsSet, "id")
	}
	if item.GetCreatedTime() != nil {
		immutableFieldsSet = append(immutableFieldsSet, "created_time")
	}
	if item.GetUpdatedTime() != nil {
		immutableFieldsSet = append(immutableFieldsSet, "updated_time")
	}
	if len(immutableFieldsSet) > 0 {
		return handlers.InvalidArgumentErrorf("Cannot specify read only fields at update time.", immutableFieldsSet)
	}

	return nil
}

func validateDeleteRequest(req *pbs.DeleteProjectRequest) error {
	if err := validateAncestors(req); err != nil {
		return err
	}
	if !validId(req.GetId(), iam.ProjectScope.Prefix()+"_") {
		return handlers.InvalidArgumentErrorf("Improperly formatted id.", []string{"id"})
	}
	return nil
}

func validId(id, prefix string) bool {
	if !strings.HasPrefix(id, prefix) {
		return false
	}
	id = strings.TrimPrefix(id, prefix)
	if reInvalidID.Match([]byte(id)) {
		return false
	}
	return true
}

type ancestorProvider interface {
	GetOrgId() string
}

// validateAncestors verifies that the ancestors of this call are properly set and provided.
func validateAncestors(r ancestorProvider) error {
	if r.GetOrgId() == "" {
		return handlers.InvalidArgumentErrorf("Missing organization id.", []string{"org_id"})
	}
	if !validId(r.GetOrgId(), iam.OrganizationScope.Prefix()+"_") {
		return handlers.InvalidArgumentErrorf("Poorly formatted org id.", []string{"org_id"})
	}
	return nil
}

// RegisterGrpcGateway satisfies the RegisterGrpcGatewayer interface.
func (s *Service) RegisterGrpcGateway(mux *runtime.ServeMux) error {
	return pbs.RegisterProjectServiceHandlerServer(context.Background(), mux, s)
}
