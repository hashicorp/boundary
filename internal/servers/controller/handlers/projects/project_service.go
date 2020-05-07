package projects

import (
	"context"

	"github.com/golang/protobuf/ptypes"
	"github.com/golang/protobuf/ptypes/wrappers"
	"github.com/grpc-ecosystem/grpc-gateway/runtime"
	pb "github.com/hashicorp/watchtower/internal/gen/controller/api/resources/projects"
	pbs "github.com/hashicorp/watchtower/internal/gen/controller/api/services"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

type projectsRepo interface {
	CreateProject(ctx context.Context, hc *repo.Project, opt ...Option) (*repo.Project, error)
	UpdateProject(ctx context.Context, hc *repo.Project, fieldMaskPaths []string, opt ...Option) (*repo.Project, error) // LookupProject returns the Host catalog based on the provided id and any error associated with the lookup.
	LookupProject(ctx context.Context, opt ...Option) (*repo.Project, error)
	DeleteProject(ctx context.Context, opt ...Option) (bool, error)

	// TODO: Sure this up with repository expectations for list operations.
	ListProjects(ctx context.Context, opt ...Option) ([]repo.Project, error)
	// TODO: Figure out the appropriate way to verify the path is appropriate, whether as a separate method or merging this into the methods above.
}

type Service struct {
	repo projectsRepo
}

func NewService(repo repo) *Service {
	return &Service{repo}
}

var _ pbs.ProjectServiceServer = &Service{}

func (s Service) ListProjects(ctx context.Context, req *pbs.ListProjectsRequest) (*pbs.ListProjectsResponse, error) {
	if err := validateListProjectsRequest(req); err != nil {
		return nil, err
	}
	return nil, status.Errorf(codes.NotFound, "Org %q not found", req.OrgId)
}

func (s Service) GetProject(ctx context.Context, req *pbs.GetProjectRequest) (*pbs.GetProjectResponse, error) {
	if err := validateGetProjectRequest(req); err != nil {
		return nil, err
	}
	p, err := s.repo.LookupProject(ctx, WithPublicId(req.GetId()))
	if err != nil {
		return nil, err
	}
	if p == nil {
		return nil, status.Errorf(codes.NotFound, "Could not find Project with id %q", req.GetId())
	}
	resp := &pbs.GetProjectResponse{}
	resp.Item = toProto(req.OrgId, p)
	return resp, nil
}

func (s Service) CreateProject(ctx context.Context, req *pbs.CreateProjectRequest) (*pbs.CreateProjectResponse, error) {
	if err := validateCreateProjectRequest(req); err != nil {
		return nil, err
	}
	return nil, status.Errorf(codes.NotFound, "Org %q not found", req.OrgId)
}

func (s Service) UpdateProject(ctx context.Context, req *pbs.UpdateProjectRequest) (*pbs.UpdateProjectResponse, error) {
	if err := validateUpdateProjectRequest(req); err != nil {
		return nil, err
	}
	return nil, status.Errorf(codes.NotFound, "Org %q not found", req.OrgId)
}

func (s Service) DeleteProject(ctx context.Context, req *pbs.DeleteProjectRequest) (*pbs.DeleteProjectResponse, error) {
	if err := validateDeleteProjectRequest(req); err != nil {
		return nil, err
	}
	existed, err := s.repo.DeleteProject(ctx, WithPublicId(req.Id))
	if err != nil {
		// TODO: Handle errors appropriately
		return nil, status.Errorf(codes.Internal, "Couldn't delete Host Catalog: %v", err)
	}
	return &pbs.DeleteProjectResponse{Existed: existed}, nil
}

func toRepo(id string, in pb.Project) repo.Project {
	out := repo.Project{ID: id}
	if in.GetName() != nil {
		out.Name = in.GetName().GetValue()
	}
	if in.GetDisabled() != nil {
		out.Disabled = in.GetDisabled().GetValue()
	}
	return out
}

func toProto(orgID, in *repo.Project) *pb.Project {
	out := pb.Project{}
	if in.Disabled {
		out.Disabled = &wrappers.BoolValue{Value: in.Disabled}
	}
	if in.Name != "" {
		out.Name = &wrappers.StringValue{Value: in.Name}
	}
	// TODO: Don't ignore the errors.
	out.CreatedTime, _ = ptypes.TimestampProto(in.CreatedTime)
	out.UpdatedTime, _ = ptypes.TimestampProto(in.UpdatedTime)
	return &out
}

// A validateX method should exist for each method above.  These methods do not make calls to any backing service but enforce
// requirements on the structure of the request.  They verify that:
//  * The path passed in is correctly formatted
//  * All required parameters are set
//  * There are no conflicting parameters provided
func validateListProjectsRequest(req *pbs.ListProjectsRequest) error {
	if err := validateAncestors(req); err != nil {
		return err
	}
	return nil
}

func validateGetProjectRequest(req *pbs.GetProjectRequest) error {
	if err := validateAncestors(req); err != nil {
		return err
	}
	return nil
}

func validateCreateProjectRequest(req *pbs.CreateProjectRequest) error {
	if err := validateAncestors(req); err != nil {
		return err
	}
	return nil
}

func validateUpdateProjectRequest(req *pbs.UpdateProjectRequest) error {
	if err := validateAncestors(req); err != nil {
		return err
	}
	return nil
}

func validateDeleteProjectRequest(req *pbs.DeleteProjectRequest) error {
	if err := validateAncestors(req); err != nil {
		return err
	}
	return nil
}

type ancestorProvider interface {
	GetOrgId() string
}

// validateAncestors verifies that the ancestors of this call are properly set and provided.
func validateAncestors(r ancestorProvider) error {
	if r.GetOrgId() == "" {
		return status.Errorf(codes.InvalidArgument, "org_id must be provided.")
	}
	return nil
}

// RegisterGrpcGateway satisfies the RegisterGrpcGatewayer interface.
func (s Service) RegisterGrpcGateway(mux *runtime.ServeMux) error {
	return pbs.RegisterProjectServiceHandlerServer(context.Background(), mux, s)
}
