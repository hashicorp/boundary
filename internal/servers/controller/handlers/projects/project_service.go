package projects

import (
	"context"

	"github.com/golang/protobuf/ptypes/wrappers"
	"github.com/grpc-ecosystem/grpc-gateway/runtime"
	pb "github.com/hashicorp/watchtower/internal/gen/controller/api/resources/projects"
	pbs "github.com/hashicorp/watchtower/internal/gen/controller/api/services"
	"github.com/hashicorp/watchtower/internal/iam"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

type scopeRepo interface {
	CreateScope(ctx context.Context, p *iam.Scope, opt ...iam.Option) (*iam.Scope, error)
	UpdateScope(ctx context.Context, p *iam.Scope, fieldMaskPaths []string, opt ...iam.Option) (*iam.Scope, error) // LookupProject returns the Host catalog based on the provided id and any error associated with the lookup.
	LookupScope(ctx context.Context, opt ...iam.Option) (*iam.Scope, error)
	DeleteScope(ctx context.Context, opt ...iam.Option) (bool, error)

	// TODO: Sure this up with repository expectations for list operations.
	ListProjects(ctx context.Context, opt ...iam.Option) ([]iam.Scope, error)
	// TODO: Figure out the appropriate way to verify the path is appropriate, whether as a separate method or merging this into the methods above.
}

type Service struct {
	repo scopeRepo
}

func NewService(repo scopeRepo) *Service {
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
	p, err := s.repo.LookupScope(ctx, iam.WitPublicId(req.GetId()))
	if err != nil {
		return nil, err
	}
	if p == nil {
		return nil, status.Errorf(codes.NotFound, "Could not find Project with id %q", req.GetId())
	}
	resp := &pbs.GetProjectResponse{}
	resp.Item = toProto(p)
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
	existed, err := s.repo.DeleteScope(ctx, iam.WitPublicId(req.Id))
	if err != nil {
		// TODO: Handle errors appropriately
		return nil, status.Errorf(codes.Internal, "Couldn't delete Host Catalog: %v", err)
	}
	return &pbs.DeleteProjectResponse{Existed: existed}, nil
}

func toRepo(orgID string, in pb.Project) *iam.Scope {
	sopt := []iam.Option{}
	// TODO: Handle setting the values to nil value.
	if name := in.GetName().GetValue(); name != "" {
		sopt = append(sopt, iam.WithName(name))
	}
	if desc := in.GetDescription().GetValue(); desc != "" {
		sopt = append(sopt, iam.WithDescription(desc))
	}
	// TODO: Don't ignore errors
	p, _ := iam.NewProject(orgID, sopt...)
	return p
}

func toProto(in *iam.Scope) *pb.Project {
	// TODO: Decide if we should put the id prefix here or in scopes.
	out := pb.Project{Id: in.GetPublicId()}
	if in.GetDescription() != "" {
		out.Description = &wrappers.StringValue{Value: in.GetDescription()}
	}
	if in.GetName() != "" {
		out.Name = &wrappers.StringValue{Value: in.GetName()}
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
