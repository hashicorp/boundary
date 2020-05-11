package projects

import (
	"context"
	"fmt"

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
	UpdateScope(ctx context.Context, p *iam.Scope, fieldMaskPaths []string, opt ...iam.Option) (*iam.Scope, error)
	LookupScope(ctx context.Context, opt ...iam.Option) (*iam.Scope, error)
}

type Service struct {
	pbs.UnimplementedProjectServiceServer
	repo scopeRepo
}

// TODO: Figure out the appropriate way to verify the path is appropriate, whether as a separate method or merging this into the methods above.
func NewService(repo scopeRepo) *Service {
	return &Service{repo: repo}
}

var _ pbs.ProjectServiceServer = &Service{}

func (s Service) GetProject(ctx context.Context, req *pbs.GetProjectRequest) (*pbs.GetProjectResponse, error) {
	if err := validateGetProjectRequest(req); err != nil {
		return nil, err
	}
	p, err := s.getFromRepo(ctx, req)
	if err != nil {
		return nil, err
	}
	resp := &pbs.GetProjectResponse{}
	resp.Item = p
	return resp, nil
}

func (s Service) CreateProject(ctx context.Context, req *pbs.CreateProjectRequest) (*pbs.CreateProjectResponse, error) {
	if err := validateCreateProjectRequest(req); err != nil {
		return nil, err
	}
	p, err := s.createInRepo(ctx, req)
	if err != nil {
		return nil, err
	}
	resp := &pbs.CreateProjectResponse{}
	resp.Uri = fmt.Sprintf("orgs/%s/projects/%s", req.GetOrgId(), p.GetId())
	resp.Item = p
	return resp, nil
}

func (s Service) UpdateProject(ctx context.Context, req *pbs.UpdateProjectRequest) (*pbs.UpdateProjectResponse, error) {
	if err := validateUpdateProjectRequest(req); err != nil {
		return nil, err
	}
	p, err := s.updateInRepo(ctx, req)
	if err != nil {
		return nil, err
	}
	resp := &pbs.UpdateProjectResponse{}
	resp.Item = p
	return resp, nil
}

func (s Service) getFromRepo(ctx context.Context, req *pbs.GetProjectRequest) (*pb.Project, error) {
	p, err := s.repo.LookupScope(ctx, iam.WithPublicId(req.GetId()))
	if err != nil {
		return nil, err
	}
	if p == nil {
		return nil, status.Errorf(codes.NotFound, "Could not find Project with id %q", req.GetId())
	}
	return toProto(p), nil
}

func (s Service) createInRepo(ctx context.Context, req *pbs.CreateProjectRequest) (*pb.Project, error) {
	in := req.GetItem()
	opts := []iam.Option{}
	if in.GetName() != nil {
		opts = append(opts, iam.WithName(in.GetName().GetValue()))
	}
	if in.GetDescription() != nil {
		opts = append(opts, iam.WithDescription(in.GetDescription().GetValue()))
	}
	p, err := iam.NewProject(req.GetOrgId(), opts...)
	if err != nil {
		return nil, err
	}
	out, err := s.repo.CreateScope(ctx, p)
	if err != nil {
		return nil, err
	}
	if out == nil {
		return nil, status.Error(codes.Internal, "Unable to create scope but no error returned from repository.")
	}
	return toProto(out), nil
}

func (s Service) updateInRepo(ctx context.Context, req *pbs.UpdateProjectRequest) (*pb.Project, error) {
	item := req.GetItem()
	// TODO: convert field masks from API field masks with snake_case to db field masks casing.
	madeUp := []string{}
	opts := []iam.Option{}
	if desc := item.GetDescription(); desc != nil {
		madeUp = append(madeUp, "Description")
		opts = append(opts, iam.WithDescription(desc.GetValue()))
	}
	if name := item.GetName(); name != nil {
		madeUp = append(madeUp, "Name")
		opts = append(opts, iam.WithName(name.GetValue()))
	}
	p, err := iam.NewProject(req.GetOrgId(), iam.WithPublicId(req.GetId()))
	if err != nil {
		return nil, err
	}
	out, err := s.repo.UpdateScope(ctx, p, madeUp)
	if err != nil {
		return nil, err
	}
	if out == nil {
		return nil, status.Error(codes.Internal, "Failed to get Project after updating it.")
	}
	return toProto(out), nil
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
func (s *Service) RegisterGrpcGateway(mux *runtime.ServeMux) error {
	return pbs.RegisterProjectServiceHandlerServer(context.Background(), mux, s)
}
