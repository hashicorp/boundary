package projects

import (
	"context"
	"fmt"
	"regexp"
	"strings"

	"github.com/golang/protobuf/ptypes/wrappers"
	"github.com/grpc-ecosystem/grpc-gateway/runtime"
	pb "github.com/hashicorp/watchtower/internal/gen/controller/api/resources/scopes"
	pbs "github.com/hashicorp/watchtower/internal/gen/controller/api/services"
	"github.com/hashicorp/watchtower/internal/iam"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

var reInvalidID = regexp.MustCompile("[^A-Za-z0-9]")

type Service struct {
	pbs.UnimplementedProjectServiceServer
	repo *iam.Repository
}

func NewService(repo *iam.Repository) *Service {
	if repo == nil {
		return nil
	}
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
	opts := []iam.Option{iam.WithPublicId(req.GetId())}
	if desc := item.GetDescription(); desc != nil {
		madeUp = append(madeUp, "Description")
		opts = append(opts, iam.WithDescription(desc.GetValue()))
	}
	if name := item.GetName(); name != nil {
		madeUp = append(madeUp, "Name")
		opts = append(opts, iam.WithName(name.GetValue()))
	}
	p, err := iam.NewProject(req.GetOrgId(), opts...)
	if err != nil {
		return nil, err
	}
	out, err := s.repo.UpdateScope(ctx, p, madeUp)
	if err != nil {
		return nil, err
	}
	if out == nil {
		return nil, status.Error(codes.NotFound, "Project doesn't exist.")
	}
	return toProto(out), nil
}

func toProto(in *iam.Scope) *pb.Project {
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
// TODO: Populate the error in a way to allow it to be converted to the previously described error format and include all invalid fields instead of just the most recent.
func validateGetProjectRequest(req *pbs.GetProjectRequest) error {
	if err := validateAncestors(req); err != nil {
		return err
	}
	if err := validateID(req.GetOrgId(), "o_"); err != nil {
		return err
	}
	if err := validateID(req.GetId(), "p_"); err != nil {
		return err
	}
	return nil
}

func validateCreateProjectRequest(req *pbs.CreateProjectRequest) error {
	if err := validateAncestors(req); err != nil {
		return err
	}
	if err := validateID(req.GetOrgId(), "o_"); err != nil {
		return err
	}
	item := req.GetItem()
	if item == nil {
		return status.Errorf(codes.InvalidArgument, "A project's fields must be set to something .")
	}
	if item.GetId() != "" {
		return status.Errorf(codes.InvalidArgument, "Cannot set ID when creating a new project.")
	}
	if item.GetCreatedTime() != nil || item.GetUpdatedTime() != nil {
		return status.Errorf(codes.InvalidArgument, "Cannot set Created or Updated time when creating a new project.")
	}
	return nil
}

func validateUpdateProjectRequest(req *pbs.UpdateProjectRequest) error {
	if err := validateAncestors(req); err != nil {
		return err
	}
	if err := validateID(req.GetId(), "p_"); err != nil {
		return err
	}
	if err := validateID(req.GetOrgId(), "o_"); err != nil {
		return err
	}
	// TODO: Either require mask to be set or document in API that an unset mask updates all fields.
	item := req.GetItem()
	if item == nil {
		// It is legitimate for no item to be specified in an update request as it indicates all fields provided in
		// the mask will be marked as unset.
		return nil
	}

	if err := validateID(item.GetId(), "p_"); item.GetId() != "" && err != nil {
		return err
	}
	if item.GetId() != "" && item.GetId() != req.GetId() {
		return status.Errorf(codes.InvalidArgument, "Id in provided item and url must match. Item Id was %q, url id was %q", item.GetId(), req.GetId())
	}
	if item.GetCreatedTime() != nil || item.GetUpdatedTime() != nil {
		return status.Errorf(codes.InvalidArgument, "Cannot set Created or Updated time when updating a project.")
	}

	return nil
}

func validateID(id, prefix string) error {
	if !strings.HasPrefix(id, prefix) {
		return status.Errorf(codes.InvalidArgument, "ID start with a %q prefix, provided %q", prefix, id)
	}
	id = strings.TrimPrefix(id, prefix)
	if reInvalidID.Match([]byte(id)) {
		return status.Errorf(codes.InvalidArgument, "Improperly formatted ID: %q", id)
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
