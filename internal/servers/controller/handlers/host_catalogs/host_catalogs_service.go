package host_catalogs

import (
	"context"

	"github.com/golang/protobuf/ptypes"
	"github.com/golang/protobuf/ptypes/wrappers"
	"github.com/grpc-ecosystem/grpc-gateway/runtime"
	pb "github.com/hashicorp/watchtower/internal/gen/controller/api/resources/hosts"
	pbs "github.com/hashicorp/watchtower/internal/gen/controller/api/services"
	"github.com/hashicorp/watchtower/internal/repo"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

type hostCatalogRepo interface {
	LookupHostCatalog(ctx context.Context, id string) (*repo.HostCatalog, error)
	ListHostCatalogs(ctx context.Context, scopeID string) ([]repo.HostCatalog, error)
	DeleteHostCatalog(ctx context.Context, id string) (bool, error)
	CreateHostCatalog(ctx context.Context, scopeID, id string, hc repo.HostCatalog) (*repo.HostCatalog, error)
	UpdateHostCatalog(ctx context.Context, scopeID, id string, hc repo.HostCatalog, masks string) (*repo.HostCatalog, error)
	// TODO: Figure out the appropriate way to verify the path is appropriate, whether as a seperate method or merging this into the methods above.
}

type Service struct {
	hcRepo hostCatalogRepo
}

func NewService(repo hostCatalogRepo) *Service {
	return &Service{repo}
}

var _ pbs.HostCatalogServiceServer = &Service{}

func (s Service) ListHostCatalogs(ctx context.Context, req *pbs.ListHostCatalogsRequest) (*pbs.ListHostCatalogsResponse, error) {
	if err := validateListHostCatalogsRequest(req); err != nil {
		return nil, err
	}
	return nil, status.Errorf(codes.NotFound, "Org %q not found", req.OrgId)
}

func (s Service) GetHostCatalog(ctx context.Context, req *pbs.GetHostCatalogRequest) (*pbs.GetHostCatalogResponse, error) {
	if err := validateGetHostCatalogRequest(req); err != nil {
		return nil, err
	}
	h, err := s.hcRepo.LookupHostCatalog(ctx, req.Id)
	if err != nil {
		return nil, err
	}
	if h == nil {
		return nil, status.Errorf(codes.NotFound, "Could not find HostCatalog with id %q", req.GetId())
	}
	resp := &pbs.GetHostCatalogResponse{}
	resp.Item = toProto(req.OrgId, req.ProjectId, h)
	return resp, nil
}

func (s Service) CreateHostCatalog(ctx context.Context, req *pbs.CreateHostCatalogRequest) (*pbs.CreateHostCatalogResponse, error) {
	if err := validateCreateHostCatalogRequest(req); err != nil {
		return nil, err
	}
	return nil, status.Errorf(codes.NotFound, "Org %q not found", req.OrgId)
}

func (s Service) UpdateHostCatalog(ctx context.Context, req *pbs.UpdateHostCatalogRequest) (*pbs.UpdateHostCatalogResponse, error) {
	if err := validateUpdateHostCatalogRequest(req); err != nil {
		return nil, err
	}
	return nil, status.Errorf(codes.NotFound, "Org %q not found", req.OrgId)
}

func (s Service) DeleteHostCatalog(ctx context.Context, req *pbs.DeleteHostCatalogRequest) (*pbs.DeleteHostCatalogResponse, error) {
	if err := validateDeleteHostCatalogRequest(req); err != nil {
		return nil, err
	}
	existed, err := s.hcRepo.DeleteHostCatalog(ctx, req.Id)
	if err != nil {
		// TODO: Handle errors appropriately
		return nil, status.Errorf(codes.Internal, "Couldn't delete Host Catalog: %v", err)
	}
	return &pbs.DeleteHostCatalogResponse{Existed: existed}, nil
}

func toRepo(id string, in pb.HostCatalog) repo.HostCatalog {
	out := repo.HostCatalog{ID: id}
	if in.GetFriendlyName() != nil {
		out.FriendlyName = in.GetFriendlyName().GetValue()
	}
	if in.GetDisabled() != nil {
		out.Disabled = in.GetDisabled().GetValue()
	}
	return out
}

func toProto(orgID, projID string, in *repo.HostCatalog) *pb.HostCatalog {
	out := pb.HostCatalog{}
	if in.Disabled {
		out.Disabled = &wrappers.BoolValue{Value: in.Disabled}
	}
	if in.FriendlyName != "" {
		out.FriendlyName = &wrappers.StringValue{Value: in.FriendlyName}
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
func validateListHostCatalogsRequest(req *pbs.ListHostCatalogsRequest) error {
	if err := validateAncestors(req); err != nil {
		return err
	}
	return nil
}

func validateGetHostCatalogRequest(req *pbs.GetHostCatalogRequest) error {
	if err := validateAncestors(req); err != nil {
		return err
	}
	return nil
}

func validateCreateHostCatalogRequest(req *pbs.CreateHostCatalogRequest) error {
	if err := validateAncestors(req); err != nil {
		return err
	}
	return nil
}

func validateUpdateHostCatalogRequest(req *pbs.UpdateHostCatalogRequest) error {
	if err := validateAncestors(req); err != nil {
		return err
	}
	return nil
}

func validateDeleteHostCatalogRequest(req *pbs.DeleteHostCatalogRequest) error {
	if err := validateAncestors(req); err != nil {
		return err
	}
	return nil
}

type ancestorProvider interface {
	GetOrgId() string
	GetProjectId() string
}

// validateAncestors verifies that the ancestors of this call are properly set and provided.
func validateAncestors(r ancestorProvider) error {
	if r.GetOrgId() == "" {
		return status.Errorf(codes.InvalidArgument, "OrgId must be provided.")
	}
	if r.GetProjectId() == "" {
		return status.Errorf(codes.InvalidArgument, "ProjectId must be provided.")
	}
	return nil
}

// RegisterGrpcGateway satisfies the RegisterGrpcGatewayer interface.
func (s Service) RegisterGrpcGateway(mux *runtime.ServeMux) error {
	return pbs.RegisterHostCatalogServiceHandlerServer(context.Background(), mux, s)
}
