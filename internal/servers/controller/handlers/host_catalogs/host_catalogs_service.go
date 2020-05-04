package host_catalogs

import (
	"context"

	"github.com/grpc-ecosystem/grpc-gateway/runtime"
	"github.com/hashicorp/watchtower/internal/gen/controller/api"
	"github.com/hashicorp/watchtower/internal/gen/controller/api/resource"
	"github.com/hashicorp/watchtower/internal/servers/controller"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

type dao interface {
	LookupHostCatalogByPublicId(ctx context.Context, id string) *resource.HostCatalog
	ListHostCatalogs(ctx context.Context, orgID, projID string) []*resource.HostCatalog
	DeleteHostCatalogByPublicId(ctx context.Context, id string) (bool, error)
	CreateHostCatalog(ctx context.Context, org, proj, id string, hc resource.HostCatalog) (resource.HostCatalog, error)
	UpdateHostCatalog(ctx context.Context, org, proj, id string, hc resource.HostCatalog, masks string) (resource.HostCatalog, error)
}

type Service struct {
	dao dao
}

var _ api.HostCatalogServiceServer = &Service{}
var _ controller.RegisterGrpcGatewayer = &Service{}

func (s Service) ListHostCatalogs(ctx context.Context, req *api.ListHostCatalogsRequest) (*api.ListHostCatalogsResponse, error) {
	if err := validateListHostCatalogsRequest(req); err != nil {
		return nil, err
	}
	return nil, status.Errorf(codes.NotFound, "Org %q not found", req.OrgId)
}

func (s Service) GetHostCatalog(ctx context.Context, req *api.GetHostCatalogRequest) (*api.GetHostCatalogResponse, error) {
	if err := validateGetHostCatalogRequest(req); err != nil {
		return nil, err
	}
	return nil, status.Errorf(codes.NotFound, "Org %q not found", req.OrgId)
}

func (s Service) CreateHostCatalog(ctx context.Context, req *api.CreateHostCatalogRequest) (*api.CreateHostCatalogResponse, error) {
	if err := validateCreateHostCatalogRequest(req); err != nil {
		return nil, err
	}
	return nil, status.Errorf(codes.NotFound, "Org %q not found", req.OrgId)
}

func (s Service) UpdateHostCatalog(ctx context.Context, req *api.UpdateHostCatalogRequest) (*api.UpdateHostCatalogResponse, error) {
	if err := validateUpdateHostCatalogRequest(req); err != nil {
		return nil, err
	}
	return nil, status.Errorf(codes.NotFound, "Org %q not found", req.OrgId)
}

func (s Service) DeleteHostCatalog(ctx context.Context, req *api.DeleteHostCatalogRequest) (*api.DeleteHostCatalogResponse, error) {
	if err := validateDeleteHostCatalogRequest(req); err != nil {
		return nil, err
	}
	return &api.DeleteHostCatalogResponse{}, nil
}

func validateListHostCatalogsRequest(req *api.ListHostCatalogsRequest) error {
	if err := validateAncestors(req); err != nil {
		return err
	}
	return nil
}

func validateGetHostCatalogRequest(req *api.GetHostCatalogRequest) error {
	if err := validateAncestors(req); err != nil {
		return err
	}
	return nil
}

func validateCreateHostCatalogRequest(req *api.CreateHostCatalogRequest) error {
	if err := validateAncestors(req); err != nil {
		return err
	}
	return nil
}

func validateUpdateHostCatalogRequest(req *api.UpdateHostCatalogRequest) error {
	if err := validateAncestors(req); err != nil {
		return err
	}
	return nil
}

func validateDeleteHostCatalogRequest(req *api.DeleteHostCatalogRequest) error {
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
	return api.RegisterHostCatalogServiceHandlerServer(context.Background(), mux, s)
}
