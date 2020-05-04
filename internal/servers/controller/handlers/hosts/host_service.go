package hosts

import (
	"context"

	"github.com/grpc-ecosystem/grpc-gateway/runtime"
	"github.com/hashicorp/watchtower/internal/gen/controller/api"
	"github.com/hashicorp/watchtower/internal/gen/controller/api/resource"
	"github.com/hashicorp/watchtower/internal/servers/controller"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// dao contains the data store lookups required by this service to satisfy it's functionality.
type dao interface {
	LookupHostByPublicId(ctx context.Context, id string) *resource.Host
	ListHosts(ctx context.Context, orgID, projID, hostCatalogID string) []*resource.Host
	DeleteHostByPublicId(ctx context.Context, id string) (bool, error)
	CreateHost(ctx context.Context, orgID, projID, hostCatalogID, id string, h resource.Host) (resource.Host, error)
	UpdateHost(ctx context.Context, orgID, projID, hostCatalogID, id string, h resource.Host, masks string) (resource.Host, error)
}

type Service struct {
	dao dao
}

var _ api.HostServiceServer = &Service{}
var _ controller.RegisterGrpcGatewayer = &Service{}

func (s Service) GetHost(ctx context.Context, req *api.GetHostRequest) (*api.GetHostResponse, error) {
	if err := validateGetHostRequest(req); err != nil {
		return nil, err
	}
	return nil, status.Errorf(codes.NotFound, "Org %q not found", req.OrgId)
}

func (s Service) CreateHost(ctx context.Context, req *api.CreateHostRequest) (*api.CreateHostResponse, error) {
	if err := validateCreateHostRequest(req); err != nil {
		return nil, err
	}
	return nil, status.Errorf(codes.NotFound, "Org %q not found", req.OrgId)
}

func (s Service) UpdateHost(ctx context.Context, req *api.UpdateHostRequest) (*api.UpdateHostResponse, error) {
	if err := validateUpdateHostRequest(req); err != nil {
		return nil, err
	}
	return nil, status.Errorf(codes.NotFound, "Org %q not found", req.OrgId)
}

func (s Service) ListHosts(ctx context.Context, req *api.ListHostsRequest) (*api.ListHostsResponse, error) {
	if err := validateListHostsRequest(req); err != nil {
		return nil, err
	}
	return nil, status.Errorf(codes.NotFound, "Org %q not found", req.OrgId)
}

func (s Service) DeleteHost(ctx context.Context, req *api.DeleteHostRequest) (*api.DeleteHostResponse, error) {
	if err := validateDeleteHostRequest(req); err != nil {
		return nil, err
	}
	return nil, status.Errorf(codes.NotFound, "Org %q not found", req.OrgId)
}

func validateGetHostRequest(req *api.GetHostRequest) error {
	if err := validateAncestors(req); err != nil {
		return err
	}
	return nil
}

func validateCreateHostRequest(req *api.CreateHostRequest) error {
	if err := validateAncestors(req); err != nil {
		return err
	}
	return nil
}

func validateUpdateHostRequest(req *api.UpdateHostRequest) error {
	if err := validateAncestors(req); err != nil {
		return err
	}
	return nil
}

func validateListHostsRequest(req *api.ListHostsRequest) error {
	if err := validateAncestors(req); err != nil {
		return err
	}
	return nil
}

func validateDeleteHostRequest(req *api.DeleteHostRequest) error {
	if err := validateAncestors(req); err != nil {
		return err
	}
	return nil
}

type ancestorProvider interface {
	GetOrgId() string
	GetProjectId() string
	GetHostCatalogId() string
}

// validateAncestors verifies that the ancestors of this call are properly set and provided.
func validateAncestors(r ancestorProvider) error {
	if r.GetOrgId() == "" {
		return status.Errorf(codes.InvalidArgument, "OrgId must be provided.")
	}
	if r.GetProjectId() == "" {
		return status.Errorf(codes.InvalidArgument, "ProjectId must be provided.")
	}
	if r.GetHostCatalogId() == "" {
		return status.Errorf(codes.InvalidArgument, "HostCatalogId must be provided.")
	}
	return nil
}

// RegisterGrpcGateway satisfies the RegisterGrpcGatewayer interface.
func (s Service) RegisterGrpcGateway(mux *runtime.ServeMux) error {
	return api.RegisterHostServiceHandlerServer(context.Background(), mux, s)
}
