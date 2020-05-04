package hosts

import (
	"context"

	"github.com/grpc-ecosystem/grpc-gateway/runtime"
	"github.com/hashicorp/watchtower/internal/gen/controller/api"
	"github.com/hashicorp/watchtower/internal/repo"
	"github.com/hashicorp/watchtower/internal/servers/controller"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// hostRepo contains the data store lookups required by this service to satisfy it's functionality.
type hostRepo interface {
	LookupHost(ctx context.Context, id string) (repo.Host, error)
	ListHosts(ctx context.Context, catalogID string) ([]repo.Host, error)
	DeleteHost(ctx context.Context, id string) (bool, error)
	CreateHost(ctx context.Context, catalogID, id string, h repo.Host) (repo.Host, error)
	UpdateHost(ctx context.Context, id string, h repo.Host, masks string) (repo.Host, error)
	// TODO: Figure out the appropriate way to verify the path is appropriate, whether as a seperate method or merging this into the methods above.
	VerifyAnsestory(ctx context.Context, id ...string) error
}

type Service struct {
	hRepo hostRepo
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

// A validateX method should exist for each method above.  These methods do not make calls to any backing service but enforce
// requirements on the structure of the request.  They verify that:
//  * The path passed in is correctly formatted
//  * All required parameters are set
//  * There are no conflicting parameters provided
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
