package host_catalogs

import (
	"context"
	"fmt"

	"github.com/golang/protobuf/ptypes"
	"github.com/golang/protobuf/ptypes/wrappers"
	"github.com/grpc-ecosystem/grpc-gateway/runtime"
	"github.com/hashicorp/watchtower/internal/gen/controller/api"
	"github.com/hashicorp/watchtower/internal/gen/controller/api/resource"
	"github.com/hashicorp/watchtower/internal/repo"
	"github.com/hashicorp/watchtower/internal/servers/controller"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

type hostCatalogRepo interface {
	LookupHostCatalog(ctx context.Context, id string) (repo.HostCatalog, error)
	ListHostCatalogs(ctx context.Context, scopeID string) ([]repo.HostCatalog, error)
	DeleteHostCatalog(ctx context.Context, id string) (bool, error)
	CreateHostCatalog(ctx context.Context, scopeID, id string, hc repo.HostCatalog) (repo.HostCatalog, error)
	UpdateHostCatalog(ctx context.Context, scopeID, id string, hc repo.HostCatalog, masks string) (repo.HostCatalog, error)
	// TODO: Figure out the appropriate way to verify the path is appropriate, whether as a seperate method or merging this into the methods above.
	VerifyAnsestory(ctx context.Context, id ...string) error
}

type Service struct {
	hcRepo hostCatalogRepo
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

func toRepo(id string, in resource.HostCatalog) repo.HostCatalog {
	out := repo.HostCatalog{ID: id}
	if in.GetFriendlyName() != nil {
		out.FriendlyName = in.GetFriendlyName().GetValue()
	}
	if in.GetDisabled() != nil {
		out.Disabled = in.GetDisabled().GetValue()
	}
	return out
}

func toProto(orgID, projID string, in repo.HostCatalog) resource.HostCatalog {
	out := resource.HostCatalog{}
	out.Uri = fmt.Sprintf("orgs/%s/projects/%s/host-catalogs/%s", orgID, projID, in.ID)
	out.Disabled = &wrappers.BoolValue{Value: in.Disabled}
	// TODO: Don't ignore the errors.
	out.CreatedTime, _ = ptypes.TimestampProto(in.CreateTime)
	out.UpdatedTime, _ = ptypes.TimestampProto(in.UpdateTime)
	return out
}

// A validateX method should exist for each method above.  These methods do not make calls to any backing service but enforce
// requirements on the structure of the request.  They verify that:
//  * The path passed in is correctly formatted
//  * All required parameters are set
//  * There are no conflicting parameters provided
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
