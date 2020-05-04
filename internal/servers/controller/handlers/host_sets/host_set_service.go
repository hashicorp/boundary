package host_sets

import (
	"context"

	"github.com/grpc-ecosystem/grpc-gateway/runtime"
	"github.com/hashicorp/watchtower/internal/gen/controller/api"
	"github.com/hashicorp/watchtower/internal/repo"
	"github.com/hashicorp/watchtower/internal/servers/controller"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

type hostSetRepo interface {
	LookupHostSet(ctx context.Context, id string) (repo.HostSet, error)
	ListHostSets(ctx context.Context, scopeID, catalogID string) ([]repo.HostSet, error)
	DeleteHostSet(ctx context.Context, id string) (bool, error)
	CreateHostSet(ctx context.Context, catalogID, id string, hs repo.HostSet) (repo.HostSet, error)
	UpdateHostSet(ctx context.Context, catalogID, id string, hs repo.HostSet, masks string) (repo.HostSet, error)
	// TODO: Figure out the appropriate way to verify the path is appropriate, whether as a seperate method or merging this into the methods above.
	VerifyAnsestory(ctx context.Context, id ...string) error
}

type Service struct {
	hsRepo hostSetRepo
}

var _ api.HostSetServiceServer = &Service{}
var _ controller.RegisterGrpcGatewayer = &Service{}

func (s Service) GetHostSet(ctx context.Context, req *api.GetHostSetRequest) (*api.GetHostSetResponse, error) {
	if err := validateListHostSetRequest(req); err != nil {
		return nil, err
	}
	return nil, status.Errorf(codes.NotFound, "Org %q not found", req.OrgId)
}

func (s Service) ListHostSets(ctx context.Context, req *api.ListHostSetsRequest) (*api.ListHostSetsResponse, error) {
	if err := validateListHostSetsRequest(req); err != nil {
		return nil, err
	}
	return nil, status.Errorf(codes.NotFound, "Org %q not found", req.OrgId)
}

func (s Service) CreateHostSet(ctx context.Context, req *api.CreateHostSetRequest) (*api.CreateHostSetResponse, error) {
	if err := validateCreateHostSetRequest(req); err != nil {
		return nil, err
	}
	return nil, status.Errorf(codes.NotFound, "Org %q not found", req.OrgId)
}

func (s Service) UpdateHostSet(ctx context.Context, req *api.UpdateHostSetRequest) (*api.UpdateHostSetResponse, error) {
	if err := validateUpdateHostSetRequest(req); err != nil {
		return nil, err
	}
	return nil, status.Errorf(codes.NotFound, "Org %q not found", req.OrgId)
}

func (s Service) DeleteHostSet(ctx context.Context, req *api.DeleteHostSetRequest) (*api.DeleteHostSetResponse, error) {
	if err := validateDeleteHostSetRequest(req); err != nil {
		return nil, err
	}
	return nil, status.Errorf(codes.NotFound, "Org %q not found", req.OrgId)
}

func (s Service) AddToHostSet(ctx context.Context, req *api.AddToHostSetRequest) (*api.AddToHostSetResponse, error) {
	if err := validateAddToHostSetRequest(req); err != nil {
		return nil, err
	}
	return nil, status.Errorf(codes.NotFound, "Org %q not found", req.OrgId)
}

func (s Service) RemoveFromHostSet(ctx context.Context, req *api.RemoveFromHostSetRequest) (*api.RemoveFromHostSetResponse, error) {
	if err := validateRemoveFromHostSetRequest(req); err != nil {
		return nil, err
	}
	return nil, status.Errorf(codes.NotFound, "Org %q not found", req.OrgId)
}

// A validateX method should exist for each method above.  These methods do not make calls to any backing service but enforce
// requirements on the structure of the request.  They verify that:
//  * The path passed in is correctly formatted
//  * All required parameters are set
//  * There are no conflicting parameters provided
func validateListHostSetRequest(req *api.GetHostSetRequest) error {
	if err := validateAncestors(req); err != nil {
		return err
	}
	return nil
}

func validateListHostSetsRequest(req *api.ListHostSetsRequest) error {
	if err := validateAncestors(req); err != nil {
		return err
	}
	return nil
}

func validateCreateHostSetRequest(req *api.CreateHostSetRequest) error {
	if err := validateAncestors(req); err != nil {
		return err
	}
	return nil
}

func validateUpdateHostSetRequest(req *api.UpdateHostSetRequest) error {
	if err := validateAncestors(req); err != nil {
		return err
	}
	return nil
}

func validateDeleteHostSetRequest(req *api.DeleteHostSetRequest) error {
	if err := validateAncestors(req); err != nil {
		return err
	}
	return nil
}

func validateAddToHostSetRequest(req *api.AddToHostSetRequest) error {
	if err := validateAncestors(req); err != nil {
		return err
	}
	return nil
}

func validateRemoveFromHostSetRequest(req *api.RemoveFromHostSetRequest) error {
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
	return api.RegisterHostSetServiceHandlerServer(context.Background(), mux, s)
}
