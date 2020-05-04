package host_sets

import (
	"context"
	"fmt"

	"github.com/golang/protobuf/ptypes"
	"github.com/golang/protobuf/ptypes/wrappers"
	"github.com/grpc-ecosystem/grpc-gateway/runtime"
	"github.com/hashicorp/watchtower/internal/gen/controller/api/resources/hosts"
	"github.com/hashicorp/watchtower/internal/gen/controller/api/services"
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

var _ services.HostSetServiceServer = &Service{}
var _ controller.RegisterGrpcGatewayer = &Service{}

func (s Service) GetHostSet(ctx context.Context, req *services.GetHostSetRequest) (*services.GetHostSetResponse, error) {
	if err := validateListHostSetRequest(req); err != nil {
		return nil, err
	}
	return nil, status.Errorf(codes.NotFound, "Org %q not found", req.OrgId)
}

func (s Service) ListHostSets(ctx context.Context, req *services.ListHostSetsRequest) (*services.ListHostSetsResponse, error) {
	if err := validateListHostSetsRequest(req); err != nil {
		return nil, err
	}
	return nil, status.Errorf(codes.NotFound, "Org %q not found", req.OrgId)
}

func (s Service) CreateHostSet(ctx context.Context, req *services.CreateHostSetRequest) (*services.CreateHostSetResponse, error) {
	if err := validateCreateHostSetRequest(req); err != nil {
		return nil, err
	}
	return nil, status.Errorf(codes.NotFound, "Org %q not found", req.OrgId)
}

func (s Service) UpdateHostSet(ctx context.Context, req *services.UpdateHostSetRequest) (*services.UpdateHostSetResponse, error) {
	if err := validateUpdateHostSetRequest(req); err != nil {
		return nil, err
	}
	return nil, status.Errorf(codes.NotFound, "Org %q not found", req.OrgId)
}

func (s Service) DeleteHostSet(ctx context.Context, req *services.DeleteHostSetRequest) (*services.DeleteHostSetResponse, error) {
	if err := validateDeleteHostSetRequest(req); err != nil {
		return nil, err
	}
	return nil, status.Errorf(codes.NotFound, "Org %q not found", req.OrgId)
}

func (s Service) AddToHostSet(ctx context.Context, req *services.AddToHostSetRequest) (*services.AddToHostSetResponse, error) {
	if err := validateAddToHostSetRequest(req); err != nil {
		return nil, err
	}
	return nil, status.Errorf(codes.NotFound, "Org %q not found", req.OrgId)
}

func (s Service) RemoveFromHostSet(ctx context.Context, req *services.RemoveFromHostSetRequest) (*services.RemoveFromHostSetResponse, error) {
	if err := validateRemoveFromHostSetRequest(req); err != nil {
		return nil, err
	}
	return nil, status.Errorf(codes.NotFound, "Org %q not found", req.OrgId)
}

func toRepo(id string, in hosts.HostSet) repo.HostSet {
	out := repo.HostSet{ID: id}
	if in.GetFriendlyName() != nil {
		out.FriendlyName = in.GetFriendlyName().GetValue()
	}
	if in.GetDisabled() != nil {
		out.Disabled = in.GetDisabled().GetValue()
	}
	return out
}

func toProto(orgID, projID, catID string, in repo.HostSet) hosts.HostSet {
	out := hosts.HostSet{}
	out.Path = fmt.Sprintf("orgs/%s/projects/%s/host-catalogs/%s/host-sets/%s", orgID, projID, catID, in.ID)
	out.Disabled = &wrappers.BoolValue{Value: in.Disabled}
	// TODO: Don't ignore the errors.
	out.CreatedTime, _ = ptypes.TimestampProto(in.CreateTime)
	out.UpdatedTime, _ = ptypes.TimestampProto(in.UpdateTime)
	out.Size = &wrappers.Int64Value{Value: in.Size}
	// TODO: Figure out conversion of Hosts for the lists
	return out
}

// A validateX method should exist for each method above.  These methods do not make calls to any backing service but enforce
// requirements on the structure of the request.  They verify that:
//  * The path passed in is correctly formatted
//  * All required parameters are set
//  * There are no conflicting parameters provided
func validateListHostSetRequest(req *services.GetHostSetRequest) error {
	if err := validateAncestors(req); err != nil {
		return err
	}
	return nil
}

func validateListHostSetsRequest(req *services.ListHostSetsRequest) error {
	if err := validateAncestors(req); err != nil {
		return err
	}
	return nil
}

func validateCreateHostSetRequest(req *services.CreateHostSetRequest) error {
	if err := validateAncestors(req); err != nil {
		return err
	}
	return nil
}

func validateUpdateHostSetRequest(req *services.UpdateHostSetRequest) error {
	if err := validateAncestors(req); err != nil {
		return err
	}
	return nil
}

func validateDeleteHostSetRequest(req *services.DeleteHostSetRequest) error {
	if err := validateAncestors(req); err != nil {
		return err
	}
	return nil
}

func validateAddToHostSetRequest(req *services.AddToHostSetRequest) error {
	if err := validateAncestors(req); err != nil {
		return err
	}
	return nil
}

func validateRemoveFromHostSetRequest(req *services.RemoveFromHostSetRequest) error {
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
	return services.RegisterHostSetServiceHandlerServer(context.Background(), mux, s)
}
