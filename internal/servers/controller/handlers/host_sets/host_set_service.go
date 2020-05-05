package host_sets

import (
	"context"
	"fmt"

	"github.com/golang/protobuf/ptypes"
	"github.com/golang/protobuf/ptypes/wrappers"
	"github.com/grpc-ecosystem/grpc-gateway/runtime"
	pb "github.com/hashicorp/watchtower/internal/gen/controller/api/resources/hosts"
	pbs "github.com/hashicorp/watchtower/internal/gen/controller/api/services"
	"github.com/hashicorp/watchtower/internal/repo"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

type hostSetRepo interface {
	LookupHostSet(ctx context.Context, id string) (*repo.HostSet, error)
	ListHostSets(ctx context.Context, scopeID, catalogID string) ([]repo.HostSet, error)
	DeleteHostSet(ctx context.Context, id string) (bool, error)
	CreateHostSet(ctx context.Context, catalogID, id string, hs repo.HostSet) (*repo.HostSet, error)
	UpdateHostSet(ctx context.Context, catalogID, id string, hs repo.HostSet, masks string) (*repo.HostSet, error)
	// TODO: Figure out the appropriate way to verify the path is appropriate, whether as a separate method or merging this into the methods above.
}

type Service struct {
	hsRepo hostSetRepo
}

func NewService(r hostSetRepo) *Service {
	return &Service{r}
}

var _ pbs.HostSetServiceServer = &Service{}

func (s Service) GetHostSet(ctx context.Context, req *pbs.GetHostSetRequest) (*pbs.GetHostSetResponse, error) {
	if err := validateListHostSetRequest(req); err != nil {
		return nil, err
	}
	return nil, status.Errorf(codes.NotFound, "Org %q not found", req.OrgId)
}

func (s Service) ListHostSets(ctx context.Context, req *pbs.ListHostSetsRequest) (*pbs.ListHostSetsResponse, error) {
	if err := validateListHostSetsRequest(req); err != nil {
		return nil, err
	}
	return nil, status.Errorf(codes.NotFound, "Org %q not found", req.OrgId)
}

func (s Service) CreateHostSet(ctx context.Context, req *pbs.CreateHostSetRequest) (*pbs.CreateHostSetResponse, error) {
	if err := validateCreateHostSetRequest(req); err != nil {
		return nil, err
	}
	return nil, status.Errorf(codes.NotFound, "Org %q not found", req.OrgId)
}

func (s Service) UpdateHostSet(ctx context.Context, req *pbs.UpdateHostSetRequest) (*pbs.UpdateHostSetResponse, error) {
	if err := validateUpdateHostSetRequest(req); err != nil {
		return nil, err
	}
	return nil, status.Errorf(codes.NotFound, "Org %q not found", req.OrgId)
}

func (s Service) DeleteHostSet(ctx context.Context, req *pbs.DeleteHostSetRequest) (*pbs.DeleteHostSetResponse, error) {
	if err := validateDeleteHostSetRequest(req); err != nil {
		return nil, err
	}

	existed, err := s.hsRepo.DeleteHostSet(ctx, req.Id)
	if err != nil {
		return nil, err
	}
	return &pbs.DeleteHostSetResponse{Existed: existed}, nil
}

func (s Service) AddToHostSet(ctx context.Context, req *pbs.AddToHostSetRequest) (*pbs.AddToHostSetResponse, error) {
	if err := validateAddToHostSetRequest(req); err != nil {
		return nil, err
	}
	return nil, status.Errorf(codes.NotFound, "Org %q not found", req.OrgId)
}

func (s Service) RemoveFromHostSet(ctx context.Context, req *pbs.RemoveFromHostSetRequest) (*pbs.RemoveFromHostSetResponse, error) {
	if err := validateRemoveFromHostSetRequest(req); err != nil {
		return nil, err
	}
	return nil, status.Errorf(codes.NotFound, "Org %q not found", req.OrgId)
}

func toRepo(id string, in *pb.HostSet) *repo.HostSet {
	out := &repo.HostSet{ID: id}
	if in.GetFriendlyName() != nil {
		out.FriendlyName = in.GetFriendlyName().GetValue()
	}
	if in.GetDisabled() != nil {
		out.Disabled = in.GetDisabled().GetValue()
	}
	return out
}

func toProto(orgID, projID, catID string, in *repo.HostSet) *pb.HostSet {
	out := &pb.HostSet{}
	out.Path = fmt.Sprintf("orgs/%s/projects/%s/host-catalogs/%s/host-sets/%s", orgID, projID, catID, in.ID)
	out.Disabled = &wrappers.BoolValue{Value: in.Disabled}
	// TODO: Don't ignore the errors.
	out.CreatedTime, _ = ptypes.TimestampProto(in.CreatedTime)
	out.UpdatedTime, _ = ptypes.TimestampProto(in.UpdatedTime)
	out.Size = &wrappers.Int64Value{Value: in.Size}
	// TODO: Figure out conversion of Hosts for the lists
	return out
}

// A validateX method should exist for each method above.  These methods do not make calls to any backing service but enforce
// requirements on the structure of the request.  They verify that:
//  * The path passed in is correctly formatted
//  * All required parameters are set
//  * There are no conflicting parameters provided
func validateListHostSetRequest(req *pbs.GetHostSetRequest) error {
	if err := validateAncestors(req); err != nil {
		return err
	}
	return nil
}

func validateListHostSetsRequest(req *pbs.ListHostSetsRequest) error {
	if err := validateAncestors(req); err != nil {
		return err
	}
	return nil
}

func validateCreateHostSetRequest(req *pbs.CreateHostSetRequest) error {
	if err := validateAncestors(req); err != nil {
		return err
	}
	return nil
}

func validateUpdateHostSetRequest(req *pbs.UpdateHostSetRequest) error {
	if err := validateAncestors(req); err != nil {
		return err
	}
	return nil
}

func validateDeleteHostSetRequest(req *pbs.DeleteHostSetRequest) error {
	if err := validateAncestors(req); err != nil {
		return err
	}
	return nil
}

func validateAddToHostSetRequest(req *pbs.AddToHostSetRequest) error {
	if err := validateAncestors(req); err != nil {
		return err
	}
	return nil
}

func validateRemoveFromHostSetRequest(req *pbs.RemoveFromHostSetRequest) error {
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
	return pbs.RegisterHostSetServiceHandlerServer(context.Background(), mux, s)
}
