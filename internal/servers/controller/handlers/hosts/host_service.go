package hosts

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

// hostRepo contains the data store lookups required by this service to satisfy it's functionality.
type hostRepo interface {
	LookupHost(ctx context.Context, id string) (*repo.Host, error)
	ListHosts(ctx context.Context, catalogID string) ([]repo.Host, error)
	DeleteHost(ctx context.Context, id string) (bool, error)
	CreateHost(ctx context.Context, catalogID, id string, h repo.Host) (*repo.Host, error)
	UpdateHost(ctx context.Context, id string, h repo.Host, masks string) (*repo.Host, error)
	// TODO: Figure out the appropriate way to verify the path is appropriate, whether as a separate method or merging this into the methods above.
}

type Service struct {
	hRepo hostRepo
}

func NewService(r hostRepo) *Service {
	return &Service{r}
}

var _ pbs.HostServiceServer = &Service{}

func (s Service) GetHost(ctx context.Context, req *pbs.GetHostRequest) (*pbs.GetHostResponse, error) {
	if err := validateGetHostRequest(req); err != nil {
		return nil, err
	}
	h, err := s.hRepo.LookupHost(ctx, req.GetId())
	if err != nil {
		return nil, err
	}
	if h == nil {
		return nil, status.Errorf(codes.NotFound, "Unable to find host with id %q", req.GetId())
	}
	resp := &pbs.GetHostResponse{Item: toProto(req.GetOrgId(), req.GetProjectId(), req.GetHostCatalogId(), h)}
	return resp, nil
}

func (s Service) CreateHost(ctx context.Context, req *pbs.CreateHostRequest) (*pbs.CreateHostResponse, error) {
	if err := validateCreateHostRequest(req); err != nil {
		return nil, err
	}
	return nil, status.Errorf(codes.NotFound, "Org %q not found", req.OrgId)
}

func (s Service) UpdateHost(ctx context.Context, req *pbs.UpdateHostRequest) (*pbs.UpdateHostResponse, error) {
	if err := validateUpdateHostRequest(req); err != nil {
		return nil, err
	}
	return nil, status.Errorf(codes.NotFound, "Org %q not found", req.OrgId)
}

func (s Service) ListHosts(ctx context.Context, req *pbs.ListHostsRequest) (*pbs.ListHostsResponse, error) {
	if err := validateListHostsRequest(req); err != nil {
		return nil, err
	}
	return nil, status.Errorf(codes.NotFound, "Org %q not found", req.OrgId)
}

func (s Service) DeleteHost(ctx context.Context, req *pbs.DeleteHostRequest) (*pbs.DeleteHostResponse, error) {
	if err := validateDeleteHostRequest(req); err != nil {
		return nil, err
	}

	existed, err := s.hRepo.DeleteHost(ctx, req.Id)
	if err != nil {
		return nil, err
	}
	return &pbs.DeleteHostResponse{Existed: existed}, nil
}

func toRepo(id string, in *pb.Host) *repo.Host {
	out := &repo.Host{ID: id}
	if in.GetFriendlyName() != nil {
		out.FriendlyName = in.GetFriendlyName().GetValue()
	}
	if in.GetDisabled() != nil {
		out.Disabled = in.GetDisabled().GetValue()
	}
	return out
}

func toProto(orgID, projID, catID string, in *repo.Host) *pb.Host {
	out := &pb.Host{}
	out.Path = fmt.Sprintf("orgs/%s/projects/%s/host-catalogs/%s/hosts/%s", orgID, projID, catID, in.ID)
	out.Disabled = &wrappers.BoolValue{Value: in.Disabled}
	// TODO: Don't ignore the errors.
	out.CreatedTime, _ = ptypes.TimestampProto(in.CreatedTime)
	out.UpdatedTime, _ = ptypes.TimestampProto(in.UpdatedTime)
	out.Address = &wrappers.StringValue{Value: in.Address}
	return out
}

// A validateX method should exist for each method above.  These methods do not make calls to any backing service but enforce
// requirements on the structure of the request.  They verify that:
//  * The path passed in is correctly formatted
//  * All required parameters are set
//  * There are no conflicting parameters provided
func validateGetHostRequest(req *pbs.GetHostRequest) error {
	if err := validateAncestors(req); err != nil {
		return err
	}
	return nil
}

func validateCreateHostRequest(req *pbs.CreateHostRequest) error {
	if err := validateAncestors(req); err != nil {
		return err
	}
	return nil
}

func validateUpdateHostRequest(req *pbs.UpdateHostRequest) error {
	if err := validateAncestors(req); err != nil {
		return err
	}
	return nil
}

func validateListHostsRequest(req *pbs.ListHostsRequest) error {
	if err := validateAncestors(req); err != nil {
		return err
	}
	return nil
}

func validateDeleteHostRequest(req *pbs.DeleteHostRequest) error {
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
	return pbs.RegisterHostServiceHandlerServer(context.Background(), mux, s)
}
