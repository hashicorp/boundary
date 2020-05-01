package hosts

import (
	"context"

	"github.com/hashicorp/watchtower/internal/gen/controller/api"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

type Service struct {
	*api.UnimplementedHostServiceServer
}

func (s Service) ListHosts(ctx context.Context, req *api.ListHostsRequest) (*api.ListHostsResponse, error) {
	return nil, status.Errorf(codes.NotFound, "Org %q not found", req.OrgId)
}

func (s Service) DeleteHost(context.Context, *api.DeleteHostRequest) (*api.DeleteHostResponse, error) {
	return &api.DeleteHostResponse{}, nil
}

var _ api.HostServiceServer = &Service{}
