package hosts

import (
	"context"

	"github.com/hashicorp/watchtower/internal/gen/controller/api/services"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

type Service struct {
	*services.UnimplementedHostServiceServer
}

func (s Service) ListHosts(ctx context.Context, req *services.ListHostsRequest) (*services.ListHostsResponse, error) {
	return nil, status.Errorf(codes.NotFound, "Org %q not found", req.OrgId)
}

func (s Service) DeleteHost(context.Context, *services.DeleteHostRequest) (*services.DeleteHostResponse, error) {
	return &services.DeleteHostResponse{}, nil
}

var _ services.HostServiceServer = &Service{}
