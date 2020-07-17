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
	return nil, status.Error(codes.Unimplemented, "Requested method is unimplemented for Hosts.")
}

func (s Service) DeleteHost(context.Context, *services.DeleteHostRequest) (*services.DeleteHostResponse, error) {
	return nil, status.Error(codes.Unimplemented, "Requested method is unimplemented for Hosts.")
}

var _ services.HostServiceServer = &Service{}
