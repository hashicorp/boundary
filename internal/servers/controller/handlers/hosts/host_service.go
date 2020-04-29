package hosts

import (
	"context"

	"github.com/hashicorp/watchtower/internal/gen/controller/api"
)

type Service struct {
	*api.UnimplementedHostServiceServer
}

func (s Service) ListHosts(context.Context, *api.ListHostsRequest) (*api.ListHostsResponse, error) {
	return &api.ListHostsResponse{}, nil
}

func (s Service) DeleteHost(context.Context, *api.DeleteHostRequest) (*api.DeleteHostResponse, error) {
	return &api.DeleteHostResponse{}, nil
}

var _ api.HostServiceServer = &Service{}
