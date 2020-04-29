package host_sets

import (
	"context"

	"github.com/hashicorp/watchtower/internal/gen/controller/api"
)

type Service struct {
	*api.UnimplementedHostSetServiceServer
}

func (s Service) ListHostSets(context.Context, *api.ListHostSetsRequest) (*api.ListHostSetsResponse, error) {
	return &api.ListHostSetsResponse{}, nil
}

func (s Service) DeleteHostSet(context.Context, *api.DeleteHostSetRequest) (*api.DeleteHostSetResponse, error) {
	return &api.DeleteHostSetResponse{Existed: false}, nil
}

var _ api.HostSetServiceServer = &Service{}
