package host_sets

import (
	"context"

	"github.com/hashicorp/watchtower/internal/gen/controller/api"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

type Service struct {
	*api.UnimplementedHostSetServiceServer
}

func (s Service) ListHostSets(ctx context.Context, req *api.ListHostSetsRequest) (*api.ListHostSetsResponse, error) {
	return nil, status.Errorf(codes.NotFound, "Org %q not found", req.OrgId)
}

func (s Service) DeleteHostSet(context.Context, *api.DeleteHostSetRequest) (*api.DeleteHostSetResponse, error) {
	return &api.DeleteHostSetResponse{Existed: false}, nil
}

var _ api.HostSetServiceServer = &Service{}
