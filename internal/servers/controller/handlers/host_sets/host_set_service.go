package host_sets

import (
	"context"

	"github.com/hashicorp/watchtower/internal/gen/controller/api/services"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

type Service struct {
	*services.UnimplementedHostSetServiceServer
}

func (s Service) ListHostSets(ctx context.Context, req *services.ListHostSetsRequest) (*services.ListHostSetsResponse, error) {
	return nil, status.Errorf(codes.NotFound, "Org %q not found", req.OrgId)
}

func (s Service) DeleteHostSet(context.Context, *services.DeleteHostSetRequest) (*services.DeleteHostSetResponse, error) {
	return &services.DeleteHostSetResponse{Existed: false}, nil
}

var _ services.HostSetServiceServer = &Service{}
