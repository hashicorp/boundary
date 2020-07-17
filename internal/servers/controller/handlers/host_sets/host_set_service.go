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
	return nil, status.Error(codes.Unimplemented, "Requested method is unimplemented for Host Sets.")
}

func (s Service) DeleteHostSet(context.Context, *services.DeleteHostSetRequest) (*services.DeleteHostSetResponse, error) {
	return nil, status.Error(codes.Unimplemented, "Requested method is unimplemented for Host Sets.")
}

var _ services.HostSetServiceServer = &Service{}
