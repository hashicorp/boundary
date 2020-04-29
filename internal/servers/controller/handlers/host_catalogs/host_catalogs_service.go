package host_catalogs

import (
	"context"

	"github.com/hashicorp/watchtower/internal/gen/controller/api"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

type Service struct {
	*api.UnimplementedHostCatalogServiceServer
}

func (s Service) ListHostCatalogs(ctx context.Context, req *api.ListHostCatalogsRequest) (*api.ListHostCatalogsResponse, error) {
	return nil, status.Errorf(codes.NotFound, "Org %q not found", req.OrgId)
}

func (s Service) DeleteHostCatalog(ctx context.Context, req *api.DeleteHostCatalogRequest) (*api.DeleteHostCatalogResponse, error) {
	return &api.DeleteHostCatalogResponse{Existed: false}, nil
}

var _ api.HostCatalogServiceServer = &Service{}
