package host_catalogs

import (
	"context"

	"github.com/hashicorp/watchtower/internal/gen/controller/api"
)

type Service struct {
	*api.UnimplementedHostCatalogServiceServer
}

func (s Service) ListHostCatalogs(context.Context, *api.ListHostCatalogsRequest) (*api.ListHostCatalogsResponse, error) {
	return &api.ListHostCatalogsResponse{}, nil
}

func (s Service) DeleteHostCatalog(context.Context, *api.DeleteHostCatalogRequest) (*api.DeleteHostCatalogResponse, error) {
	return &api.DeleteHostCatalogResponse{Existed: false}, nil
}

var _ api.HostCatalogServiceServer = &Service{}
