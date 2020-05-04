package host_catalogs

import (
	"context"

	"github.com/hashicorp/watchtower/internal/gen/controller/api/services"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

type Service struct {
	*services.UnimplementedHostCatalogServiceServer
}

func (s Service) ListHostCatalogs(ctx context.Context, req *services.ListHostCatalogsRequest) (*services.ListHostCatalogsResponse, error) {
	return nil, status.Errorf(codes.NotFound, "Org %q not found", req.OrgId)
}

func (s Service) DeleteHostCatalog(ctx context.Context, req *services.DeleteHostCatalogRequest) (*services.DeleteHostCatalogResponse, error) {
	return &services.DeleteHostCatalogResponse{Existed: false}, nil
}

var _ services.HostCatalogServiceServer = &Service{}
