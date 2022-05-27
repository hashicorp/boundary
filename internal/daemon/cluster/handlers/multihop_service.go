package handlers

import (
	"context"
	"fmt"

	pbs "github.com/hashicorp/nodeenrollment/multihop"
	"github.com/hashicorp/nodeenrollment/nodeauth"
	"github.com/hashicorp/nodeenrollment/registration"
	"github.com/hashicorp/nodeenrollment/tls"
	"github.com/hashicorp/nodeenrollment/types"
)

type multihopServiceServer struct {
	pbs.UnimplementedMultihopServiceServer

	currentParams nodeauth.CurrentParameterFactory
}

func NewMultihopServiceServer(
	currentParams nodeauth.CurrentParameterFactory,
) *multihopServiceServer {
	return &multihopServiceServer{
		currentParams: currentParams,
	}
}

var _ pbs.MultihopServiceServer = (*multihopServiceServer)(nil)

func (m *multihopServiceServer) FetchNodeCredentials(ctx context.Context, req *types.FetchNodeCredentialsRequest) (*types.FetchNodeCredentialsResponse, error) {
	const op = "workers.(multihopServiceServer).FetchNodeCredentials"
	_, storage, opt, err := m.currentParams()
	if err != nil {
		return nil, fmt.Errorf("%s: error getting current parameters: %w", op, err)
	}
	return registration.FetchNodeCredentials(ctx, storage, req, opt...)
}

func (m *multihopServiceServer) GenerateServerCertificates(ctx context.Context, req *types.GenerateServerCertificatesRequest) (*types.GenerateServerCertificatesResponse, error) {
	const op = "workers.(multihopServiceServer).GenerateServerCertificates"
	_, storage, opt, err := m.currentParams()
	if err != nil {
		return nil, fmt.Errorf("%s: error getting current parameters: %w", op, err)
	}
	return tls.GenerateServerCertificates(ctx, storage, req, opt...)
}
