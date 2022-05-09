package workers

import (
	"context"
	"fmt"

	pbs "github.com/hashicorp/nodeenrollment/multihop"
	"github.com/hashicorp/nodeenrollment/nodeauth"
	"github.com/hashicorp/nodeenrollment/noderegistration"
	"github.com/hashicorp/nodeenrollment/nodetls"
	"github.com/hashicorp/nodeenrollment/nodetypes"
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

func (m *multihopServiceServer) FetchNodeCredentials(ctx context.Context, req *nodetypes.FetchNodeCredentialsRequest) (*nodetypes.FetchNodeCredentialsResponse, error) {
	const op = "workers.(multihopServiceServer).FetchNodeCredentials"
	_, storage, opt, err := m.currentParams()
	if err != nil {
		return nil, fmt.Errorf("%s: error getting current parameters: %w", op, err)
	}
	return noderegistration.FetchNodeCredentials(ctx, storage, req, opt...)
}

func (m *multihopServiceServer) GenerateServerCertificates(ctx context.Context, req *nodetypes.GenerateServerCertificatesRequest) (*nodetypes.GenerateServerCertificatesResponse, error) {
	const op = "workers.(multihopServiceServer).GenerateServerCertificates"
	_, storage, opt, err := m.currentParams()
	if err != nil {
		return nil, fmt.Errorf("%s: error getting current parameters: %w", op, err)
	}
	return nodetls.GenerateServerCertificates(ctx, storage, req, opt...)
}
