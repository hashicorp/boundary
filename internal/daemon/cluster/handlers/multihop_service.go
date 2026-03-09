// Copyright IBM Corp. 2020, 2025
// SPDX-License-Identifier: BUSL-1.1

package handlers

import (
	"context"
	"errors"
	"fmt"
	"sync/atomic"

	"github.com/hashicorp/nodeenrollment"
	"github.com/hashicorp/nodeenrollment/multihop"
	"github.com/hashicorp/nodeenrollment/registration"
	"github.com/hashicorp/nodeenrollment/rotation"
	"github.com/hashicorp/nodeenrollment/tls"
	"github.com/hashicorp/nodeenrollment/types"
	"github.com/hashicorp/nodeenrollment/util/temperror"
)

type multihopServiceServer struct {
	multihop.UnsafeMultihopServiceServer

	storage nodeenrollment.Storage
	direct  bool
	client  *atomic.Value
	options []nodeenrollment.Option
}

var _ multihop.MultihopServiceServer = (*multihopServiceServer)(nil)

// NewMultihopServiceServer creates a new service implementing
// MultihopServiceServer, storing values used for the implementing functions.
func NewMultihopServiceServer(storage nodeenrollment.Storage, direct bool, client *atomic.Value, opt ...nodeenrollment.Option) (*multihopServiceServer, error) {
	const op = "cluster.handlers.NewMultihopServiceServer"

	switch {
	case direct && nodeenrollment.IsNil(storage):
		return nil, fmt.Errorf("%s: running on controller and nil storage provided", op)
	case !direct && client == nil:
		return nil, fmt.Errorf("%s: running on worker and nil client provided", op)
	}

	return &multihopServiceServer{
		storage: storage,
		direct:  direct,
		client:  client,
		options: opt,
	}, nil
}

// FetchNodeCredentials implements the MultihopServiceServer interface. If it's
// direct (e.g. running on a controller) it handles the request directly,
// otherwise sends it to its next hop.
func (m *multihopServiceServer) FetchNodeCredentials(ctx context.Context, req *types.FetchNodeCredentialsRequest) (*types.FetchNodeCredentialsResponse, error) {
	const op = "cluster.handlers.(multihopServiceServer).FetchNodeCredentials"
	switch m.direct {
	case true:
		return registration.FetchNodeCredentials(ctx, m.storage, req, m.options...)

	default:
		client := m.client.Load()
		if client == nil {
			return nil, fmt.Errorf("%s: error fetching multihop connection, client is nil", op)
		}
		multihopClient, ok := client.(multihop.MultihopServiceClient)
		if !ok {
			return nil, temperror.New(errors.New("client could not be understood as a multihop service client"))
		}
		return multihopClient.FetchNodeCredentials(ctx, req)
	}
}

// GenerateServerCertificates implements the MultihopServiceServer interface. If
// it's direct (e.g. running on a controller) it handles the request directly,
// otherwise sends it to its next hop.
func (m *multihopServiceServer) GenerateServerCertificates(ctx context.Context, req *types.GenerateServerCertificatesRequest) (*types.GenerateServerCertificatesResponse, error) {
	const op = "cluster.handlers.(multihopServiceServer).GenerateServerCertificates"
	switch m.direct {
	case true:
		return tls.GenerateServerCertificates(ctx, m.storage, req, m.options...)

	default:
		client := m.client.Load()
		if client == nil {
			return nil, fmt.Errorf("%s: error fetching multihop connection, client is nil", op)
		}
		multihopClient, ok := client.(multihop.MultihopServiceClient)
		if !ok {
			return nil, temperror.New(errors.New("client could not be understood as a multihop service client"))
		}
		return multihopClient.GenerateServerCertificates(ctx, req)
	}
}

// RotateNodeCredentials implements the MultihopServiceServer interface. If it's
// direct (e.g. running on a controller) it handles the request directly,
// otherwise sends it to its next hop.
func (m *multihopServiceServer) RotateNodeCredentials(ctx context.Context, req *types.RotateNodeCredentialsRequest) (*types.RotateNodeCredentialsResponse, error) {
	const op = "cluster.handlers.(multihopServiceServer).RotateNodeCredentials"
	switch m.direct {
	case true:
		return rotation.RotateNodeCredentials(ctx, m.storage, req, m.options...)

	default:
		client := m.client.Load()
		if client == nil {
			return nil, fmt.Errorf("%s: error fetching multihop connection, client is nil", op)
		}
		multihopClient, ok := client.(multihop.MultihopServiceClient)
		if !ok {
			return nil, temperror.New(errors.New("client could not be understood as a multihop service client"))
		}
		return multihopClient.RotateNodeCredentials(ctx, req)
	}
}
