// Copyright IBM Corp. 2020, 2025
// SPDX-License-Identifier: BUSL-1.1

package handlers

import (
	"context"
	"net"
	"sync"
	"testing"

	pbs "github.com/hashicorp/boundary/internal/gen/controller/servers/services"
	"github.com/hashicorp/nodeenrollment"
	"github.com/hashicorp/nodeenrollment/registration"
	"github.com/hashicorp/nodeenrollment/rotation"
	nodeefile "github.com/hashicorp/nodeenrollment/storage/file"
	"github.com/hashicorp/nodeenrollment/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/test/bufconn"
	"google.golang.org/protobuf/proto"
)

// TestUpstreamService starts a controller with a downstream worker, which are
// tore down at the end of the test.
//
// Returns a UpstreamMessageServiceClientProducer for the worker, the worker's
// NodeInformation and the worker's KeyId.
func TestUpstreamService(t *testing.T) (UpstreamMessageServiceClientProducer, *types.NodeInformation, string) {
	t.Helper()
	testCtx := context.Background()

	// Get an initial set of authorized node credentials for the worker that's
	// sending upstream requests
	initStorage, err := nodeefile.New(testCtx)
	require.NoError(t, err)
	t.Cleanup(func() {
		assert.NoError(t, initStorage.Cleanup(testCtx))
	})
	_, err = rotation.RotateRootCertificates(testCtx, initStorage)
	require.NoError(t, err)
	initNodeCreds, err := types.NewNodeCredentials(testCtx, initStorage)
	require.NoError(t, err)
	req, err := initNodeCreds.CreateFetchNodeCredentialsRequest(testCtx)
	require.NoError(t, err)
	_, err = registration.AuthorizeNode(testCtx, initStorage, req)
	require.NoError(t, err)
	fetchResp, err := registration.FetchNodeCredentials(testCtx, initStorage, req)
	require.NoError(t, err)
	initNodeCreds, err = initNodeCreds.HandleFetchNodeCredentialsResponse(testCtx, initStorage, fetchResp)
	require.NoError(t, err)
	initKeyId, err := nodeenrollment.KeyIdFromPkix(initNodeCreds.CertificatePublicKeyPkix)
	require.NoError(t, err)

	nodeInfo, err := types.LoadNodeInformation(testCtx, initStorage, initKeyId)
	require.NoError(t, err)

	// start an upstream controller
	testController, err := NewControllerUpstreamMessageServiceServer(testCtx, initStorage)
	require.NoError(t, err)
	require.NotNil(t, testController)

	controllerClient := pbs.NewUpstreamMessageServiceClient(grpcCCToServer(t, testCtx, testController))
	controllerClientProducer := func(context.Context) (pbs.UpstreamMessageServiceClient, error) {
		return controllerClient, nil
	}

	// start an upstream worker
	testWorker, err := NewWorkerUpstreamMessageServiceServer(testCtx, controllerClientProducer)
	require.NoError(t, err)
	workerConn := grpcCCToServer(t, testCtx, testWorker)
	workerClient := pbs.NewUpstreamMessageServiceClient(workerConn)

	workerClientProducer := func(context.Context) (pbs.UpstreamMessageServiceClient, error) {
		return workerClient, nil
	}

	return workerClientProducer, nodeInfo, initKeyId
}

// TestRegisterHandlerFn returns a func that will register a handler for the
// test and then unregister it when the test is complete.  This should not be
// used with t.Parallel() since it modifies the registered handlers for the pkg.
func TestRegisterHandlerFn(t *testing.T, msgType pbs.MsgType, h UpstreamMessageHandler) func(*testing.T) {
	return func(t *testing.T) {
		t.Helper()
		testCtx := context.Background()
		cpHandlerRegistry := new(sync.Map)
		upstreamMessageHandler.Range(func(k, v interface{}) bool {
			cpHandlerRegistry.Store(k, v)
			return true
		})
		cpTypeSpecifierRegister := new(sync.Map)
		upstreamMessageTypeSpecifier.Range(func(k, v interface{}) bool {
			cpTypeSpecifierRegister.Store(k, v)
			return true
		})

		require.NoError(t, RegisterUpstreamMessageHandler(testCtx, msgType, h))
		t.Cleanup(func() {
			upstreamMessageHandler = cpHandlerRegistry
			upstreamMessageTypeSpecifier = cpTypeSpecifierRegister
		})
	}
}

// TestMockUpstreamMessageHandler provides a test mock handler
type TestMockUpstreamMessageHandler struct {
	WantHandlerErr error
	WantResp       proto.Message
}

// Handler implements the handler for the mock
func (h *TestMockUpstreamMessageHandler) Handler(ctx context.Context, request proto.Message) (proto.Message, error) {
	switch {
	case h.WantHandlerErr != nil:
		return nil, h.WantHandlerErr
	case h.WantResp != nil:
		return h.WantResp, nil
	default:
		return &pbs.EchoUpstreamMessageRequest{
			Msg: request.(*pbs.EchoUpstreamMessageRequest).Msg,
		}, nil
	}
}

// Encrypted returns false; since the handler's request/response must be
// encrypted.
func (*TestMockUpstreamMessageHandler) Encrypted() bool { return false }

// AllocRequest returns an allocated proto for the handler's request.
func (*TestMockUpstreamMessageHandler) AllocRequest() proto.Message {
	return new(pbs.EchoUpstreamMessageRequest)
}

// AllocResponse returns an allocated proto for the handler's response.
func (*TestMockUpstreamMessageHandler) AllocResponse() proto.Message {
	return new(pbs.EchoUpstreamMessageResponse)
}

// TestMockEncryptedUpstreamMessageHandler provides a test mock handler
type TestMockEncryptedUpstreamMessageHandler struct {
	WantHandlerErr error
	WantResp       proto.Message
}

// Handler implements the handler for the mock
func (h *TestMockEncryptedUpstreamMessageHandler) Handler(ctx context.Context, request proto.Message) (proto.Message, error) {
	switch {
	case h.WantHandlerErr != nil:
		return nil, h.WantHandlerErr
	case h.WantResp != nil:
		return h.WantResp, nil
	default:
		return &pbs.EchoUpstreamMessageRequest{
			Msg: request.(*pbs.EchoUpstreamMessageRequest).Msg,
		}, nil
	}
}

// Encrypted returns true; since the handler's request/response must be
// encrypted.
func (*TestMockEncryptedUpstreamMessageHandler) Encrypted() bool { return true }

// AllocRequest returns an allocated proto for the handler's request.
func (*TestMockEncryptedUpstreamMessageHandler) AllocRequest() proto.Message {
	return new(pbs.EchoUpstreamMessageRequest)
}

// AllocResponse returns an allocated proto for the handler's response.
func (*TestMockEncryptedUpstreamMessageHandler) AllocResponse() proto.Message {
	return new(pbs.EchoUpstreamMessageResponse)
}

// grpcCCToServer starts a grpc service that is cleaned up after the test and
// returns a client connection to that service.
func grpcCCToServer(t *testing.T, ctx context.Context, srv pbs.UpstreamMessageServiceServer) *grpc.ClientConn {
	t.Helper()
	require := require.New(t)

	buffer := 1024 * 1024
	listener := bufconn.Listen(buffer)

	s := grpc.NewServer()
	pbs.RegisterUpstreamMessageServiceServer(s, srv)

	go func() {
		if err := s.Serve(listener); err != nil {
			require.NoError(err)
		}
	}()

	conn, err := grpc.DialContext(ctx, "", grpc.WithContextDialer(func(context.Context, string) (net.Conn, error) {
		return listener.Dial()
	}), grpc.WithTransportCredentials(insecure.NewCredentials()), grpc.WithBlock())
	require.NoError(err)

	t.Cleanup(func() { s.Stop() })
	return conn
}
