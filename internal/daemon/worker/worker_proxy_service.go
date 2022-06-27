package worker

import (
	"context"
	"google.golang.org/grpc"
	"sync/atomic"

	pbs "github.com/hashicorp/boundary/internal/gen/controller/servers/services"
)

type workerProxyServiceServer struct {
	pbs.UnimplementedServerCoordinationServiceServer
	pbs.UnimplementedSessionServiceServer

	scsClient *atomic.Value
	ssClient  pbs.SessionServiceClient
}

func NewWorkerProxyServiceServer(
	cc *grpc.ClientConn,
	scsClient *atomic.Value,
) *workerProxyServiceServer {
	return &workerProxyServiceServer{
		scsClient: scsClient,
		ssClient:  pbs.NewSessionServiceClient(cc),
	}
}

var (
	_ pbs.ServerCoordinationServiceServer = &workerProxyServiceServer{}
	_ pbs.SessionServiceServer            = &workerProxyServiceServer{}
)

func (ws *workerProxyServiceServer) Status(ctx context.Context, req *pbs.StatusRequest) (*pbs.StatusResponse, error) {
	resp, err := ws.scsClient.Load().(pbs.ServerCoordinationServiceClient).Status(ctx, req)

	if resp != nil {
		// We don't currently support distributing new addreses to workers
		// multiple hops away so ensure they're stripped out
		resp.CalculatedUpstreams = nil
	}

	return resp, err
}

func (ws *workerProxyServiceServer) LookupSession(ctx context.Context, req *pbs.LookupSessionRequest) (*pbs.LookupSessionResponse, error) {
	return ws.ssClient.LookupSession(ctx, req)
}

func (ws *workerProxyServiceServer) CancelSession(ctx context.Context, req *pbs.CancelSessionRequest) (*pbs.CancelSessionResponse, error) {
	return ws.ssClient.CancelSession(ctx, req)
}

func (ws *workerProxyServiceServer) ActivateSession(ctx context.Context, req *pbs.ActivateSessionRequest) (*pbs.ActivateSessionResponse, error) {
	return ws.ssClient.ActivateSession(ctx, req)
}

func (ws *workerProxyServiceServer) AuthorizeConnection(ctx context.Context, req *pbs.AuthorizeConnectionRequest) (*pbs.AuthorizeConnectionResponse, error) {
	return ws.ssClient.AuthorizeConnection(ctx, req)
}

func (ws *workerProxyServiceServer) ConnectConnection(ctx context.Context, req *pbs.ConnectConnectionRequest) (*pbs.ConnectConnectionResponse, error) {
	return ws.ssClient.ConnectConnection(ctx, req)
}

func (ws *workerProxyServiceServer) CloseConnection(ctx context.Context, req *pbs.CloseConnectionRequest) (*pbs.CloseConnectionResponse, error) {
	return ws.ssClient.CloseConnection(ctx, req)
}
