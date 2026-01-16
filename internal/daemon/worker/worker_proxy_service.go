// Copyright IBM Corp. 2020, 2025
// SPDX-License-Identifier: BUSL-1.1

package worker

import (
	"context"

	pbs "github.com/hashicorp/boundary/internal/gen/controller/servers/services"
	"google.golang.org/grpc"
)

type workerProxyServiceServer struct {
	pbs.UnsafeServerCoordinationServiceServer
	pbs.UnsafeSessionServiceServer

	cc *grpc.ClientConn
}

var (
	_ pbs.ServerCoordinationServiceServer = (*workerProxyServiceServer)(nil)
	_ pbs.SessionServiceServer            = (*workerProxyServiceServer)(nil)
)

func NewWorkerProxyServiceServer(
	cc *grpc.ClientConn,
) *workerProxyServiceServer {
	return &workerProxyServiceServer{
		cc: cc,
	}
}

func (ws *workerProxyServiceServer) Statistics(ctx context.Context, req *pbs.StatisticsRequest) (*pbs.StatisticsResponse, error) {
	return pbs.NewServerCoordinationServiceClient(ws.cc).Statistics(ctx, req)
}

func (ws *workerProxyServiceServer) SessionInfo(ctx context.Context, req *pbs.SessionInfoRequest) (*pbs.SessionInfoResponse, error) {
	return pbs.NewServerCoordinationServiceClient(ws.cc).SessionInfo(ctx, req)
}

func (ws *workerProxyServiceServer) Status(ctx context.Context, req *pbs.StatusRequest) (*pbs.StatusResponse, error) {
	resp, err := pbs.NewServerCoordinationServiceClient(ws.cc).Status(ctx, req)

	if resp != nil {
		// We don't currently support distributing new addreses to workers
		// multiple hops away so ensure they're stripped out
		resp.CalculatedUpstreams = nil
	}

	return resp, err
}

func (ws *workerProxyServiceServer) ListHcpbWorkers(ctx context.Context, req *pbs.ListHcpbWorkersRequest) (*pbs.ListHcpbWorkersResponse, error) {
	return pbs.NewServerCoordinationServiceClient(ws.cc).ListHcpbWorkers(ctx, req)
}

func (ws *workerProxyServiceServer) RoutingInfo(ctx context.Context, req *pbs.RoutingInfoRequest) (*pbs.RoutingInfoResponse, error) {
	resp, err := pbs.NewServerCoordinationServiceClient(ws.cc).RoutingInfo(ctx, req)

	if resp != nil {
		// We don't currently support distributing new addreses to workers
		// multiple hops away so ensure they're stripped out
		resp.CalculatedUpstreamAddresses = nil
	}

	return resp, err
}

func (ws *workerProxyServiceServer) LookupSession(ctx context.Context, req *pbs.LookupSessionRequest) (*pbs.LookupSessionResponse, error) {
	return pbs.NewSessionServiceClient(ws.cc).LookupSession(ctx, req)
}

func (ws *workerProxyServiceServer) CancelSession(ctx context.Context, req *pbs.CancelSessionRequest) (*pbs.CancelSessionResponse, error) {
	return pbs.NewSessionServiceClient(ws.cc).CancelSession(ctx, req)
}

func (ws *workerProxyServiceServer) ActivateSession(ctx context.Context, req *pbs.ActivateSessionRequest) (*pbs.ActivateSessionResponse, error) {
	return pbs.NewSessionServiceClient(ws.cc).ActivateSession(ctx, req)
}

func (ws *workerProxyServiceServer) AuthorizeConnection(ctx context.Context, req *pbs.AuthorizeConnectionRequest) (*pbs.AuthorizeConnectionResponse, error) {
	return pbs.NewSessionServiceClient(ws.cc).AuthorizeConnection(ctx, req)
}

func (ws *workerProxyServiceServer) ConnectConnection(ctx context.Context, req *pbs.ConnectConnectionRequest) (*pbs.ConnectConnectionResponse, error) {
	return pbs.NewSessionServiceClient(ws.cc).ConnectConnection(ctx, req)
}

func (ws *workerProxyServiceServer) CloseConnection(ctx context.Context, req *pbs.CloseConnectionRequest) (*pbs.CloseConnectionResponse, error) {
	return pbs.NewSessionServiceClient(ws.cc).CloseConnection(ctx, req)
}
