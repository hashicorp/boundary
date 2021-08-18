package services

import (
	"context"

	"google.golang.org/grpc"
)

// TODO (lcr 08/2021): implement mockSessionServiceClient outside of primitive support for
// ConnectConnection
type mockSessionServiceClient struct{}

func NewMockSessionServiceClient() SessionServiceClient {
	return &mockSessionServiceClient{}
}

func (c *mockSessionServiceClient) LookupSession(_ context.Context, _ *LookupSessionRequest, _ ...grpc.CallOption) (*LookupSessionResponse, error) {
	panic("not implemented")
}

func (c *mockSessionServiceClient) ActivateSession(_ context.Context, _ *ActivateSessionRequest, _ ...grpc.CallOption) (*ActivateSessionResponse, error) {
	panic("not implemented")
}

func (c *mockSessionServiceClient) CancelSession(_ context.Context, _ *CancelSessionRequest, _ ...grpc.CallOption) (*CancelSessionResponse, error) {
	panic("not implemented")
}

func (c *mockSessionServiceClient) AuthorizeConnection(_ context.Context, _ *AuthorizeConnectionRequest, _ ...grpc.CallOption) (*AuthorizeConnectionResponse, error) {
	panic("not implemented")
}

func (c *mockSessionServiceClient) ConnectConnection(_ context.Context, _ *ConnectConnectionRequest, _ ...grpc.CallOption) (*ConnectConnectionResponse, error) {
	return &ConnectConnectionResponse{
		Status: CONNECTIONSTATUS_CONNECTIONSTATUS_CONNECTED,
	}, nil
}

func (c *mockSessionServiceClient) CloseConnection(_ context.Context, _ *CloseConnectionRequest, _ ...grpc.CallOption) (*CloseConnectionResponse, error) {
	panic("not implemented")
}
