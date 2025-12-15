// Copyright IBM Corp. 2020, 2025
// SPDX-License-Identifier: BUSL-1.1

package services

import (
	"context"

	"google.golang.org/grpc"
)

type mockSessionServiceClient struct {
	LookupSessionFn       func(context.Context, *LookupSessionRequest) (*LookupSessionResponse, error)
	ActivateSessionFn     func(context.Context, *ActivateSessionRequest) (*ActivateSessionResponse, error)
	CancelSessionFn       func(context.Context, *CancelSessionRequest) (*CancelSessionResponse, error)
	AuthorizeConnectionFn func(context.Context, *AuthorizeConnectionRequest) (*AuthorizeConnectionResponse, error)
	ConnectConnectionFn   func(context.Context, *ConnectConnectionRequest) (*ConnectConnectionResponse, error)
	CloseConnectionFn     func(context.Context, *CloseConnectionRequest) (*CloseConnectionResponse, error)
}

// NewMockSessionServiceClient returns a mock SessionServiceClient which allows
// the mocking out specific calls to a SessionService by assigning values to
// the respective mock client member variables.
func NewMockSessionServiceClient() *mockSessionServiceClient {
	return &mockSessionServiceClient{}
}

func (c *mockSessionServiceClient) LookupSession(ctx context.Context, req *LookupSessionRequest, _ ...grpc.CallOption) (*LookupSessionResponse, error) {
	if c.LookupSessionFn != nil {
		return c.LookupSessionFn(ctx, req)
	}
	panic("not implemented")
}

func (c *mockSessionServiceClient) ActivateSession(ctx context.Context, req *ActivateSessionRequest, _ ...grpc.CallOption) (*ActivateSessionResponse, error) {
	if c.ActivateSessionFn != nil {
		return c.ActivateSessionFn(ctx, req)
	}
	panic("not implemented")
}

func (c *mockSessionServiceClient) CancelSession(ctx context.Context, req *CancelSessionRequest, _ ...grpc.CallOption) (*CancelSessionResponse, error) {
	if c.CancelSessionFn != nil {
		return c.CancelSessionFn(ctx, req)
	}
	panic("not implemented")
}

func (c *mockSessionServiceClient) AuthorizeConnection(ctx context.Context, req *AuthorizeConnectionRequest, _ ...grpc.CallOption) (*AuthorizeConnectionResponse, error) {
	if c.AuthorizeConnectionFn != nil {
		return c.AuthorizeConnectionFn(ctx, req)
	}
	panic("not implemented")
}

func (c *mockSessionServiceClient) ConnectConnection(ctx context.Context, req *ConnectConnectionRequest, _ ...grpc.CallOption) (*ConnectConnectionResponse, error) {
	if c.ConnectConnectionFn != nil {
		return c.ConnectConnectionFn(ctx, req)
	}
	panic("not implemented")
}

func (c *mockSessionServiceClient) CloseConnection(ctx context.Context, req *CloseConnectionRequest, _ ...grpc.CallOption) (*CloseConnectionResponse, error) {
	if c.CloseConnectionFn != nil {
		return c.CloseConnectionFn(ctx, req)
	}
	panic("not implemented")
}
