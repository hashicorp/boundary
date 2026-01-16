// Copyright IBM Corp. 2020, 2025
// SPDX-License-Identifier: BUSL-1.1

package session

import (
	"context"

	"github.com/hashicorp/boundary/internal/errors"
)

// ConnectWith defines the boundary data that is saved in the repo when the
// worker has established a connection between the client and the endpoint.
type ConnectWith struct {
	ConnectionId       string
	ClientTcpAddress   string
	ClientTcpPort      uint32
	EndpointTcpAddress string
	EndpointTcpPort    uint32
	UserClientIp       string
}

func (c ConnectWith) validate(ctx context.Context) error {
	const op = "session.(ConnectWith).validate"
	if c.ConnectionId == "" {
		return errors.New(ctx, errors.InvalidParameter, op, "missing session id")
	}
	if c.ClientTcpAddress == "" {
		return errors.New(ctx, errors.InvalidParameter, op, "missing client tcp address")
	}
	if c.ClientTcpPort == 0 {
		return errors.New(ctx, errors.InvalidParameter, op, "missing client ctp port")
	}
	if c.EndpointTcpAddress == "" {
		return errors.New(ctx, errors.InvalidParameter, op, "missing endpoint tcp address")
	}
	if c.EndpointTcpPort == 0 {
		return errors.New(ctx, errors.InvalidParameter, op, "missing endpoint ctp port")
	}
	if c.UserClientIp == "" {
		return errors.New(ctx, errors.InvalidParameter, op, "missing user client ip")
	}
	return nil
}
