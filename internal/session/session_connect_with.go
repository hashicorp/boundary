package session

import (
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
}

func (c ConnectWith) validate() error {
	const op = "session.(ConnectWith).validate"
	if c.ConnectionId == "" {
		return errors.NewDeprecated(errors.InvalidParameter, op, "missing session id")
	}
	if c.ClientTcpAddress == "" {
		return errors.NewDeprecated(errors.InvalidParameter, op, "missing client tcp address")
	}
	if c.ClientTcpPort == 0 {
		return errors.NewDeprecated(errors.InvalidParameter, op, "missing client ctp port")
	}
	if c.EndpointTcpAddress == "" {
		return errors.NewDeprecated(errors.InvalidParameter, op, "missing endpoint tcp address")
	}
	if c.EndpointTcpPort == 0 {
		return errors.NewDeprecated(errors.InvalidParameter, op, "missing endpoint ctp port")
	}
	return nil
}
