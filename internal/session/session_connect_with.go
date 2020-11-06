package session

import (
	"fmt"

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
	if c.ConnectionId == "" {
		return fmt.Errorf("missing session id: %w", errors.ErrInvalidParameter)
	}
	if c.ClientTcpAddress == "" {
		return fmt.Errorf("missing client tcp address: %w", errors.ErrInvalidParameter)
	}
	if c.ClientTcpPort == 0 {
		return fmt.Errorf("missing client ctp port: %w", errors.ErrInvalidParameter)
	}
	if c.EndpointTcpAddress == "" {
		return fmt.Errorf("missing endpoint tcp address: %w", errors.ErrInvalidParameter)
	}
	if c.EndpointTcpPort == 0 {
		return fmt.Errorf("missing endpoint ctp port: %w", errors.ErrInvalidParameter)
	}
	return nil
}
