package session

import (
	"fmt"

	"github.com/hashicorp/boundary/internal/db"
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
		return fmt.Errorf("missing session id: %w", db.ErrInvalidParameter)
	}
	if c.ClientTcpAddress == "" {
		return fmt.Errorf("missing client tcp address: %w", db.ErrInvalidParameter)
	}
	if c.ClientTcpPort == 0 {
		return fmt.Errorf("missing client ctp port: %w", db.ErrInvalidParameter)
	}
	if c.EndpointTcpAddress == "" {
		return fmt.Errorf("missing endpoint tcp address: %w", db.ErrInvalidParameter)
	}
	if c.EndpointTcpPort == 0 {
		return fmt.Errorf("missing endpoint ctp port: %w", db.ErrInvalidParameter)
	}
	return nil
}
