package session

import (
	"fmt"

	"github.com/hashicorp/boundary/internal/db"
)

// ClosedWith defines the boundary data that is saved in the repo when the
// worker closes a connection between the client and the endpoint.
type ClosedWith struct {
	ConnectionId      string
	ConnectionVersion uint32
	BytesUp           uint64
	BytesDown         uint64
	ClosedReason      ClosedReason
}

func (c ClosedWith) validate() error {
	if c.ConnectionId == "" {
		return fmt.Errorf("missing connection id: %w", db.ErrInvalidParameter)
	}
	if c.ConnectionVersion == 0 {
		return fmt.Errorf("missing connection version: %w", db.ErrInvalidParameter)
	}
	if c.BytesUp == 0 {
		return fmt.Errorf("missing bytes up id: %w", db.ErrInvalidParameter)
	}
	if c.BytesDown == 0 {
		return fmt.Errorf("missing bytes down id: %w", db.ErrInvalidParameter)
	}
	if c.ClosedReason.String() == "" {
		return fmt.Errorf("missing closed reason: %w", db.ErrInvalidParameter)
	}
	return nil
}
