package session

import (
	"fmt"

	"github.com/hashicorp/boundary/internal/errors"
)

// CloseWith defines the boundary data that is saved in the repo when the
// worker closes a connection between the client and the endpoint.
type CloseWith struct {
	ConnectionId string
	BytesUp      uint64
	BytesDown    uint64
	ClosedReason ClosedReason
}

func (c CloseWith) validate() error {
	if c.ConnectionId == "" {
		return fmt.Errorf("missing connection id: %w", errors.ErrInvalidParameter)
	}
	if c.ClosedReason.String() == "" {
		return fmt.Errorf("missing closed reason: %w", errors.ErrInvalidParameter)
	}
	// 0 is valid for BytesUp and BytesDown
	return nil
}
