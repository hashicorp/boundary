package session

import (
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
	const op = "session.(CloseWith).validate"
	if c.ConnectionId == "" {
		return errors.NewDeprecated(errors.InvalidParameter, op, "missing connection id")
	}
	if c.ClosedReason.String() == "" {
		return errors.NewDeprecated(errors.InvalidParameter, op, "missing closed reason")
	}
	// 0 is valid for BytesUp and BytesDown
	return nil
}
