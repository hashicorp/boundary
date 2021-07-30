package session

import (
	"fmt"

	"github.com/hashicorp/boundary/internal/errors"
)

// ClosedReason of the connection
type ClosedReason string

const (
	UnknownReason          ClosedReason = "unknown"
	ConnectionTimedOut     ClosedReason = "timed out"
	ConnectionClosedByUser ClosedReason = "closed by end-user"
	ConnectionCanceled     ClosedReason = "canceled"
	ConnectionNetworkError ClosedReason = "network error"
	ConnectionSystemError  ClosedReason = "system error"
)

// String representation of the termination reason
func (r ClosedReason) String() string {
	return string(r)
}

func convertToClosedReason(s string) (ClosedReason, error) {
	const op = "session.convertToClosedReason"
	switch s {
	case UnknownReason.String():
		return UnknownReason, nil
	case ConnectionTimedOut.String():
		return ConnectionTimedOut, nil
	case ConnectionClosedByUser.String():
		return ConnectionClosedByUser, nil
	case ConnectionCanceled.String():
		return ConnectionCanceled, nil
	case ConnectionNetworkError.String():
		return ConnectionNetworkError, nil
	case ConnectionSystemError.String():
		return ConnectionSystemError, nil
	default:
		return "", errors.NewDeprecated(errors.InvalidParameter, op, fmt.Sprintf("%s is not a valid reason", s))
	}
}
