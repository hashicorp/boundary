package session

import (
	"fmt"

	"github.com/hashicorp/boundary/internal/db"
)

// TerminationReason of the session
type TerminationReason string

const (
	UnknownTermination TerminationReason = "unknown"
	TimedOut           TerminationReason = "timed out"
	ClosedByUser       TerminationReason = "closed by end-user"
	Terminated         TerminationReason = "terminated"
	NetworkError       TerminationReason = "network error"
	SystemError        TerminationReason = "system error"
)

// String representation of the termination reason
func (r TerminationReason) String() string {
	return string(r)
}
func convertToReason(s string) (TerminationReason, error) {
	switch s {
	case UnknownTermination.String():
		return UnknownTermination, nil
	case TimedOut.String():
		return TimedOut, nil
	case ClosedByUser.String():
		return ClosedByUser, nil
	case Terminated.String():
		return Terminated, nil
	case NetworkError.String():
		return NetworkError, nil
	case SystemError.String():
		return SystemError, nil
	default:
		return "", fmt.Errorf("termination reason: %s is not a valid reason: %w", s, db.ErrInvalidParameter)
	}
}
