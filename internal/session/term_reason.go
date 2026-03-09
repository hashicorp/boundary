// Copyright IBM Corp. 2020, 2025
// SPDX-License-Identifier: BUSL-1.1

package session

import (
	"context"
	"fmt"

	"github.com/hashicorp/boundary/internal/errors"
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
	ConnectionLimit    TerminationReason = "connection limit"
	SessionCanceled    TerminationReason = "canceled"
)

// String representation of the termination reason
func (r TerminationReason) String() string {
	return string(r)
}

func convertToReason(ctx context.Context, s string) (TerminationReason, error) {
	const op = "session.convertToReason"
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
	case ConnectionLimit.String():
		return ConnectionLimit, nil
	default:
		return "", errors.New(ctx, errors.InvalidParameter, op, fmt.Sprintf("%s is not a valid reason", s))
	}
}
