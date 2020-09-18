package session

import "errors"

// Errors returned from this package may be tested against these errors
// with errors.Is.
var (
	// ErrCancelledOrTerminatedSession indicates a connection cannot be made
	// because the session has been cancelled or terminated.
	ErrCancelledOrTerminatedSession = errors.New("session has been cancelled or terminated")

	// ErrSessionNotPending indicates that a session cannot be activated
	// because it's not in a pending state.
	ErrSessionNotPending = errors.New("session is not in a pending state")

	// ErrOpenConnection indicates that a session can not be terminated because
	// it has open connections.
	ErrOpenConnection = errors.New("session has open connections")
)
