package session

import "errors"

// Errors returned from this package may be tested against these errors
// with errors.Is.
var (
	// ErrInvalidStateForOperation indicates the session's state does not allow the
	// operation.
	ErrInvalidStateForOperation = errors.New("state is invalid for operation")

	// ErrSessionNotPending indicates that a session cannot be activated
	// because it's not in a pending state.
	ErrSessionNotPending = errors.New("session is not in a pending state")

	// ErrOpenConnection indicates that a session can not be terminated because
	// it has open connections.
	ErrOpenConnection = errors.New("session has open connections")
)
