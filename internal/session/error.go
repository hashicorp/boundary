package session

import "errors"

// Errors returned from this package may be tested against these errors
// with errors.Is.
var (
	// ErrInvalidStateForOperation indicates the session's state does not allow the
	// operation.
	ErrInvalidStateForOperation = errors.New("state is invalid for operation")
)
