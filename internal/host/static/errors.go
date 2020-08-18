package static

import "errors"

var (
	// ErrInvalidAddress results from attempting to perform an operation
	// that sets an address on a host to an invalid value.
	ErrInvalidAddress = errors.New("invalid address")
)
