package password

import "errors"

var (
	// ErrTooShort is returned when a new password is to short.
	ErrTooShort = errors.New("password to short")
)
