package password

import "github.com/hashicorp/boundary/internal/errors"

// TODO: remove these errors once all code has been refactored to creating inline domain errors
var (
	// ErrTooShort results from attempting to set a password which is to
	// short.
	ErrTooShort = errors.E(errors.WithCode(errors.PasswordTooShort))

	// ErrUnsupportedConfiguration results from attempting to perform an
	// operation that sets a password configuration to an unsupported type.
	ErrUnsupportedConfiguration = errors.E(errors.WithCode(errors.PasswordUnsupportedConfiguration))

	// ErrInvalidConfiguration results from attempting to perform an
	// operation that sets a password configuration with invalid settings.
	ErrInvalidConfiguration = errors.E(errors.WithCode(errors.PasswordInvalidConfiguration))

	// ErrPasswordsEqual is returned from ChangePassword when the old and
	// new passwords are equal.
	ErrPasswordsEqual = errors.E(errors.WithCode(errors.PasswordsEqual))
)
