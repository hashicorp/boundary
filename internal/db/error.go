package db

import "errors"

// Errors returned from this package may be tested against these errors
// with errors.Is.
var (
	// ErrInvalidPublicId indicates an invalid PublicId.
	ErrInvalidPublicId = errors.New("invalid publicId")

	// ErrInvalidParameter is returned by create and update methods if
	// an attribute on a struct contains illegal or invalid values.
	ErrInvalidParameter = errors.New("invalid parameter")

	// ErrNotUnique is returned by create and update methods when a write
	// to the repository resulted in a unique constraint violation.
	ErrNotUnique = errors.New("unique constraint violation")

	// ErrNilParameter is returned when a required parameter is nil.
	ErrNilParameter = errors.New("nil parameter")
)

