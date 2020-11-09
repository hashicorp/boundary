package api

import (
	"errors"

	"google.golang.org/grpc/codes"
)

var (
	ErrNotFound         = &Error{Kind: codes.NotFound.String()}
	ErrInvalidArgument  = &Error{Kind: codes.InvalidArgument.String()}
	ErrPermissionDenied = &Error{Kind: codes.PermissionDenied.String()}
	ErrUnauthorized     = &Error{Kind: codes.Unauthenticated.String()}
)

// AsServerError returns an api *Error from the provided error.  If the provided error
// is not an api Error nil is returned instead.
func AsServerError(in error) *Error {
	var serverErr *Error
	if !errors.As(in, &serverErr) {
		return nil
	}
	return serverErr
}

// Error satisfies the error interface.
func (e *Error) Error() string {
	return e.response.Body.String()
}

// Errors are considered the same iff they are both api.Errors and their statuses are the same.
func (e *Error) Is(target error) bool {
	tApiErr := AsServerError(target)
	return tApiErr != nil && tApiErr.Kind == e.Kind
}
