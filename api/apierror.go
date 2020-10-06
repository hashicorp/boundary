package api

import (
	"errors"
	"net/http"

	"google.golang.org/grpc/codes"
)

var (
	ErrNotFound         = &Error{Status: http.StatusNotFound, Code: codes.NotFound.String()}
	ErrInvalidArgument  = &Error{Status: http.StatusBadRequest, Code: codes.InvalidArgument.String()}
	ErrPermissionDenied = &Error{Status: http.StatusForbidden, Code: codes.PermissionDenied.String()}
	ErrUnauthorized     = &Error{Status: http.StatusUnauthorized, Code: codes.Unauthenticated.String()}
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
	return e.responseBody.String()
}

// Errors are considered the same iff they are both api.Errors and their statuses are the same.
func (e *Error) Is(target error) bool {
	tApiErr := AsServerError(target)
	return tApiErr != nil && tApiErr.Code == e.Code && tApiErr.Status == e.Status
}
