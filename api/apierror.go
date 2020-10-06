package api

import (
	"errors"
	"fmt"
	"net/http"
	"strings"

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
	msg := []string{fmt.Sprintf("%s\n", e.Message), fmt.Sprintf("  %d, %s\n\n", e.Status, e.Code)}

	if e.Details != nil {
		if e.Details.ErrorId != "" {
			msg = append(msg, fmt.Sprintf("  Error ID: %s\n", e.Details.ErrorId))
		}
		if e.Details.RequestId != "" {
			msg = append(msg, fmt.Sprintf("  Request ID: %s\n", e.Details.RequestId))
		}
		if e.Details.TraceId != "" {
			msg = append(msg, fmt.Sprintf("  Trace ID: %s\n", e.Details.TraceId))
		}
		for _, rf := range e.Details.RequestFields {
			msg = append(msg, fmt.Sprintf("  '-%s': %s\n", strings.ReplaceAll(rf.Name, "_", "-"), rf.Description))
		}
	}

	return strings.Join(msg, "")
}

// Errors are considered the same iff they are both api.Errors and their statuses are the same.
func (e *Error) Is(target error) bool {
	tApiErr := AsServerError(target)
	return tApiErr != nil && tApiErr.Code == e.Code && tApiErr.Status == e.Status
}
