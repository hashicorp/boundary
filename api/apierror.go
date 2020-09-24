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
	res := fmt.Sprintf("Status: %d, Code: %q, Error: %q", e.Status, e.Code, e.Message)
	var dets []string
	if e.Details != nil {
		if e.Details.ErrorId != "" {
			dets = append(dets, fmt.Sprintf("error_id: %q", e.Details.ErrorId))
		}
		if e.Details.RequestId != "" {
			dets = append(dets, fmt.Sprintf("request_id: %q", e.Details.RequestId))
		}
		if e.Details.TraceId != "" {
			dets = append(dets, fmt.Sprintf("TraceId: %q", e.Details.TraceId))
		}
		for _, rf := range e.Details.RequestFields {
			dets = append(dets, fmt.Sprintf("request_field: {name: %q, desc: %q}", rf.Name, rf.Description))
		}
	}
	if len(dets) > 0 {
		det := strings.Join(dets, ", ")
		res = fmt.Sprintf("%s, Details: {%s}", res, det)
	}
	return res
}

// Errors are considered the same iff they are both api.Errors and their statuses are the same.
func (e *Error) Is(target error) bool {
	tApiErr := AsServerError(target)
	return tApiErr != nil && tApiErr.Code == e.Code && tApiErr.Status == e.Status
}
