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

func IsServerError(in error) bool {
	var serverErr *Error
	return in != nil && errors.As(in, &serverErr)
}

func (e *Error) Error() string {
	res := fmt.Sprintf("Status: %d, Code: %q, Error: %q", e.Status, e.Code, e.Message)
	var dets []string
	if e.Details != nil {
		for _, rf := range e.Details.RequestFields {
			dets = append(dets, fmt.Sprintf("{name: %q, desc: %q}", rf.Name, rf.Description))
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
	var tApiErr *Error
	if !errors.As(target, &tApiErr) {
		return false
	}
	return tApiErr.Code == e.Code && tApiErr.Status == e.Status
}
