package api

import (
	"fmt"
	"net/http"
	"strings"
)

var (
	ErrNotFound     = &Error{Status: http.StatusNotFound}
	ErrBadRequest   = &Error{Status: http.StatusBadRequest}
	ErrForbidden    = &Error{Status: http.StatusForbidden}
	ErrUnauthorized = &Error{Status: http.StatusUnauthorized}
)

// Reports the api error code, message, and field errors for invalid argument errors.
func (e *Error) Error() string {
	details := e.Details
	var fieldDetails []string
	if details != nil {
		for _, fe := range details.RequestFields {
			if fe == nil {
				continue
			}
			fieldDetails = append(fieldDetails, fmt.Sprintf("%q: %q", fe.Name, fe.Description))
		}
	}

	ret := fmt.Sprintf("%s: %s", e.Code, e.Message)
	if len(fieldDetails) > 0 {
		ret = fmt.Sprintf("%s: Details: {%s}", ret, strings.Join(fieldDetails, ", "))
	}

	return ret
}

// Errors are considered the same iff they are both api.Errors and their statuses are the same.
// TODO: Change the status to code checks to allow for more fine grain checks.
func (e *Error) Is(target error) bool {
	if t, ok := target.(*Error); ok {
		return t.Status == e.Status
	}
	return false
}
