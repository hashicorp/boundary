// Copyright IBM Corp. 2020, 2025
// SPDX-License-Identifier: MPL-2.0

package api

import (
	"errors"
	"net/http"

	"google.golang.org/grpc/codes"
)

var (
	ErrNotFound         = &Error{Kind: codes.NotFound.String(), response: &Response{resp: &http.Response{StatusCode: http.StatusNotFound}}}
	ErrInvalidArgument  = &Error{Kind: codes.InvalidArgument.String(), response: &Response{resp: &http.Response{StatusCode: http.StatusBadRequest}}}
	ErrPermissionDenied = &Error{Kind: codes.PermissionDenied.String(), response: &Response{resp: &http.Response{StatusCode: http.StatusForbidden}}}
	ErrUnauthorized     = &Error{Kind: codes.Unauthenticated.String(), response: &Response{resp: &http.Response{StatusCode: http.StatusUnauthorized}}}
	// internal/daemon/controller/handlers/errors.go detects status.Code(inErr) == codes.Unimplemented
	// and sets http status http.StatusMethodNotAllowed
	ErrUnimplemented    = &Error{Kind: codes.Unimplemented.String(), response: &Response{resp: &http.Response{StatusCode: http.StatusMethodNotAllowed}}}
	ErrInvalidListToken = &Error{Kind: "invalid list token", response: &Response{resp: &http.Response{StatusCode: http.StatusBadRequest}}}
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
	return tApiErr != nil && tApiErr.Kind == e.Kind && e.Response().StatusCode() == tApiErr.Response().StatusCode()
}

// Response returns the API response associated with the error
func (e *Error) Response() *Response {
	return e.response
}
