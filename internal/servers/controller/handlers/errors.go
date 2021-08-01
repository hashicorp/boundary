package handlers

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"sort"
	"strings"

	"github.com/grpc-ecosystem/grpc-gateway/v2/runtime"
	"github.com/hashicorp/boundary/internal/errors"
	pb "github.com/hashicorp/boundary/internal/gen/controller/api"
	"github.com/hashicorp/boundary/internal/observability/event"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

const (
	genericUniquenessMsg = "Invalid request.  Request attempted to make second resource with the same field value that must be unique."
	genericNotFoundMsg   = "Unable to find requested resource."
)

type apiError struct {
	status int32
	inner  *pb.Error
}

func (e *apiError) Error() string {
	res := fmt.Sprintf("Status: %d, Kind: %q, Error: %q", e.status, e.inner.GetKind(), e.inner.GetMessage())
	var dets []string
	for _, rf := range e.inner.GetDetails().GetRequestFields() {
		dets = append(dets, fmt.Sprintf("{name: %q, desc: %q}", rf.GetName(), rf.GetDescription()))
	}
	if len(dets) > 0 {
		det := strings.Join(dets, ", ")
		res = fmt.Sprintf("%s, Details: {%s}", res, det)
	}
	return res
}

func (e *apiError) Is(target error) bool {
	var tApiErr *apiError
	if !errors.As(target, &tApiErr) {
		return false
	}
	return tApiErr.inner.Kind == e.inner.Kind && tApiErr.status == e.status
}

// ApiErrorWithCode returns an api error with the provided code.
func ApiErrorWithCode(c codes.Code) error {
	return &apiError{
		status: int32(runtime.HTTPStatusFromCode(c)),
		inner: &pb.Error{
			Kind: c.String(),
		},
	}
}

// ApiErrorWithCodeAndMessage returns an api error with the provided code and message.
func ApiErrorWithCodeAndMessage(c codes.Code, msg string, args ...interface{}) error {
	return &apiError{
		status: int32(runtime.HTTPStatusFromCode(c)),
		inner: &pb.Error{
			Kind:    c.String(),
			Message: fmt.Sprintf(msg, args...),
		},
	}
}

// NotFoundError returns an ApiError indicating a resource couldn't be found.
func NotFoundError() error {
	return &apiError{
		status: http.StatusNotFound,
		inner: &pb.Error{
			Kind:    codes.NotFound.String(),
			Message: "Resource not found.",
		},
	}
}

// NotFoundErrorf returns an ApiError indicating a resource couldn't be found.
func NotFoundErrorf(msg string, a ...interface{}) *apiError {
	return &apiError{
		status: http.StatusNotFound,
		inner: &pb.Error{
			Kind:    codes.NotFound.String(),
			Message: fmt.Sprintf(msg, a...),
		},
	}
}

var unauthorizedError = &apiError{
	status: http.StatusForbidden,
	inner: &pb.Error{
		Kind:    codes.PermissionDenied.String(),
		Message: "Forbidden.",
	},
}

func ForbiddenError() error {
	return unauthorizedError
}

var unauthenticatedError = &apiError{
	status: http.StatusUnauthorized,
	inner: &pb.Error{
		Kind:    codes.Unauthenticated.String(),
		Message: "Unauthenticated, or invalid token.",
	},
}

func UnauthenticatedError() error {
	return unauthenticatedError
}

func InvalidArgumentErrorf(msg string, fields map[string]string) *apiError {
	const op = "handlers.InvalidArgumentErrorf"
	ctx := context.TODO()
	err := ApiErrorWithCodeAndMessage(codes.InvalidArgument, msg)
	var apiErr *apiError
	if !errors.As(err, &apiErr) {
		event.WriteError(ctx, op, err, event.WithInfoMsg("Unable to build invalid argument api error."))
	}

	if len(fields) > 0 {
		apiErr.inner.Details = &pb.ErrorDetails{}
	}
	for k, v := range fields {
		apiErr.inner.Details.RequestFields = append(apiErr.inner.Details.RequestFields, &pb.FieldError{Name: k, Description: v})
	}
	sort.Slice(apiErr.inner.GetDetails().GetRequestFields(), func(i, j int) bool {
		return apiErr.inner.Details.RequestFields[i].GetName() < apiErr.inner.Details.RequestFields[j].GetName()
	})
	return apiErr
}

// Converts a known errors into an error that can presented to an end user over the API.
func backendErrorToApiError(inErr error) *apiError {
	stErr := status.Convert(inErr)

	switch {
	case errors.Is(inErr, runtime.ErrNotMatch):
		// grpc gateway uses this error when the path was not matched, but the error uses codes.Unimplemented which doesn't match the intention.
		// Overwrite the error to match our expected behavior.
		return &apiError{
			status: http.StatusNotFound,
			inner: &pb.Error{
				Kind:    codes.NotFound.String(),
				Message: http.StatusText(http.StatusNotFound),
			},
		}
	case status.Code(inErr) == codes.Unimplemented:
		// Instead of returning a 501 we always want to return a 405 when a method isn't implemented.
		return &apiError{
			status: http.StatusMethodNotAllowed,
			inner: &pb.Error{
				Kind:    codes.Unimplemented.String(),
				Message: stErr.Message(),
			},
		}
	case errors.Match(errors.T(errors.RecordNotFound), inErr):
		return NotFoundErrorf(genericNotFoundMsg)
	case errors.Match(errors.T(errors.AccountAlreadyAssociated), inErr):
		return InvalidArgumentErrorf(inErr.Error(), nil)
	case errors.Match(errors.T(errors.InvalidFieldMask), inErr), errors.Match(errors.T(errors.EmptyFieldMask), inErr):
		return InvalidArgumentErrorf("Error in provided request", map[string]string{"update_mask": "Invalid update mask provided."})
	case errors.IsUniqueError(inErr):
		return InvalidArgumentErrorf(genericUniquenessMsg, nil)
	}

	var statusCode int32 = http.StatusInternalServerError
	var domainErr *errors.Err
	if errors.As(inErr, &domainErr) && domainErr.Code >= 400 && domainErr.Code <= 599 {
		// Domain error codes 400-599 align with http client and server error codes, use the domain error code instead of 500
		statusCode = int32(domainErr.Code)
	}

	// TODO: Don't return potentially sensitive information (like which user id an account
	//  is already associated with when attempting to re-associate it).
	return &apiError{
		status: statusCode,
		inner:  &pb.Error{Kind: codes.Internal.String(), Message: inErr.Error()},
	}
}

func ErrorHandler() runtime.ErrorHandlerFunc {
	const op = "handlers.ErrorHandler"
	const errorFallback = `{"error": "failed to marshal error message"}`
	return func(ctx context.Context, _ *runtime.ServeMux, mar runtime.Marshaler, w http.ResponseWriter, r *http.Request, inErr error) {
		// API specified error, otherwise we need to translate repo/db errors.
		var apiErr *apiError
		isApiErr := errors.As(inErr, &apiErr)
		if !isApiErr {
			if err := backendErrorToApiError(inErr); err != nil && !errors.As(err, &apiErr) {
				event.WriteError(ctx, op, err, event.WithInfoMsg("failed to cast error to api error"))
			}
		}

		if apiErr.status == http.StatusInternalServerError {
			event.WriteError(ctx, op, inErr, event.WithInfoMsg("internal error returned"))
		}

		buf, merr := mar.Marshal(apiErr.inner)
		if merr != nil {
			event.WriteError(ctx, op, merr, event.WithInfoMsg("failed to marshal error response", "response", fmt.Sprintf("%#v", apiErr.inner)))
			w.WriteHeader(http.StatusInternalServerError)
			if _, err := io.WriteString(w, errorFallback); err != nil {
				event.WriteError(ctx, op, err, event.WithInfoMsg("failed to write response"))
			}
			return
		}

		w.Header().Set("Content-Type", mar.ContentType(apiErr.inner))
		w.WriteHeader(int(apiErr.status))
		if _, err := w.Write(buf); err != nil {
			event.WriteError(ctx, op, err, event.WithInfoMsg("failed to send response chunk"))
			return
		}
	}
}

func ToApiError(e error) *pb.Error {
	return backendErrorToApiError(e).inner
}
