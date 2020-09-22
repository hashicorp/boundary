package handlers

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"sort"
	"strings"

	"github.com/grpc-ecosystem/grpc-gateway/v2/runtime"
	"github.com/hashicorp/boundary/internal/db"
	pb "github.com/hashicorp/boundary/internal/gen/controller/api"
	"github.com/hashicorp/go-hclog"
	"github.com/hashicorp/vault/sdk/helper/base62"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

const (
	genericUniquenessMsg = "Invalid request.  Request attempted to make second resource with the same field value that must be unique."
	genericNotFoundMsg   = "Unable to find requested resource."
)

type apiError struct {
	inner *pb.Error
}

func (e *apiError) Error() string {
	res := fmt.Sprintf("Status: %d, Code: %q, Error: %q", e.inner.GetStatus(), e.inner.GetCode(), e.inner.GetMessage())
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
	return tApiErr.inner.Code == e.inner.Code && tApiErr.inner.Status == e.inner.Status
}

// ApiErrorWithCode returns an api error with the provided code.
func ApiErrorWithCode(c codes.Code) error {
	return &apiError{inner: &pb.Error{
		Status: int32(runtime.HTTPStatusFromCode(c)),
		Code:   c.String(),
	}}
}

// ApiErrorWithCodeAndMessage returns an api error with the provided code and message.
func ApiErrorWithCodeAndMessage(c codes.Code, msg string, args ...interface{}) error {
	return &apiError{inner: &pb.Error{
		Status:  int32(runtime.HTTPStatusFromCode(c)),
		Code:    c.String(),
		Message: fmt.Sprintf(msg, args...),
	}}
}

// NotFoundError returns an ApiError indicating a resource couldn't be found.
func NotFoundError() error {
	return &apiError{&pb.Error{
		Status:  http.StatusNotFound,
		Code:    codes.NotFound.String(),
		Message: "Resource not found.",
	}}
}

// NotFoundErrorf returns an ApiError indicating a resource couldn't be found.
func NotFoundErrorf(msg string, a ...interface{}) error {
	return &apiError{&pb.Error{
		Status:  http.StatusNotFound,
		Code:    codes.NotFound.String(),
		Message: fmt.Sprintf(msg, a...),
	}}
}

func ForbiddenError() error {
	return &apiError{&pb.Error{
		Status:  http.StatusForbidden,
		Code:    codes.PermissionDenied.String(),
		Message: "Forbidden.",
	}}
}

func UnauthenticatedError() error {
	return &apiError{&pb.Error{
		Status:  http.StatusUnauthorized,
		Code:    codes.Unauthenticated.String(),
		Message: "Unauthenticated, or invalid token.",
	}}
}

func InvalidArgumentErrorf(msg string, fields map[string]string) error {
	err := ApiErrorWithCodeAndMessage(codes.InvalidArgument, msg)
	var apiErr *apiError
	if !errors.As(err, &apiErr) {
		hclog.L().Error("Unable to build invalid argument api error.", "original error", err)
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
func backendErrorToApiError(inErr error) error {
	stErr := status.Convert(inErr)

	switch {
	case errors.Is(inErr, runtime.ErrNotMatch):
		// grpc gateway uses this error when the path was not matched, but the error uses codes.Unimplemented which doesn't match the intention.
		// Overwrite the error to match our expected behavior.
		return &apiError{inner: &pb.Error{
			Status:  http.StatusNotFound,
			Code:    codes.NotFound.String(),
			Message: http.StatusText(http.StatusNotFound),
		}}
	case status.Code(inErr) == codes.Unimplemented:
		// Instead of returning a 501 we always want to return a 405 when a method isn't implemented.
		return &apiError{inner: &pb.Error{
			Status:  http.StatusMethodNotAllowed,
			Code:    codes.Unimplemented.String(),
			Message: stErr.Message(),
		}}
	case errors.Is(inErr, db.ErrRecordNotFound):
		return NotFoundErrorf(genericNotFoundMsg)
	case errors.Is(inErr, db.ErrInvalidFieldMask), errors.Is(inErr, db.ErrEmptyFieldMask):
		return InvalidArgumentErrorf("Error in provided request", map[string]string{"update_mask": "Invalid update mask provided."})
	case db.IsUniqueError(inErr), errors.Is(inErr, db.ErrNotUnique):
		return InvalidArgumentErrorf(genericUniquenessMsg, nil)
	}
	return nil
}

func getInternalError(id string) *apiError {
	return &apiError{&pb.Error{
		Status:  http.StatusInternalServerError,
		Code:    codes.Internal.String(),
		Details: &pb.ErrorDetails{ErrorId: id},
	}}
}

func internalErrorId() (string, error) {
	errId, err := base62.Random(10)
	if err != nil {
		return "", fmt.Errorf("unable to generate id: %w", err)
	}
	return errId, nil
}

func ErrorHandler(logger hclog.Logger) runtime.ErrorHandlerFunc {
	const errorFallback = `{"error": "failed to marshal error message"}`
	return func(ctx context.Context, _ *runtime.ServeMux, mar runtime.Marshaler, w http.ResponseWriter, r *http.Request, inErr error) {
		// API specified error, otherwise we need to translate repo/db errors.
		var apiErr *apiError
		isApiErr := errors.As(inErr, &apiErr)
		if !isApiErr {
			if err := backendErrorToApiError(inErr); err != nil && !errors.As(err, &apiErr) {
				logger.Error("failed to cast error to api error", "error", err)
			}
		}

		if apiErr == nil || apiErr.inner.GetStatus() == http.StatusInternalServerError {
			errId, err := internalErrorId()
			if err != nil {
				logger.Error("unable to generate internal error id", "error", err)
				errId = "failed_to_generate_error_id"
			}
			logger.Error("internal error returned", "error id", errId, "error", inErr)
			apiErr = getInternalError(errId)
		}

		buf, merr := mar.Marshal(apiErr.inner)
		if merr != nil {
			logger.Error("failed to marshal error response", "response", fmt.Sprintf("%#v", apiErr.inner), "error", merr)
			w.WriteHeader(http.StatusInternalServerError)
			if _, err := io.WriteString(w, errorFallback); err != nil {
				logger.Error("failed to write response", "error", err)
			}
			return
		}

		w.Header().Set("Content-Type", mar.ContentType(apiErr.inner))
		w.WriteHeader(int(apiErr.inner.GetStatus()))
		if _, err := w.Write(buf); err != nil {
			logger.Error("failed to send response chunk", "error", err)
			return
		}
	}
}
