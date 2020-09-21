package handlers

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"sort"

	"github.com/grpc-ecosystem/grpc-gateway/v2/runtime"
	"github.com/hashicorp/boundary/internal/db"
	pb "github.com/hashicorp/boundary/internal/gen/controller/api"
	"github.com/hashicorp/go-hclog"
	"google.golang.org/genproto/googleapis/rpc/errdetails"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

const (
	genericUniquenessMsg = "Invalid request.  Request attempted to make second resource with the same field value that must be unique."
	genericNotFoundMsg   = "Unable to find requested resource."
)

// NotFoundError returns an ApiError indicating a resource couldn't be found.
func NotFoundError() error {
	return status.Error(codes.NotFound, "Resource not found.")
}

// NotFoundErrorf returns an ApiError indicating a resource couldn't be found.
func NotFoundErrorf(msg string, a ...interface{}) error {
	return status.Errorf(codes.NotFound, msg, a...)
}

func ForbiddenError() error {
	return status.Error(codes.PermissionDenied, "Forbidden.")
}

func UnauthenticatedError() error {
	return status.Error(codes.Unauthenticated, "Unauthenticated, or invalid token.")
}

func InvalidArgumentErrorf(msg string, fields map[string]string) error {
	st := status.New(codes.InvalidArgument, msg)
	br := &errdetails.BadRequest{}
	for k, v := range fields {
		br.FieldViolations = append(br.FieldViolations, &errdetails.BadRequest_FieldViolation{Field: k, Description: v})
	}
	sort.Slice(br.FieldViolations, func(i, j int) bool {
		return br.FieldViolations[i].GetField() < br.FieldViolations[j].GetField()
	})
	st, err := st.WithDetails(br)
	if err != nil {
		hclog.Default().Error("failure building status with details", "details", br, "error", err)
		return status.Error(codes.Internal, "Failed to build InvalidArgument error.")
	}
	return st.Err()
}

// Converts a known errors into an error that can presented to an end user over the API.
func translateKnownErrors(inErr error) error {
	switch {
	case errors.Is(inErr, db.ErrRecordNotFound):
		return NotFoundErrorf(genericNotFoundMsg)
	case errors.Is(inErr, db.ErrInvalidFieldMask), errors.Is(inErr, db.ErrEmptyFieldMask):
		return InvalidArgumentErrorf("Error in provided request", map[string]string{"update_mask": "Invalid update mask provided."})
	case db.IsUniqueError(inErr), errors.Is(inErr, db.ErrNotUnique):
		return InvalidArgumentErrorf(genericUniquenessMsg, nil)
	}
	return inErr
}

func statusErrorToApiError(s *status.Status) *pb.Error {
	apiErr := &pb.Error{}
	apiErr.Status = int32(runtime.HTTPStatusFromCode(s.Code()))
	if s.Code() == codes.Unimplemented {
		// Instead of returning a 501 we always want to return a 405 when a method isn't implemented.
		apiErr.Status = http.StatusMethodNotAllowed
	}
	apiErr.Message = s.Message()
	// TODO(ICU-193): Decouple from the status codes and instead use codes defined specifically for our API.
	apiErr.Code = s.Code().String()

	for _, ed := range s.Details() {
		switch ed.(type) {
		case *errdetails.BadRequest:
			br := ed.(*errdetails.BadRequest)
			for _, fv := range br.GetFieldViolations() {
				if apiErr.Details == nil {
					apiErr.Details = &pb.ErrorDetails{}
				}
				apiErr.Details.RequestFields = append(apiErr.Details.RequestFields, &pb.FieldError{Name: fv.GetField(), Description: fv.GetDescription()})
			}
		}
	}
	return apiErr
}

func ErrorHandler(logger hclog.Logger) runtime.ErrorHandlerFunc {
	const errorFallback = `{"error": "failed to marshal error message"}`
	return func(ctx context.Context, _ *runtime.ServeMux, mar runtime.Marshaler, w http.ResponseWriter, r *http.Request, inErr error) {
		if inErr == runtime.ErrNotMatch {
			// grpc gateway uses this error when the path was not matched, but the error uses codes.Unimplemented which doesn't match the intention.
			// Overwrite the error to match our expected behavior.
			inErr = status.Error(codes.NotFound, http.StatusText(http.StatusNotFound))
		}
		inErr = translateKnownErrors(inErr)
		s, ok := status.FromError(inErr)
		if !ok {
			s = status.New(codes.Internal, inErr.Error())
		}
		if s.Code() == codes.Internal {
			errorId := "123"
			logger.Error("internal error returned", "error", inErr, "error id", errorId)
			s = status.Newf(codes.Internal, "Error Id: %s", errorId)
		}
		apiErr := statusErrorToApiError(s)
		buf, merr := mar.Marshal(apiErr)
		if merr != nil {
			logger.Error("failed to marshal error response", "response", fmt.Sprintf("%#v", apiErr), "error", merr)
			w.WriteHeader(http.StatusInternalServerError)
			if _, err := io.WriteString(w, errorFallback); err != nil {
				logger.Error("failed to write response", "error", err)
			}
			return
		}

		w.Header().Set("Content-Type", mar.ContentType(apiErr))
		w.WriteHeader(int(apiErr.GetStatus()))
		if _, err := w.Write(buf); err != nil {
			logger.Error("failed to send response chunk", "error", err)
			return
		}
	}
}
