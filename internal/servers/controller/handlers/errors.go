package handlers

import (
	"context"
	"fmt"
	"io"
	"net/http"

	"github.com/grpc-ecosystem/grpc-gateway/runtime"
	"github.com/hashicorp/go-hclog"
	pb "github.com/hashicorp/watchtower/internal/gen/controller/api"
	"google.golang.org/genproto/googleapis/rpc/errdetails"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

type apiCode int

const (
	ok apiCode = iota
	timeout
	notFound
	unimplemented
	duplicateName
	invalidArgument
	unknown
)

// String is the code in string format as described by the API.
func (c apiCode) String() string {
	switch c {
	case ok:
		return "OK"
	case notFound:
		return "resource_not_found"
	case timeout:
		return "request_timed_out"
	case duplicateName:
		return "duplicate_name"
	case unimplemented:
		return "unimplmeneted"
	case invalidArgument:
		return "invalid_request"
	}
	return "unknown"
}

func (c apiCode) httpStatus() int32 {
	switch c {
	case ok:
		return http.StatusOK
	case timeout:
		return http.StatusRequestTimeout
	case notFound:
		return http.StatusNotFound
	case duplicateName, invalidArgument:
		return http.StatusBadRequest
	case unimplemented:
		return http.StatusMethodNotAllowed
	}
	return http.StatusInternalServerError
}

// ApiError is an error to capture the information that should be returned to external users.
type ApiError struct {
	inner pb.Error
	code  apiCode
}

var _ error = ApiError{}

func (e ApiError) Error() string {
	return e.inner.GetMessage()
}

// An error is the same as this error if it is an ApiError and has the same code.
func (e ApiError) Is(target error) bool {
	if t, ok := target.(ApiError); ok {
		return t.code == e.code
	}
	return false
}

// NotFoundError returns an ApiError indicating a resource couldn't be found.
func NotFoundErrorf(msg string, a ...interface{}) error {
	return status.Errorf(codes.NotFound, msg, a...)
}

func InvalidArgumentErrorf(msg string, fields map[string]string) error {
	st := status.New(codes.InvalidArgument, msg)
	br := &errdetails.BadRequest{}
	for k, v := range fields {
		br.FieldViolations = append(br.FieldViolations, &errdetails.BadRequest_FieldViolation{Field: k, Description: v})
	}
	st, err := st.WithDetails(br)
	if err != nil {
		hclog.Default().Error("failure building status with details", "details", br, "error", err)
		return status.Error(codes.Internal, "Failed to build InvalidArgument error.")
	}
	return st.Err()
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

// TODO(ICU-194): Remove all information from internal errors.
func ErrorHandler(logger hclog.Logger) runtime.ProtoErrorHandlerFunc {
	const errorFallback = `{"error": "failed to marshal error message"}`
	return func(ctx context.Context, _ *runtime.ServeMux, marshaler runtime.Marshaler, w http.ResponseWriter, r *http.Request, inErr error) {
		if inErr == runtime.ErrUnknownURI {
			// grpc gateway uses this error when the path was not matched, but the error uses codes.Unimplemented which doesn't match the intention.
			// Overwrite the error to match our expected behavior.
			inErr = status.Error(codes.NotFound, http.StatusText(http.StatusNotFound))
		}
		s, ok := status.FromError(inErr)
		if !ok {
			s = status.New(codes.Unknown, inErr.Error())
		}
		apiErr := statusErrorToApiError(s)
		buf, merr := marshaler.Marshal(apiErr)
		if merr != nil {
			logger.Error("failed to marshal error response", "response", fmt.Sprintf("%#v", apiErr), "error", merr)
			w.WriteHeader(http.StatusInternalServerError)
			if _, err := io.WriteString(w, errorFallback); err != nil {
				logger.Error("failed to write response", "error", err)
			}
			return
		}

		w.Header().Set("Content-Type", marshaler.ContentType())
		w.WriteHeader(int(apiErr.GetStatus()))
		if _, err := w.Write(buf); err != nil {
			logger.Error("failed to send response chunk", "error", err)
			return
		}
	}
}
