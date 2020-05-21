package handlers

import (
	"context"
	"fmt"
	"io"
	"net/http"

	"github.com/golang/protobuf/proto"
	"github.com/grpc-ecosystem/grpc-gateway/runtime"
	"github.com/hashicorp/go-hclog"
	pb "github.com/hashicorp/watchtower/internal/gen/controller/api"
	"google.golang.org/genproto/googleapis/rpc/errdetails"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

func NotFoundErrorf(msg string, a ...interface{}) error {
	return status.Errorf(codes.NotFound, msg, a...)
}

func InvalidArgumentErrorf(msg string, fields []string) error {
	st := status.New(codes.InvalidArgument, msg)
	br := &errdetails.BadRequest{}
	for _, f := range fields {
		br.FieldViolations = append(br.FieldViolations, &errdetails.BadRequest_FieldViolation{Field: f})
	}
	st, err := st.WithDetails(br)
	if err != nil {
		panic(fmt.Sprintf("Unexpected error attaching metadata: %v", err))
	}
	return st.Err()
}

func statusErrorToApiError(s *status.Status) *pb.Error {
	apiErr := &pb.Error{}
	apiErr.Status = int32(runtime.HTTPStatusFromCode(s.Code()))
	apiErr.Message = s.Message()
	apiErr.Code = s.Code().String()

	d := &pb.ErrorDetails{}
	for _, ed := range s.Details() {
		switch ed.(type) {
		case *errdetails.BadRequest:
			br := ed.(*errdetails.BadRequest)
			for _, fv := range br.GetFieldViolations() {
				d.RequestFields = append(d.RequestFields, fv.GetField())
			}
		}
	}

	if !proto.Equal(d, &pb.ErrorDetails{}) {
		apiErr.Details = d
	}
	return apiErr
}

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
			logger.Warn("Failed to marshal error message %q: %v", apiErr, merr)
			w.WriteHeader(http.StatusInternalServerError)
			if _, err := io.WriteString(w, errorFallback); err != nil {
				logger.Warn("Failed to write response: %v", err)
			}
			return
		}

		w.Header().Set("Content-Type", marshaler.ContentType())
		w.WriteHeader(int(apiErr.GetStatus()))
		if _, err := w.Write(buf); err != nil {
			logger.Warn("Failed to send response chunk: %v", err)
			return
		}
	}
}
