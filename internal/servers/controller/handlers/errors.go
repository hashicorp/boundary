package handlers

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"

	"github.com/golang/protobuf/proto"
	"github.com/grpc-ecosystem/grpc-gateway/runtime"
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

func statusErrorToApiError(e error) (*pb.Error, bool) {
	s, ok := status.FromError(e)
	if !ok {
		return nil, false
	}

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
		default:
			// We don't know what this is... do nothing.
		}
	}

	if !proto.Equal(d, &pb.ErrorDetails{}) {
		apiErr.Details = d
	}
	return apiErr, true
}

func ErrorHandler(ctx context.Context, mux *runtime.ServeMux, marshaler runtime.Marshaler, w http.ResponseWriter, r *http.Request, inErr error) {
	if inErr == runtime.ErrUnknownURI {
		// grpc gateway uses this error when the path was not matched, but the error uses codes.Unimplemented which doesn't match the intention.
		// Overwrite the error to match our expected behavior.
		inErr = status.Error(codes.NotFound, "Path not found.")
	}

	apiErr, ok := statusErrorToApiError(inErr)
	if !ok {
		runtime.GlobalHTTPErrorHandler(ctx, mux, marshaler, w, r, inErr)
		return
	}

	w.Header().Set("Content-type", marshaler.ContentType())
	w.WriteHeader(int(apiErr.GetStatus()))

	if err := json.NewEncoder(w).Encode(apiErr); err != nil {
		fmt.Printf("Failed encode json: %v", err)
	}
}
