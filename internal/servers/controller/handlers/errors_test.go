package handlers

import (
	"context"
	"io/ioutil"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/golang/protobuf/proto"
	"github.com/grpc-ecosystem/grpc-gateway/runtime"
	"github.com/hashicorp/go-hclog"
	pb "github.com/hashicorp/watchtower/internal/gen/controller/api"
	"github.com/stretchr/testify/assert"
	sdpb "google.golang.org/genproto/googleapis/rpc/errdetails"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

func TestApiErrorHandler(t *testing.T) {
	ctx := context.Background()
	req, err := http.NewRequest("GET", "madeup/for/the/test", nil)
	if err != nil {
		t.Fatalf("Couldn't create test request")
	}
	mux := runtime.NewServeMux()
	_, outMarsh := runtime.MarshalerForRequest(mux, req)

	tested := ErrorHandler(hclog.L())

	testCases := []struct {
		name          string
		err           error
		statusDetails []proto.Message
		expected      *pb.Error
	}{
		{
			name: "Not Found",
			err:  status.Error(codes.NotFound, "test"),
			expected: &pb.Error{
				Status:  404,
				Code:    codes.NotFound.String(),
				Message: "test",
			},
		},
		{
			name: "GrpcGateway Routing Error",
			err:  runtime.ErrUnknownURI,
			expected: &pb.Error{
				Status:  404,
				Code:    codes.NotFound.String(),
				Message: http.StatusText(http.StatusNotFound),
			},
		},
		{
			name: "Invalid Fields",
			err:  status.Error(codes.InvalidArgument, "test"),
			statusDetails: []proto.Message{
				&sdpb.BadRequest{
					FieldViolations: []*sdpb.BadRequest_FieldViolation{
						{Field: "first", Description: "first desc"},
						{Field: "second", Description: "second desc"},
					},
				},
			},
			expected: &pb.Error{
				Status:  400,
				Code:    codes.InvalidArgument.String(),
				Message: "test",
				Details: &pb.ErrorDetails{
					RequestFields: []*pb.FieldError{{
						Name:        "first",
						Description: "first desc",
					},
						{
							Name:        "second",
							Description: "second desc",
						}},
				},
			},
		},
	}
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			assert := assert.New(t)

			if tc.statusDetails != nil {
				s, ok := status.FromError(tc.err)
				assert.True(ok)
				s, err := s.WithDetails(tc.statusDetails...)
				assert.NoError(err)
				tc.err = s.Err()
			}

			w := httptest.NewRecorder()
			tested(ctx, mux, outMarsh, w, req, tc.err)
			resp := w.Result()
			assert.EqualValues(tc.expected.Status, resp.StatusCode)

			got, err := ioutil.ReadAll(resp.Body)
			assert.NoError(err)
			want, err := outMarsh.Marshal(tc.expected)
			t.Logf("Got marshaled error: %q", want)
			assert.NoError(err)
			assert.JSONEq(string(want), string(got))
		})
	}
}
