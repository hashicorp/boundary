package handlers

import (
	"context"
	"errors"
	"io/ioutil"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/grpc-ecosystem/grpc-gateway/runtime"
	"github.com/hashicorp/go-hclog"
	pb "github.com/hashicorp/watchtower/internal/gen/controller/api"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/testing/protocmp"
)

func TestApiErrorHandler(t *testing.T) {
	assert, require := assert.New(t), require.New(t)
	ctx := context.Background()
	req, err := http.NewRequest("GET", "madeup/for/the/test", nil)
	require.NoError(err)
	mux := runtime.NewServeMux()
	inMarsh, outMarsh := runtime.MarshalerForRequest(mux, req)

	tested := ErrorHandler(hclog.L())

	testCases := []struct {
		name     string
		err      error
		expected *pb.Error
	}{
		{
			name: "Not Found",
			err:  NotFoundErrorf("Test"),
			expected: &pb.Error{
				Status:  http.StatusNotFound,
				Code:    "NotFound",
				Message: "Test",
			},
		},
		{
			name: "Invalid Fields",
			err: InvalidArgumentErrorf("Test", map[string]string{
				"k1": "v1",
				"k2": "v2",
			}),
			expected: &pb.Error{
				Status:  http.StatusBadRequest,
				Code:    "InvalidArgument",
				Message: "Test",
				Details: &pb.ErrorDetails{
					RequestFields: []*pb.FieldError{{
						Name:        "k1",
						Description: "v1",
					},
						{
							Name:        "k2",
							Description: "v2",
						}},
				},
			},
		},
		{
			name: "GrpcGateway Routing Error",
			err:  runtime.ErrUnknownURI,
			expected: &pb.Error{
				Status:  http.StatusNotFound,
				Code:    "NotFound",
				Message: http.StatusText(http.StatusNotFound),
			},
		},
		{
			name: "Unknown error",
			err:  errors.New("Some random error"),
			expected: &pb.Error{
				Status:  http.StatusInternalServerError,
				Code:    "Unknown",
				Message: "Some random error",
			},
		},
	}
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			w := httptest.NewRecorder()
			tested(ctx, mux, outMarsh, w, req, tc.err)
			resp := w.Result()
			assert.EqualValues(tc.expected.Status, resp.StatusCode)

			got, err := ioutil.ReadAll(resp.Body)
			require.NoError(err)

			gotErr := &pb.Error{}
			err = inMarsh.Unmarshal(got, gotErr)
			require.NoError(err)
			assert.Empty(cmp.Diff(tc.expected, gotErr, protocmp.Transform()))
		})
	}
}
