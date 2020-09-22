package handlers

import (
	"context"
	"errors"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/grpc-ecosystem/grpc-gateway/v2/runtime"
	"github.com/hashicorp/boundary/internal/db"
	pb "github.com/hashicorp/boundary/internal/gen/controller/api"
	"github.com/hashicorp/go-hclog"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/testing/protocmp"
)

func TestApiErrorHandler(t *testing.T) {
	ctx := context.Background()
	req, err := http.NewRequest("GET", "madeup/for/the/test", nil)
	require.NoError(t, err)
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
					RequestFields: []*pb.FieldError{
						{
							Name:        "k1",
							Description: "v1",
						},
						{
							Name:        "k2",
							Description: "v2",
						},
					},
				},
			},
		},
		{
			name: "GrpcGateway Routing Error",
			err:  runtime.ErrNotMatch,
			expected: &pb.Error{
				Status:  http.StatusNotFound,
				Code:    "NotFound",
				Message: http.StatusText(http.StatusNotFound),
			},
		},
		{
			name: "Unimplemented error",
			err:  status.Error(codes.Unimplemented, "Test"),
			expected: &pb.Error{
				Status:  http.StatusMethodNotAllowed,
				Code:    "Unimplemented",
				Message: "Test",
			},
		},
		{
			name: "Unknown error",
			err:  errors.New("Some random error"),
			expected: &pb.Error{
				Status:  http.StatusInternalServerError,
				Code:    "Internal",
				Details: &pb.ErrorDetails{ErrorId: ""},
			},
		},
		{
			name: "Db invalid public id error",
			err:  fmt.Errorf("test error: %w", db.ErrInvalidPublicId),
			expected: &pb.Error{
				Status:  http.StatusInternalServerError,
				Code:    "Internal",
				Details: &pb.ErrorDetails{ErrorId: ""},
			},
		},
		{
			name: "Db invalid parameter",
			err:  fmt.Errorf("test error: %w", db.ErrInvalidParameter),
			expected: &pb.Error{
				Status:  http.StatusInternalServerError,
				Code:    "Internal",
				Details: &pb.ErrorDetails{ErrorId: ""},
			},
		},
		{
			name: "Db invalid field mask",
			err:  fmt.Errorf("test error: %w", db.ErrInvalidFieldMask),
			expected: &pb.Error{
				Status:  http.StatusBadRequest,
				Code:    "InvalidArgument",
				Message: "Error in provided request",
				Details: &pb.ErrorDetails{RequestFields: []*pb.FieldError{{Name: "update_mask", Description: "Invalid update mask provided."}}},
			},
		},
		{
			name: "Db empty field mask",
			err:  fmt.Errorf("test error: %w", db.ErrEmptyFieldMask),
			expected: &pb.Error{
				Status:  http.StatusBadRequest,
				Code:    "InvalidArgument",
				Message: "Error in provided request",
				Details: &pb.ErrorDetails{RequestFields: []*pb.FieldError{{Name: "update_mask", Description: "Invalid update mask provided."}}},
			},
		},
		{
			name: "Db not unique",
			err:  fmt.Errorf("test error: %w", db.ErrNotUnique),
			expected: &pb.Error{
				Status:  http.StatusBadRequest,
				Code:    "InvalidArgument",
				Message: genericUniquenessMsg,
			},
		},
		{
			name: "Db record not found",
			err:  fmt.Errorf("test error: %w", db.ErrRecordNotFound),
			expected: &pb.Error{
				Status:  http.StatusNotFound,
				Code:    "NotFound",
				Message: genericNotFoundMsg,
			},
		},
		{
			name: "Db multiple records",
			err:  fmt.Errorf("test error: %w", db.ErrMultipleRecords),
			expected: &pb.Error{
				Status:  http.StatusInternalServerError,
				Code:    "Internal",
				Details: &pb.ErrorDetails{ErrorId: ""},
			},
		},
	}
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			assert, require := assert.New(t), require.New(t)
			w := httptest.NewRecorder()
			tested(ctx, mux, outMarsh, w, req, tc.err)
			resp := w.Result()
			assert.EqualValues(tc.expected.Status, resp.StatusCode)

			got, err := ioutil.ReadAll(resp.Body)
			require.NoError(err)

			gotErr := &pb.Error{}
			err = inMarsh.Unmarshal(got, gotErr)
			require.NoError(err)

			if tc.expected.Status == http.StatusInternalServerError {
				require.NotNil(tc.expected.GetDetails())
				tc.expected.GetDetails().ErrorId = gotErr.GetDetails().GetErrorId()
			}

			assert.Empty(cmp.Diff(tc.expected, gotErr, protocmp.Transform()))
		})
	}
}
