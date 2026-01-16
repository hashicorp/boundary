// Copyright IBM Corp. 2020, 2025
// SPDX-License-Identifier: BUSL-1.1

package worker

import (
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/google/go-cmp/cmp"
	opsservices "github.com/hashicorp/boundary/internal/gen/ops/services"
	pbhealth "github.com/hashicorp/boundary/internal/gen/worker/health"
	"github.com/hashicorp/boundary/internal/server"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/testing/protocmp"
	"google.golang.org/protobuf/types/known/wrapperspb"
)

func TestGetHealth(t *testing.T) {
	w := NewTestWorker(t, &TestWorkerOpts{
		InitialUpstreams: []string{"0.0.0.0"},
	})
	defer w.Shutdown()
	handler, err := w.Worker().GetHealthHandler()
	require.NoError(t, err)

	tests := []struct {
		name             string
		method           string
		queryParams      string
		expectedResponse *opsservices.GetHealthResponse
		expCode          int
	}{
		{
			name:             "healthy reply",
			method:           http.MethodGet,
			expCode:          http.StatusOK,
			expectedResponse: &opsservices.GetHealthResponse{},
		},
		{
			name:        "healthy reply with worker info",
			method:      http.MethodGet,
			queryParams: "worker_info=1",
			expCode:     http.StatusOK,
			expectedResponse: &opsservices.GetHealthResponse{
				WorkerProcessInfo: &pbhealth.HealthInfo{
					State:              server.ActiveOperationalState.String(),
					ActiveSessionCount: wrapperspb.UInt32(0),
				},
			},
		},
		{
			name:             "Post request",
			method:           http.MethodPost,
			queryParams:      "worker_info=1",
			expCode:          http.StatusNotImplemented,
			expectedResponse: &opsservices.GetHealthResponse{},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			path := "/health"
			if tt.queryParams != "" {
				path = fmt.Sprintf("%s?%s", path, tt.queryParams)
			}
			req, err := http.NewRequest(tt.method, path, nil)
			require.NoError(t, err)
			rr := httptest.NewRecorder()
			handler.ServeHTTP(rr, req)

			assert.Equal(t, tt.expCode, rr.Result().StatusCode)
			b, err := io.ReadAll(rr.Result().Body)
			require.NoError(t, err)
			resp := &opsservices.GetHealthResponse{}
			require.NoError(t, healthCheckMarshaler.Unmarshal(b, resp))

			assert.Empty(t,
				cmp.Diff(
					tt.expectedResponse,
					resp,
					protocmp.Transform(),
					protocmp.IgnoreFields(&pbhealth.HealthInfo{}, "upstream_connection_state"),
				),
			)
		})
	}
}
