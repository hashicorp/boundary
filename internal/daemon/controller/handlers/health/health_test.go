// Copyright IBM Corp. 2020, 2025
// SPDX-License-Identifier: BUSL-1.1

package health

import (
	"context"
	"fmt"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/hashicorp/boundary/internal/gen/ops/services"
	pbhealth "github.com/hashicorp/boundary/internal/gen/worker/health"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
	"google.golang.org/grpc/metadata"
	"google.golang.org/protobuf/testing/protocmp"
	"google.golang.org/protobuf/types/known/wrapperspb"
)

func TestGetHealth(t *testing.T) {
	workerInfo := &pbhealth.HealthInfo{
		ActiveSessionCount: wrapperspb.UInt32(2),
		SessionConnections: map[string]uint32{
			"foo": uint32(2),
			"bar": uint32(1),
		},
	}

	tests := []struct {
		name                 string
		ctx                  context.Context
		workerInfoFn         func() *pbhealth.HealthInfo
		serviceUnavailable   bool
		request              *services.GetHealthRequest
		expGetHealthResponse *services.GetHealthResponse
		expErr               bool
		expErrMsg            string
	}{
		{
			name:                 "healthy reply",
			ctx:                  context.Background(),
			serviceUnavailable:   false,
			request:              &services.GetHealthRequest{},
			expGetHealthResponse: &services.GetHealthResponse{},
			expErr:               false,
		},
		{
			name:                 "with worker info no query parameter",
			ctx:                  context.Background(),
			workerInfoFn:         func() *pbhealth.HealthInfo { return workerInfo },
			serviceUnavailable:   false,
			request:              &services.GetHealthRequest{},
			expGetHealthResponse: &services.GetHealthResponse{},
			expErr:               false,
		},
		{
			name:                 "with worker info and query param",
			ctx:                  context.Background(),
			workerInfoFn:         func() *pbhealth.HealthInfo { return workerInfo },
			serviceUnavailable:   false,
			request:              &services.GetHealthRequest{WorkerInfo: true},
			expGetHealthResponse: &services.GetHealthResponse{WorkerProcessInfo: workerInfo},
			expErr:               false,
		},
		{
			name:                 "service unavailable reply",
			ctx:                  grpc.NewContextWithServerTransportStream(context.Background(), &testServerTransportStream{expHttpCode: "503"}),
			serviceUnavailable:   true,
			request:              &services.GetHealthRequest{},
			expGetHealthResponse: &services.GetHealthResponse{},
			expErr:               false,
		},
		{
			name:                 "service unavailable with worker info reply",
			ctx:                  grpc.NewContextWithServerTransportStream(context.Background(), &testServerTransportStream{expHttpCode: "503"}),
			workerInfoFn:         func() *pbhealth.HealthInfo { return workerInfo },
			serviceUnavailable:   true,
			request:              &services.GetHealthRequest{WorkerInfo: true},
			expGetHealthResponse: &services.GetHealthResponse{WorkerProcessInfo: workerInfo},
			expErr:               false,
		},
		{
			name:               "get health error",
			ctx:                context.Background(),
			serviceUnavailable: true,
			request:            &services.GetHealthRequest{},
			expErr:             true,
			expErrMsg:          "handlers.SetHttpStatusCode: internal error, unknown: error #500: rpc error: code = Internal desc = grpc: failed to fetch the stream from the context context.Background",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			hs := NewService()

			if tt.workerInfoFn != nil {
				require.NoError(t, hs.SetWorkerProcessInformationFunc(tt.workerInfoFn))
			}

			if tt.serviceUnavailable {
				hs.StartServiceUnavailableReplies()
			}

			rsp, err := hs.GetHealth(tt.ctx, tt.request)
			if tt.expErr {
				require.Error(t, err)
				require.EqualError(t, err, tt.expErrMsg)
				return
			}

			require.NoError(t, err)
			assert.Empty(t, cmp.Diff(tt.expGetHealthResponse, rsp, protocmp.Transform()))
		})
	}
}

type testServerTransportStream struct {
	expHttpCode string
}

func (s *testServerTransportStream) Method() string                  { return "" }
func (s *testServerTransportStream) SendHeader(md metadata.MD) error { return nil }
func (s *testServerTransportStream) SetTrailer(md metadata.MD) error { return nil }
func (s *testServerTransportStream) SetHeader(md metadata.MD) error {
	codes, ok := md["x-http-code"]
	if !ok {
		return fmt.Errorf("x-http-code header not found")
	}
	if len(codes) != 1 {
		return fmt.Errorf("expected only one element in http codes, got %d", len(codes))
	}
	if codes[0] != s.expHttpCode {
		return fmt.Errorf("expected http code %q, got %q", s.expHttpCode, codes[0])
	}
	return nil
}
