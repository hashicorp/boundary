package metric

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/hashicorp/boundary/internal/daemon/metric"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/wrapperspb"
)

func TestInitializeClusterClientCollectors(t *testing.T) {
	require.NotPanics(t, func() { InitializeClusterClientCollectors(nil) })
	require.NotPanics(t, func() { InitializeClusterClientCollectors(prometheus.NewRegistry()) })
}

func TestRecorder(t *testing.T) {
	cases := []struct {
		name         string
		methodName   string
		err          error
		wantedLabels prometheus.Labels
	}{
		{
			name:       "basic",
			methodName: "/some.service.path/method",
			err:        nil,
			wantedLabels: map[string]string{
				metric.LabelGRpcCode:    "OK",
				metric.LabelGRpcMethod:  "method",
				metric.LabelGRpcService: "some.service.path",
			},
		},
		{
			name:       "unrecognized method path format",
			methodName: "unrecognized",
			err:        nil,
			wantedLabels: map[string]string{
				metric.LabelGRpcCode:    "OK",
				metric.LabelGRpcMethod:  "unknown",
				metric.LabelGRpcService: "unknown",
			},
		},
		{
			name:       "cancel error",
			methodName: "/some.service.path/method",
			err:        status.Error(codes.Canceled, ""),
			wantedLabels: map[string]string{
				metric.LabelGRpcCode:    "Canceled",
				metric.LabelGRpcMethod:  "method",
				metric.LabelGRpcService: "some.service.path",
			},
		},
		{
			name:       "permission error",
			methodName: "/some.service.path/method",
			err:        status.Error(codes.PermissionDenied, ""),
			wantedLabels: map[string]string{
				metric.LabelGRpcCode:    "PermissionDenied",
				metric.LabelGRpcMethod:  "method",
				metric.LabelGRpcService: "some.service.path",
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			ogReqLatency := gRpcRequestLatency
			defer func() { gRpcRequestLatency = ogReqLatency }()

			handler := metric.StatsHandler{Metric: gRpcServerRequestLatency}
			testableLatency := &metric.TestableObserverVec{}
			handler.Metric = testableLatency

			start := time.Now()
			tested := metric.NewRequestRecorder(tc.methodName, handler)
			tested.Record(tc.err)

			require.Len(t, testableLatency.Observations, 1)
			assert.Greater(t, testableLatency.Observations[0].Observation, float64(0))
			assert.LessOrEqual(t, testableLatency.Observations[0].Observation, time.Since(start).Seconds())
			assert.Equal(t, testableLatency.Observations[0].Labels, tc.wantedLabels)
		})
	}
}

func TestInstrumentClusterClient(t *testing.T) {
	ogReqLatency := gRpcRequestLatency
	defer func() { gRpcRequestLatency = ogReqLatency }()

	testableLatency := &metric.TestableObserverVec{}
	gRpcRequestLatency = testableLatency

	interceptor := InstrumentClusterClient()
	i := &metric.TestInvoker{T: t, RetErr: nil}

	start := time.Now()
	err := interceptor(context.Background(), "/some.service.path/method", wrapperspb.Bytes([]byte{1}), nil, nil, i.Invoke, []grpc.CallOption{}...)
	require.NoError(t, err)
	require.True(t, i.Called)

	require.Len(t, testableLatency.Observations, 1)
	assert.Greater(t, testableLatency.Observations[0].Observation, float64(0))
	assert.LessOrEqual(t, testableLatency.Observations[0].Observation, time.Since(start).Seconds())
}

func TestInstrumentClusterClient_InvokerError(t *testing.T) {
	ogReqLatency := gRpcRequestLatency
	defer func() { gRpcRequestLatency = ogReqLatency }()

	testableLatency := &metric.TestableObserverVec{}
	gRpcRequestLatency = testableLatency

	interceptor := InstrumentClusterClient()
	i := &metric.TestInvoker{T: t, RetErr: fmt.Errorf("oops!")}

	start := time.Now()
	err := interceptor(context.Background(), "/some.service.path/method", wrapperspb.Bytes([]byte{1}), nil, nil, i.Invoke, []grpc.CallOption{}...)
	require.EqualError(t, err, "oops!")
	require.True(t, i.Called)

	// We still assert request latency in error states.
	require.Len(t, testableLatency.Observations, 1)
	assert.Greater(t, testableLatency.Observations[0].Observation, float64(0))
	assert.LessOrEqual(t, testableLatency.Observations[0].Observation, time.Since(start).Seconds())
}
