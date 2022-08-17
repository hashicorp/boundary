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
				grpcLabels.Code:    "OK",
				grpcLabels.Method:  "method",
				grpcLabels.Service: "some.service.path",
			},
		},
		{
			name:       "unrecognized method path format",
			methodName: "unrecognized",
			err:        nil,
			wantedLabels: map[string]string{
				grpcLabels.Code:    "OK",
				grpcLabels.Method:  "unknown",
				grpcLabels.Service: "unknown",
			},
		},
		{
			name:       "cancel error",
			methodName: "/some.service.path/method",
			err:        status.Error(codes.Canceled, ""),
			wantedLabels: map[string]string{
				grpcLabels.Code:    "Canceled",
				grpcLabels.Method:  "method",
				grpcLabels.Service: "some.service.path",
			},
		},
		{
			name:       "permission error",
			methodName: "/some.service.path/method",
			err:        status.Error(codes.PermissionDenied, ""),
			wantedLabels: map[string]string{
				grpcLabels.Code:    "PermissionDenied",
				grpcLabels.Method:  "method",
				grpcLabels.Service: "some.service.path",
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			ogReqLatency := grpcRequestLatency
			defer func() { grpcRequestLatency = ogReqLatency }()

			handler := metric.StatsHandler{Metric: grpcServerRequestLatency, Labels: grpcLabels}
			testableLatency := &testableObserverVec{}
			handler.Metric = testableLatency

			start := time.Now()
			tested := metric.NewRequestRecorder(tc.methodName, handler)
			tested.Record(tc.err)

			require.Len(t, testableLatency.observations, 1)
			assert.Greater(t, testableLatency.observations[0].observation, float64(0))
			assert.LessOrEqual(t, testableLatency.observations[0].observation, time.Since(start).Seconds())
			assert.Equal(t, testableLatency.observations[0].labels, tc.wantedLabels)
		})
	}
}

func TestInstrumentClusterClient(t *testing.T) {
	ogReqLatency := grpcRequestLatency
	defer func() { grpcRequestLatency = ogReqLatency }()

	testableLatency := &testableObserverVec{}
	grpcRequestLatency = testableLatency

	interceptor := InstrumentClusterClient()
	i := &testInvoker{t: t, retErr: nil}

	start := time.Now()
	err := interceptor(context.Background(), "/some.service.path/method", wrapperspb.Bytes([]byte{1}), nil, nil, i.invoke, []grpc.CallOption{}...)
	require.NoError(t, err)
	require.True(t, i.called)

	require.Len(t, testableLatency.observations, 1)
	assert.Greater(t, testableLatency.observations[0].observation, float64(0))
	assert.LessOrEqual(t, testableLatency.observations[0].observation, time.Since(start).Seconds())
}

func TestInstrumentClusterClient_InvokerError(t *testing.T) {
	ogReqLatency := grpcRequestLatency
	defer func() { grpcRequestLatency = ogReqLatency }()

	testableLatency := &testableObserverVec{}
	grpcRequestLatency = testableLatency

	interceptor := InstrumentClusterClient()
	i := &testInvoker{t: t, retErr: fmt.Errorf("oops!")}

	start := time.Now()
	err := interceptor(context.Background(), "/some.service.path/method", wrapperspb.Bytes([]byte{1}), nil, nil, i.invoke, []grpc.CallOption{}...)
	require.EqualError(t, err, "oops!")
	require.True(t, i.called)

	// We still assert request latency in error states.
	require.Len(t, testableLatency.observations, 1)
	assert.Greater(t, testableLatency.observations[0].observation, float64(0))
	assert.LessOrEqual(t, testableLatency.observations[0].observation, time.Since(start).Seconds())
}

type testInvoker struct {
	t      *testing.T
	called bool
	retErr error
}

func (i *testInvoker) invoke(ctx context.Context, method string, req, reply interface{}, cc *grpc.ClientConn, opts ...grpc.CallOption) error {
	i.called = true

	require.NotNil(i.t, ctx)
	require.NotEmpty(i.t, method)
	require.NotNil(i.t, req)
	return i.retErr
}

// testableObserverVec allows us to assert which observations are being made
// with which labels.
type testableObserverVec struct {
	observations []*testableObserver
	prometheus.ObserverVec
}

func (v *testableObserverVec) With(l prometheus.Labels) prometheus.Observer {
	ret := &testableObserver{labels: l}
	v.observations = append(v.observations, ret)
	return ret
}

type testableObserver struct {
	labels      prometheus.Labels
	observation float64
}

func (o *testableObserver) Observe(f float64) {
	o.observation = f
}
