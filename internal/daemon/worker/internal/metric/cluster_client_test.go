// Copyright IBM Corp. 2020, 2025
// SPDX-License-Identifier: BUSL-1.1

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
	"google.golang.org/protobuf/types/known/wrapperspb"
)

func TestInitializeClusterClientCollectors(t *testing.T) {
	require.NotPanics(t, func() { InitializeClusterClientCollectors(nil) })
	require.NotPanics(t, func() { InitializeClusterClientCollectors(prometheus.NewRegistry()) })
}

func TestInstrumentClusterClient(t *testing.T) {
	ogReqLatency := grpcRequestLatency
	defer func() { grpcRequestLatency = ogReqLatency }()

	testableLatency := &metric.TestableObserverVec{}
	grpcRequestLatency = testableLatency

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
	ogReqLatency := grpcRequestLatency
	defer func() { grpcRequestLatency = ogReqLatency }()

	testableLatency := &metric.TestableObserverVec{}
	grpcRequestLatency = testableLatency

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
