// Copyright IBM Corp. 2020, 2025
// SPDX-License-Identifier: BUSL-1.1

package metric

import (
	"context"
	"testing"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
)

// testableObserverVec allows us to assert which observations are being made
// with which labels.
type TestableObserverVec struct {
	Observations []*testableObserver
	prometheus.ObserverVec
}

func (v *TestableObserverVec) With(l prometheus.Labels) prometheus.Observer {
	ret := &testableObserver{Labels: l}
	v.Observations = append(v.Observations, ret)
	return ret
}

type testableObserver struct {
	Labels      prometheus.Labels
	Observation float64
}

func (o *testableObserver) Observe(f float64) {
	o.Observation = f
}

type TestInvoker struct {
	T      *testing.T
	Called bool
	RetErr error
}

func (i *TestInvoker) Invoke(ctx context.Context, method string, req, reply any, cc *grpc.ClientConn, opts ...grpc.CallOption) error {
	i.Called = true

	require.NotNil(i.T, ctx)
	require.NotEmpty(i.T, method)
	require.NotNil(i.T, req)
	return i.RetErr
}
