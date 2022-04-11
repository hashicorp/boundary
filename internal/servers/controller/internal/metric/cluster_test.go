package metric

import (
	"context"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/wrapperspb"
)

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

func floatPtr(i int) *float64 {
	f := float64(i)
	return &f
}

func TestRecorder(t *testing.T) {
	bkpLatency := gRpcRequestLatency
	bkpRespSize := gRpcResponseSize
	bkpReqSize := gRpcRequestSize
	defer func() {
		gRpcRequestLatency = bkpLatency
		gRpcResponseSize = bkpRespSize
		gRpcRequestSize = bkpReqSize
	}()
	ctx := context.Background()

	cases := []struct {
		name           string
		methodName     string
		req            interface{}
		resp           interface{}
		err            error
		wantedLabels   prometheus.Labels
		wantedReqSize  *float64
		wantedRespSize *float64
	}{
		{
			name:       "basic",
			methodName: "/some.service.path/method",
			req:        wrapperspb.Bytes([]byte{1, 2, 3}),
			resp:       wrapperspb.Bytes([]byte{1, 2, 3, 4}),
			err:        nil,
			wantedLabels: map[string]string{
				labelGRpcCode:    "OK",
				labelGRpcMethod:  "method",
				labelGRpcService: "some.service.path",
			},
			wantedReqSize:  floatPtr(proto.Size(wrapperspb.Bytes([]byte{1, 2, 3}))),
			wantedRespSize: floatPtr(proto.Size(wrapperspb.Bytes([]byte{1, 2, 3, 4}))),
		},
		{
			name:       "empty request",
			methodName: "/some.service.path/method",
			req:        wrapperspb.Bytes(nil),
			resp:       wrapperspb.Bytes([]byte{1, 2, 3, 4}),
			err:        nil,
			wantedLabels: map[string]string{
				labelGRpcCode:    "OK",
				labelGRpcMethod:  "method",
				labelGRpcService: "some.service.path",
			},
			wantedReqSize:  floatPtr(0),
			wantedRespSize: floatPtr(proto.Size(wrapperspb.Bytes([]byte{1, 2, 3, 4}))),
		},
		{
			name:       "empty response",
			methodName: "/some.service.path/method",
			req:        wrapperspb.Bytes([]byte{1, 2, 3}),
			resp:       wrapperspb.Bytes(nil),
			err:        nil,
			wantedLabels: map[string]string{
				labelGRpcCode:    "OK",
				labelGRpcMethod:  "method",
				labelGRpcService: "some.service.path",
			},
			wantedReqSize:  floatPtr(proto.Size(wrapperspb.Bytes([]byte{1, 2, 3}))),
			wantedRespSize: floatPtr(0),
		},
		{
			name:       "unrecognized method path format",
			methodName: "unrecognized",
			req:        wrapperspb.Bytes([]byte{1, 2, 3}),
			resp:       wrapperspb.Bytes([]byte{1, 2, 3, 4}),
			err:        nil,
			wantedLabels: map[string]string{
				labelGRpcCode:    "OK",
				labelGRpcMethod:  "unknown",
				labelGRpcService: "unknown",
			},
			wantedReqSize:  floatPtr(proto.Size(wrapperspb.Bytes([]byte{1, 2, 3}))),
			wantedRespSize: floatPtr(proto.Size(wrapperspb.Bytes([]byte{1, 2, 3, 4}))),
		},
		{
			name:       "cancel error",
			methodName: "/some.service.path/method",
			req:        wrapperspb.Bytes([]byte{1, 2, 3}),
			resp:       (*wrapperspb.BytesValue)(nil),
			err:        status.Error(codes.Canceled, ""),
			wantedLabels: map[string]string{
				labelGRpcCode:    "Canceled",
				labelGRpcMethod:  "method",
				labelGRpcService: "some.service.path",
			},
			wantedReqSize:  floatPtr(proto.Size(wrapperspb.Bytes([]byte{1, 2, 3}))),
			wantedRespSize: floatPtr(0),
		},
		{
			name:       "permission error",
			methodName: "/some.service.path/method",
			req:        wrapperspb.Bytes([]byte{1, 2, 3}),
			resp:       (*wrapperspb.BytesValue)(nil),
			err:        status.Error(codes.PermissionDenied, ""),
			wantedLabels: map[string]string{
				labelGRpcCode:    "PermissionDenied",
				labelGRpcMethod:  "method",
				labelGRpcService: "some.service.path",
			},
			wantedReqSize:  floatPtr(proto.Size(wrapperspb.Bytes([]byte{1, 2, 3}))),
			wantedRespSize: floatPtr(0),
		},
		{
			name:       "error and response",
			methodName: "/some.service.path/method",
			req:        wrapperspb.Bytes([]byte{1, 2, 3}),
			resp:       wrapperspb.Bytes([]byte{1, 2, 3, 4}),
			err:        status.Error(codes.PermissionDenied, ""),
			wantedLabels: map[string]string{
				labelGRpcCode:    "PermissionDenied",
				labelGRpcMethod:  "method",
				labelGRpcService: "some.service.path",
			},
			wantedReqSize:  floatPtr(proto.Size(wrapperspb.Bytes([]byte{1, 2, 3}))),
			wantedRespSize: floatPtr(proto.Size(wrapperspb.Bytes([]byte{1, 2, 3, 4}))),
		},
		{
			name:       "bad request",
			methodName: "/some.service.path/method",
			req:        "foo",
			resp:       wrapperspb.Bytes([]byte{1, 2, 3, 4}),
			err:        status.Error(codes.PermissionDenied, ""),
			wantedLabels: map[string]string{
				labelGRpcCode:    "PermissionDenied",
				labelGRpcMethod:  "method",
				labelGRpcService: "some.service.path",
			},
			wantedReqSize:  nil,
			wantedRespSize: floatPtr(proto.Size(wrapperspb.Bytes([]byte{1, 2, 3, 4}))),
		},
		{
			name:       "bad response",
			methodName: "/some.service.path/method",
			req:        wrapperspb.Bytes([]byte{1, 2, 3, 4}),
			resp:       "foo",
			err:        status.Error(codes.PermissionDenied, ""),
			wantedLabels: map[string]string{
				labelGRpcCode:    "PermissionDenied",
				labelGRpcMethod:  "method",
				labelGRpcService: "some.service.path",
			},
			wantedReqSize:  floatPtr(proto.Size(wrapperspb.Bytes([]byte{1, 2, 3, 4}))),
			wantedRespSize: nil,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			testableLatency := &testableObserverVec{}
			testableReqSize := &testableObserverVec{}
			testableRespSize := &testableObserverVec{}
			gRpcRequestLatency = testableLatency
			gRpcResponseSize = testableRespSize
			gRpcRequestSize = testableReqSize

			// record something
			start := time.Now()
			tested := newRequestRecorder(ctx, tc.req, tc.methodName)
			tested.record(ctx, tc.resp, tc.err)

			require.Len(t, testableLatency.observations, 1)
			assert.LessOrEqual(t, testableLatency.observations[0].observation, time.Since(start).Seconds())
			assert.Greater(t, testableLatency.observations[0].observation, float64(0))
			assert.Equal(t, testableLatency.observations[0].labels, tc.wantedLabels)

			if tc.wantedReqSize == nil {
				require.Len(t, testableReqSize.observations, 0)
			} else {
				require.Len(t, testableReqSize.observations, 1)
				assert.Equal(t, testableReqSize.observations[0],
					&testableObserver{observation: *tc.wantedReqSize, labels: tc.wantedLabels})
			}

			if tc.wantedRespSize == nil {
				require.Len(t, testableRespSize.observations, 0)
			} else {
				require.Len(t, testableRespSize.observations, 1)
				assert.Equal(t, testableRespSize.observations[0],
					&testableObserver{observation: *tc.wantedRespSize, labels: tc.wantedLabels})
			}
		})
	}
}
