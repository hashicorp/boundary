package metric

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/hashicorp/boundary/globals"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/stats"
	"google.golang.org/grpc/status"
)

var grpcRequestLatency prometheus.ObserverVec = prometheus.NewHistogramVec(
	prometheus.HistogramOpts{
		Namespace: globals.MetricNamespace,
		Subsystem: "test_metric",
		Name:      "grpc_request_duration_seconds",
		Help:      "Test histogram.",
		Buckets:   prometheus.DefBuckets,
	},
	ListGrpcLabels,
)

func TestNewStatsHandler(t *testing.T) {
	cases := []struct {
		name           string
		stats          []stats.RPCStats
		fullMethodName string
		wantedLabels   prometheus.Labels
		wantedLatency  float64
	}{
		{
			name:           "basic",
			fullMethodName: "/some.service.path/method",
			stats: []stats.RPCStats{
				&stats.End{
					BeginTime: time.Time{}.Add(time.Second),
					EndTime:   time.Time{}.Add(5 * time.Second),
				},
			},
			wantedLabels: map[string]string{
				LabelGrpcCode:    "OK",
				LabelGrpcMethod:  "method",
				LabelGrpcService: "some.service.path",
			},
			wantedLatency: (4 * time.Second).Seconds(),
		},
		{
			name:           "ignored stats",
			fullMethodName: "/some.service.path/method",
			stats: []stats.RPCStats{
				&stats.Begin{
					BeginTime:                 time.Time{},
					IsTransparentRetryAttempt: true,
				},
				&stats.InPayload{
					Length:     5,
					WireLength: 15,
					RecvTime:   time.Time{}.Add(time.Second).Add(500 * time.Millisecond),
				},
				&stats.OutPayload{
					Length:     5,
					WireLength: 15,
					SentTime:   time.Time{}.Add(2 * time.Second),
				},
				&stats.End{
					BeginTime: time.Time{}.Add(time.Second),
					EndTime:   time.Time{}.Add(5 * time.Second),
				},
			},
			wantedLabels: map[string]string{
				LabelGrpcCode:    "OK",
				LabelGrpcMethod:  "method",
				LabelGrpcService: "some.service.path",
			},
			wantedLatency: (4 * time.Second).Seconds(),
		},
		{
			name:           "bad method name",
			fullMethodName: "",
			stats: []stats.RPCStats{
				&stats.End{
					BeginTime: time.Time{}.Add(time.Second),
					EndTime:   time.Time{}.Add(5 * time.Second),
				},
			},
			wantedLabels: map[string]string{
				LabelGrpcCode:    "OK",
				LabelGrpcMethod:  "unknown",
				LabelGrpcService: "unknown",
			},
			wantedLatency: (4 * time.Second).Seconds(),
		},
		{
			name:           "error code",
			fullMethodName: "/some.service.path/method",
			stats: []stats.RPCStats{
				&stats.End{
					BeginTime: time.Time{}.Add(time.Second),
					EndTime:   time.Time{}.Add(5 * time.Second),
					Error:     status.Error(codes.Canceled, "test"),
				},
			},
			wantedLabels: map[string]string{
				LabelGrpcCode:    "Canceled",
				LabelGrpcMethod:  "method",
				LabelGrpcService: "some.service.path",
			},
			wantedLatency: (4 * time.Second).Seconds(),
		},
		{
			name:           "wrapped error",
			fullMethodName: "/some.service.path/method",
			stats: []stats.RPCStats{
				&stats.End{
					BeginTime: time.Time{}.Add(time.Second),
					EndTime:   time.Time{}.Add(5 * time.Second),
					Error:     fmt.Errorf("%w", status.Error(codes.InvalidArgument, "test")),
				},
			},
			wantedLabels: map[string]string{
				LabelGrpcCode:    "InvalidArgument",
				LabelGrpcMethod:  "method",
				LabelGrpcService: "some.service.path",
			},
			wantedLatency: (4 * time.Second).Seconds(),
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			ctx := context.Background()
			testableLatency := &TestableObserverVec{}
			handler, err := NewStatsHandler(ctx, testableLatency)
			require.NoError(t, err)

			ctx = handler.TagRPC(ctx, &stats.RPCTagInfo{
				FullMethodName: tc.fullMethodName,
			})

			for _, i := range tc.stats {
				handler.HandleRPC(ctx, i)
			}

			assert.Len(t, testableLatency.Observations, 1)
			assert.Equal(t, testableLatency.Observations[0].Observation, tc.wantedLatency)
			assert.Equal(t, testableLatency.Observations[0].Labels, tc.wantedLabels)
		})
	}
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
				LabelGrpcCode:    "OK",
				LabelGrpcMethod:  "method",
				LabelGrpcService: "some.service.path",
			},
		},
		{
			name:       "unrecognized method path format",
			methodName: "unrecognized",
			err:        nil,
			wantedLabels: map[string]string{
				LabelGrpcCode:    "OK",
				LabelGrpcMethod:  "unknown",
				LabelGrpcService: "unknown",
			},
		},
		{
			name:       "cancel error",
			methodName: "/some.service.path/method",
			err:        status.Error(codes.Canceled, ""),
			wantedLabels: map[string]string{
				LabelGrpcCode:    "Canceled",
				LabelGrpcMethod:  "method",
				LabelGrpcService: "some.service.path",
			},
		},
		{
			name:       "permission error",
			methodName: "/some.service.path/method",
			err:        status.Error(codes.PermissionDenied, ""),
			wantedLabels: map[string]string{
				LabelGrpcCode:    "PermissionDenied",
				LabelGrpcMethod:  "method",
				LabelGrpcService: "some.service.path",
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			ogReqLatency := grpcRequestLatency
			defer func() { grpcRequestLatency = ogReqLatency }()
			testableLatency := &TestableObserverVec{}
			start := time.Now()
			tested := NewGrpcRequestRecorder(tc.methodName, testableLatency)
			tested.Record(tc.err)

			require.Len(t, testableLatency.Observations, 1)
			assert.Greater(t, testableLatency.Observations[0].Observation, float64(0))
			assert.LessOrEqual(t, testableLatency.Observations[0].Observation, time.Since(start).Seconds())
			assert.Equal(t, testableLatency.Observations[0].Labels, tc.wantedLabels)
		})
	}
}
