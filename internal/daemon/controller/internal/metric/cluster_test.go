package metric

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/stretchr/testify/assert"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/stats"
	"google.golang.org/grpc/status"
)

func TestStatsHandler(t *testing.T) {
	bkpLatency := grpcRequestLatency
	defer func() {
		grpcRequestLatency = bkpLatency
	}()

	handler := InstrumentClusterStatsHandler()

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
				grpcLabels.Code:    "OK",
				grpcLabels.Method:  "method",
				grpcLabels.Service: "some.service.path",
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
				grpcLabels.Code:    "OK",
				grpcLabels.Method:  "method",
				grpcLabels.Service: "some.service.path",
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
				grpcLabels.Code:    "OK",
				grpcLabels.Method:  "unknown",
				grpcLabels.Service: "unknown",
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
				grpcLabels.Code:    "Canceled",
				grpcLabels.Method:  "method",
				grpcLabels.Service: "some.service.path",
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
				grpcLabels.Code:    "InvalidArgument",
				grpcLabels.Method:  "method",
				grpcLabels.Service: "some.service.path",
			},
			wantedLatency: (4 * time.Second).Seconds(),
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			testableLatency := &testableObserverVec{}
			handler.Metric = testableLatency

			ctx := context.Background()
			ctx = handler.TagRPC(ctx, &stats.RPCTagInfo{
				FullMethodName: tc.fullMethodName,
			})

			for _, i := range tc.stats {
				handler.HandleRPC(ctx, i)
			}

			assert.Len(t, testableLatency.observations, 1)
			assert.Equal(t, testableLatency.observations[0].observation, tc.wantedLatency)
			assert.Equal(t, testableLatency.observations[0].labels, tc.wantedLabels)
		})
	}
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
