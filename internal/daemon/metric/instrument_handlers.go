// Package metric provides functions to initialize the controller specific
// collectors and hooks to measure metrics and update the relevant collectors.
package metric

import (
	"context"
	"strings"
	"time"

	"github.com/hashicorp/boundary/internal/errors"
	"github.com/hashicorp/boundary/internal/util"
	"github.com/prometheus/client_golang/prometheus"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/stats"
	"google.golang.org/grpc/status"
)

/* The following methods are used to instrument handlers for gRPC server and client connections. */

// statsHandler satisfies grpc's stats.Handler interface. This helps measure the latency of grpc requests as close to the
// wire as possible, and allows us to capture error codes returned by the grpc go library which our service may
// never return, or error codes for requests that our service may never even see.
type statsHandler struct {
	reqLatency prometheus.ObserverVec
}

// NewStatsHandler takes a request latency metric (prometheus.ObserverVec) and
// returns a grpc stats.Handler that updates the provided metric with the
// request latency.
func NewStatsHandler(ctx context.Context, o prometheus.ObserverVec) (*statsHandler, error) {
	const op = "metric.NewStatsHandler"
	if util.IsNil(o) {
		return nil, errors.New(ctx, errors.InvalidParameter, op, "prometheus.ObserverVec is nil")
	}
	return &statsHandler{reqLatency: o}, nil
}

var _ stats.Handler = (*statsHandler)(nil)

type metricMethodNameContextKey struct{}

func (sh *statsHandler) TagRPC(ctx context.Context, i *stats.RPCTagInfo) context.Context {
	return context.WithValue(ctx, metricMethodNameContextKey{}, i.FullMethodName)
}

func (sh *statsHandler) TagConn(ctx context.Context, _ *stats.ConnTagInfo) context.Context {
	return ctx
}

func (sh *statsHandler) HandleConn(context.Context, stats.ConnStats) {
}

func (sh *statsHandler) HandleRPC(ctx context.Context, s stats.RPCStats) {
	switch v := s.(type) {
	case *stats.End:
		// Accept the ok, but ignore it. This code doesn't need to panic
		// and if "fullName" is an empty string SplitMethodName will
		// set service and method to "unknown".
		fullName, _ := ctx.Value(metricMethodNameContextKey{}).(string)
		service, method := SplitMethodName(fullName)
		labels := prometheus.Labels{
			LabelGrpcMethod:  method,
			LabelGrpcService: service,
			LabelGrpcCode:    StatusFromError(v.Error).Code().String(),
		}
		sh.reqLatency.With(labels).Observe(v.EndTime.Sub(v.BeginTime).Seconds())
	}
}

type requestRecorder struct {
	reqLatency prometheus.ObserverVec
	labels     prometheus.Labels

	// measurements
	start time.Time
}

// NewGrpcRequestRecorder creates a requestRecorder struct which is used to measure gRPC client request latencies.
func NewGrpcRequestRecorder(fullMethodName string, reqLatency prometheus.ObserverVec) requestRecorder {
	service, method := SplitMethodName(fullMethodName)
	r := requestRecorder{
		reqLatency: reqLatency,
		labels: prometheus.Labels{
			LabelGrpcMethod:  method,
			LabelGrpcService: service,
		},
		start: time.Now(),
	}

	return r
}

func (r requestRecorder) Record(err error) {
	r.labels[LabelGrpcCode] = StatusFromError(err).Code().String()
	r.reqLatency.With(r.labels).Observe(time.Since(r.start).Seconds())
}

// StatusFromError retrieves the *status.Status from the provided error.  It'll
// attempt to unwrap the *status.Error, which is something status.FromError
// does not do.
func StatusFromError(err error) *status.Status {
	if s, ok := status.FromError(err); ok {
		return s
	}

	type gRPCStatus interface {
		GRPCStatus() *status.Status
	}
	var unwrappedStatus gRPCStatus
	if ok := errors.As(err, &unwrappedStatus); ok {
		return unwrappedStatus.GRPCStatus()
	}

	return status.New(codes.Unknown, "Unknown Code")
}

// SplitMethodName returns the service and the method name when given the full
// method name as provided by the grpc request handler.
func SplitMethodName(fullMethodName string) (string, string) {
	fullMethodName = strings.TrimPrefix(fullMethodName, "/") // remove leading slash
	if i := strings.Index(fullMethodName, "/"); i >= 0 {
		return fullMethodName[:i], fullMethodName[i+1:]
	}
	return "unknown", "unknown"
}
