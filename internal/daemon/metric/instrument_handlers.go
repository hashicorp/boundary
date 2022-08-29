// Package metric provides functions to initialize the controller specific
// collectors and hooks to measure metrics and update the relevant collectors.
package metric

import (
	"context"
	"strings"
	"time"

	"github.com/hashicorp/boundary/internal/errors"
	"github.com/prometheus/client_golang/prometheus"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/stats"
	"google.golang.org/grpc/status"
)

/* The following methods are used to instrument handlers for gRPC server and client connections. */

// StatsHandler satisfies grpc's stats.Handler interface. This helps measure the latency of grpc requests as close to the
// wire as possible, and allows us to capture error codes returned by the grpc go library which our service may
// never return, or error codes for requests that our service may never even see.
type StatsHandler struct {
	Metric prometheus.ObserverVec
}

var _ stats.Handler = (*StatsHandler)(nil)

type metricMethodNameContextKey struct{}

func (sh StatsHandler) TagRPC(ctx context.Context, i *stats.RPCTagInfo) context.Context {
	return context.WithValue(ctx, metricMethodNameContextKey{}, i.FullMethodName)
}

func (sh StatsHandler) TagConn(ctx context.Context, _ *stats.ConnTagInfo) context.Context {
	return ctx
}

func (sh StatsHandler) HandleConn(context.Context, stats.ConnStats) {
}

func (sh StatsHandler) HandleRPC(ctx context.Context, s stats.RPCStats) {
	switch v := s.(type) {
	case *stats.End:
		// Accept the ok, but ignore it. This code doesn't need to panic
		// and if "fullName" is an empty string splitMethodName will
		// set service and method to "unknown".
		fullName, _ := ctx.Value(metricMethodNameContextKey{}).(string)
		service, method := splitMethodName(fullName)
		labels := prometheus.Labels{
			LabelGrpcMethod:  method,
			LabelGrpcService: service,
			LabelGrpcCode:    statusFromError(v.Error).Code().String(),
		}
		sh.Metric.With(labels).Observe(v.EndTime.Sub(v.BeginTime).Seconds())
	}
}

type requestRecorder struct {
	handler StatsHandler
	labels  prometheus.Labels

	// measurements
	start time.Time
}

// NewRequestRecorder creates a requestRecorder struct which is used to measure gRPC client request latencies.
// For testing purposes, this method is exported.
func NewRequestRecorder(fullMethodName string, handler StatsHandler) requestRecorder {
	service, method := splitMethodName(fullMethodName)
	r := requestRecorder{
		handler: handler,
		labels: prometheus.Labels{
			LabelGrpcMethod:  method,
			LabelGrpcService: service,
		},
		start: time.Now(),
	}

	return r
}

func (r requestRecorder) Record(err error) {
	r.labels[LabelGrpcCode] = statusFromError(err).Code().String()
	r.handler.Metric.With(r.labels).Observe(time.Since(r.start).Seconds())
}

// statusFromError retrieves the *status.Status from the provided error.  It'll
// attempt to unwrap the *status.Error, which is something status.FromError
// does not do.
func statusFromError(err error) *status.Status {
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

func splitMethodName(fullMethodName string) (string, string) {
	fullMethodName = strings.TrimPrefix(fullMethodName, "/") // remove leading slash
	if i := strings.Index(fullMethodName, "/"); i >= 0 {
		return fullMethodName[:i], fullMethodName[i+1:]
	}
	return "unknown", "unknown"
}

// InstrumentClusterClient wraps a UnaryClientInterceptor and records
// observations for the collectors associated with gRPC connections
// between the cluster and its clients.
func InstrumentClusterClient(sh StatsHandler) grpc.UnaryClientInterceptor {
	return func(ctx context.Context, method string, req, reply interface{}, cc *grpc.ClientConn, invoker grpc.UnaryInvoker, opts ...grpc.CallOption) error {
		r := NewRequestRecorder(method, sh)
		err := invoker(ctx, method, req, reply, cc, opts...)
		r.Record(err)
		return err
	}
}
