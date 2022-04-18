package metric

import (
	"context"
	"strings"
	"time"

	"github.com/hashicorp/boundary/globals"
	"github.com/hashicorp/boundary/internal/errors"
	"github.com/hashicorp/boundary/internal/observability/event"
	"github.com/prometheus/client_golang/prometheus"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/proto"
)

const (
	labelGRpcCode    = "grpc_code"
	labelGRpcService = "grpc_service"
	labelGRpcMethod  = "grpc_method"
	clusterSubSystem = "controller_cluster"
)

var (
	// 100 bytes, 1kb, 10kb, 100kb, 1mb, 10mb
	gRpcMsgSizeBuckets = prometheus.ExponentialBuckets(100, 10, 6)

	// gRpcRequestLatency collects measurements of how long it takes
	// the boundary system to reply to a request to the controller cluster
	// from the time that boundary received the request.
	gRpcRequestLatency prometheus.ObserverVec = prometheus.NewHistogramVec(
		prometheus.HistogramOpts{
			Namespace: globals.MetricNamespace,
			Subsystem: clusterSubSystem,
			Name:      "grpc_request_duration_seconds",
			Help:      "Histogram of latencies for gRPC requests.",
			Buckets:   prometheus.DefBuckets,
		},
		[]string{labelGRpcCode, labelGRpcService, labelGRpcMethod},
	)

	// gRpcRequestSize collections measurements of how large each request
	// to the boundary controller cluster is.
	gRpcRequestSize prometheus.ObserverVec = prometheus.NewHistogramVec(
		prometheus.HistogramOpts{
			Namespace: globals.MetricNamespace,
			Subsystem: clusterSubSystem,
			Name:      "grpc_request_size_bytes",
			Help:      "Histogram of request sizes for gRPC requests.",
			Buckets:   gRpcMsgSizeBuckets,
		},
		[]string{labelGRpcCode, labelGRpcService, labelGRpcMethod},
	)

	// gRpcResponseSize collections measurements of how large each response
	// from the boundary controller cluster is.
	gRpcResponseSize prometheus.ObserverVec = prometheus.NewHistogramVec(
		prometheus.HistogramOpts{
			Namespace: globals.MetricNamespace,
			Subsystem: clusterSubSystem,
			Name:      "grpc_response_size_bytes",
			Help:      "Histogram of response sizes for gRPC responses.",
			Buckets:   gRpcMsgSizeBuckets,
		},
		[]string{labelGRpcCode, labelGRpcService, labelGRpcMethod},
	)
)

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

type requestRecorder struct {
	labels prometheus.Labels

	// measurements
	reqSize *int
	start   time.Time
}

func newRequestRecorder(ctx context.Context, req interface{}, fullMethodName string) requestRecorder {
	const op = "metric.newRequestRecorder"
	service, method := splitMethodName(fullMethodName)
	r := requestRecorder{
		labels: prometheus.Labels{
			labelGRpcMethod:  method,
			labelGRpcService: service,
		},
		start: time.Now(),
	}

	reqProto, ok := req.(proto.Message)
	switch {
	case ok:
		reqSize := proto.Size(reqProto)
		r.reqSize = &reqSize
	default:
		event.WriteError(ctx, op, errors.New(ctx, errors.Internal, op, "unable to cast to proto.Message"))
	}
	return r
}

func (r requestRecorder) record(ctx context.Context, resp interface{}, err error) {
	const op = "metric.(requestRecorder).record"
	st := statusFromError(err)
	r.labels[labelGRpcCode] = st.Code().String()

	gRpcRequestLatency.With(r.labels).Observe(time.Since(r.start).Seconds())

	if r.reqSize != nil {
		gRpcRequestSize.With(r.labels).Observe(float64(*r.reqSize))
	}

	if respProto, ok := resp.(proto.Message); ok {
		respSize := proto.Size(respProto)
		gRpcResponseSize.With(r.labels).Observe(float64(respSize))
	} else {
		event.WriteError(ctx, op, errors.New(ctx, errors.Internal, op, "unable to cast to proto.Message"))
	}
}

// InstrumentClusterInterceptor wraps a UnaryServerInterceptor and records
// observations for the collectors associated with the cluster's grpc service.
func InstrumentClusterInterceptor() grpc.UnaryServerInterceptor {
	return func(ctx context.Context, req interface{}, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (interface{}, error) {
		recorder := newRequestRecorder(ctx, req, info.FullMethod)
		resp, err := handler(ctx, req)
		recorder.record(ctx, resp, err)
		return resp, err
	}
}

var allCodes = []codes.Code{
	codes.OK, codes.Canceled, codes.Unknown, codes.InvalidArgument, codes.DeadlineExceeded, codes.NotFound,
	codes.AlreadyExists, codes.PermissionDenied, codes.Unauthenticated, codes.ResourceExhausted,
	codes.FailedPrecondition, codes.Aborted, codes.OutOfRange, codes.Unimplemented, codes.Internal,
	codes.Unavailable, codes.DataLoss,
}

// InitializeClusterCollectors registers the cluster metrics to the default
// prometheus register and initializes them to 0 for all possible label
// combinations.
func InitializeClusterCollectors(r prometheus.Registerer, server *grpc.Server) {
	if r == nil {
		return
	}
	r.MustRegister(gRpcRequestLatency, gRpcRequestSize, gRpcResponseSize)

	for serviceName, info := range server.GetServiceInfo() {
		for _, mInfo := range info.Methods {
			for _, c := range allCodes {
				l := prometheus.Labels{
					labelGRpcMethod:  mInfo.Name,
					labelGRpcService: serviceName,
					labelGRpcCode:    c.String(),
				}
				gRpcRequestLatency.With(l)
				gRpcRequestSize.With(l)
				gRpcResponseSize.With(l)
			}
		}
	}
}
