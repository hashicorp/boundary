package metric

import (
	"context"
	"strings"
	"time"

	"github.com/hashicorp/boundary/globals"
	"github.com/prometheus/client_golang/prometheus"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/proto"
)

const (
	invalidValue = "invalid"

	labelGRpcCode    = "grpc_code"
	labelGRpcService = "grpc_service"
	labelGRpcMethod  = "grpc_method"
	clusterSubSystem = "controller_cluster"
)

var (
	gRpcMsgSizeBuckets = prometheus.ExponentialBuckets(100, 10, 8)

	// gRpcRequestLatency collects measurements of how long it takes
	// the boundary system to reply to a request to the controller api
	// from the time that boundary received the request.
	gRpcRequestLatency prometheus.ObserverVec = prometheus.NewHistogramVec(
		prometheus.HistogramOpts{
			Namespace: globals.MetricNamespace,
			Subsystem: clusterSubSystem,
			Name:      "grpc_request_duration_seconds",
			Help:      "Histogram of latencies for HTTP requests.",
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
			Help:      "Histogram of request sizes for HTTP requests.",
			// 100 bytes, 1kb, 10kb, 100kb, 1mb, 10mb, 100mb, 1gb
			Buckets: gRpcMsgSizeBuckets,
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
			Help:      "Histogram of response sizes for HTTP responses.",
			// 100 bytes, 1kb, 10kb, 100kb, 1mb, 10mb, 100mb, 1gb
			Buckets: gRpcMsgSizeBuckets,
		},
		[]string{labelGRpcCode, labelGRpcService, labelGRpcMethod},
	)
)

func statusFromError(err error) *status.Status {
	if s, ok := status.FromError(err); ok {
		return s
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
	reqSize int
	start   time.Time
}

func newRequestRecorder(req interface{}, fullMethodName string) requestRecorder {
	reqProto, ok := req.(proto.Message)
	if !ok {
		// do something
	}
	reqSize := proto.Size(reqProto)
	service, method := splitMethodName(fullMethodName)
	return requestRecorder{
		labels: prometheus.Labels{
			labelGRpcMethod:  method,
			labelGRpcService: service,
		},
		start:   time.Now(),
		reqSize: reqSize,
	}
}

func (r requestRecorder) record(resp interface{}, err error) {
	st := statusFromError(err)
	r.labels[labelGRpcCode] = st.Code().String()

	respProto, ok := resp.(proto.Message)
	if !ok {
		// do something
	}
	respSize := proto.Size(respProto)

	gRpcRequestSize.With(r.labels).Observe(float64(r.reqSize))
	gRpcResponseSize.With(r.labels).Observe(float64(respSize))
	gRpcRequestLatency.With(r.labels).Observe(time.Since(r.start).Seconds())
}

// InstrumentClusterInterceptor wraps a UnaryServerInterceptor and measures
func InstrumentClusterInterceptor() grpc.UnaryServerInterceptor {
	return func(ctx context.Context, req interface{}, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (interface{}, error) {
		recorder := newRequestRecorder(req, info.FullMethod)
		resp, err := handler(ctx, req)
		recorder.record(resp, err)
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
