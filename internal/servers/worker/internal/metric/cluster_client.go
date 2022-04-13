package metric

import (
	"context"
	"strings"
	"time"

	"github.com/hashicorp/boundary/globals"
	"github.com/hashicorp/boundary/internal/errors"
	"github.com/hashicorp/boundary/internal/gen/controller/servers/services"
	"github.com/prometheus/client_golang/prometheus"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/reflect/protoreflect"
	"google.golang.org/protobuf/reflect/protoregistry"
)

const (
	labelGrpcCode    = "grpc_code"
	labelGrpcService = "grpc_service"
	labelGrpcMethod  = "grpc_method"

	clusterClientSubsystem = "cluster_client"
)

// grpcRequestLatency collects measurements of how long a gRPC
// request between a cluster and its clients takes.
var grpcRequestLatency prometheus.ObserverVec = prometheus.NewHistogramVec(
	prometheus.HistogramOpts{
		Namespace: globals.MetricNamespace,
		Subsystem: clusterClientSubsystem,
		Name:      "grpc_request_duration_seconds",
		Help:      "Histogram of latencies for gRPC requests between the cluster and any of its clients.",
		Buckets:   prometheus.DefBuckets,
	},
	[]string{labelGrpcCode, labelGrpcService, labelGrpcMethod},
)

// statusFromError retrieves the *status.Status from the provided error. It'll
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
	start time.Time
}

func newRequestRecorder(fullMethodName string) requestRecorder {
	service, method := splitMethodName(fullMethodName)
	r := requestRecorder{
		labels: prometheus.Labels{
			labelGrpcMethod:  method,
			labelGrpcService: service,
		},
		start: time.Now(),
	}

	return r
}

func (r requestRecorder) record(err error) {
	r.labels[labelGrpcCode] = statusFromError(err).Code().String()
	grpcRequestLatency.With(r.labels).Observe(time.Since(r.start).Seconds())
}

// InstrumentClusterClient wraps a UnaryClientInterceptor and records
// observations for the collectors associated with gRPC connections
// between the cluster and its clients.
func InstrumentClusterClient() grpc.UnaryClientInterceptor {
	return func(ctx context.Context, method string, req, reply interface{}, cc *grpc.ClientConn, invoker grpc.UnaryInvoker, opts ...grpc.CallOption) error {
		r := newRequestRecorder(method)
		err := invoker(ctx, method, req, reply, cc, opts...)
		r.record(err)
		return err
	}
}

var allCodes = []codes.Code{
	codes.OK, codes.Canceled, codes.Unknown, codes.InvalidArgument, codes.DeadlineExceeded, codes.NotFound,
	codes.AlreadyExists, codes.PermissionDenied, codes.Unauthenticated, codes.ResourceExhausted,
	codes.FailedPrecondition, codes.Aborted, codes.OutOfRange, codes.Unimplemented, codes.Internal,
	codes.Unavailable, codes.DataLoss,
}

func InitializeClusterClientCollectors(r prometheus.Registerer) {
	if r == nil {
		return
	}
	r.MustRegister(grpcRequestLatency)

	serviceNamesToMethodNames := make(map[string][]string, 0)
	protoregistry.GlobalFiles.RangeFilesByPackage(
		services.File_controller_servers_services_v1_session_service_proto.Package(),
		func(fd protoreflect.FileDescriptor) bool { return rangeProtofiles(serviceNamesToMethodNames, fd) },
	)

	for serviceName, serviceMethods := range serviceNamesToMethodNames {
		for _, sm := range serviceMethods {
			for _, c := range allCodes {
				grpcRequestLatency.With(prometheus.Labels{
					labelGrpcCode:    c.String(),
					labelGrpcMethod:  sm,
					labelGrpcService: serviceName,
				})
			}
		}
	}
}

func rangeProtofiles(m map[string][]string, fd protoreflect.FileDescriptor) bool {
	if fd.Services().Len() == 0 {
		return true
	}

	for i := 0; i < fd.Services().Len(); i++ {
		s := fd.Services().Get(i)
		if s.Methods().Len() == 0 {
			continue
		}

		methods := []string{}
		for j := 0; j < s.Methods().Len(); j++ {
			methods = append(methods, string(s.Methods().Get(j).Name()))
		}
		m[string(s.FullName())] = methods
	}

	return true
}
