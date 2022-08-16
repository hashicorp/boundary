package metric

import (
	"github.com/hashicorp/boundary/globals"
	"github.com/hashicorp/boundary/internal/daemon/metric"
	"github.com/hashicorp/boundary/internal/gen/controller/servers/services"
	"github.com/prometheus/client_golang/prometheus"
	"google.golang.org/grpc"
)

const (
	clusterClientSubsystem = "cluster_client"
	workerClusterSubsystem = "worker_cluster"
)

var grpcLabels = metric.LabelNames{
	Service: "grpc_service",
	Method:  "grpc_method",
	Code:    "grpc_code",
}

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
	grpcLabels.ToList(),
)

var grpcServerRequestLatency prometheus.ObserverVec = prometheus.NewHistogramVec(
	prometheus.HistogramOpts{
		Namespace: globals.MetricNamespace,
		Subsystem: workerClusterSubsystem,
		Name:      "grpc_request_duration_seconds",
		Help:      "Histogram of latencies for gRPC requests between the a worker server and a worker client.",
		Buckets:   prometheus.DefBuckets,
	},
	grpcLabels.ToList(),
)

// InstrumentClusterClient wraps a UnaryClientInterceptor and records
// observations for the collectors associated with gRPC connections
// between the cluster and its clients.
func InstrumentClusterClient() grpc.UnaryClientInterceptor {
	return metric.InstrumentClusterClient(metric.RPCStatsHandler{Metric: grpcRequestLatency, Labels: grpcLabels})
}

// InitializeClusterClientCollectors registers the cluster client metrics to the
// prometheus register and initializes them to 0 for all possible label
// combinations.
func InitializeClusterClientCollectors(r prometheus.Registerer) {
	metric.InitializeGrpcCollectorsFromPackage(r, grpcRequestLatency, grpcLabels, services.File_controller_servers_services_v1_session_service_proto)
}

// InstrumentClusterStatsHandler returns a gRPC stats.Handler which observes
// cluster-specific metrics for a gRPC server.
func InstrumentClusterStatsHandler() metric.RPCStatsHandler {
	return metric.RPCStatsHandler{Metric: grpcServerRequestLatency, Labels: grpcLabels}
}

// InitializeClusterServerCollectors registers the cluster server metrics to the
// prometheus register and initializes them to 0 for all possible label
// combinations.
func InitializeClusterServerCollectors(r prometheus.Registerer, server *grpc.Server) {
	metric.InitializeGrpcCollectorsFromServer(r, grpcServerRequestLatency, grpcLabels, server)
}
