package metric

import (
	"github.com/hashicorp/boundary/globals"
	"github.com/hashicorp/boundary/internal/daemon/metric"
	"github.com/prometheus/client_golang/prometheus"
	"google.golang.org/grpc"
)

const (
	workerClusterSubsystem = "worker_cluster"
)

// Because we use grpc's stats.Handler to track close-to-the-wire server-side communication over grpc,
// there is no easy way to measure request and response size as we are recording latency. Thus we only
// track the request latency for server-side grpc connections.

var gRpcServerRequestLatency prometheus.ObserverVec = prometheus.NewHistogramVec(
	prometheus.HistogramOpts{
		Namespace: globals.MetricNamespace,
		Subsystem: workerClusterSubsystem,
		Name:      "grpc_request_duration_seconds",
		Help:      "Histogram of latencies for gRPC requests between the a worker server and a worker client.",
		Buckets:   prometheus.DefBuckets,
	},
	metric.ListGrpcLabels,
)

// InstrumentClusterStatsHandler returns a gRPC stats.Handler which observes
// cluster-specific metrics for a gRPC server.
func InstrumentClusterStatsHandler() metric.StatsHandler {
	return metric.StatsHandler{Metric: gRpcServerRequestLatency}
}

// InitializeClusterServerCollectors registers the cluster server metrics to the
// prometheus register and initializes them to 0 for all possible label
// combinations.
func InitializeClusterServerCollectors(r prometheus.Registerer, server *grpc.Server) {
	metric.InitializeGRpcCollectorsFromServer(r, gRpcServerRequestLatency, server)
}
