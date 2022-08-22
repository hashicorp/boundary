package metric

import (
	"github.com/hashicorp/boundary/globals"
	"github.com/hashicorp/boundary/internal/daemon/metric"
	"github.com/prometheus/client_golang/prometheus"
	"google.golang.org/grpc"
)

const (
	clusterSubSystem = "controller_cluster"
)

// Because we use grpc's stats.Handler to track close-to-the-wire server-side communication over grpc,
// there is no easy way to measure request and response size as we are recording latency. Thus we only
// track the request latency for server-side grpc connections.

// gRpcRequestLatency collects measurements of how long it takes
// the boundary system to reply to a request to the controller cluster
// from the time that boundary received the request.
var gRpcRequestLatency prometheus.ObserverVec = prometheus.NewHistogramVec(
	prometheus.HistogramOpts{
		Namespace: globals.MetricNamespace,
		Subsystem: clusterSubSystem,
		Name:      "grpc_request_duration_seconds",
		Help:      "Histogram of latencies for gRPC requests.",
		Buckets:   prometheus.DefBuckets,
	},
	metric.ListGrpcLabels,
)

// InstrumentClusterStatsHandler returns a gRPC stats.Handler which observes
// cluster specific metrics. Use with the cluster gRPC server.
func InstrumentClusterStatsHandler() metric.StatsHandler {
	return metric.StatsHandler{Metric: gRpcRequestLatency}
}

// InitializeClusterCollectors registers the cluster metrics to the default
// prometheus register and initializes them to 0 for all possible label
// combinations.
func InitializeClusterCollectors(r prometheus.Registerer, server *grpc.Server) {
	metric.InitializeGrpcCollectorsFromServer(r, gRpcRequestLatency, server)
}
