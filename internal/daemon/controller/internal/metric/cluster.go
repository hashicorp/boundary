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

// gRpcRequestLatency collects measurements of how long it takes
// the boundary system to reply to a request to the controller cluster
// from the time that boundary received the request.
var grpcRequestLatency prometheus.ObserverVec = prometheus.NewHistogramVec(
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
	return metric.StatsHandler{Metric: grpcRequestLatency}
}

// InitializeClusterCollectors registers the cluster metrics to the default
// prometheus register and initializes them to 0 for all possible label
// combinations.
func InitializeClusterCollectors(r prometheus.Registerer, server *grpc.Server) {
	metric.InitializeGrpcCollectorsFromServer(r, grpcRequestLatency, server)
}
