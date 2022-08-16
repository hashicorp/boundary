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

var grpcLabels = metric.LabelNames{
	Service: "grpc_service",
	Method:  "grpc_method",
	Code:    "grpc_code",
}

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
	grpcLabels.ToList(),
)

// InstrumentClusterStatsHandler returns a gRPC stats.Handler which observes
// cluster specific metrics. Use with the cluster gRPC server.
func InstrumentClusterStatsHandler() metric.RPCStatsHandler {
	return metric.RPCStatsHandler{Metric: grpcRequestLatency, Labels: grpcLabels}
}

// InitializeClusterCollectors registers the cluster metrics to the default
// prometheus register and initializes them to 0 for all possible label
// combinations.
func InitializeClusterCollectors(r prometheus.Registerer, server *grpc.Server) {
	metric.InitializeGrpcCollectorsFromServer(r, grpcRequestLatency, grpcLabels, server)
}
