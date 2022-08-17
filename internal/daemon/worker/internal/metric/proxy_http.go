// Package metric provides functions to initialize the worker specific
// collectors and hooks to measure metrics and update the relevant collectors.
package metric

import (
	"net/http"

	"github.com/hashicorp/boundary/globals"
	"github.com/hashicorp/boundary/internal/daemon/metric"
	"github.com/prometheus/client_golang/prometheus"
)

const (
	proxySubSystem = "worker_proxy"
)

var httpLabels = metric.LabelNames{
	Service: "path",
	Method:  "method",
	Code:    "code",
}

// httpTimeUntilHeader collects measurements of how long it takes
// the boundary worker to write back the first header to the requester.
var httpTimeUntilHeader prometheus.ObserverVec = prometheus.NewHistogramVec(
	prometheus.HistogramOpts{
		Namespace: globals.MetricNamespace,
		Subsystem: proxySubSystem,
		Name:      "http_write_header_duration_seconds",
		Help:      "Histogram of time elapsed after the TLS connection is established to when the first http header is written back from the server.",
		Buckets:   prometheus.DefBuckets,
	},
	httpLabels.ToList(),
)

// InstrumentHttpHandler provides a handler which measures time until header
// is written by the server and attaches status code, method, and path
// labels for the relevant measurements.
func InstrumentHttpHandler(wrapped http.Handler) http.Handler {
	return metric.InstrumentHttpHandler(wrapped, metric.StatsHandler{
		Metric: httpTimeUntilHeader,
		Labels: httpLabels,
	})
}

// InitializeHttpCollectors registers the proxy collectors to the provided
// prometheus register and initializes them to 0 for the most likely label
// combinations.
func InitializeHttpCollectors(r prometheus.Registerer) {
	metric.InitializeHttpCollectors(r, httpTimeUntilHeader, httpLabels)
}
