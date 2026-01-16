// Copyright IBM Corp. 2020, 2025
// SPDX-License-Identifier: BUSL-1.1

// Package metric provides functions to initialize the worker specific
// collectors and hooks to measure metrics and update the relevant collectors.
package metric

import (
	"fmt"
	"net/http"
	"path"

	"github.com/hashicorp/boundary/globals"
	"github.com/hashicorp/boundary/internal/daemon/metric"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

const (
	proxySubsystem   = "worker_proxy"
	proxyPathValue   = "/v1/proxy"
	invalidPathValue = "invalid"
)

var (
	expectedPathsToMethods = map[string][]string{
		proxyPathValue: {http.MethodGet},
	}

	expectedHttpErrCodes = []int{
		http.StatusUpgradeRequired,
		http.StatusMethodNotAllowed,
		http.StatusBadRequest,
		http.StatusForbidden,
		http.StatusNotImplemented,
		http.StatusSwitchingProtocols,
		http.StatusInternalServerError,
	}

	expectedCodesPerMethod = map[string][]int{
		http.MethodGet: expectedHttpErrCodes,
	}
)

// httpTimeUntilHeader collects measurements of how long it takes
// the boundary worker to write back the first header to the requester.
var httpTimeUntilHeader prometheus.ObserverVec = prometheus.NewHistogramVec(
	prometheus.HistogramOpts{
		Namespace: globals.MetricNamespace,
		Subsystem: proxySubsystem,
		Name:      "http_write_header_duration_seconds",
		Help:      "Histogram of time elapsed after the TLS connection is established to when the first http header is written back from the server.",
		Buckets:   prometheus.DefBuckets,
	},
	metric.ListHttpLabels,
)

// pathLabel maps the requested path to the label value recorded for metric
func pathLabel(incomingPath string) string {
	if incomingPath == "" || incomingPath[0] != '/' {
		incomingPath = fmt.Sprintf("/%s", incomingPath)
	}
	incomingPath = path.Clean(incomingPath)

	if incomingPath == proxyPathValue {
		return proxyPathValue
	}
	return invalidPathValue
}

// InstrumentHttpHandler provides a handler which measures time until header
// is written by the server and attaches status code, method, and path
// labels for the relevant measurements.
func InstrumentHttpHandler(wrapped http.Handler) http.Handler {
	return http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) {
		l := prometheus.Labels{
			metric.LabelHttpPath: pathLabel(req.URL.Path),
		}
		promhttp.InstrumentHandlerTimeToWriteHeader(
			httpTimeUntilHeader.MustCurryWith(l),
			wrapped,
		).ServeHTTP(rw, req)
	})
}

// InitializeHttpCollectors registers the proxy collectors to the provided
// prometheus register and initializes them to 0 for the most likely label
// combinations.
func InitializeHttpCollectors(r prometheus.Registerer) {
	metric.InitializeApiCollectors(r, httpTimeUntilHeader, expectedPathsToMethods, expectedCodesPerMethod)
}
