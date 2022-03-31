// Package metric provides functions to initialize the worker specific
// collectors and hooks to measure metrics and update the relevant collectors.
package metric

import (
	"fmt"
	"net/http"
	"path"
	"strconv"
	"strings"

	"github.com/hashicorp/boundary/globals"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

const (
	invalidPathValue = "invalid"
	proxyPathValue   = "/v1/proxy"

	labelHttpCode   = "code"
	labelHttpPath   = "path"
	labelHttpMethod = "method"
	proxySubSystem  = "worker_proxy"
)

var (
	// httpTimeUntilHeader collects measurements of how long it takes
	// the boundary system to hijack an HTTP request into a websocket connection
	// for the proxy worker.
	httpTimeUntilHeader prometheus.ObserverVec = prometheus.NewHistogramVec(
		prometheus.HistogramOpts{
			Namespace: globals.MetricNamespace,
			Subsystem: proxySubSystem,
			Name:      "http_write_header_duration_seconds",
			Help:      "Histogram of latencies for HTTP to websocket conversions.",
			Buckets:   prometheus.DefBuckets,
		},
		[]string{labelHttpCode, labelHttpPath, labelHttpMethod},
	)
)

var expectedHttpErrCodes = []int{
	http.StatusUpgradeRequired,
	http.StatusMethodNotAllowed,
	http.StatusBadRequest,
	http.StatusForbidden,
	http.StatusNotImplemented,
	http.StatusSwitchingProtocols,
	http.StatusInternalServerError,
}

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

// InstrumentProxyHttpHandler provides a proxy handler which measures
// 1. The response size
// 2. The request size
// 3. The request latency
// and attaches status code, method, and path labels for each of these
// measurements.
func InstrumentProxyHttpHandler(wrapped http.Handler) http.Handler {
	return http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) {
		l := prometheus.Labels{
			labelHttpPath: pathLabel(req.URL.Path),
		}
		promhttp.InstrumentHandlerTimeToWriteHeader(
			httpTimeUntilHeader.MustCurryWith(l),
			wrapped,
		).ServeHTTP(rw, req)
	})
}

// InstrumentProxyHttpCollectors registers the proxy collectors to the default
// prometheus register and initializes them to 0 for all possible label
// combinations.
func InstrumentProxyHttpCollectors(r prometheus.Registerer) {
	if r == nil {
		return
	}
	r.MustRegister(httpTimeUntilHeader)

	p := proxyPathValue
	method := http.MethodGet
	for _, sc := range expectedHttpErrCodes {
		l := prometheus.Labels{labelHttpCode: strconv.Itoa(sc), labelHttpPath: p, labelHttpMethod: strings.ToLower(method)}
		httpTimeUntilHeader.With(l)
	}

	// When an invalid path is found, any method is possible, but we expect
	// an error response.
	p = invalidPathValue
	for _, sc := range []int{http.StatusNotFound, http.StatusMethodNotAllowed} {
		l := prometheus.Labels{labelHttpCode: strconv.Itoa(sc), labelHttpPath: p, labelHttpMethod: strings.ToLower(method)}
		httpTimeUntilHeader.With(l)
	}
}
