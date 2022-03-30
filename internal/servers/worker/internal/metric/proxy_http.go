// Package metric provides functions to initialize the controller specific
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
	apiSubSystem    = "worker_api"
)

var (
	msgSizeBuckets = prometheus.ExponentialBuckets(100, 10, 8)

	// httpRequestLatency collects measurements of how long it takes
	// the boundary system to reply to a request to the controller api
	// from the time that boundary received the request.
	httpRequestLatency prometheus.ObserverVec = prometheus.NewHistogramVec(
		prometheus.HistogramOpts{
			Namespace: globals.MetricNamespace,
			Subsystem: apiSubSystem,
			Name:      "http_request_duration_seconds",
			Help:      "Histogram of latencies for HTTP requests.",
			Buckets:   prometheus.DefBuckets,
		},
		[]string{labelHttpCode, labelHttpPath, labelHttpMethod},
	)

	// httpRequestSize collections measurements of how large each request
	// to the boundary controller api is.
	httpRequestSize prometheus.ObserverVec = prometheus.NewHistogramVec(
		prometheus.HistogramOpts{
			Namespace: globals.MetricNamespace,
			Subsystem: apiSubSystem,
			Name:      "http_request_size_bytes",
			Help:      "Histogram of request sizes for HTTP requests.",
			// 100 bytes, 1kb, 10kb, 100kb, 1mb, 10mb, 100mb, 1gb
			Buckets: msgSizeBuckets,
		},
		[]string{labelHttpCode, labelHttpPath, labelHttpMethod},
	)

	// httpRequestSize collections measurements of how large each response
	// from the boundary controller api is.
	httpResponseSize prometheus.ObserverVec = prometheus.NewHistogramVec(
		prometheus.HistogramOpts{
			Namespace: globals.MetricNamespace,
			Subsystem: apiSubSystem,
			Name:      "http_response_size_bytes",
			Help:      "Histogram of response sizes for HTTP responses.",
			// 100 bytes, 1kb, 10kb, 100kb, 1mb, 10mb, 100mb, 1gb
			Buckets: msgSizeBuckets,
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
		promhttp.InstrumentHandlerDuration(
			httpRequestLatency.MustCurryWith(l),
			promhttp.InstrumentHandlerRequestSize(
				httpResponseSize.MustCurryWith(l),
				promhttp.InstrumentHandlerResponseSize(
					httpResponseSize.MustCurryWith(l),
					wrapped,
				),
			),
		).ServeHTTP(rw, req)
	})
}

// InstrumentProxyHttpCollectors registers the proxy collectors to the default
// prometheus register and initializes them to 0 for all possible label
// combinations.
func InstrumentProxyHttpCollectors() {
	prometheus.DefaultRegisterer.MustRegister(httpResponseSize, httpRequestSize, httpRequestLatency)

	p := proxyPathValue
	method := http.MethodGet
	for _, sc := range expectedHttpErrCodes {
		l := prometheus.Labels{labelHttpCode: strconv.Itoa(sc), labelHttpPath: p, labelHttpMethod: strings.ToLower(method)}
		httpResponseSize.With(l)
		httpRequestSize.With(l)
		httpRequestLatency.With(l)
	}

	// When an invalid path is found, any method is possible, but we expect
	// an error response.
	p = invalidPathValue
	for _, sc := range []int{http.StatusNotFound, http.StatusMethodNotAllowed} {
		l := prometheus.Labels{labelHttpCode: strconv.Itoa(sc), labelHttpPath: p, labelHttpMethod: strings.ToLower(method)}
		httpResponseSize.With(l)
		httpRequestSize.With(l)
		httpRequestLatency.With(l)
	}
}
