// Package metrics contains the singleton metric vectors and methods to access
// them through the controller code base.  Only exposing the metrics through
// their respective functions ensures they remain singletons and allows
// the code to enforce the appropriate labels are used.
package metrics

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

var expectedPathsToMethods map[string][]string

func init() {
	// worker only expects the /proxy path
	expectedPathsToMethods[proxyPathValue] = []string{http.MethodGet}
}

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

var expectedHttpCodes = append(expectedHttpErrCodes, http.StatusOK)

var expectedStatusCodesPerMethod = map[string][]int{
	http.MethodGet: expectedHttpCodes,
}

// pathLabel maps the requested path to the label value recorded for metrics
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

// ProxyMetricHandler provides a metric handler which measures
// 1. The response size
// 2. The request size
// 3. The request latency
// and attaches status code, method, and path labels for each of these
// measurements.
func ProxyMetricHandler(wrapped http.Handler) http.Handler {
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

// InitializeProxyMetrics registers the controller metrics and initializes them to 0
// for all possible label combinations.
func InitializeProxyMetrics() {
	prometheus.DefaultRegisterer.MustRegister(httpResponseSize, httpRequestSize, httpRequestLatency)

	for p, methods := range expectedPathsToMethods {
		for _, m := range methods {
			for _, sc := range expectedStatusCodesPerMethod[m] {
				l := prometheus.Labels{labelHttpCode: strconv.Itoa(sc), labelHttpPath: p, labelHttpMethod: strings.ToLower(m)}
				httpResponseSize.With(l)
				httpRequestSize.With(l)
				httpRequestLatency.With(l)
			}
		}
	}

	// When an invalid path is found, any method is possible, but we expect
	// an error response.
	p := invalidPathValue
	for m := range expectedStatusCodesPerMethod {
		for _, sc := range expectedHttpErrCodes {
			l := prometheus.Labels{labelHttpCode: strconv.Itoa(sc), labelHttpPath: p, labelHttpMethod: strings.ToLower(m)}
			httpResponseSize.With(l)
			httpRequestSize.With(l)
			httpRequestLatency.With(l)
		}
	}
}
