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
	[]string{labelHttpCode, labelHttpPath, labelHttpMethod},
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

// InstrumentHttpHandler provides a handler which measures time until header
// is written by the server and attaches status code, method, and path
// labels for the relevant measurements.
func InstrumentHttpHandler(wrapped http.Handler) http.Handler {
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

// InitializeHttpCollectors registers the proxy collectors to the provided
// prometheus register and initializes them to 0 for the most likely label
// combinations.
func InitializeHttpCollectors(r prometheus.Registerer) {
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
