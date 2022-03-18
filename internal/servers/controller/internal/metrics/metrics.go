// Package metrics contains the singleton metric vectors and methods to access
// them through the controller code base.  Only exposing the metrics through
// their respective functions ensures they remain singletons and allows
// the code to enforce the appropriate labels are used.
package metrics

import (
	"fmt"
	"net/http"
	"regexp"
	"strconv"
	"strings"

	"github.com/hashicorp/boundary/globals"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

var expectedPaths map[*regexp.Regexp]string

func init() {
	expectedPaths = make(map[*regexp.Regexp]string)

	// TODO: These are just an incomplete set of place holders for now,
	//  populate this using the proto service descriptions proto options.
	paths := []string{
		"/v1/auth-methods",
		"/v1/groups",
		"/v1/groups/{id}",
		"/v1/users",
		"/v1/roles",
		"/v1/roles/{id}",
		"/v1/roles/{id}:add-principles",
	}
	for _, p := range paths {
		expectedPaths[buildRegexFromPath(p)] = p
	}
}

const idRegexp = "[[:alnum:]]{1,}_[[:alnum:]]{10,}"

func buildRegexFromPath(p string) *regexp.Regexp {
	pWithId := strings.Replace(p, "{id}", idRegexp, 1)
	escaped := pWithId
	return regexp.MustCompile(fmt.Sprintf("^%s$", escaped))
}

const (
	labelHttpCode   = "code"
	labelHttpPath   = "path"
	labelHttpMethod = "method"
	apiSubSystem    = "controller_api"
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

	// httpRequestSize collections measurements of how large each rresponse
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

var universalStatusCodes = []string{
	strconv.Itoa(http.StatusUnauthorized),
	strconv.Itoa(http.StatusForbidden),
	strconv.Itoa(http.StatusNotFound),
	strconv.Itoa(http.StatusMethodNotAllowed),
	strconv.Itoa(http.StatusBadRequest),

	strconv.Itoa(http.StatusInternalServerError),
	strconv.Itoa(http.StatusGatewayTimeout),
}

// Codes which are only currently used in the authentication flow
var authenticationStatusCodes = []string{
	strconv.Itoa(http.StatusAccepted),
	strconv.Itoa(http.StatusFound),
}

var expectedStatusCodesPerMethod = map[string][]string{
	strings.ToLower(http.MethodGet): append(universalStatusCodes,
		strconv.Itoa(http.StatusOK)),
	strings.ToLower(http.MethodPost): append(universalStatusCodes,
		append(authenticationStatusCodes, strconv.Itoa(http.StatusOK))...),
	strings.ToLower(http.MethodPatch): append(universalStatusCodes,
		strconv.Itoa(http.StatusOK)),

	// delete methods always returns no content instead of a StatusOK
	strings.ToLower(http.MethodDelete): append(universalStatusCodes,
		strconv.Itoa(http.StatusNoContent)),

	strings.ToLower(http.MethodOptions): {
		strconv.Itoa(http.StatusNoContent),
		strconv.Itoa(http.StatusForbidden),
		strconv.Itoa(http.StatusMethodNotAllowed),
	},
}

// ApiMetricHandler provides a metric handler which measures
// 1. The response size
// 2. The request size
// 3. The request latency
// and attaches status code, method, and path labels for each of these
// measurements.
func ApiMetricHandler(wrapped http.Handler) http.Handler {
	return http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) {
		p := "invalid"
		for r, ep := range expectedPaths {
			if r.Match([]byte(req.URL.Path)) {
				p = ep
				break
			}
		}
		l := prometheus.Labels{
			labelHttpPath: p,
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

// RegisterMetrics registers the controller metrics and initializes them to 0
// for all possible label combinations.
func RegisterMetrics(r prometheus.Registerer) {
	r.MustRegister(httpResponseSize, httpRequestSize, httpRequestLatency)

	for m, sCodes := range expectedStatusCodesPerMethod {
		for _, sc := range sCodes {
			for _, p := range expectedPaths {
				l := prometheus.Labels{labelHttpCode: sc, labelHttpPath: p, labelHttpMethod: m}
				httpResponseSize.With(l)
				httpRequestSize.With(l)
				httpRequestLatency.With(l)
			}
			// if a path doesn't match a regexp, it is invalid.
			l := prometheus.Labels{labelHttpCode: sc, labelHttpPath: "invalid", labelHttpMethod: m}
			httpResponseSize.With(l)
			httpRequestSize.With(l)
			httpRequestLatency.With(l)
		}
	}
}
