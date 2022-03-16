// Package metrics contains the singleton metric vectors and methods to access
// them through the controller code base.  Only exposing the metrics through
// their respective functions ensures they remain singletons and allows
// the code to enforce the appropriate labels are used.
package metrics

import (
	"net/http"
	"strings"

	"github.com/hashicorp/boundary/globals"
	"github.com/prometheus/client_golang/prometheus"
)

type initialControllerMetrics struct {
	httpRequestLatency *prometheus.HistogramVec
	httpRequestSize    *prometheus.HistogramVec
	httpResponseSize   *prometheus.HistogramVec
}

func (d *initialControllerMetrics) HttpRequestLatency(l prometheus.Labels) prometheus.Observer {
	return d.httpRequestLatency.With(l)
}

func (d *initialControllerMetrics) HttpRequestSize(l prometheus.Labels) prometheus.Observer {
	return d.httpRequestSize.With(l)
}

func (d *initialControllerMetrics) HttpResponseSize(l prometheus.Labels) prometheus.Observer {
	return d.httpResponseSize.With(l)
}

func (d *initialControllerMetrics) Register(r prometheus.Registerer) {
	if r == nil {
		return
	}
	r.MustRegister(d.httpRequestLatency, d.httpRequestSize, d.httpResponseSize)
}

const (
	MetricsLabelHttpCode   = "code"
	MetricsLabelHttpPath   = "path"
	MetricsLabelHttpMethod = "method"
	apiSubSystem           = "controller_api"
)

var (
	msgSizeBuckets = prometheus.ExponentialBuckets(100, 10, 8)

	// defaultMetrics is a global object which can be overwritten to make
	// testing the helper functions in this package easier.
	defaultMetrics controllerMetrics = &initialControllerMetrics{
		// httpRequestLatency collects measurements of how long it takes
		// the boundary system to reply to a request to the controller api
		// from the time that boundary received the request.
		httpRequestLatency: prometheus.NewHistogramVec(
			prometheus.HistogramOpts{
				Namespace: globals.MetricNamespace,
				Subsystem: apiSubSystem,
				Name:      "http_request_duration_seconds",
				Help:      "Histogram of latencies for HTTP requests.",
				Buckets:   prometheus.DefBuckets,
			},
			[]string{MetricsLabelHttpCode, MetricsLabelHttpPath, MetricsLabelHttpMethod},
		),
		// httpRequestSize collections measurements of how large each request
		// to the boundary controller api is.
		httpRequestSize: prometheus.NewHistogramVec(
			prometheus.HistogramOpts{
				Namespace: globals.MetricNamespace,
				Subsystem: apiSubSystem,
				Name:      "http_request_size_bytes",
				Help:      "Histogram of request sizes for HTTP requests.",
				// 100 bytes, 1kb, 10kb, 100kb, 1mb, 10mb, 100mb, 1gb
				Buckets: msgSizeBuckets,
			},
			[]string{MetricsLabelHttpCode, MetricsLabelHttpPath, MetricsLabelHttpMethod},
		),
		// httpRequestSize collections measurements of how large each rresponse
		// from the boundary controller api is.
		httpResponseSize: prometheus.NewHistogramVec(
			prometheus.HistogramOpts{
				Namespace: globals.MetricNamespace,
				Subsystem: apiSubSystem,
				Name:      "http_response_size_bytes",
				Help:      "Histogram of response sizes for HTTP responses.",
				// 100 bytes, 1kb, 10kb, 100kb, 1mb, 10mb, 100mb, 1gb
				Buckets: msgSizeBuckets,
			},
			[]string{MetricsLabelHttpCode, MetricsLabelHttpPath, MetricsLabelHttpMethod},
		),
	}
)

type HttpStatusCode int
type HttpPath string
type HttpMethod string

// String returns the http method in a format expected by the metrics system.
// if the method is not one of the predetermined known methods the value
// "invalid" is returned.
func (m HttpMethod) String() string {
	v := strings.ToLower(string(m))
	switch v {
	case "get", "post", "delete", "patch", "put":
		return v
	default:
		return "invalid"
	}
}

// String returns the http path in a normalized format expected by the metrics
// system.  If the path is not one that is recognized or expected by the metrics
// system "invalid" is returned.
func (p HttpPath) String() string {
	// TODO: Get the pathing in from the protos and validate these values
	//   against those.
	return strings.ToLower(string(p))
}

// String returns the string representation of the http status code. If the
// code has no known string representation the value "unknown" is returned.
func (s HttpStatusCode) String() string {
	statusText := http.StatusText(int(s))
	if statusText == "" {
		statusText = "unknown"
	}
	return statusText
}

func httpLabels(c HttpStatusCode, p HttpPath, m HttpMethod) prometheus.Labels {
	return prometheus.Labels{
		MetricsLabelHttpCode:   c.String(),
		MetricsLabelHttpPath:   p.String(),
		MetricsLabelHttpMethod: m.String(),
	}
}

// controllerMetrics provide the methods needed to register controller metrics
// and to retrieve each metric collector.
type controllerMetrics interface {
	HttpRequestLatency(prometheus.Labels) prometheus.Observer
	HttpRequestSize(prometheus.Labels) prometheus.Observer
	HttpResponseSize(prometheus.Labels) prometheus.Observer
	Register(prometheus.Registerer)
}

// HttpRequestLatency provides an observer to the http_request_latency metric
// which can be used to record measurements.
// Expected usage:
// http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
// ...
// statusCode := ... get status code
// var latency float64 := ... calculate latency
// metrics.HttpRequestLatency(metrics.StatusCode(statusCode), metrics.HttpPath(req.URL.Path),
//     metrics.HttpMethod(req.Method)).Observe(latency)
// ...
// }
func HttpRequestLatency(c HttpStatusCode, p HttpPath, m HttpMethod) prometheus.Observer {
	return defaultMetrics.HttpRequestLatency(httpLabels(c, p, m))
}

// HttpRequestSize provides an observer to the http_request_size_bytes metric
// which can be used to record measurements.
// Expected usage:
// http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
// ...
// statusCode := ... get status code
// var reqSize float64 := ... calculate size
// metrics.HttpRequestSize(metrics.StatusCode(statusCode), metrics.HttpPath(req.URL.Path),
//     metrics.HttpMethod(req.Method)).Observe(reqSize)
// ...
// }
func HttpRequestSize(c HttpStatusCode, p HttpPath, m HttpMethod) prometheus.Observer {
	return defaultMetrics.HttpRequestSize(httpLabels(c, p, m))
}

// HttpResponseSize provides an observer to the http_request_size_bytes metric
// which can be used to record measurements.
// Expected usage:
// http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
// ...
// statusCode := ... get status code
// var respSize float64 := ... calculate size
// metrics.HttpRequestSize(metrics.StatusCode(statusCode), metrics.HttpPath(req.URL.Path),
//     metrics.HttpMethod(req.Method)).Observe(respSize)
// ...
// }
func HttpResponseSize(c HttpStatusCode, p HttpPath, m HttpMethod) prometheus.Observer {
	return defaultMetrics.HttpResponseSize(httpLabels(c, p, m))
}

func RegisterMetrics(r prometheus.Registerer) {
	defaultMetrics.Register(r)
}
