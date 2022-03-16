package metrics

import (
	"net/http"
	"strings"

	"github.com/hashicorp/boundary/globals"
	"github.com/prometheus/client_golang/prometheus"
)

type initialWorkerMetrics struct {
	httpRequestLatency         *prometheus.HistogramVec
	httpRequestSize            *prometheus.HistogramVec
	httpResponseSize           *prometheus.HistogramVec
	websocketActiveConnections *prometheus.GaugeVec
	websocketBytesReceived     *prometheus.CounterVec
	websocketBytesSent         *prometheus.CounterVec
}

func (d *initialWorkerMetrics) HttpRequestLatency(l prometheus.Labels) prometheus.Observer {
	return d.httpRequestLatency.With(l)
}

func (d *initialWorkerMetrics) HttpRequestSize(l prometheus.Labels) prometheus.Observer {
	return d.httpRequestSize.With(l)
}

func (d *initialWorkerMetrics) HttpResponseSize(l prometheus.Labels) prometheus.Observer {
	return d.httpResponseSize.With(l)
}

func (d *initialWorkerMetrics) WebsocketActiveConnections(l prometheus.Labels) prometheus.Gauge {
	return d.websocketActiveConnections.With(l)
}

func (d *initialWorkerMetrics) WebsocketBytesReceived(l prometheus.Labels) prometheus.Counter {
	return d.websocketBytesReceived.With(l)

}

func (d *initialWorkerMetrics) WebsocketBytesSent(l prometheus.Labels) prometheus.Counter {
	return d.websocketBytesSent.With(l)
}

func (d *initialWorkerMetrics) Register(r prometheus.Registerer) {
	if r == nil {
		return
	}
	r.MustRegister(d.httpRequestLatency, d.httpRequestSize, d.httpResponseSize)
}

const (
	MetricsLabelHttpCode   = "code"
	MetricsLabelHttpPath   = "path"
	MetricsLabelHttpMethod = "method"
	proxySubSystem         = "worker_proxy"
)

var (
	msgSizeBuckets = prometheus.ExponentialBuckets(100, 10, 8)

	// defaultMetrics is a global object which can be overwritten to make
	// testing the helper functions in this package easier.
	defaultMetrics workerMetrics = &initialWorkerMetrics{
		// httpRequestLatency collects measurements of how long it takes
		// the boundary system to reply to a request to the worker proxy
		// from the time that boundary received the request.
		httpRequestLatency: prometheus.NewHistogramVec(
			prometheus.HistogramOpts{
				Namespace: globals.MetricNamespace,
				Subsystem: proxySubSystem,
				Name:      "http_request_duration_seconds",
				Help:      "Histogram of latencies for HTTP requests.",
				Buckets:   prometheus.DefBuckets,
			},
			[]string{MetricsLabelHttpCode, MetricsLabelHttpPath, MetricsLabelHttpMethod},
		),
		// httpRequestSize collections measurements of how large each request
		// to the boundary worker proxy is.
		httpRequestSize: prometheus.NewHistogramVec(
			prometheus.HistogramOpts{
				Namespace: globals.MetricNamespace,
				Subsystem: proxySubSystem,
				Name:      "http_request_size_bytes",
				Help:      "Histogram of request sizes for HTTP requests.",
				// 100 bytes, 1kb, 10kb, 100kb, 1mb, 10mb, 100mb, 1gb
				Buckets: msgSizeBuckets,
			},
			[]string{MetricsLabelHttpCode, MetricsLabelHttpPath, MetricsLabelHttpMethod},
		),
		// httpRequestSize collections measurements of how large each response
		// from the boundary worker proxy is.
		httpResponseSize: prometheus.NewHistogramVec(
			prometheus.HistogramOpts{
				Namespace: globals.MetricNamespace,
				Subsystem: proxySubSystem,
				Name:      "http_response_size_bytes",
				Help:      "Histogram of response sizes for HTTP responses.",
				// 100 bytes, 1kb, 10kb, 100kb, 1mb, 10mb, 100mb, 1gb
				Buckets: msgSizeBuckets,
			},
			[]string{MetricsLabelHttpCode, MetricsLabelHttpPath, MetricsLabelHttpMethod},
		),
		// httpActiveConnections gauges the number of active websocket connections a worker proxy has established
		websocketActiveConnections: prometheus.NewGaugeVec(
			prometheus.GaugeOpts{
				Namespace: globals.MetricNamespace,
				Subsystem: proxySubSystem,
				Name:      "websocket_active_connections",
				Help:      "Gauge of number of active websocket connections for worker proxy.",
			},
			[]string{MetricsLabelHttpCode, MetricsLabelHttpPath, MetricsLabelHttpMethod},
		),
		websocketBytesReceived: prometheus.NewCounterVec(
			prometheus.CounterOpts{
				Namespace: globals.MetricNamespace,
				Subsystem: proxySubSystem,
				Name:      "websocket_received_bytes_total",
				Help:      "Counter of total received bytes for worker proxy.",
			},
			[]string{MetricsLabelHttpCode, MetricsLabelHttpPath, MetricsLabelHttpMethod},
		),
		websocketBytesSent: prometheus.NewCounterVec(
			prometheus.CounterOpts{
				Namespace: globals.MetricNamespace,
				Subsystem: proxySubSystem,
				Name:      "websocket_sent_bytes_total",
				Help:      "Counter of total sent bytes for worker proxy.",
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

// workerMetrics provide the methods needed to register worker metrics
// and to retrieve each metric collector.
type workerMetrics interface {
	HttpRequestLatency(prometheus.Labels) prometheus.Observer
	HttpRequestSize(prometheus.Labels) prometheus.Observer
	HttpResponseSize(prometheus.Labels) prometheus.Observer
	Register(prometheus.Registerer)
	WebsocketActiveConnections(prometheus.Labels) prometheus.Gauge
	WebsocketBytesReceived(prometheus.Labels) prometheus.Counter
	WebsocketBytesSent(prometheus.Labels) prometheus.Counter
}

func HttpRequestLatency(c HttpStatusCode, p HttpPath, m HttpMethod) prometheus.Observer {
	return defaultMetrics.HttpRequestLatency(httpLabels(c, p, m))
}

func HttpRequestSize(c HttpStatusCode, p HttpPath, m HttpMethod) prometheus.Observer {
	return defaultMetrics.HttpRequestSize(httpLabels(c, p, m))
}

func HttpResponseSize(c HttpStatusCode, p HttpPath, m HttpMethod) prometheus.Observer {
	return defaultMetrics.HttpResponseSize(httpLabels(c, p, m))
}

func WebsocketActiveConnections(c HttpStatusCode, p HttpPath, m HttpMethod) prometheus.Gauge {
	return defaultMetrics.WebsocketActiveConnections(httpLabels(c, p, m))
}

func WebsocketBytesReceived(c HttpStatusCode, p HttpPath, m HttpMethod) prometheus.Counter {
	return defaultMetrics.WebsocketBytesReceived(httpLabels(c, p, m))

}

func WebsocketBytesSent(c HttpStatusCode, p HttpPath, m HttpMethod) prometheus.Counter {
	return defaultMetrics.WebsocketBytesSent(httpLabels(c, p, m))

}

func RegisterMetrics(r prometheus.Registerer) {
	defaultMetrics.Register(r)
}
