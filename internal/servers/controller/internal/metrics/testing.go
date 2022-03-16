package metrics

import "github.com/prometheus/client_golang/prometheus"

// Noop observer used by our Test Metric
type testObserver struct{}

func (t testObserver) Observe(float64) {}

type testMetrics struct {
	httpLatencyFn  func(prometheus.Labels)
	httpReqSizeFn  func(prometheus.Labels)
	httpRespSizeFn func(prometheus.Labels)
	registerFn     func(prometheus.Registerer)
}

func (t *testMetrics) HttpRequestLatency(l prometheus.Labels) prometheus.Observer {
	if t.httpLatencyFn != nil {
		t.httpLatencyFn(l)
	}
	return testObserver{}
}

func (t *testMetrics) HttpRequestSize(l prometheus.Labels) prometheus.Observer {
	if t.httpReqSizeFn != nil {
		t.httpReqSizeFn(l)
	}
	return testObserver{}
}

func (t *testMetrics) HttpResponseSize(l prometheus.Labels) prometheus.Observer {
	if t.httpRespSizeFn != nil {
		t.httpRespSizeFn(l)
	}
	return testObserver{}
}

func (t *testMetrics) Register(r prometheus.Registerer) {
	if t.registerFn != nil {
		t.registerFn(r)
	}
}

var _ prometheus.Observer = testObserver{}
