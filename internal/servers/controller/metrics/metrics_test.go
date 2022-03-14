package metrics

import (
	"net/http"
	"strings"
	"testing"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/stretchr/testify/assert"
)

func TestLabelNormalization_Code(t *testing.T) {
	testHelper := &testMetrics{}
	defaultMetrics = testHelper

	cases := []struct {
		name     string
		code     int
		expected string
	}{
		{
			name:     "ok",
			code:     http.StatusOK,
			expected: "OK",
		},
		{
			name:     "accepted",
			code:     http.StatusAccepted,
			expected: "Accepted",
		},
		{
			name:     "bad gateway",
			code:     http.StatusBadGateway,
			expected: "Bad Gateway",
		},
		{
			name:     "unknown",
			code:     987,
			expected: "unknown",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			testHelper.httpLatencyFn = func(l prometheus.Labels) {
				assert.Equal(t, tc.expected, l[MetricsLabelHttpCode])
			}
			HttpRequestLatency(HttpStatusCode(tc.code), "path", "method")
		})
	}
}

func TestLabelNormalization_Method(t *testing.T) {
	testHelper := &testMetrics{}
	defaultMetrics = testHelper

	cases := []struct {
		name     string
		input    HttpMethod
		expected string
	}{
		{
			name:     "get",
			input:    "get",
			expected: "get",
		},
		{
			name:     "post",
			input:    "post",
			expected: "post",
		},
		{
			name:     "delete",
			input:    "delete",
			expected: "delete",
		},
		{
			name:     "patch",
			input:    "patch",
			expected: "patch",
		},
		{
			name:     "put",
			input:    "put",
			expected: "put",
		},
		{
			name:     "unrecognized",
			input:    "something",
			expected: "invalid",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			testHelper.httpLatencyFn = func(l prometheus.Labels) {
				assert.Equal(t, tc.expected, l[MetricsLabelHttpMethod])
			}
			HttpRequestLatency(HttpStatusCode(http.StatusOK), "ignore", tc.input)
			HttpRequestLatency(HttpStatusCode(http.StatusOK), "ignore", HttpMethod(strings.ToUpper(string(tc.input))))
		})
	}
}

func TestLabelNormalization_Path(t *testing.T) {
	testHelper := &testMetrics{}
	defaultMetrics = testHelper

	// TODO: Add negative cases and filtering our parts of the path
	//  which are from ids or would cause this value to be unbounded.
	cases := []struct {
		name     string
		input    HttpPath
		expected string
	}{
		{
			name:     "regular path",
			input:    "/v1/groups",
			expected: "/v1/groups",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			testHelper.httpLatencyFn = func(l prometheus.Labels) {
				assert.Equal(t, tc.expected, l[MetricsLabelHttpPath])
			}
			HttpRequestLatency(HttpStatusCode(http.StatusOK), tc.input, "ignored")
			HttpRequestLatency(HttpStatusCode(http.StatusOK), HttpPath(strings.ToUpper(string(tc.input))), "ignored")
		})
	}
}

func TestHelperFunctionsPassOnToGlobalObject(t *testing.T) {
	var latencyCalled bool
	var reqSizeCalled bool
	var respSizeCalled bool
	var registerCalled bool
	testHelper := &testMetrics{
		httpLatencyFn: func(prometheus.Labels) {
			latencyCalled = true
		},
		httpReqSizeFn: func(prometheus.Labels) {
			reqSizeCalled = true
		},
		httpRespSizeFn: func(prometheus.Labels) {
			respSizeCalled = true
		},
		registerFn: func(prometheus.Registerer) {
			registerCalled = true
		},
	}
	defaultMetrics = testHelper

	assert.False(t, latencyCalled)
	HttpRequestLatency(1, "", "")
	assert.True(t, latencyCalled)

	assert.False(t, reqSizeCalled)
	HttpRequestSize(1, "", "")
	assert.True(t, reqSizeCalled)

	assert.False(t, respSizeCalled)
	HttpResponseSize(1, "", "")
	assert.True(t, respSizeCalled)

	assert.False(t, registerCalled)
	RegisterMetrics(prometheus.NewRegistry())
	assert.True(t, registerCalled)
}
