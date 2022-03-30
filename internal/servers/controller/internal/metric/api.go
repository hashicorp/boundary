// Package metric provides functions to initialize the controller specific
// collectors and hooks to measure metrics and update the relevant collectors.
package metric

import (
	"fmt"
	"net/http"
	"path"
	"regexp"
	"strconv"
	"strings"

	"github.com/hashicorp/boundary/globals"
	"github.com/hashicorp/boundary/internal/gen/controller/api/services"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	grpcpb "google.golang.org/genproto/googleapis/api/annotations"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/reflect/protoreflect"
	"google.golang.org/protobuf/reflect/protoregistry"
	"google.golang.org/protobuf/types/descriptorpb"
)

var (
	pathRegex              map[*regexp.Regexp]string
	expectedPathsToMethods map[string][]string
)

func init() {
	expectedPathsToMethods = apiPathsAndMethods()
	pathRegex = make(map[*regexp.Regexp]string)
	for p := range expectedPathsToMethods {
		pathRegex[buildRegexFromPath(p)] = p
	}
}

// gatherPathInfo populates the provided map with the paths associated with
// the provided HttpRule proto option as well as the path information contained
// in any embedded AdditionalBindings in that HttpRule.
func gatherPathInfo(rule *grpcpb.HttpRule, paths map[string][]string) {
	switch r := rule.GetPattern().(type) {
	case *grpcpb.HttpRule_Get:
		paths[r.Get] = append(paths[r.Get], http.MethodGet)
	case *grpcpb.HttpRule_Post:
		paths[r.Post] = append(paths[r.Post], http.MethodPost)
	case *grpcpb.HttpRule_Patch:
		paths[r.Patch] = append(paths[r.Patch], http.MethodPatch)
	case *grpcpb.HttpRule_Put:
		paths[r.Put] = append(paths[r.Put], http.MethodPut)
	case *grpcpb.HttpRule_Delete:
		paths[r.Delete] = append(paths[r.Delete], http.MethodDelete)
	default:
		panic("unknown rule of ")
	}
	for _, additional := range rule.AdditionalBindings {
		gatherPathInfo(additional, paths)
	}
}

func gatherServicePathsAndMethods(fd protoreflect.FileDescriptor, paths map[string][]string) error {
	for j := 0; j < fd.Services().Len(); j++ {
		sd := fd.Services().Get(j)
		for i := 0; i < sd.Methods().Len(); i++ {
			r := sd.Methods().Get(i)
			opts := r.Options().(*descriptorpb.MethodOptions)
			httpRule := proto.GetExtension(opts, grpcpb.E_Http).(*grpcpb.HttpRule)
			if proto.Equal(httpRule, &grpcpb.HttpRule{}) || httpRule == nil {
				return fmt.Errorf("empty or no http rule found on service method %q", r.FullName())
			}
			gatherPathInfo(httpRule, paths)
		}
	}
	return nil
}

// apiPathsAndMethods provides the pathing information for all services
// registered to the controller API.  This does not include any paths that are
// defined outside of the protobufs such as anything using the OPTION method
// or any other paths registered like the dev UI passthrough path.
func apiPathsAndMethods() map[string][]string {
	paths := make(map[string][]string)
	protoregistry.GlobalFiles.RangeFilesByPackage(
		services.File_controller_api_services_v1_user_service_proto.Package(),
		func(f protoreflect.FileDescriptor) bool {
			if err := gatherServicePathsAndMethods(f, paths); err != nil {
				panic(err)
			}
			return true
		})
	return paths
}

func buildRegexFromPath(p string) *regexp.Regexp {
	// a public id in boundary consists of a some prefix, an underscore and
	// at least 10 alphanumerical characters like "h_1234567890".
	const idRegexp = "[[:alnum:]]{1,}_[[:alnum:]]{10,}"

	// Replace any tag in the form of {id} or {auth_method_id} with the above
	// regex so we can match paths to that when measuring requests.
	pWithId := string(regexp.MustCompile("\\{[^\\}]*id\\}").ReplaceAll([]byte(p), []byte(idRegexp)))

	// Escape everything except for our id regexp.
	var seg []string
	for _, s := range strings.Split(pWithId, idRegexp) {
		seg = append(seg, regexp.QuoteMeta(s))
	}
	escapedPathRegex := strings.Join(seg, idRegexp)
	return regexp.MustCompile(fmt.Sprintf("^%s$", escapedPathRegex))
}

const (
	invalidPathValue = "invalid"

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

var universalStatusCodes = []int{
	http.StatusUnauthorized,
	http.StatusForbidden,
	http.StatusNotFound,
	http.StatusMethodNotAllowed,
	http.StatusBadRequest,

	http.StatusInternalServerError,
	http.StatusGatewayTimeout,
}

// Codes which are only currently used in the authentication flow
var authenticationStatusCodes = []int{
	http.StatusAccepted,
	http.StatusFound,
}

var expectedStatusCodesPerMethod = map[string][]int{
	http.MethodGet: append(universalStatusCodes,
		http.StatusOK),
	http.MethodPost: append(universalStatusCodes,
		append(authenticationStatusCodes, http.StatusOK)...),
	http.MethodPatch: append(universalStatusCodes,
		http.StatusOK),

	// delete methods always returns no content instead of a StatusOK
	http.MethodDelete: append(universalStatusCodes,
		http.StatusNoContent),

	http.MethodOptions: {
		http.StatusNoContent,
		http.StatusForbidden,
		http.StatusMethodNotAllowed,
	},
}

// pathLabel maps the requested path the the label value recorded for metrics
func pathLabel(incomingPath string) string {
	if incomingPath == "" || incomingPath[0] != '/' {
		incomingPath = fmt.Sprintf("/%s", incomingPath)
	}
	incomingPath = path.Clean(incomingPath)

	for r, ep := range pathRegex {
		if r.Match([]byte(incomingPath)) {
			return ep
		}
	}
	return invalidPathValue
}

// InstrumentApiHandler provides a handler which measures api
// 1. The response size
// 2. The request size
// 3. The request latency
// and attaches status code, method, and path labels for each of these
// measurements.
func InstrumentApiHandler(wrapped http.Handler) http.Handler {
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

// InitializeApiCollectors registers the api collectors to the default
// prometheus register and initializes them to 0 for all possible label
// combinations.
func InitializeApiCollectors(r prometheus.Registerer) {
	if r == nil {
		return
	}
	r.MustRegister(httpResponseSize, httpRequestSize, httpRequestLatency)

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

	// When an invalid path is found, any method is possible both we expect
	// an error response.
	p := invalidPathValue
	for m := range expectedStatusCodesPerMethod {
		for _, sc := range []int{http.StatusNotFound, http.StatusMethodNotAllowed} {
			l := prometheus.Labels{labelHttpCode: strconv.Itoa(sc), labelHttpPath: p, labelHttpMethod: strings.ToLower(m)}
			httpResponseSize.With(l)
			httpRequestSize.With(l)
			httpRequestLatency.With(l)
		}
	}
}
