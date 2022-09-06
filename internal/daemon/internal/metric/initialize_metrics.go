// Package metric provides functions to initialize the controller specific
// collectors and hooks to measure metrics and update the relevant collectors.
package metric

import (
	"net/http"
	"strconv"
	"strings"

	"github.com/prometheus/client_golang/prometheus"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/protobuf/reflect/protoreflect"
	"google.golang.org/protobuf/reflect/protoregistry"
)

const (
	LabelGrpcService = "grpc_service"
	LabelGrpcMethod  = "grpc_method"
	LabelGrpcCode    = "grpc_code"
	LabelHttpPath    = "path"
	LabelHttpMethod  = "method"
	LabelHttpCode    = "code"

	invalidPathValue = "invalid"
)

var (
	ListGrpcLabels = []string{LabelGrpcService, LabelGrpcMethod, LabelGrpcCode}
	ListHttpLabels = []string{LabelHttpPath, LabelHttpMethod, LabelHttpCode}
)

/* The following methods are used to initialize Prometheus histogram vectors for gRPC connections. */

func rangeProtoFiles(m map[string][]string, fd protoreflect.FileDescriptor) bool {
	if fd.Services().Len() == 0 {
		return true
	}

	for i := 0; i < fd.Services().Len(); i++ {
		s := fd.Services().Get(i)
		if s.Methods().Len() == 0 {
			continue
		}

		methods := []string{}
		for j := 0; j < s.Methods().Len(); j++ {
			methods = append(methods, string(s.Methods().Get(j).Name()))
		}
		m[string(s.FullName())] = methods
	}

	return true
}

// InitializeGrpcCollectorsFromPackage registers and zeroes a Prometheus
// histogram, populating all service and method labels by ranging through a
// given protobuf package.
func InitializeGrpcCollectorsFromPackage(r prometheus.Registerer, v prometheus.ObserverVec, pkg protoreflect.FileDescriptor, codes []codes.Code) {
	if r == nil {
		return
	}
	r.MustRegister(v)

	serviceNamesToMethodNames := make(map[string][]string, 0)
	protoregistry.GlobalFiles.RangeFilesByPackage(
		pkg.Package(),
		func(fd protoreflect.FileDescriptor) bool { return rangeProtoFiles(serviceNamesToMethodNames, fd) },
	)

	for serviceName, serviceMethods := range serviceNamesToMethodNames {
		for _, sm := range serviceMethods {
			for _, c := range codes {
				v.With(prometheus.Labels{LabelGrpcService: serviceName, LabelGrpcMethod: sm, LabelGrpcCode: c.String()})
			}
		}
	}
}

// InitializeGrpcCollectorsFromServer registers and zeroes a Prometheus
// histogram, finding all service and method labels from the provided gRPC
// server.
func InitializeGrpcCollectorsFromServer(r prometheus.Registerer, v prometheus.ObserverVec, server *grpc.Server, codes []codes.Code) {
	if r == nil {
		return
	}
	r.MustRegister(v)

	for serviceName, info := range server.GetServiceInfo() {
		for _, mInfo := range info.Methods {
			for _, c := range codes {
				v.With(prometheus.Labels{LabelGrpcService: serviceName, LabelGrpcMethod: mInfo.Name, LabelGrpcCode: c.String()})
			}
		}
	}
}

/* The following methods are used to initialize Prometheus histogram vectors for http requests. */

// InitializeApiCollectors registers and zeroes a Prometheus
// histogram, populating all path, code, and method labels from the
// provided maps in its parameters.
func InitializeApiCollectors(r prometheus.Registerer, v prometheus.ObserverVec, expectedPathsToMethods map[string][]string, expectedStatusCodesPerMethod map[string][]int) {
	if r == nil {
		return
	}
	r.MustRegister(v)

	for p, methods := range expectedPathsToMethods {
		for _, m := range methods {
			for _, sc := range expectedStatusCodesPerMethod[m] {
				v.With(prometheus.Labels{LabelHttpPath: p, LabelHttpMethod: strings.ToLower(m), LabelHttpCode: strconv.Itoa(sc)})
			}
		}
	}

	// When an invalid path is found, any method is possible, but we expect an error response.
	p := invalidPathValue
	for m := range expectedStatusCodesPerMethod {
		for _, sc := range []int{http.StatusNotFound, http.StatusMethodNotAllowed} {
			v.With(prometheus.Labels{LabelHttpPath: p, LabelHttpMethod: strings.ToLower(m), LabelHttpCode: strconv.Itoa(sc)})
		}
	}
}
