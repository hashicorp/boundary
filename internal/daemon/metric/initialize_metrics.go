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

type LabelNames struct {
	Service string
	Method  string
	Code    string
}

// ToList is useful for defining label names when creating a new Prometheus vector.
func (l LabelNames) ToList() []string {
	return []string{l.Code, l.Service, l.Method}
}

// ToPromLabels converts the LabelNames struct to a prometheus.Labels object, given the corresponding params.
func (l LabelNames) ToPromLabels(code string, service string, method string) prometheus.Labels {
	return prometheus.Labels{l.Code: code, l.Service: service, l.Method: method}
}

/* The following methods are used to initialize Prometheus histogram vectors for gRPC connections. */

func rangeProtofiles(m map[string][]string, fd protoreflect.FileDescriptor) bool {
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

var allGrpcCodes = []codes.Code{
	codes.OK, codes.InvalidArgument, codes.PermissionDenied, codes.FailedPrecondition,
	codes.Canceled, codes.Unknown, codes.DeadlineExceeded,
	codes.ResourceExhausted, codes.Unimplemented, codes.Internal,
	codes.Unavailable, codes.Unauthenticated,
}

// InitializeGrpcCollectorsFromPackage registers and zeroes a Prometheus histogram, populating all service and method labels
// by ranging through a given protobuf package.
func InitializeGrpcCollectorsFromPackage(r prometheus.Registerer, v prometheus.ObserverVec, labels LabelNames, pkg protoreflect.FileDescriptor) {
	if r == nil {
		return
	}
	r.MustRegister(v)

	serviceNamesToMethodNames := make(map[string][]string, 0)
	protoregistry.GlobalFiles.RangeFilesByPackage(
		pkg.Package(),
		func(fd protoreflect.FileDescriptor) bool { return rangeProtofiles(serviceNamesToMethodNames, fd) },
	)

	for serviceName, serviceMethods := range serviceNamesToMethodNames {
		for _, sm := range serviceMethods {
			for _, c := range allGrpcCodes {
				v.With(labels.ToPromLabels(c.String(), serviceName, sm))
			}
		}
	}
}

// InitializeGrpcCollectorsFromServer registers and zeroes a Prometheus histogram, finding all service and method labels
// from the provided gRPC server.
func InitializeGrpcCollectorsFromServer(r prometheus.Registerer, v prometheus.ObserverVec, labels LabelNames, server *grpc.Server) {
	if r == nil {
		return
	}
	r.MustRegister(v)

	for serviceName, info := range server.GetServiceInfo() {
		for _, mInfo := range info.Methods {
			for _, c := range allGrpcCodes {
				v.With(labels.ToPromLabels(c.String(), serviceName, mInfo.Name))
			}
		}
	}
}

/* The following methods are used to initialize Prometheus histogram vectors for http requests. */

const (
	invalidPathValue = "invalid"
)

func InitializeApiCollectors(r prometheus.Registerer, sh StatsHandler, expectedPathsToMethods map[string][]string, expectedStatusCodesPerMethod map[string][]int) {
	if r == nil {
		return
	}
	r.MustRegister(sh.Metric)

	for p, methods := range expectedPathsToMethods {
		for _, m := range methods {
			for _, sc := range expectedStatusCodesPerMethod[m] {
				sh.Metric.With(sh.Labels.ToPromLabels(strconv.Itoa(sc), p, strings.ToLower(m)))
			}
		}
	}

	// When an invalid path is found, any method is possible, but we expect
	// an error response.
	p := invalidPathValue
	for m := range expectedStatusCodesPerMethod {
		for _, sc := range []int{http.StatusNotFound, http.StatusMethodNotAllowed} {
			sh.Metric.With(sh.Labels.ToPromLabels(strconv.Itoa(sc), p, strings.ToLower(m)))
		}
	}
}
