// Copyright IBM Corp. 2020, 2025
// SPDX-License-Identifier: BUSL-1.1

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
	LabelConnectionType = "conn_type"
	LabelGrpcService    = "grpc_service"
	LabelGrpcMethod     = "grpc_method"
	LabelGrpcCode       = "grpc_code"
	LabelHttpPath       = "path"
	LabelHttpMethod     = "method"
	LabelHttpCode       = "code"

	invalidPathValue = "invalid"
)

var (
	ListGrpcLabels = []string{LabelGrpcService, LabelGrpcMethod, LabelGrpcCode}
	ListHttpLabels = []string{LabelHttpPath, LabelHttpMethod, LabelHttpCode}
)

/* The following methods are used to initialize Prometheus histogram vectors for gRPC connections. */

// rangeProtoFiles returns true while there are services with associated methods in the proto package.
// It relies on RangeFilesByPackage to range through the package, and it adds them into map m.
// Services and methods for which filter() returns true are not added into the map.
func rangeProtoFiles(m map[string][]string, fd protoreflect.FileDescriptor, filter func(string, string) bool) bool {
	if fd.Services().Len() == 0 {
		return true
	}

	for i := 0; i < fd.Services().Len(); i++ {
		s := fd.Services().Get(i)
		if s.Methods().Len() == 0 {
			continue
		}

		serviceName := string(s.FullName())
		methods := []string{}
		for j := 0; j < s.Methods().Len(); j++ {
			methodName := string(s.Methods().Get(j).Name())
			if filter(serviceName, methodName) {
				continue
			}
			methods = append(methods, methodName)
		}
		if len(methods) > 0 {
			m[serviceName] = methods
		}
	}

	return true
}

// appendServicesAndMethods ranges through all registered files in a specified proto package
// and appends service and method names to the provided map m.
func appendServicesAndMethods(m map[string][]string, pkg protoreflect.FileDescriptor, filter func(string, string) bool) {
	protoregistry.GlobalFiles.RangeFilesByPackage(
		pkg.Package(),
		func(fd protoreflect.FileDescriptor) bool { return rangeProtoFiles(m, fd, filter) },
	)
}

// InitializeGrpcCollectorsFromPackage registers and zeroes a Prometheus
// histogram, populating all service and method labels by ranging through
// the package containing the provided FileDescriptor.
// The filter function takes in a service name and method name and skips adding them as labels
// upon returning true.
// Note: inputting a protoreflect.FileDescriptor will populate all services and methods
// found in its package, not just methods associated with that specific FileDescriptor.
func InitializeGrpcCollectorsFromPackage(r prometheus.Registerer, v prometheus.ObserverVec,
	pkgs []protoreflect.FileDescriptor, codes []codes.Code, filter func(string, string) bool,
) {
	if r == nil {
		return
	}
	r.MustRegister(v)

	serviceNamesToMethodNames := make(map[string][]string, 0)
	for _, p := range pkgs {
		appendServicesAndMethods(serviceNamesToMethodNames, p, filter)
	}

	for serviceName, serviceMethods := range serviceNamesToMethodNames {
		for _, sm := range serviceMethods {
			for _, c := range codes {
				v.With(prometheus.Labels{LabelGrpcService: serviceName, LabelGrpcMethod: sm, LabelGrpcCode: c.String()})
			}
		}
	}
}

func InitializeConnectionCounters(r prometheus.Registerer, counters []prometheus.CounterVec) {
	if r == nil {
		return
	}
	for _, c := range counters {
		r.MustRegister(c)
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
