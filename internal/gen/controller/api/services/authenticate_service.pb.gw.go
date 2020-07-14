// Code generated by protoc-gen-grpc-gateway. DO NOT EDIT.
// source: controller/api/services/v1/authenticate_service.proto

/*
Package services is a reverse proxy.

It translates gRPC into RESTful JSON APIs.
*/
package services

import (
	"context"
	"io"
	"net/http"

	"github.com/golang/protobuf/descriptor"
	"github.com/golang/protobuf/proto"
	"github.com/grpc-ecosystem/grpc-gateway/runtime"
	"github.com/grpc-ecosystem/grpc-gateway/utilities"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/grpclog"
	"google.golang.org/grpc/status"
)

// Suppress "imported and not used" errors
var _ codes.Code
var _ io.Reader
var _ status.Status
var _ = runtime.String
var _ = utilities.NewDoubleArray
var _ = descriptor.ForMessage

func request_AuthenticationService_Authenticate_0(ctx context.Context, marshaler runtime.Marshaler, client AuthenticationServiceClient, req *http.Request, pathParams map[string]string) (proto.Message, runtime.ServerMetadata, error) {
	var protoReq AuthenticateRequest
	var metadata runtime.ServerMetadata

	newReader, berr := utilities.IOReaderFactory(req.Body)
	if berr != nil {
		return nil, metadata, status.Errorf(codes.InvalidArgument, "%v", berr)
	}
	if err := marshaler.NewDecoder(newReader()).Decode(&protoReq); err != nil && err != io.EOF {
		return nil, metadata, status.Errorf(codes.InvalidArgument, "%v", err)
	}

	var (
		val string
		ok  bool
		err error
		_   = err
	)

	val, ok = pathParams["org_id"]
	if !ok {
		return nil, metadata, status.Errorf(codes.InvalidArgument, "missing parameter %s", "org_id")
	}

	protoReq.OrgId, err = runtime.String(val)

	if err != nil {
		return nil, metadata, status.Errorf(codes.InvalidArgument, "type mismatch, parameter: %s, error: %v", "org_id", err)
	}

	val, ok = pathParams["auth_method_id"]
	if !ok {
		return nil, metadata, status.Errorf(codes.InvalidArgument, "missing parameter %s", "auth_method_id")
	}

	protoReq.AuthMethodId, err = runtime.String(val)

	if err != nil {
		return nil, metadata, status.Errorf(codes.InvalidArgument, "type mismatch, parameter: %s, error: %v", "auth_method_id", err)
	}

	msg, err := client.Authenticate(ctx, &protoReq, grpc.Header(&metadata.HeaderMD), grpc.Trailer(&metadata.TrailerMD))
	return msg, metadata, err

}

func local_request_AuthenticationService_Authenticate_0(ctx context.Context, marshaler runtime.Marshaler, server AuthenticationServiceServer, req *http.Request, pathParams map[string]string) (proto.Message, runtime.ServerMetadata, error) {
	var protoReq AuthenticateRequest
	var metadata runtime.ServerMetadata

	newReader, berr := utilities.IOReaderFactory(req.Body)
	if berr != nil {
		return nil, metadata, status.Errorf(codes.InvalidArgument, "%v", berr)
	}
	if err := marshaler.NewDecoder(newReader()).Decode(&protoReq); err != nil && err != io.EOF {
		return nil, metadata, status.Errorf(codes.InvalidArgument, "%v", err)
	}

	var (
		val string
		ok  bool
		err error
		_   = err
	)

	val, ok = pathParams["org_id"]
	if !ok {
		return nil, metadata, status.Errorf(codes.InvalidArgument, "missing parameter %s", "org_id")
	}

	protoReq.OrgId, err = runtime.String(val)

	if err != nil {
		return nil, metadata, status.Errorf(codes.InvalidArgument, "type mismatch, parameter: %s, error: %v", "org_id", err)
	}

	val, ok = pathParams["auth_method_id"]
	if !ok {
		return nil, metadata, status.Errorf(codes.InvalidArgument, "missing parameter %s", "auth_method_id")
	}

	protoReq.AuthMethodId, err = runtime.String(val)

	if err != nil {
		return nil, metadata, status.Errorf(codes.InvalidArgument, "type mismatch, parameter: %s, error: %v", "auth_method_id", err)
	}

	msg, err := server.Authenticate(ctx, &protoReq)
	return msg, metadata, err

}

func request_AuthenticationService_Deauthenticate_0(ctx context.Context, marshaler runtime.Marshaler, client AuthenticationServiceClient, req *http.Request, pathParams map[string]string) (proto.Message, runtime.ServerMetadata, error) {
	var protoReq DeauthenticateRequest
	var metadata runtime.ServerMetadata

	var (
		val string
		ok  bool
		err error
		_   = err
	)

	val, ok = pathParams["org_id"]
	if !ok {
		return nil, metadata, status.Errorf(codes.InvalidArgument, "missing parameter %s", "org_id")
	}

	protoReq.OrgId, err = runtime.String(val)

	if err != nil {
		return nil, metadata, status.Errorf(codes.InvalidArgument, "type mismatch, parameter: %s, error: %v", "org_id", err)
	}

	msg, err := client.Deauthenticate(ctx, &protoReq, grpc.Header(&metadata.HeaderMD), grpc.Trailer(&metadata.TrailerMD))
	return msg, metadata, err

}

func local_request_AuthenticationService_Deauthenticate_0(ctx context.Context, marshaler runtime.Marshaler, server AuthenticationServiceServer, req *http.Request, pathParams map[string]string) (proto.Message, runtime.ServerMetadata, error) {
	var protoReq DeauthenticateRequest
	var metadata runtime.ServerMetadata

	var (
		val string
		ok  bool
		err error
		_   = err
	)

	val, ok = pathParams["org_id"]
	if !ok {
		return nil, metadata, status.Errorf(codes.InvalidArgument, "missing parameter %s", "org_id")
	}

	protoReq.OrgId, err = runtime.String(val)

	if err != nil {
		return nil, metadata, status.Errorf(codes.InvalidArgument, "type mismatch, parameter: %s, error: %v", "org_id", err)
	}

	msg, err := server.Deauthenticate(ctx, &protoReq)
	return msg, metadata, err

}

// RegisterAuthenticationServiceHandlerServer registers the http handlers for service AuthenticationService to "mux".
// UnaryRPC     :call AuthenticationServiceServer directly.
// StreamingRPC :currently unsupported pending https://github.com/grpc/grpc-go/issues/906.
func RegisterAuthenticationServiceHandlerServer(ctx context.Context, mux *runtime.ServeMux, server AuthenticationServiceServer) error {

	mux.Handle("POST", pattern_AuthenticationService_Authenticate_0, func(w http.ResponseWriter, req *http.Request, pathParams map[string]string) {
		ctx, cancel := context.WithCancel(req.Context())
		defer cancel()
		inboundMarshaler, outboundMarshaler := runtime.MarshalerForRequest(mux, req)
		rctx, err := runtime.AnnotateIncomingContext(ctx, mux, req)
		if err != nil {
			runtime.HTTPError(ctx, mux, outboundMarshaler, w, req, err)
			return
		}
		resp, md, err := local_request_AuthenticationService_Authenticate_0(rctx, inboundMarshaler, server, req, pathParams)
		ctx = runtime.NewServerMetadataContext(ctx, md)
		if err != nil {
			runtime.HTTPError(ctx, mux, outboundMarshaler, w, req, err)
			return
		}

		forward_AuthenticationService_Authenticate_0(ctx, mux, outboundMarshaler, w, req, response_AuthenticationService_Authenticate_0{resp}, mux.GetForwardResponseOptions()...)

	})

	mux.Handle("POST", pattern_AuthenticationService_Deauthenticate_0, func(w http.ResponseWriter, req *http.Request, pathParams map[string]string) {
		ctx, cancel := context.WithCancel(req.Context())
		defer cancel()
		inboundMarshaler, outboundMarshaler := runtime.MarshalerForRequest(mux, req)
		rctx, err := runtime.AnnotateIncomingContext(ctx, mux, req)
		if err != nil {
			runtime.HTTPError(ctx, mux, outboundMarshaler, w, req, err)
			return
		}
		resp, md, err := local_request_AuthenticationService_Deauthenticate_0(rctx, inboundMarshaler, server, req, pathParams)
		ctx = runtime.NewServerMetadataContext(ctx, md)
		if err != nil {
			runtime.HTTPError(ctx, mux, outboundMarshaler, w, req, err)
			return
		}

		forward_AuthenticationService_Deauthenticate_0(ctx, mux, outboundMarshaler, w, req, resp, mux.GetForwardResponseOptions()...)

	})

	return nil
}

// RegisterAuthenticationServiceHandlerFromEndpoint is same as RegisterAuthenticationServiceHandler but
// automatically dials to "endpoint" and closes the connection when "ctx" gets done.
func RegisterAuthenticationServiceHandlerFromEndpoint(ctx context.Context, mux *runtime.ServeMux, endpoint string, opts []grpc.DialOption) (err error) {
	conn, err := grpc.Dial(endpoint, opts...)
	if err != nil {
		return err
	}
	defer func() {
		if err != nil {
			if cerr := conn.Close(); cerr != nil {
				grpclog.Infof("Failed to close conn to %s: %v", endpoint, cerr)
			}
			return
		}
		go func() {
			<-ctx.Done()
			if cerr := conn.Close(); cerr != nil {
				grpclog.Infof("Failed to close conn to %s: %v", endpoint, cerr)
			}
		}()
	}()

	return RegisterAuthenticationServiceHandler(ctx, mux, conn)
}

// RegisterAuthenticationServiceHandler registers the http handlers for service AuthenticationService to "mux".
// The handlers forward requests to the grpc endpoint over "conn".
func RegisterAuthenticationServiceHandler(ctx context.Context, mux *runtime.ServeMux, conn *grpc.ClientConn) error {
	return RegisterAuthenticationServiceHandlerClient(ctx, mux, NewAuthenticationServiceClient(conn))
}

// RegisterAuthenticationServiceHandlerClient registers the http handlers for service AuthenticationService
// to "mux". The handlers forward requests to the grpc endpoint over the given implementation of "AuthenticationServiceClient".
// Note: the gRPC framework executes interceptors within the gRPC handler. If the passed in "AuthenticationServiceClient"
// doesn't go through the normal gRPC flow (creating a gRPC client etc.) then it will be up to the passed in
// "AuthenticationServiceClient" to call the correct interceptors.
func RegisterAuthenticationServiceHandlerClient(ctx context.Context, mux *runtime.ServeMux, client AuthenticationServiceClient) error {

	mux.Handle("POST", pattern_AuthenticationService_Authenticate_0, func(w http.ResponseWriter, req *http.Request, pathParams map[string]string) {
		ctx, cancel := context.WithCancel(req.Context())
		defer cancel()
		inboundMarshaler, outboundMarshaler := runtime.MarshalerForRequest(mux, req)
		rctx, err := runtime.AnnotateContext(ctx, mux, req)
		if err != nil {
			runtime.HTTPError(ctx, mux, outboundMarshaler, w, req, err)
			return
		}
		resp, md, err := request_AuthenticationService_Authenticate_0(rctx, inboundMarshaler, client, req, pathParams)
		ctx = runtime.NewServerMetadataContext(ctx, md)
		if err != nil {
			runtime.HTTPError(ctx, mux, outboundMarshaler, w, req, err)
			return
		}

		forward_AuthenticationService_Authenticate_0(ctx, mux, outboundMarshaler, w, req, response_AuthenticationService_Authenticate_0{resp}, mux.GetForwardResponseOptions()...)

	})

	mux.Handle("POST", pattern_AuthenticationService_Deauthenticate_0, func(w http.ResponseWriter, req *http.Request, pathParams map[string]string) {
		ctx, cancel := context.WithCancel(req.Context())
		defer cancel()
		inboundMarshaler, outboundMarshaler := runtime.MarshalerForRequest(mux, req)
		rctx, err := runtime.AnnotateContext(ctx, mux, req)
		if err != nil {
			runtime.HTTPError(ctx, mux, outboundMarshaler, w, req, err)
			return
		}
		resp, md, err := request_AuthenticationService_Deauthenticate_0(rctx, inboundMarshaler, client, req, pathParams)
		ctx = runtime.NewServerMetadataContext(ctx, md)
		if err != nil {
			runtime.HTTPError(ctx, mux, outboundMarshaler, w, req, err)
			return
		}

		forward_AuthenticationService_Deauthenticate_0(ctx, mux, outboundMarshaler, w, req, resp, mux.GetForwardResponseOptions()...)

	})

	return nil
}

type response_AuthenticationService_Authenticate_0 struct {
	proto.Message
}

func (m response_AuthenticationService_Authenticate_0) XXX_ResponseBody() interface{} {
	response := m.Message.(*AuthenticateResponse)
	return response.Item
}

var (
	pattern_AuthenticationService_Authenticate_0 = runtime.MustPattern(runtime.NewPattern(1, []int{2, 0, 2, 1, 1, 0, 4, 1, 5, 2, 2, 3, 1, 0, 4, 1, 5, 4}, []string{"v1", "orgs", "org_id", "auth-methods", "auth_method_id"}, "authenticate", runtime.AssumeColonVerbOpt(true)))

	pattern_AuthenticationService_Deauthenticate_0 = runtime.MustPattern(runtime.NewPattern(1, []int{2, 0, 2, 1, 1, 0, 4, 1, 5, 2}, []string{"v1", "orgs", "org_id"}, "deauthenticate", runtime.AssumeColonVerbOpt(true)))
)

var (
	forward_AuthenticationService_Authenticate_0 = runtime.ForwardResponseMessage

	forward_AuthenticationService_Deauthenticate_0 = runtime.ForwardResponseMessage
)
