// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: BUSL-1.1

// Code generated by protoc-gen-go-grpc. DO NOT EDIT.
// versions:
// - protoc-gen-go-grpc v1.3.0
// - protoc             (unknown)
// source: controller/servers/services/v1/server_coordination_service.proto

package services

import (
	context "context"
	grpc "google.golang.org/grpc"
	codes "google.golang.org/grpc/codes"
	status "google.golang.org/grpc/status"
)

// This is a compile-time assertion to ensure that this generated file
// is compatible with the grpc package it is being compiled against.
// Requires gRPC-Go v1.32.0 or later.
const _ = grpc.SupportPackageIsVersion7

const (
	ServerCoordinationService_Status_FullMethodName          = "/controller.servers.services.v1.ServerCoordinationService/Status"
	ServerCoordinationService_ListHcpbWorkers_FullMethodName = "/controller.servers.services.v1.ServerCoordinationService/ListHcpbWorkers"
)

// ServerCoordinationServiceClient is the client API for ServerCoordinationService service.
//
// For semantics around ctx use and closing/ending streaming RPCs, please refer to https://pkg.go.dev/google.golang.org/grpc/?tab=doc#ClientConn.NewStream.
type ServerCoordinationServiceClient interface {
	// Status gets worker status requests which include the ongoing jobs the worker is handling and
	// returns the status response which includes the changes the controller would like to make to
	// jobs as well as provide a list of the controllers in the system.
	Status(ctx context.Context, in *StatusRequest, opts ...grpc.CallOption) (*StatusResponse, error)
	// Returns the addresses of HCP Boundary workers, if any
	ListHcpbWorkers(ctx context.Context, in *ListHcpbWorkersRequest, opts ...grpc.CallOption) (*ListHcpbWorkersResponse, error)
}

type serverCoordinationServiceClient struct {
	cc grpc.ClientConnInterface
}

func NewServerCoordinationServiceClient(cc grpc.ClientConnInterface) ServerCoordinationServiceClient {
	return &serverCoordinationServiceClient{cc}
}

func (c *serverCoordinationServiceClient) Status(ctx context.Context, in *StatusRequest, opts ...grpc.CallOption) (*StatusResponse, error) {
	out := new(StatusResponse)
	err := c.cc.Invoke(ctx, ServerCoordinationService_Status_FullMethodName, in, out, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (c *serverCoordinationServiceClient) ListHcpbWorkers(ctx context.Context, in *ListHcpbWorkersRequest, opts ...grpc.CallOption) (*ListHcpbWorkersResponse, error) {
	out := new(ListHcpbWorkersResponse)
	err := c.cc.Invoke(ctx, ServerCoordinationService_ListHcpbWorkers_FullMethodName, in, out, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

// ServerCoordinationServiceServer is the server API for ServerCoordinationService service.
// All implementations must embed UnimplementedServerCoordinationServiceServer
// for forward compatibility
type ServerCoordinationServiceServer interface {
	// Status gets worker status requests which include the ongoing jobs the worker is handling and
	// returns the status response which includes the changes the controller would like to make to
	// jobs as well as provide a list of the controllers in the system.
	Status(context.Context, *StatusRequest) (*StatusResponse, error)
	// Returns the addresses of HCP Boundary workers, if any
	ListHcpbWorkers(context.Context, *ListHcpbWorkersRequest) (*ListHcpbWorkersResponse, error)
	mustEmbedUnimplementedServerCoordinationServiceServer()
}

// UnimplementedServerCoordinationServiceServer must be embedded to have forward compatible implementations.
type UnimplementedServerCoordinationServiceServer struct {
}

func (UnimplementedServerCoordinationServiceServer) Status(context.Context, *StatusRequest) (*StatusResponse, error) {
	return nil, status.Errorf(codes.Unimplemented, "method Status not implemented")
}
func (UnimplementedServerCoordinationServiceServer) ListHcpbWorkers(context.Context, *ListHcpbWorkersRequest) (*ListHcpbWorkersResponse, error) {
	return nil, status.Errorf(codes.Unimplemented, "method ListHcpbWorkers not implemented")
}
func (UnimplementedServerCoordinationServiceServer) mustEmbedUnimplementedServerCoordinationServiceServer() {
}

// UnsafeServerCoordinationServiceServer may be embedded to opt out of forward compatibility for this service.
// Use of this interface is not recommended, as added methods to ServerCoordinationServiceServer will
// result in compilation errors.
type UnsafeServerCoordinationServiceServer interface {
	mustEmbedUnimplementedServerCoordinationServiceServer()
}

func RegisterServerCoordinationServiceServer(s grpc.ServiceRegistrar, srv ServerCoordinationServiceServer) {
	s.RegisterService(&ServerCoordinationService_ServiceDesc, srv)
}

func _ServerCoordinationService_Status_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(StatusRequest)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(ServerCoordinationServiceServer).Status(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: ServerCoordinationService_Status_FullMethodName,
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(ServerCoordinationServiceServer).Status(ctx, req.(*StatusRequest))
	}
	return interceptor(ctx, in, info, handler)
}

func _ServerCoordinationService_ListHcpbWorkers_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(ListHcpbWorkersRequest)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(ServerCoordinationServiceServer).ListHcpbWorkers(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: ServerCoordinationService_ListHcpbWorkers_FullMethodName,
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(ServerCoordinationServiceServer).ListHcpbWorkers(ctx, req.(*ListHcpbWorkersRequest))
	}
	return interceptor(ctx, in, info, handler)
}

// ServerCoordinationService_ServiceDesc is the grpc.ServiceDesc for ServerCoordinationService service.
// It's only intended for direct use with grpc.RegisterService,
// and not to be introspected or modified (even as a copy)
var ServerCoordinationService_ServiceDesc = grpc.ServiceDesc{
	ServiceName: "controller.servers.services.v1.ServerCoordinationService",
	HandlerType: (*ServerCoordinationServiceServer)(nil),
	Methods: []grpc.MethodDesc{
		{
			MethodName: "Status",
			Handler:    _ServerCoordinationService_Status_Handler,
		},
		{
			MethodName: "ListHcpbWorkers",
			Handler:    _ServerCoordinationService_ListHcpbWorkers_Handler,
		},
	},
	Streams:  []grpc.StreamDesc{},
	Metadata: "controller/servers/services/v1/server_coordination_service.proto",
}
