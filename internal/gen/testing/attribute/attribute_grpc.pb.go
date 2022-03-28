// Code generated by protoc-gen-go-grpc. DO NOT EDIT.

package attribute

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

// TestResourceServiceClient is the client API for TestResourceService service.
//
// For semantics around ctx use and closing/ending streaming RPCs, please refer to https://pkg.go.dev/google.golang.org/grpc/?tab=doc#ClientConn.NewStream.
type TestResourceServiceClient interface {
	TestListResource(ctx context.Context, in *TestListResourceRequest, opts ...grpc.CallOption) (*TestListResourceResponse, error)
	TestGetResource(ctx context.Context, in *TestGetResourceRequest, opts ...grpc.CallOption) (*TestGetResourceResponse, error)
}

type testResourceServiceClient struct {
	cc grpc.ClientConnInterface
}

func NewTestResourceServiceClient(cc grpc.ClientConnInterface) TestResourceServiceClient {
	return &testResourceServiceClient{cc}
}

func (c *testResourceServiceClient) TestListResource(ctx context.Context, in *TestListResourceRequest, opts ...grpc.CallOption) (*TestListResourceResponse, error) {
	out := new(TestListResourceResponse)
	err := c.cc.Invoke(ctx, "/testing.attribute.v1.TestResourceService/TestListResource", in, out, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (c *testResourceServiceClient) TestGetResource(ctx context.Context, in *TestGetResourceRequest, opts ...grpc.CallOption) (*TestGetResourceResponse, error) {
	out := new(TestGetResourceResponse)
	err := c.cc.Invoke(ctx, "/testing.attribute.v1.TestResourceService/TestGetResource", in, out, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

// TestResourceServiceServer is the server API for TestResourceService service.
// All implementations must embed UnimplementedTestResourceServiceServer
// for forward compatibility
type TestResourceServiceServer interface {
	TestListResource(context.Context, *TestListResourceRequest) (*TestListResourceResponse, error)
	TestGetResource(context.Context, *TestGetResourceRequest) (*TestGetResourceResponse, error)
	mustEmbedUnimplementedTestResourceServiceServer()
}

// UnimplementedTestResourceServiceServer must be embedded to have forward compatible implementations.
type UnimplementedTestResourceServiceServer struct {
}

func (UnimplementedTestResourceServiceServer) TestListResource(context.Context, *TestListResourceRequest) (*TestListResourceResponse, error) {
	return nil, status.Errorf(codes.Unimplemented, "method TestListResource not implemented")
}
func (UnimplementedTestResourceServiceServer) TestGetResource(context.Context, *TestGetResourceRequest) (*TestGetResourceResponse, error) {
	return nil, status.Errorf(codes.Unimplemented, "method TestGetResource not implemented")
}
func (UnimplementedTestResourceServiceServer) mustEmbedUnimplementedTestResourceServiceServer() {}

// UnsafeTestResourceServiceServer may be embedded to opt out of forward compatibility for this service.
// Use of this interface is not recommended, as added methods to TestResourceServiceServer will
// result in compilation errors.
type UnsafeTestResourceServiceServer interface {
	mustEmbedUnimplementedTestResourceServiceServer()
}

func RegisterTestResourceServiceServer(s grpc.ServiceRegistrar, srv TestResourceServiceServer) {
	s.RegisterService(&TestResourceService_ServiceDesc, srv)
}

func _TestResourceService_TestListResource_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(TestListResourceRequest)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(TestResourceServiceServer).TestListResource(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: "/testing.attribute.v1.TestResourceService/TestListResource",
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(TestResourceServiceServer).TestListResource(ctx, req.(*TestListResourceRequest))
	}
	return interceptor(ctx, in, info, handler)
}

func _TestResourceService_TestGetResource_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(TestGetResourceRequest)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(TestResourceServiceServer).TestGetResource(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: "/testing.attribute.v1.TestResourceService/TestGetResource",
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(TestResourceServiceServer).TestGetResource(ctx, req.(*TestGetResourceRequest))
	}
	return interceptor(ctx, in, info, handler)
}

// TestResourceService_ServiceDesc is the grpc.ServiceDesc for TestResourceService service.
// It's only intended for direct use with grpc.RegisterService,
// and not to be introspected or modified (even as a copy)
var TestResourceService_ServiceDesc = grpc.ServiceDesc{
	ServiceName: "testing.attribute.v1.TestResourceService",
	HandlerType: (*TestResourceServiceServer)(nil),
	Methods: []grpc.MethodDesc{
		{
			MethodName: "TestListResource",
			Handler:    _TestResourceService_TestListResource_Handler,
		},
		{
			MethodName: "TestGetResource",
			Handler:    _TestResourceService_TestGetResource_Handler,
		},
	},
	Streams:  []grpc.StreamDesc{},
	Metadata: "testing/attribute/v1/attribute.proto",
}
