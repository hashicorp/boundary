// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

// Code generated by protoc-gen-go-grpc. DO NOT EDIT.
// versions:
// - protoc-gen-go-grpc v1.3.0
// - protoc             (unknown)
// source: controller/api/services/v1/alias_service.proto

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
	AliasService_GetAlias_FullMethodName    = "/controller.api.services.v1.AliasService/GetAlias"
	AliasService_ListAliases_FullMethodName = "/controller.api.services.v1.AliasService/ListAliases"
	AliasService_CreateAlias_FullMethodName = "/controller.api.services.v1.AliasService/CreateAlias"
	AliasService_UpdateAlias_FullMethodName = "/controller.api.services.v1.AliasService/UpdateAlias"
	AliasService_DeleteAlias_FullMethodName = "/controller.api.services.v1.AliasService/DeleteAlias"
)

// AliasServiceClient is the client API for AliasService service.
//
// For semantics around ctx use and closing/ending streaming RPCs, please refer to https://pkg.go.dev/google.golang.org/grpc/?tab=doc#ClientConn.NewStream.
type AliasServiceClient interface {
	// GetAlias returns a stored alias if present. The provided request must
	// include the id for the alias be retrieved. If missing, malformed or
	// referencing a non existing alias an error is returned.
	GetAlias(ctx context.Context, in *GetAliasRequest, opts ...grpc.CallOption) (*GetAliasResponse, error)
	// ListAliases returns a list of stored aliases which exist inside the
	// provided Scope. The request must include the Scope id which
	// contains the aliases being listed. If missing or malformed, an error
	// is returned.
	ListAliases(ctx context.Context, in *ListAliasesRequest, opts ...grpc.CallOption) (*ListAliasesResponse, error)
	// CreateAlias creates and stores an alias in boundary. The provided
	// request must include the Scope ID in which the alias will be
	// created. If the Scope ID is missing, malformed, or references a non
	// existing resource an error is returned. If a name or login_name is
	// provided that is in use in another alias in the same Scope an
	// error is returned.
	CreateAlias(ctx context.Context, in *CreateAliasRequest, opts ...grpc.CallOption) (*CreateAliasResponse, error)
	// UpdateAlias updates an existing alias in boundary. The provided alias
	// must not have any read only fields set. The update mask must be included in
	// the request and contain at least 1 mutable field. To unset a field's value,
	// include the field in the update mask and don't set it in the provided
	// alias. An error is returned if the alias id is missing or references a
	// non-existing resource. An error is also returned if the request attempts
	// to update the name or login_name to one that is already in use in the
	// containing Scope.
	UpdateAlias(ctx context.Context, in *UpdateAliasRequest, opts ...grpc.CallOption) (*UpdateAliasResponse, error)
	// DeleteAlias removes an alias from Boundary. If the provided alias Id
	// is malformed or not provided an error is returned.
	DeleteAlias(ctx context.Context, in *DeleteAliasRequest, opts ...grpc.CallOption) (*DeleteAliasResponse, error)
}

type aliasServiceClient struct {
	cc grpc.ClientConnInterface
}

func NewAliasServiceClient(cc grpc.ClientConnInterface) AliasServiceClient {
	return &aliasServiceClient{cc}
}

func (c *aliasServiceClient) GetAlias(ctx context.Context, in *GetAliasRequest, opts ...grpc.CallOption) (*GetAliasResponse, error) {
	out := new(GetAliasResponse)
	err := c.cc.Invoke(ctx, AliasService_GetAlias_FullMethodName, in, out, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (c *aliasServiceClient) ListAliases(ctx context.Context, in *ListAliasesRequest, opts ...grpc.CallOption) (*ListAliasesResponse, error) {
	out := new(ListAliasesResponse)
	err := c.cc.Invoke(ctx, AliasService_ListAliases_FullMethodName, in, out, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (c *aliasServiceClient) CreateAlias(ctx context.Context, in *CreateAliasRequest, opts ...grpc.CallOption) (*CreateAliasResponse, error) {
	out := new(CreateAliasResponse)
	err := c.cc.Invoke(ctx, AliasService_CreateAlias_FullMethodName, in, out, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (c *aliasServiceClient) UpdateAlias(ctx context.Context, in *UpdateAliasRequest, opts ...grpc.CallOption) (*UpdateAliasResponse, error) {
	out := new(UpdateAliasResponse)
	err := c.cc.Invoke(ctx, AliasService_UpdateAlias_FullMethodName, in, out, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (c *aliasServiceClient) DeleteAlias(ctx context.Context, in *DeleteAliasRequest, opts ...grpc.CallOption) (*DeleteAliasResponse, error) {
	out := new(DeleteAliasResponse)
	err := c.cc.Invoke(ctx, AliasService_DeleteAlias_FullMethodName, in, out, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

// AliasServiceServer is the server API for AliasService service.
// All implementations must embed UnimplementedAliasServiceServer
// for forward compatibility
type AliasServiceServer interface {
	// GetAlias returns a stored alias if present. The provided request must
	// include the id for the alias be retrieved. If missing, malformed or
	// referencing a non existing alias an error is returned.
	GetAlias(context.Context, *GetAliasRequest) (*GetAliasResponse, error)
	// ListAliases returns a list of stored aliases which exist inside the
	// provided Scope. The request must include the Scope id which
	// contains the aliases being listed. If missing or malformed, an error
	// is returned.
	ListAliases(context.Context, *ListAliasesRequest) (*ListAliasesResponse, error)
	// CreateAlias creates and stores an alias in boundary. The provided
	// request must include the Scope ID in which the alias will be
	// created. If the Scope ID is missing, malformed, or references a non
	// existing resource an error is returned. If a name or login_name is
	// provided that is in use in another alias in the same Scope an
	// error is returned.
	CreateAlias(context.Context, *CreateAliasRequest) (*CreateAliasResponse, error)
	// UpdateAlias updates an existing alias in boundary. The provided alias
	// must not have any read only fields set. The update mask must be included in
	// the request and contain at least 1 mutable field. To unset a field's value,
	// include the field in the update mask and don't set it in the provided
	// alias. An error is returned if the alias id is missing or references a
	// non-existing resource. An error is also returned if the request attempts
	// to update the name or login_name to one that is already in use in the
	// containing Scope.
	UpdateAlias(context.Context, *UpdateAliasRequest) (*UpdateAliasResponse, error)
	// DeleteAlias removes an alias from Boundary. If the provided alias Id
	// is malformed or not provided an error is returned.
	DeleteAlias(context.Context, *DeleteAliasRequest) (*DeleteAliasResponse, error)
	mustEmbedUnimplementedAliasServiceServer()
}

// UnimplementedAliasServiceServer must be embedded to have forward compatible implementations.
type UnimplementedAliasServiceServer struct {
}

func (UnimplementedAliasServiceServer) GetAlias(context.Context, *GetAliasRequest) (*GetAliasResponse, error) {
	return nil, status.Errorf(codes.Unimplemented, "method GetAlias not implemented")
}
func (UnimplementedAliasServiceServer) ListAliases(context.Context, *ListAliasesRequest) (*ListAliasesResponse, error) {
	return nil, status.Errorf(codes.Unimplemented, "method ListAliases not implemented")
}
func (UnimplementedAliasServiceServer) CreateAlias(context.Context, *CreateAliasRequest) (*CreateAliasResponse, error) {
	return nil, status.Errorf(codes.Unimplemented, "method CreateAlias not implemented")
}
func (UnimplementedAliasServiceServer) UpdateAlias(context.Context, *UpdateAliasRequest) (*UpdateAliasResponse, error) {
	return nil, status.Errorf(codes.Unimplemented, "method UpdateAlias not implemented")
}
func (UnimplementedAliasServiceServer) DeleteAlias(context.Context, *DeleteAliasRequest) (*DeleteAliasResponse, error) {
	return nil, status.Errorf(codes.Unimplemented, "method DeleteAlias not implemented")
}
func (UnimplementedAliasServiceServer) mustEmbedUnimplementedAliasServiceServer() {}

// UnsafeAliasServiceServer may be embedded to opt out of forward compatibility for this service.
// Use of this interface is not recommended, as added methods to AliasServiceServer will
// result in compilation errors.
type UnsafeAliasServiceServer interface {
	mustEmbedUnimplementedAliasServiceServer()
}

func RegisterAliasServiceServer(s grpc.ServiceRegistrar, srv AliasServiceServer) {
	s.RegisterService(&AliasService_ServiceDesc, srv)
}

func _AliasService_GetAlias_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(GetAliasRequest)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(AliasServiceServer).GetAlias(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: AliasService_GetAlias_FullMethodName,
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(AliasServiceServer).GetAlias(ctx, req.(*GetAliasRequest))
	}
	return interceptor(ctx, in, info, handler)
}

func _AliasService_ListAliases_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(ListAliasesRequest)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(AliasServiceServer).ListAliases(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: AliasService_ListAliases_FullMethodName,
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(AliasServiceServer).ListAliases(ctx, req.(*ListAliasesRequest))
	}
	return interceptor(ctx, in, info, handler)
}

func _AliasService_CreateAlias_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(CreateAliasRequest)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(AliasServiceServer).CreateAlias(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: AliasService_CreateAlias_FullMethodName,
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(AliasServiceServer).CreateAlias(ctx, req.(*CreateAliasRequest))
	}
	return interceptor(ctx, in, info, handler)
}

func _AliasService_UpdateAlias_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(UpdateAliasRequest)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(AliasServiceServer).UpdateAlias(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: AliasService_UpdateAlias_FullMethodName,
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(AliasServiceServer).UpdateAlias(ctx, req.(*UpdateAliasRequest))
	}
	return interceptor(ctx, in, info, handler)
}

func _AliasService_DeleteAlias_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(DeleteAliasRequest)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(AliasServiceServer).DeleteAlias(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: AliasService_DeleteAlias_FullMethodName,
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(AliasServiceServer).DeleteAlias(ctx, req.(*DeleteAliasRequest))
	}
	return interceptor(ctx, in, info, handler)
}

// AliasService_ServiceDesc is the grpc.ServiceDesc for AliasService service.
// It's only intended for direct use with grpc.RegisterService,
// and not to be introspected or modified (even as a copy)
var AliasService_ServiceDesc = grpc.ServiceDesc{
	ServiceName: "controller.api.services.v1.AliasService",
	HandlerType: (*AliasServiceServer)(nil),
	Methods: []grpc.MethodDesc{
		{
			MethodName: "GetAlias",
			Handler:    _AliasService_GetAlias_Handler,
		},
		{
			MethodName: "ListAliases",
			Handler:    _AliasService_ListAliases_Handler,
		},
		{
			MethodName: "CreateAlias",
			Handler:    _AliasService_CreateAlias_Handler,
		},
		{
			MethodName: "UpdateAlias",
			Handler:    _AliasService_UpdateAlias_Handler,
		},
		{
			MethodName: "DeleteAlias",
			Handler:    _AliasService_DeleteAlias_Handler,
		},
	},
	Streams:  []grpc.StreamDesc{},
	Metadata: "controller/api/services/v1/alias_service.proto",
}
