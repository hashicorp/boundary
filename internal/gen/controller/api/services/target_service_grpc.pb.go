// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

// Code generated by protoc-gen-go-grpc. DO NOT EDIT.
// versions:
// - protoc-gen-go-grpc v1.3.0
// - protoc             (unknown)
// source: controller/api/services/v1/target_service.proto

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
	TargetService_GetTarget_FullMethodName                     = "/controller.api.services.v1.TargetService/GetTarget"
	TargetService_ListTargets_FullMethodName                   = "/controller.api.services.v1.TargetService/ListTargets"
	TargetService_CreateTarget_FullMethodName                  = "/controller.api.services.v1.TargetService/CreateTarget"
	TargetService_UpdateTarget_FullMethodName                  = "/controller.api.services.v1.TargetService/UpdateTarget"
	TargetService_DeleteTarget_FullMethodName                  = "/controller.api.services.v1.TargetService/DeleteTarget"
	TargetService_AuthorizeSession_FullMethodName              = "/controller.api.services.v1.TargetService/AuthorizeSession"
	TargetService_AddTargetHostSources_FullMethodName          = "/controller.api.services.v1.TargetService/AddTargetHostSources"
	TargetService_SetTargetHostSources_FullMethodName          = "/controller.api.services.v1.TargetService/SetTargetHostSources"
	TargetService_RemoveTargetHostSources_FullMethodName       = "/controller.api.services.v1.TargetService/RemoveTargetHostSources"
	TargetService_AddTargetCredentialSources_FullMethodName    = "/controller.api.services.v1.TargetService/AddTargetCredentialSources"
	TargetService_SetTargetCredentialSources_FullMethodName    = "/controller.api.services.v1.TargetService/SetTargetCredentialSources"
	TargetService_RemoveTargetCredentialSources_FullMethodName = "/controller.api.services.v1.TargetService/RemoveTargetCredentialSources"
)

// TargetServiceClient is the client API for TargetService service.
//
// For semantics around ctx use and closing/ending streaming RPCs, please refer to https://pkg.go.dev/google.golang.org/grpc/?tab=doc#ClientConn.NewStream.
type TargetServiceClient interface {
	// GetTarget returns a stored Target if present.  The provided request
	// must include the Target ID for the Target being retrieved. If
	// that ID is missing, malformed or reference a non existing
	// resource an error is returned.
	GetTarget(ctx context.Context, in *GetTargetRequest, opts ...grpc.CallOption) (*GetTargetResponse, error)
	// ListTargets returns a list of stored Targets which exist inside the project
	// referenced inside the request. The request must include the scope ID for
	// the Targets being retrieved. If the scope ID is missing, malformed, or
	// reference a non existing scope, an error is returned.
	ListTargets(ctx context.Context, in *ListTargetsRequest, opts ...grpc.CallOption) (*ListTargetsResponse, error)
	// CreateTarget creates and stores a Target in boundary.  The provided
	// request must include the scope id in which the Target will be created.
	// If the scope id is missing, malformed or references a non existing
	// scope, an error is returned.  If a name is provided that is in
	// use in another Target in the same scope, an error is returned.
	CreateTarget(ctx context.Context, in *CreateTargetRequest, opts ...grpc.CallOption) (*CreateTargetResponse, error)
	// UpdateTarget updates an existing Target in boundary.  The provided
	// Target must not have any read only fields set.  The update mask must be
	// included in the request and contain at least 1 mutable field.  To unset
	// a field's value, include the field in the update mask and don't set it
	// in the provided Target. An error is returned if the Target ID is missing
	// or reference a non-existing resource.  An error is also returned if the
	// request attempts to update the name to one that is already in use in
	// this scope.
	UpdateTarget(ctx context.Context, in *UpdateTargetRequest, opts ...grpc.CallOption) (*UpdateTargetResponse, error)
	// DeleteTarget removes a Target from Boundary. If the provided Target ID
	// is malformed or not provided an error is returned.
	DeleteTarget(ctx context.Context, in *DeleteTargetRequest, opts ...grpc.CallOption) (*DeleteTargetResponse, error)
	// AuthorizeSession creates authorization information from a given Target.
	// Note that unlike most APIs, since we support using a target name along with
	// scope ID or name to identify a target, this uses a pattern that allows the
	// "id" field to have any number of segments, which works so long as the last
	// part of the path is the verb, which is our normal pattern.
	AuthorizeSession(ctx context.Context, in *AuthorizeSessionRequest, opts ...grpc.CallOption) (*AuthorizeSessionResponse, error)
	// AddTargetHostSources adds Host Sources to this Target. The provided request
	// must include the Target ID to which the Host Sources will be added. All
	// Host Sources added to the provided Target must be a child of a Catalog that
	// is a child of the same scope as this Target. If the scope or Target IDs are
	// missing, malformed, or reference non-existing resources, an error is
	// returned. An error is returned if a Host Source is attempted to be added to
	// a target that is already present on the Target. If the given target already
	// has its address field set, a Bad Request error is returned.
	AddTargetHostSources(ctx context.Context, in *AddTargetHostSourcesRequest, opts ...grpc.CallOption) (*AddTargetHostSourcesResponse, error)
	// SetTargetHostSources sets the Target's Host Sources. Any existing Host
	// Sources on the Target are deleted if they are not included in this request.
	// The provided request must include the scope, and the Target ID on which the
	// Host Sources will be set. All Host Sources in the request must be a child
	// of a Catalog that is in the same scope as the provided Target. If any IDs
	// are missing, malformed, or references a non-existing resource, an error is
	// returned. If the given target already has its address field set, a Bad
	// Request error is returned.
	SetTargetHostSources(ctx context.Context, in *SetTargetHostSourcesRequest, opts ...grpc.CallOption) (*SetTargetHostSourcesResponse, error)
	// RemoveTargetHostSources removes the Host Sources from the specified Target.
	// The provided request must include the Target ID for the Target from which
	// the Host Sources will be removed. If the ID is missing, malformed, or
	// references a non-existing scope or Catalog, an error is returned.  An error
	// is returned if a Host Source is attempted to be removed from the Target
	// when the Target does not have the Host Set.
	RemoveTargetHostSources(ctx context.Context, in *RemoveTargetHostSourcesRequest, opts ...grpc.CallOption) (*RemoveTargetHostSourcesResponse, error)
	// AddTargetCredentialSources adds Credential Sources to this Target.
	// The provided request must include the Target ID to which the Credential
	// Sources will be added. All Credential Sources added to the provided
	// Target must be a child of a Store that is in the same scope as this
	// Target. If the scope or Target IDs are missing, malformed, or reference
	// non-existing resources, an error is returned. An error is returned if a
	// Credential Source is attempted to be added to a target that is already
	// present on the Target.
	AddTargetCredentialSources(ctx context.Context, in *AddTargetCredentialSourcesRequest, opts ...grpc.CallOption) (*AddTargetCredentialSourcesResponse, error)
	// SetTargetCredentialSources sets the Target's Credential Sources.
	// Any existing Credential Sources on the Target are deleted if they are
	// not included in this request. The provided request must include the scope,
	// and the Target ID on which the Credential Sources will be set.  All
	// Credential Sources in the request must be a child of a Store that is
	// in the same scope as the provided Target. If any IDs are missing,
	// malformed, or references a non-existing resource, an error is returned.
	SetTargetCredentialSources(ctx context.Context, in *SetTargetCredentialSourcesRequest, opts ...grpc.CallOption) (*SetTargetCredentialSourcesResponse, error)
	// RemoveTargetCredentialSources removes the Credential Sources from the
	// specified Target. The provided request must include the Target ID for the
	// Target from which the Credential Sources will be removed. If the ID is
	// missing, or malformed, an error is returned.  An error is returned if a
	// Credential Source is attempted to be removed from the Target when the
	// Target does not have the Credential Source.
	RemoveTargetCredentialSources(ctx context.Context, in *RemoveTargetCredentialSourcesRequest, opts ...grpc.CallOption) (*RemoveTargetCredentialSourcesResponse, error)
}

type targetServiceClient struct {
	cc grpc.ClientConnInterface
}

func NewTargetServiceClient(cc grpc.ClientConnInterface) TargetServiceClient {
	return &targetServiceClient{cc}
}

func (c *targetServiceClient) GetTarget(ctx context.Context, in *GetTargetRequest, opts ...grpc.CallOption) (*GetTargetResponse, error) {
	out := new(GetTargetResponse)
	err := c.cc.Invoke(ctx, TargetService_GetTarget_FullMethodName, in, out, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (c *targetServiceClient) ListTargets(ctx context.Context, in *ListTargetsRequest, opts ...grpc.CallOption) (*ListTargetsResponse, error) {
	out := new(ListTargetsResponse)
	err := c.cc.Invoke(ctx, TargetService_ListTargets_FullMethodName, in, out, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (c *targetServiceClient) CreateTarget(ctx context.Context, in *CreateTargetRequest, opts ...grpc.CallOption) (*CreateTargetResponse, error) {
	out := new(CreateTargetResponse)
	err := c.cc.Invoke(ctx, TargetService_CreateTarget_FullMethodName, in, out, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (c *targetServiceClient) UpdateTarget(ctx context.Context, in *UpdateTargetRequest, opts ...grpc.CallOption) (*UpdateTargetResponse, error) {
	out := new(UpdateTargetResponse)
	err := c.cc.Invoke(ctx, TargetService_UpdateTarget_FullMethodName, in, out, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (c *targetServiceClient) DeleteTarget(ctx context.Context, in *DeleteTargetRequest, opts ...grpc.CallOption) (*DeleteTargetResponse, error) {
	out := new(DeleteTargetResponse)
	err := c.cc.Invoke(ctx, TargetService_DeleteTarget_FullMethodName, in, out, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (c *targetServiceClient) AuthorizeSession(ctx context.Context, in *AuthorizeSessionRequest, opts ...grpc.CallOption) (*AuthorizeSessionResponse, error) {
	out := new(AuthorizeSessionResponse)
	err := c.cc.Invoke(ctx, TargetService_AuthorizeSession_FullMethodName, in, out, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (c *targetServiceClient) AddTargetHostSources(ctx context.Context, in *AddTargetHostSourcesRequest, opts ...grpc.CallOption) (*AddTargetHostSourcesResponse, error) {
	out := new(AddTargetHostSourcesResponse)
	err := c.cc.Invoke(ctx, TargetService_AddTargetHostSources_FullMethodName, in, out, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (c *targetServiceClient) SetTargetHostSources(ctx context.Context, in *SetTargetHostSourcesRequest, opts ...grpc.CallOption) (*SetTargetHostSourcesResponse, error) {
	out := new(SetTargetHostSourcesResponse)
	err := c.cc.Invoke(ctx, TargetService_SetTargetHostSources_FullMethodName, in, out, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (c *targetServiceClient) RemoveTargetHostSources(ctx context.Context, in *RemoveTargetHostSourcesRequest, opts ...grpc.CallOption) (*RemoveTargetHostSourcesResponse, error) {
	out := new(RemoveTargetHostSourcesResponse)
	err := c.cc.Invoke(ctx, TargetService_RemoveTargetHostSources_FullMethodName, in, out, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (c *targetServiceClient) AddTargetCredentialSources(ctx context.Context, in *AddTargetCredentialSourcesRequest, opts ...grpc.CallOption) (*AddTargetCredentialSourcesResponse, error) {
	out := new(AddTargetCredentialSourcesResponse)
	err := c.cc.Invoke(ctx, TargetService_AddTargetCredentialSources_FullMethodName, in, out, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (c *targetServiceClient) SetTargetCredentialSources(ctx context.Context, in *SetTargetCredentialSourcesRequest, opts ...grpc.CallOption) (*SetTargetCredentialSourcesResponse, error) {
	out := new(SetTargetCredentialSourcesResponse)
	err := c.cc.Invoke(ctx, TargetService_SetTargetCredentialSources_FullMethodName, in, out, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (c *targetServiceClient) RemoveTargetCredentialSources(ctx context.Context, in *RemoveTargetCredentialSourcesRequest, opts ...grpc.CallOption) (*RemoveTargetCredentialSourcesResponse, error) {
	out := new(RemoveTargetCredentialSourcesResponse)
	err := c.cc.Invoke(ctx, TargetService_RemoveTargetCredentialSources_FullMethodName, in, out, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

// TargetServiceServer is the server API for TargetService service.
// All implementations must embed UnimplementedTargetServiceServer
// for forward compatibility
type TargetServiceServer interface {
	// GetTarget returns a stored Target if present.  The provided request
	// must include the Target ID for the Target being retrieved. If
	// that ID is missing, malformed or reference a non existing
	// resource an error is returned.
	GetTarget(context.Context, *GetTargetRequest) (*GetTargetResponse, error)
	// ListTargets returns a list of stored Targets which exist inside the project
	// referenced inside the request. The request must include the scope ID for
	// the Targets being retrieved. If the scope ID is missing, malformed, or
	// reference a non existing scope, an error is returned.
	ListTargets(context.Context, *ListTargetsRequest) (*ListTargetsResponse, error)
	// CreateTarget creates and stores a Target in boundary.  The provided
	// request must include the scope id in which the Target will be created.
	// If the scope id is missing, malformed or references a non existing
	// scope, an error is returned.  If a name is provided that is in
	// use in another Target in the same scope, an error is returned.
	CreateTarget(context.Context, *CreateTargetRequest) (*CreateTargetResponse, error)
	// UpdateTarget updates an existing Target in boundary.  The provided
	// Target must not have any read only fields set.  The update mask must be
	// included in the request and contain at least 1 mutable field.  To unset
	// a field's value, include the field in the update mask and don't set it
	// in the provided Target. An error is returned if the Target ID is missing
	// or reference a non-existing resource.  An error is also returned if the
	// request attempts to update the name to one that is already in use in
	// this scope.
	UpdateTarget(context.Context, *UpdateTargetRequest) (*UpdateTargetResponse, error)
	// DeleteTarget removes a Target from Boundary. If the provided Target ID
	// is malformed or not provided an error is returned.
	DeleteTarget(context.Context, *DeleteTargetRequest) (*DeleteTargetResponse, error)
	// AuthorizeSession creates authorization information from a given Target.
	// Note that unlike most APIs, since we support using a target name along with
	// scope ID or name to identify a target, this uses a pattern that allows the
	// "id" field to have any number of segments, which works so long as the last
	// part of the path is the verb, which is our normal pattern.
	AuthorizeSession(context.Context, *AuthorizeSessionRequest) (*AuthorizeSessionResponse, error)
	// AddTargetHostSources adds Host Sources to this Target. The provided request
	// must include the Target ID to which the Host Sources will be added. All
	// Host Sources added to the provided Target must be a child of a Catalog that
	// is a child of the same scope as this Target. If the scope or Target IDs are
	// missing, malformed, or reference non-existing resources, an error is
	// returned. An error is returned if a Host Source is attempted to be added to
	// a target that is already present on the Target. If the given target already
	// has its address field set, a Bad Request error is returned.
	AddTargetHostSources(context.Context, *AddTargetHostSourcesRequest) (*AddTargetHostSourcesResponse, error)
	// SetTargetHostSources sets the Target's Host Sources. Any existing Host
	// Sources on the Target are deleted if they are not included in this request.
	// The provided request must include the scope, and the Target ID on which the
	// Host Sources will be set. All Host Sources in the request must be a child
	// of a Catalog that is in the same scope as the provided Target. If any IDs
	// are missing, malformed, or references a non-existing resource, an error is
	// returned. If the given target already has its address field set, a Bad
	// Request error is returned.
	SetTargetHostSources(context.Context, *SetTargetHostSourcesRequest) (*SetTargetHostSourcesResponse, error)
	// RemoveTargetHostSources removes the Host Sources from the specified Target.
	// The provided request must include the Target ID for the Target from which
	// the Host Sources will be removed. If the ID is missing, malformed, or
	// references a non-existing scope or Catalog, an error is returned.  An error
	// is returned if a Host Source is attempted to be removed from the Target
	// when the Target does not have the Host Set.
	RemoveTargetHostSources(context.Context, *RemoveTargetHostSourcesRequest) (*RemoveTargetHostSourcesResponse, error)
	// AddTargetCredentialSources adds Credential Sources to this Target.
	// The provided request must include the Target ID to which the Credential
	// Sources will be added. All Credential Sources added to the provided
	// Target must be a child of a Store that is in the same scope as this
	// Target. If the scope or Target IDs are missing, malformed, or reference
	// non-existing resources, an error is returned. An error is returned if a
	// Credential Source is attempted to be added to a target that is already
	// present on the Target.
	AddTargetCredentialSources(context.Context, *AddTargetCredentialSourcesRequest) (*AddTargetCredentialSourcesResponse, error)
	// SetTargetCredentialSources sets the Target's Credential Sources.
	// Any existing Credential Sources on the Target are deleted if they are
	// not included in this request. The provided request must include the scope,
	// and the Target ID on which the Credential Sources will be set.  All
	// Credential Sources in the request must be a child of a Store that is
	// in the same scope as the provided Target. If any IDs are missing,
	// malformed, or references a non-existing resource, an error is returned.
	SetTargetCredentialSources(context.Context, *SetTargetCredentialSourcesRequest) (*SetTargetCredentialSourcesResponse, error)
	// RemoveTargetCredentialSources removes the Credential Sources from the
	// specified Target. The provided request must include the Target ID for the
	// Target from which the Credential Sources will be removed. If the ID is
	// missing, or malformed, an error is returned.  An error is returned if a
	// Credential Source is attempted to be removed from the Target when the
	// Target does not have the Credential Source.
	RemoveTargetCredentialSources(context.Context, *RemoveTargetCredentialSourcesRequest) (*RemoveTargetCredentialSourcesResponse, error)
	mustEmbedUnimplementedTargetServiceServer()
}

// UnimplementedTargetServiceServer must be embedded to have forward compatible implementations.
type UnimplementedTargetServiceServer struct {
}

func (UnimplementedTargetServiceServer) GetTarget(context.Context, *GetTargetRequest) (*GetTargetResponse, error) {
	return nil, status.Errorf(codes.Unimplemented, "method GetTarget not implemented")
}
func (UnimplementedTargetServiceServer) ListTargets(context.Context, *ListTargetsRequest) (*ListTargetsResponse, error) {
	return nil, status.Errorf(codes.Unimplemented, "method ListTargets not implemented")
}
func (UnimplementedTargetServiceServer) CreateTarget(context.Context, *CreateTargetRequest) (*CreateTargetResponse, error) {
	return nil, status.Errorf(codes.Unimplemented, "method CreateTarget not implemented")
}
func (UnimplementedTargetServiceServer) UpdateTarget(context.Context, *UpdateTargetRequest) (*UpdateTargetResponse, error) {
	return nil, status.Errorf(codes.Unimplemented, "method UpdateTarget not implemented")
}
func (UnimplementedTargetServiceServer) DeleteTarget(context.Context, *DeleteTargetRequest) (*DeleteTargetResponse, error) {
	return nil, status.Errorf(codes.Unimplemented, "method DeleteTarget not implemented")
}
func (UnimplementedTargetServiceServer) AuthorizeSession(context.Context, *AuthorizeSessionRequest) (*AuthorizeSessionResponse, error) {
	return nil, status.Errorf(codes.Unimplemented, "method AuthorizeSession not implemented")
}
func (UnimplementedTargetServiceServer) AddTargetHostSources(context.Context, *AddTargetHostSourcesRequest) (*AddTargetHostSourcesResponse, error) {
	return nil, status.Errorf(codes.Unimplemented, "method AddTargetHostSources not implemented")
}
func (UnimplementedTargetServiceServer) SetTargetHostSources(context.Context, *SetTargetHostSourcesRequest) (*SetTargetHostSourcesResponse, error) {
	return nil, status.Errorf(codes.Unimplemented, "method SetTargetHostSources not implemented")
}
func (UnimplementedTargetServiceServer) RemoveTargetHostSources(context.Context, *RemoveTargetHostSourcesRequest) (*RemoveTargetHostSourcesResponse, error) {
	return nil, status.Errorf(codes.Unimplemented, "method RemoveTargetHostSources not implemented")
}
func (UnimplementedTargetServiceServer) AddTargetCredentialSources(context.Context, *AddTargetCredentialSourcesRequest) (*AddTargetCredentialSourcesResponse, error) {
	return nil, status.Errorf(codes.Unimplemented, "method AddTargetCredentialSources not implemented")
}
func (UnimplementedTargetServiceServer) SetTargetCredentialSources(context.Context, *SetTargetCredentialSourcesRequest) (*SetTargetCredentialSourcesResponse, error) {
	return nil, status.Errorf(codes.Unimplemented, "method SetTargetCredentialSources not implemented")
}
func (UnimplementedTargetServiceServer) RemoveTargetCredentialSources(context.Context, *RemoveTargetCredentialSourcesRequest) (*RemoveTargetCredentialSourcesResponse, error) {
	return nil, status.Errorf(codes.Unimplemented, "method RemoveTargetCredentialSources not implemented")
}
func (UnimplementedTargetServiceServer) mustEmbedUnimplementedTargetServiceServer() {}

// UnsafeTargetServiceServer may be embedded to opt out of forward compatibility for this service.
// Use of this interface is not recommended, as added methods to TargetServiceServer will
// result in compilation errors.
type UnsafeTargetServiceServer interface {
	mustEmbedUnimplementedTargetServiceServer()
}

func RegisterTargetServiceServer(s grpc.ServiceRegistrar, srv TargetServiceServer) {
	s.RegisterService(&TargetService_ServiceDesc, srv)
}

func _TargetService_GetTarget_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(GetTargetRequest)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(TargetServiceServer).GetTarget(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: TargetService_GetTarget_FullMethodName,
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(TargetServiceServer).GetTarget(ctx, req.(*GetTargetRequest))
	}
	return interceptor(ctx, in, info, handler)
}

func _TargetService_ListTargets_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(ListTargetsRequest)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(TargetServiceServer).ListTargets(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: TargetService_ListTargets_FullMethodName,
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(TargetServiceServer).ListTargets(ctx, req.(*ListTargetsRequest))
	}
	return interceptor(ctx, in, info, handler)
}

func _TargetService_CreateTarget_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(CreateTargetRequest)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(TargetServiceServer).CreateTarget(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: TargetService_CreateTarget_FullMethodName,
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(TargetServiceServer).CreateTarget(ctx, req.(*CreateTargetRequest))
	}
	return interceptor(ctx, in, info, handler)
}

func _TargetService_UpdateTarget_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(UpdateTargetRequest)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(TargetServiceServer).UpdateTarget(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: TargetService_UpdateTarget_FullMethodName,
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(TargetServiceServer).UpdateTarget(ctx, req.(*UpdateTargetRequest))
	}
	return interceptor(ctx, in, info, handler)
}

func _TargetService_DeleteTarget_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(DeleteTargetRequest)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(TargetServiceServer).DeleteTarget(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: TargetService_DeleteTarget_FullMethodName,
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(TargetServiceServer).DeleteTarget(ctx, req.(*DeleteTargetRequest))
	}
	return interceptor(ctx, in, info, handler)
}

func _TargetService_AuthorizeSession_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(AuthorizeSessionRequest)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(TargetServiceServer).AuthorizeSession(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: TargetService_AuthorizeSession_FullMethodName,
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(TargetServiceServer).AuthorizeSession(ctx, req.(*AuthorizeSessionRequest))
	}
	return interceptor(ctx, in, info, handler)
}

func _TargetService_AddTargetHostSources_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(AddTargetHostSourcesRequest)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(TargetServiceServer).AddTargetHostSources(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: TargetService_AddTargetHostSources_FullMethodName,
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(TargetServiceServer).AddTargetHostSources(ctx, req.(*AddTargetHostSourcesRequest))
	}
	return interceptor(ctx, in, info, handler)
}

func _TargetService_SetTargetHostSources_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(SetTargetHostSourcesRequest)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(TargetServiceServer).SetTargetHostSources(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: TargetService_SetTargetHostSources_FullMethodName,
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(TargetServiceServer).SetTargetHostSources(ctx, req.(*SetTargetHostSourcesRequest))
	}
	return interceptor(ctx, in, info, handler)
}

func _TargetService_RemoveTargetHostSources_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(RemoveTargetHostSourcesRequest)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(TargetServiceServer).RemoveTargetHostSources(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: TargetService_RemoveTargetHostSources_FullMethodName,
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(TargetServiceServer).RemoveTargetHostSources(ctx, req.(*RemoveTargetHostSourcesRequest))
	}
	return interceptor(ctx, in, info, handler)
}

func _TargetService_AddTargetCredentialSources_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(AddTargetCredentialSourcesRequest)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(TargetServiceServer).AddTargetCredentialSources(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: TargetService_AddTargetCredentialSources_FullMethodName,
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(TargetServiceServer).AddTargetCredentialSources(ctx, req.(*AddTargetCredentialSourcesRequest))
	}
	return interceptor(ctx, in, info, handler)
}

func _TargetService_SetTargetCredentialSources_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(SetTargetCredentialSourcesRequest)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(TargetServiceServer).SetTargetCredentialSources(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: TargetService_SetTargetCredentialSources_FullMethodName,
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(TargetServiceServer).SetTargetCredentialSources(ctx, req.(*SetTargetCredentialSourcesRequest))
	}
	return interceptor(ctx, in, info, handler)
}

func _TargetService_RemoveTargetCredentialSources_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(RemoveTargetCredentialSourcesRequest)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(TargetServiceServer).RemoveTargetCredentialSources(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: TargetService_RemoveTargetCredentialSources_FullMethodName,
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(TargetServiceServer).RemoveTargetCredentialSources(ctx, req.(*RemoveTargetCredentialSourcesRequest))
	}
	return interceptor(ctx, in, info, handler)
}

// TargetService_ServiceDesc is the grpc.ServiceDesc for TargetService service.
// It's only intended for direct use with grpc.RegisterService,
// and not to be introspected or modified (even as a copy)
var TargetService_ServiceDesc = grpc.ServiceDesc{
	ServiceName: "controller.api.services.v1.TargetService",
	HandlerType: (*TargetServiceServer)(nil),
	Methods: []grpc.MethodDesc{
		{
			MethodName: "GetTarget",
			Handler:    _TargetService_GetTarget_Handler,
		},
		{
			MethodName: "ListTargets",
			Handler:    _TargetService_ListTargets_Handler,
		},
		{
			MethodName: "CreateTarget",
			Handler:    _TargetService_CreateTarget_Handler,
		},
		{
			MethodName: "UpdateTarget",
			Handler:    _TargetService_UpdateTarget_Handler,
		},
		{
			MethodName: "DeleteTarget",
			Handler:    _TargetService_DeleteTarget_Handler,
		},
		{
			MethodName: "AuthorizeSession",
			Handler:    _TargetService_AuthorizeSession_Handler,
		},
		{
			MethodName: "AddTargetHostSources",
			Handler:    _TargetService_AddTargetHostSources_Handler,
		},
		{
			MethodName: "SetTargetHostSources",
			Handler:    _TargetService_SetTargetHostSources_Handler,
		},
		{
			MethodName: "RemoveTargetHostSources",
			Handler:    _TargetService_RemoveTargetHostSources_Handler,
		},
		{
			MethodName: "AddTargetCredentialSources",
			Handler:    _TargetService_AddTargetCredentialSources_Handler,
		},
		{
			MethodName: "SetTargetCredentialSources",
			Handler:    _TargetService_SetTargetCredentialSources_Handler,
		},
		{
			MethodName: "RemoveTargetCredentialSources",
			Handler:    _TargetService_RemoveTargetCredentialSources_Handler,
		},
	},
	Streams:  []grpc.StreamDesc{},
	Metadata: "controller/api/services/v1/target_service.proto",
}
