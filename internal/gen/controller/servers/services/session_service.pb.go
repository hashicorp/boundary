// Code generated by protoc-gen-go. DO NOT EDIT.
// versions:
// 	protoc-gen-go v1.25.0
// 	protoc        v3.12.4
// source: controller/servers/services/v1/session_service.proto

package services

import (
	context "context"
	proto "github.com/golang/protobuf/proto"
	_ "github.com/golang/protobuf/ptypes/timestamp"
	sessions "github.com/hashicorp/boundary/internal/gen/controller/api/resources/sessions"
	_ "github.com/hashicorp/boundary/internal/servers"
	grpc "google.golang.org/grpc"
	codes "google.golang.org/grpc/codes"
	status "google.golang.org/grpc/status"
	protoreflect "google.golang.org/protobuf/reflect/protoreflect"
	protoimpl "google.golang.org/protobuf/runtime/protoimpl"
	reflect "reflect"
	sync "sync"
)

const (
	// Verify that this generated code is sufficiently up-to-date.
	_ = protoimpl.EnforceVersion(20 - protoimpl.MinVersion)
	// Verify that runtime/protoimpl is sufficiently up-to-date.
	_ = protoimpl.EnforceVersion(protoimpl.MaxVersion - 20)
)

// This is a compile-time assertion that a sufficiently up-to-date version
// of the legacy proto package is being used.
const _ = proto.ProtoPackageIsVersion4

type GetSessionCredsRequest struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	// The session ID from the client
	Id string `protobuf:"bytes,10,opt,name=id,proto3" json:"id,omitempty"`
}

func (x *GetSessionCredsRequest) Reset() {
	*x = GetSessionCredsRequest{}
	if protoimpl.UnsafeEnabled {
		mi := &file_controller_servers_services_v1_session_service_proto_msgTypes[0]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *GetSessionCredsRequest) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*GetSessionCredsRequest) ProtoMessage() {}

func (x *GetSessionCredsRequest) ProtoReflect() protoreflect.Message {
	mi := &file_controller_servers_services_v1_session_service_proto_msgTypes[0]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use GetSessionCredsRequest.ProtoReflect.Descriptor instead.
func (*GetSessionCredsRequest) Descriptor() ([]byte, []int) {
	return file_controller_servers_services_v1_session_service_proto_rawDescGZIP(), []int{0}
}

func (x *GetSessionCredsRequest) GetId() string {
	if x != nil {
		return x.Id
	}
	return ""
}

// SessionResponse contains information necessary for a client to establish a session
type GetSessionCredsResponse struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	SessionCreds *sessions.SessionCreds `protobuf:"bytes,1,opt,name=session_creds,json=sessionCreds,proto3" json:"session_creds,omitempty"`
}

func (x *GetSessionCredsResponse) Reset() {
	*x = GetSessionCredsResponse{}
	if protoimpl.UnsafeEnabled {
		mi := &file_controller_servers_services_v1_session_service_proto_msgTypes[1]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *GetSessionCredsResponse) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*GetSessionCredsResponse) ProtoMessage() {}

func (x *GetSessionCredsResponse) ProtoReflect() protoreflect.Message {
	mi := &file_controller_servers_services_v1_session_service_proto_msgTypes[1]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use GetSessionCredsResponse.ProtoReflect.Descriptor instead.
func (*GetSessionCredsResponse) Descriptor() ([]byte, []int) {
	return file_controller_servers_services_v1_session_service_proto_rawDescGZIP(), []int{1}
}

func (x *GetSessionCredsResponse) GetSessionCreds() *sessions.SessionCreds {
	if x != nil {
		return x.SessionCreds
	}
	return nil
}

var File_controller_servers_services_v1_session_service_proto protoreflect.FileDescriptor

var file_controller_servers_services_v1_session_service_proto_rawDesc = []byte{
	0x0a, 0x34, 0x63, 0x6f, 0x6e, 0x74, 0x72, 0x6f, 0x6c, 0x6c, 0x65, 0x72, 0x2f, 0x73, 0x65, 0x72,
	0x76, 0x65, 0x72, 0x73, 0x2f, 0x73, 0x65, 0x72, 0x76, 0x69, 0x63, 0x65, 0x73, 0x2f, 0x76, 0x31,
	0x2f, 0x73, 0x65, 0x73, 0x73, 0x69, 0x6f, 0x6e, 0x5f, 0x73, 0x65, 0x72, 0x76, 0x69, 0x63, 0x65,
	0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x12, 0x1e, 0x63, 0x6f, 0x6e, 0x74, 0x72, 0x6f, 0x6c, 0x6c,
	0x65, 0x72, 0x2e, 0x73, 0x65, 0x72, 0x76, 0x65, 0x72, 0x73, 0x2e, 0x73, 0x65, 0x72, 0x76, 0x69,
	0x63, 0x65, 0x73, 0x2e, 0x76, 0x31, 0x1a, 0x1f, 0x67, 0x6f, 0x6f, 0x67, 0x6c, 0x65, 0x2f, 0x70,
	0x72, 0x6f, 0x74, 0x6f, 0x62, 0x75, 0x66, 0x2f, 0x74, 0x69, 0x6d, 0x65, 0x73, 0x74, 0x61, 0x6d,
	0x70, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x1a, 0x23, 0x63, 0x6f, 0x6e, 0x74, 0x72, 0x6f, 0x6c,
	0x6c, 0x65, 0x72, 0x2f, 0x73, 0x65, 0x72, 0x76, 0x65, 0x72, 0x73, 0x2f, 0x76, 0x31, 0x2f, 0x73,
	0x65, 0x72, 0x76, 0x65, 0x72, 0x73, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x1a, 0x32, 0x63, 0x6f,
	0x6e, 0x74, 0x72, 0x6f, 0x6c, 0x6c, 0x65, 0x72, 0x2f, 0x61, 0x70, 0x69, 0x2f, 0x72, 0x65, 0x73,
	0x6f, 0x75, 0x72, 0x63, 0x65, 0x73, 0x2f, 0x73, 0x65, 0x73, 0x73, 0x69, 0x6f, 0x6e, 0x73, 0x2f,
	0x76, 0x31, 0x2f, 0x73, 0x65, 0x73, 0x73, 0x69, 0x6f, 0x6e, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f,
	0x22, 0x28, 0x0a, 0x16, 0x47, 0x65, 0x74, 0x53, 0x65, 0x73, 0x73, 0x69, 0x6f, 0x6e, 0x43, 0x72,
	0x65, 0x64, 0x73, 0x52, 0x65, 0x71, 0x75, 0x65, 0x73, 0x74, 0x12, 0x0e, 0x0a, 0x02, 0x69, 0x64,
	0x18, 0x0a, 0x20, 0x01, 0x28, 0x09, 0x52, 0x02, 0x69, 0x64, 0x22, 0x72, 0x0a, 0x17, 0x47, 0x65,
	0x74, 0x53, 0x65, 0x73, 0x73, 0x69, 0x6f, 0x6e, 0x43, 0x72, 0x65, 0x64, 0x73, 0x52, 0x65, 0x73,
	0x70, 0x6f, 0x6e, 0x73, 0x65, 0x12, 0x57, 0x0a, 0x0d, 0x73, 0x65, 0x73, 0x73, 0x69, 0x6f, 0x6e,
	0x5f, 0x63, 0x72, 0x65, 0x64, 0x73, 0x18, 0x01, 0x20, 0x01, 0x28, 0x0b, 0x32, 0x32, 0x2e, 0x63,
	0x6f, 0x6e, 0x74, 0x72, 0x6f, 0x6c, 0x6c, 0x65, 0x72, 0x2e, 0x61, 0x70, 0x69, 0x2e, 0x72, 0x65,
	0x73, 0x6f, 0x75, 0x72, 0x63, 0x65, 0x73, 0x2e, 0x73, 0x65, 0x73, 0x73, 0x69, 0x6f, 0x6e, 0x73,
	0x2e, 0x76, 0x31, 0x2e, 0x53, 0x65, 0x73, 0x73, 0x69, 0x6f, 0x6e, 0x43, 0x72, 0x65, 0x64, 0x73,
	0x52, 0x0c, 0x73, 0x65, 0x73, 0x73, 0x69, 0x6f, 0x6e, 0x43, 0x72, 0x65, 0x64, 0x73, 0x32, 0xa1,
	0x01, 0x0a, 0x18, 0x53, 0x65, 0x73, 0x73, 0x69, 0x6f, 0x6e, 0x4d, 0x61, 0x6e, 0x61, 0x67, 0x65,
	0x6d, 0x65, 0x6e, 0x74, 0x53, 0x65, 0x72, 0x76, 0x69, 0x63, 0x65, 0x12, 0x84, 0x01, 0x0a, 0x0f,
	0x47, 0x65, 0x74, 0x53, 0x65, 0x73, 0x73, 0x69, 0x6f, 0x6e, 0x43, 0x72, 0x65, 0x64, 0x73, 0x12,
	0x36, 0x2e, 0x63, 0x6f, 0x6e, 0x74, 0x72, 0x6f, 0x6c, 0x6c, 0x65, 0x72, 0x2e, 0x73, 0x65, 0x72,
	0x76, 0x65, 0x72, 0x73, 0x2e, 0x73, 0x65, 0x72, 0x76, 0x69, 0x63, 0x65, 0x73, 0x2e, 0x76, 0x31,
	0x2e, 0x47, 0x65, 0x74, 0x53, 0x65, 0x73, 0x73, 0x69, 0x6f, 0x6e, 0x43, 0x72, 0x65, 0x64, 0x73,
	0x52, 0x65, 0x71, 0x75, 0x65, 0x73, 0x74, 0x1a, 0x37, 0x2e, 0x63, 0x6f, 0x6e, 0x74, 0x72, 0x6f,
	0x6c, 0x6c, 0x65, 0x72, 0x2e, 0x73, 0x65, 0x72, 0x76, 0x65, 0x72, 0x73, 0x2e, 0x73, 0x65, 0x72,
	0x76, 0x69, 0x63, 0x65, 0x73, 0x2e, 0x76, 0x31, 0x2e, 0x47, 0x65, 0x74, 0x53, 0x65, 0x73, 0x73,
	0x69, 0x6f, 0x6e, 0x43, 0x72, 0x65, 0x64, 0x73, 0x52, 0x65, 0x73, 0x70, 0x6f, 0x6e, 0x73, 0x65,
	0x22, 0x00, 0x42, 0x51, 0x5a, 0x4f, 0x67, 0x69, 0x74, 0x68, 0x75, 0x62, 0x2e, 0x63, 0x6f, 0x6d,
	0x2f, 0x68, 0x61, 0x73, 0x68, 0x69, 0x63, 0x6f, 0x72, 0x70, 0x2f, 0x62, 0x6f, 0x75, 0x6e, 0x64,
	0x61, 0x72, 0x79, 0x2f, 0x69, 0x6e, 0x74, 0x65, 0x72, 0x6e, 0x61, 0x6c, 0x2f, 0x67, 0x65, 0x6e,
	0x2f, 0x63, 0x6f, 0x6e, 0x74, 0x72, 0x6f, 0x6c, 0x6c, 0x65, 0x72, 0x2f, 0x73, 0x65, 0x72, 0x76,
	0x65, 0x72, 0x73, 0x2f, 0x73, 0x65, 0x72, 0x76, 0x69, 0x63, 0x65, 0x73, 0x3b, 0x73, 0x65, 0x72,
	0x76, 0x69, 0x63, 0x65, 0x73, 0x62, 0x06, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x33,
}

var (
	file_controller_servers_services_v1_session_service_proto_rawDescOnce sync.Once
	file_controller_servers_services_v1_session_service_proto_rawDescData = file_controller_servers_services_v1_session_service_proto_rawDesc
)

func file_controller_servers_services_v1_session_service_proto_rawDescGZIP() []byte {
	file_controller_servers_services_v1_session_service_proto_rawDescOnce.Do(func() {
		file_controller_servers_services_v1_session_service_proto_rawDescData = protoimpl.X.CompressGZIP(file_controller_servers_services_v1_session_service_proto_rawDescData)
	})
	return file_controller_servers_services_v1_session_service_proto_rawDescData
}

var file_controller_servers_services_v1_session_service_proto_msgTypes = make([]protoimpl.MessageInfo, 2)
var file_controller_servers_services_v1_session_service_proto_goTypes = []interface{}{
	(*GetSessionCredsRequest)(nil),  // 0: controller.servers.services.v1.GetSessionCredsRequest
	(*GetSessionCredsResponse)(nil), // 1: controller.servers.services.v1.GetSessionCredsResponse
	(*sessions.SessionCreds)(nil),   // 2: controller.api.resources.sessions.v1.SessionCreds
}
var file_controller_servers_services_v1_session_service_proto_depIdxs = []int32{
	2, // 0: controller.servers.services.v1.GetSessionCredsResponse.session_creds:type_name -> controller.api.resources.sessions.v1.SessionCreds
	0, // 1: controller.servers.services.v1.SessionManagementService.GetSessionCreds:input_type -> controller.servers.services.v1.GetSessionCredsRequest
	1, // 2: controller.servers.services.v1.SessionManagementService.GetSessionCreds:output_type -> controller.servers.services.v1.GetSessionCredsResponse
	2, // [2:3] is the sub-list for method output_type
	1, // [1:2] is the sub-list for method input_type
	1, // [1:1] is the sub-list for extension type_name
	1, // [1:1] is the sub-list for extension extendee
	0, // [0:1] is the sub-list for field type_name
}

func init() { file_controller_servers_services_v1_session_service_proto_init() }
func file_controller_servers_services_v1_session_service_proto_init() {
	if File_controller_servers_services_v1_session_service_proto != nil {
		return
	}
	if !protoimpl.UnsafeEnabled {
		file_controller_servers_services_v1_session_service_proto_msgTypes[0].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*GetSessionCredsRequest); i {
			case 0:
				return &v.state
			case 1:
				return &v.sizeCache
			case 2:
				return &v.unknownFields
			default:
				return nil
			}
		}
		file_controller_servers_services_v1_session_service_proto_msgTypes[1].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*GetSessionCredsResponse); i {
			case 0:
				return &v.state
			case 1:
				return &v.sizeCache
			case 2:
				return &v.unknownFields
			default:
				return nil
			}
		}
	}
	type x struct{}
	out := protoimpl.TypeBuilder{
		File: protoimpl.DescBuilder{
			GoPackagePath: reflect.TypeOf(x{}).PkgPath(),
			RawDescriptor: file_controller_servers_services_v1_session_service_proto_rawDesc,
			NumEnums:      0,
			NumMessages:   2,
			NumExtensions: 0,
			NumServices:   1,
		},
		GoTypes:           file_controller_servers_services_v1_session_service_proto_goTypes,
		DependencyIndexes: file_controller_servers_services_v1_session_service_proto_depIdxs,
		MessageInfos:      file_controller_servers_services_v1_session_service_proto_msgTypes,
	}.Build()
	File_controller_servers_services_v1_session_service_proto = out.File
	file_controller_servers_services_v1_session_service_proto_rawDesc = nil
	file_controller_servers_services_v1_session_service_proto_goTypes = nil
	file_controller_servers_services_v1_session_service_proto_depIdxs = nil
}

// Reference imports to suppress errors if they are not otherwise used.
var _ context.Context
var _ grpc.ClientConnInterface

// This is a compile-time assertion to ensure that this generated file
// is compatible with the grpc package it is being compiled against.
const _ = grpc.SupportPackageIsVersion6

// SessionManagementServiceClient is the client API for SessionManagementService service.
//
// For semantics around ctx use and closing/ending streaming RPCs, please refer to https://godoc.org/google.golang.org/grpc#ClientConn.NewStream.
type SessionManagementServiceClient interface {
	// Validate session allows a worker to retrieve session information from the controller.
	// This endpoint validates the session
	GetSessionCreds(ctx context.Context, in *GetSessionCredsRequest, opts ...grpc.CallOption) (*GetSessionCredsResponse, error)
}

type sessionManagementServiceClient struct {
	cc grpc.ClientConnInterface
}

func NewSessionManagementServiceClient(cc grpc.ClientConnInterface) SessionManagementServiceClient {
	return &sessionManagementServiceClient{cc}
}

func (c *sessionManagementServiceClient) GetSessionCreds(ctx context.Context, in *GetSessionCredsRequest, opts ...grpc.CallOption) (*GetSessionCredsResponse, error) {
	out := new(GetSessionCredsResponse)
	err := c.cc.Invoke(ctx, "/controller.servers.services.v1.SessionManagementService/GetSessionCreds", in, out, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

// SessionManagementServiceServer is the server API for SessionManagementService service.
type SessionManagementServiceServer interface {
	// Validate session allows a worker to retrieve session information from the controller.
	// This endpoint validates the session
	GetSessionCreds(context.Context, *GetSessionCredsRequest) (*GetSessionCredsResponse, error)
}

// UnimplementedSessionManagementServiceServer can be embedded to have forward compatible implementations.
type UnimplementedSessionManagementServiceServer struct {
}

func (*UnimplementedSessionManagementServiceServer) GetSessionCreds(context.Context, *GetSessionCredsRequest) (*GetSessionCredsResponse, error) {
	return nil, status.Errorf(codes.Unimplemented, "method GetSessionCreds not implemented")
}

func RegisterSessionManagementServiceServer(s *grpc.Server, srv SessionManagementServiceServer) {
	s.RegisterService(&_SessionManagementService_serviceDesc, srv)
}

func _SessionManagementService_GetSessionCreds_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(GetSessionCredsRequest)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(SessionManagementServiceServer).GetSessionCreds(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: "/controller.servers.services.v1.SessionManagementService/GetSessionCreds",
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(SessionManagementServiceServer).GetSessionCreds(ctx, req.(*GetSessionCredsRequest))
	}
	return interceptor(ctx, in, info, handler)
}

var _SessionManagementService_serviceDesc = grpc.ServiceDesc{
	ServiceName: "controller.servers.services.v1.SessionManagementService",
	HandlerType: (*SessionManagementServiceServer)(nil),
	Methods: []grpc.MethodDesc{
		{
			MethodName: "GetSessionCreds",
			Handler:    _SessionManagementService_GetSessionCreds_Handler,
		},
	},
	Streams:  []grpc.StreamDesc{},
	Metadata: "controller/servers/services/v1/session_service.proto",
}
