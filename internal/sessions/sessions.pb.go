// Code generated by protoc-gen-go. DO NOT EDIT.
// versions:
// 	protoc-gen-go v1.25.0
// 	protoc        v3.12.4
// source: controller/sessions/v1/sessions.proto

package sessions

import (
	proto "github.com/golang/protobuf/proto"
	_ "github.com/hashicorp/boundary/internal/db/timestamp"
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

// SessionResponse contains information necessary for a client to establish a session
type SessionResponse struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	// ID of the session job
	Id string `protobuf:"bytes,10,opt,name=id,proto3" json:"id,omitempty"`
	// Type of the session (e.g. tcp, ssh, etc.)
	Type string `protobuf:"bytes,20,opt,name=type,proto3" json:"type,omitempty"`
	// The certificate to use when connecting (or if using custom certs, to
	// serve as the "login"). Raw DER bytes.
	Certificate []byte `protobuf:"bytes,30,opt,name=certificate,proto3" json:"certificate,omitempty"`
	// The private key to use when connecting (or if using custom certs, to pass
	// as the "password").
	PrivateKey []byte `protobuf:"bytes,40,opt,name=private_key,json=privateKey,proto3" json:"private_key,omitempty"`
	// Worker information. The first worker in the slice should be prioritized.
	Workers []*Worker `protobuf:"bytes,50,rep,name=workers,proto3" json:"workers,omitempty"`
}

func (x *SessionResponse) Reset() {
	*x = SessionResponse{}
	if protoimpl.UnsafeEnabled {
		mi := &file_controller_sessions_v1_sessions_proto_msgTypes[0]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *SessionResponse) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*SessionResponse) ProtoMessage() {}

func (x *SessionResponse) ProtoReflect() protoreflect.Message {
	mi := &file_controller_sessions_v1_sessions_proto_msgTypes[0]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use SessionResponse.ProtoReflect.Descriptor instead.
func (*SessionResponse) Descriptor() ([]byte, []int) {
	return file_controller_sessions_v1_sessions_proto_rawDescGZIP(), []int{0}
}

func (x *SessionResponse) GetId() string {
	if x != nil {
		return x.Id
	}
	return ""
}

func (x *SessionResponse) GetType() string {
	if x != nil {
		return x.Type
	}
	return ""
}

func (x *SessionResponse) GetCertificate() []byte {
	if x != nil {
		return x.Certificate
	}
	return nil
}

func (x *SessionResponse) GetPrivateKey() []byte {
	if x != nil {
		return x.PrivateKey
	}
	return nil
}

func (x *SessionResponse) GetWorkers() []*Worker {
	if x != nil {
		return x.Workers
	}
	return nil
}

type Worker struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	// The address of the worker
	Address string `protobuf:"bytes,10,opt,name=address,proto3" json:"address,omitempty"`
}

func (x *Worker) Reset() {
	*x = Worker{}
	if protoimpl.UnsafeEnabled {
		mi := &file_controller_sessions_v1_sessions_proto_msgTypes[1]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *Worker) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*Worker) ProtoMessage() {}

func (x *Worker) ProtoReflect() protoreflect.Message {
	mi := &file_controller_sessions_v1_sessions_proto_msgTypes[1]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use Worker.ProtoReflect.Descriptor instead.
func (*Worker) Descriptor() ([]byte, []int) {
	return file_controller_sessions_v1_sessions_proto_rawDescGZIP(), []int{1}
}

func (x *Worker) GetAddress() string {
	if x != nil {
		return x.Address
	}
	return ""
}

var File_controller_sessions_v1_sessions_proto protoreflect.FileDescriptor

var file_controller_sessions_v1_sessions_proto_rawDesc = []byte{
	0x0a, 0x25, 0x63, 0x6f, 0x6e, 0x74, 0x72, 0x6f, 0x6c, 0x6c, 0x65, 0x72, 0x2f, 0x73, 0x65, 0x73,
	0x73, 0x69, 0x6f, 0x6e, 0x73, 0x2f, 0x76, 0x31, 0x2f, 0x73, 0x65, 0x73, 0x73, 0x69, 0x6f, 0x6e,
	0x73, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x12, 0x16, 0x63, 0x6f, 0x6e, 0x74, 0x72, 0x6f, 0x6c,
	0x6c, 0x65, 0x72, 0x2e, 0x73, 0x65, 0x73, 0x73, 0x69, 0x6f, 0x6e, 0x73, 0x2e, 0x76, 0x31, 0x1a,
	0x2f, 0x63, 0x6f, 0x6e, 0x74, 0x72, 0x6f, 0x6c, 0x6c, 0x65, 0x72, 0x2f, 0x73, 0x74, 0x6f, 0x72,
	0x61, 0x67, 0x65, 0x2f, 0x74, 0x69, 0x6d, 0x65, 0x73, 0x74, 0x61, 0x6d, 0x70, 0x2f, 0x76, 0x31,
	0x2f, 0x74, 0x69, 0x6d, 0x65, 0x73, 0x74, 0x61, 0x6d, 0x70, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f,
	0x22, 0xb2, 0x01, 0x0a, 0x0f, 0x53, 0x65, 0x73, 0x73, 0x69, 0x6f, 0x6e, 0x52, 0x65, 0x73, 0x70,
	0x6f, 0x6e, 0x73, 0x65, 0x12, 0x0e, 0x0a, 0x02, 0x69, 0x64, 0x18, 0x0a, 0x20, 0x01, 0x28, 0x09,
	0x52, 0x02, 0x69, 0x64, 0x12, 0x12, 0x0a, 0x04, 0x74, 0x79, 0x70, 0x65, 0x18, 0x14, 0x20, 0x01,
	0x28, 0x09, 0x52, 0x04, 0x74, 0x79, 0x70, 0x65, 0x12, 0x20, 0x0a, 0x0b, 0x63, 0x65, 0x72, 0x74,
	0x69, 0x66, 0x69, 0x63, 0x61, 0x74, 0x65, 0x18, 0x1e, 0x20, 0x01, 0x28, 0x0c, 0x52, 0x0b, 0x63,
	0x65, 0x72, 0x74, 0x69, 0x66, 0x69, 0x63, 0x61, 0x74, 0x65, 0x12, 0x1f, 0x0a, 0x0b, 0x70, 0x72,
	0x69, 0x76, 0x61, 0x74, 0x65, 0x5f, 0x6b, 0x65, 0x79, 0x18, 0x28, 0x20, 0x01, 0x28, 0x0c, 0x52,
	0x0a, 0x70, 0x72, 0x69, 0x76, 0x61, 0x74, 0x65, 0x4b, 0x65, 0x79, 0x12, 0x38, 0x0a, 0x07, 0x77,
	0x6f, 0x72, 0x6b, 0x65, 0x72, 0x73, 0x18, 0x32, 0x20, 0x03, 0x28, 0x0b, 0x32, 0x1e, 0x2e, 0x63,
	0x6f, 0x6e, 0x74, 0x72, 0x6f, 0x6c, 0x6c, 0x65, 0x72, 0x2e, 0x73, 0x65, 0x73, 0x73, 0x69, 0x6f,
	0x6e, 0x73, 0x2e, 0x76, 0x31, 0x2e, 0x57, 0x6f, 0x72, 0x6b, 0x65, 0x72, 0x52, 0x07, 0x77, 0x6f,
	0x72, 0x6b, 0x65, 0x72, 0x73, 0x22, 0x22, 0x0a, 0x06, 0x57, 0x6f, 0x72, 0x6b, 0x65, 0x72, 0x12,
	0x18, 0x0a, 0x07, 0x61, 0x64, 0x64, 0x72, 0x65, 0x73, 0x73, 0x18, 0x0a, 0x20, 0x01, 0x28, 0x09,
	0x52, 0x07, 0x61, 0x64, 0x64, 0x72, 0x65, 0x73, 0x73, 0x42, 0x3a, 0x5a, 0x38, 0x67, 0x69, 0x74,
	0x68, 0x75, 0x62, 0x2e, 0x63, 0x6f, 0x6d, 0x2f, 0x68, 0x61, 0x73, 0x68, 0x69, 0x63, 0x6f, 0x72,
	0x70, 0x2f, 0x62, 0x6f, 0x75, 0x6e, 0x64, 0x61, 0x72, 0x79, 0x2f, 0x69, 0x6e, 0x74, 0x65, 0x72,
	0x6e, 0x61, 0x6c, 0x2f, 0x73, 0x65, 0x73, 0x73, 0x69, 0x6f, 0x6e, 0x73, 0x3b, 0x73, 0x65, 0x73,
	0x73, 0x69, 0x6f, 0x6e, 0x73, 0x62, 0x06, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x33,
}

var (
	file_controller_sessions_v1_sessions_proto_rawDescOnce sync.Once
	file_controller_sessions_v1_sessions_proto_rawDescData = file_controller_sessions_v1_sessions_proto_rawDesc
)

func file_controller_sessions_v1_sessions_proto_rawDescGZIP() []byte {
	file_controller_sessions_v1_sessions_proto_rawDescOnce.Do(func() {
		file_controller_sessions_v1_sessions_proto_rawDescData = protoimpl.X.CompressGZIP(file_controller_sessions_v1_sessions_proto_rawDescData)
	})
	return file_controller_sessions_v1_sessions_proto_rawDescData
}

var file_controller_sessions_v1_sessions_proto_msgTypes = make([]protoimpl.MessageInfo, 2)
var file_controller_sessions_v1_sessions_proto_goTypes = []interface{}{
	(*SessionResponse)(nil), // 0: controller.sessions.v1.SessionResponse
	(*Worker)(nil),          // 1: controller.sessions.v1.Worker
}
var file_controller_sessions_v1_sessions_proto_depIdxs = []int32{
	1, // 0: controller.sessions.v1.SessionResponse.workers:type_name -> controller.sessions.v1.Worker
	1, // [1:1] is the sub-list for method output_type
	1, // [1:1] is the sub-list for method input_type
	1, // [1:1] is the sub-list for extension type_name
	1, // [1:1] is the sub-list for extension extendee
	0, // [0:1] is the sub-list for field type_name
}

func init() { file_controller_sessions_v1_sessions_proto_init() }
func file_controller_sessions_v1_sessions_proto_init() {
	if File_controller_sessions_v1_sessions_proto != nil {
		return
	}
	if !protoimpl.UnsafeEnabled {
		file_controller_sessions_v1_sessions_proto_msgTypes[0].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*SessionResponse); i {
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
		file_controller_sessions_v1_sessions_proto_msgTypes[1].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*Worker); i {
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
			RawDescriptor: file_controller_sessions_v1_sessions_proto_rawDesc,
			NumEnums:      0,
			NumMessages:   2,
			NumExtensions: 0,
			NumServices:   0,
		},
		GoTypes:           file_controller_sessions_v1_sessions_proto_goTypes,
		DependencyIndexes: file_controller_sessions_v1_sessions_proto_depIdxs,
		MessageInfos:      file_controller_sessions_v1_sessions_proto_msgTypes,
	}.Build()
	File_controller_sessions_v1_sessions_proto = out.File
	file_controller_sessions_v1_sessions_proto_rawDesc = nil
	file_controller_sessions_v1_sessions_proto_goTypes = nil
	file_controller_sessions_v1_sessions_proto_depIdxs = nil
}
