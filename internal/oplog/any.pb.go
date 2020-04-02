// Code generated by protoc-gen-go. DO NOT EDIT.
// versions:
// 	protoc-gen-go v1.20.1
// 	protoc        v3.11.4
// source: internal/oplog/any.proto

package oplog

import (
	proto "github.com/golang/protobuf/proto"
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

// OpType provides the type of operation the Any message represents (create,
// update, delete)
type OpType int32

const (
	// UNKNOWN_OP is an unknown operation
	OpType_UNKNOWN_OP OpType = 0
	// CREATE_OP is a create operation
	OpType_CREATE_OP OpType = 1
	// UPDATE_OP is an update operation
	OpType_UPDATE_OP OpType = 2
	// DELETE_OP is a delete operation
	OpType_DELETE_OP OpType = 3
)

// Enum value maps for OpType.
var (
	OpType_name = map[int32]string{
		0: "UNKNOWN_OP",
		1: "CREATE_OP",
		2: "UPDATE_OP",
		3: "DELETE_OP",
	}
	OpType_value = map[string]int32{
		"UNKNOWN_OP": 0,
		"CREATE_OP":  1,
		"UPDATE_OP":  2,
		"DELETE_OP":  3,
	}
)

func (x OpType) Enum() *OpType {
	p := new(OpType)
	*p = x
	return p
}

func (x OpType) String() string {
	return protoimpl.X.EnumStringOf(x.Descriptor(), protoreflect.EnumNumber(x))
}

func (OpType) Descriptor() protoreflect.EnumDescriptor {
	return file_internal_oplog_any_proto_enumTypes[0].Descriptor()
}

func (OpType) Type() protoreflect.EnumType {
	return &file_internal_oplog_any_proto_enumTypes[0]
}

func (x OpType) Number() protoreflect.EnumNumber {
	return protoreflect.EnumNumber(x)
}

// Deprecated: Use OpType.Descriptor instead.
func (OpType) EnumDescriptor() ([]byte, []int) {
	return file_internal_oplog_any_proto_rawDescGZIP(), []int{0}
}

// AnyOperation provides a message for anything and the type of operation it
// represents.
type AnyOperation struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	TypeName      string `protobuf:"bytes,1,opt,name=type_name,json=typeName,proto3" json:"type_name,omitempty"`
	Value         []byte `protobuf:"bytes,2,opt,name=value,proto3" json:"value,omitempty"`
	OperationType OpType `protobuf:"varint,3,opt,name=operation_type,json=operationType,proto3,enum=hashicorp.watchtower.controller.oplog.v1.OpType" json:"operation_type,omitempty"`
	FieldMask     string `protobuf:"bytes,4,opt,name=field_mask,json=fieldMask,proto3" json:"field_mask,omitempty"`
}

func (x *AnyOperation) Reset() {
	*x = AnyOperation{}
	if protoimpl.UnsafeEnabled {
		mi := &file_internal_oplog_any_proto_msgTypes[0]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *AnyOperation) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*AnyOperation) ProtoMessage() {}

func (x *AnyOperation) ProtoReflect() protoreflect.Message {
	mi := &file_internal_oplog_any_proto_msgTypes[0]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use AnyOperation.ProtoReflect.Descriptor instead.
func (*AnyOperation) Descriptor() ([]byte, []int) {
	return file_internal_oplog_any_proto_rawDescGZIP(), []int{0}
}

func (x *AnyOperation) GetTypeName() string {
	if x != nil {
		return x.TypeName
	}
	return ""
}

func (x *AnyOperation) GetValue() []byte {
	if x != nil {
		return x.Value
	}
	return nil
}

func (x *AnyOperation) GetOperationType() OpType {
	if x != nil {
		return x.OperationType
	}
	return OpType_UNKNOWN_OP
}

func (x *AnyOperation) GetFieldMask() string {
	if x != nil {
		return x.FieldMask
	}
	return ""
}

var File_internal_oplog_any_proto protoreflect.FileDescriptor

var file_internal_oplog_any_proto_rawDesc = []byte{
	0x0a, 0x18, 0x69, 0x6e, 0x74, 0x65, 0x72, 0x6e, 0x61, 0x6c, 0x2f, 0x6f, 0x70, 0x6c, 0x6f, 0x67,
	0x2f, 0x61, 0x6e, 0x79, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x12, 0x28, 0x68, 0x61, 0x73, 0x68,
	0x69, 0x63, 0x6f, 0x72, 0x70, 0x2e, 0x77, 0x61, 0x74, 0x63, 0x68, 0x74, 0x6f, 0x77, 0x65, 0x72,
	0x2e, 0x63, 0x6f, 0x6e, 0x74, 0x72, 0x6f, 0x6c, 0x6c, 0x65, 0x72, 0x2e, 0x6f, 0x70, 0x6c, 0x6f,
	0x67, 0x2e, 0x76, 0x31, 0x22, 0xb9, 0x01, 0x0a, 0x0c, 0x41, 0x6e, 0x79, 0x4f, 0x70, 0x65, 0x72,
	0x61, 0x74, 0x69, 0x6f, 0x6e, 0x12, 0x1b, 0x0a, 0x09, 0x74, 0x79, 0x70, 0x65, 0x5f, 0x6e, 0x61,
	0x6d, 0x65, 0x18, 0x01, 0x20, 0x01, 0x28, 0x09, 0x52, 0x08, 0x74, 0x79, 0x70, 0x65, 0x4e, 0x61,
	0x6d, 0x65, 0x12, 0x14, 0x0a, 0x05, 0x76, 0x61, 0x6c, 0x75, 0x65, 0x18, 0x02, 0x20, 0x01, 0x28,
	0x0c, 0x52, 0x05, 0x76, 0x61, 0x6c, 0x75, 0x65, 0x12, 0x57, 0x0a, 0x0e, 0x6f, 0x70, 0x65, 0x72,
	0x61, 0x74, 0x69, 0x6f, 0x6e, 0x5f, 0x74, 0x79, 0x70, 0x65, 0x18, 0x03, 0x20, 0x01, 0x28, 0x0e,
	0x32, 0x30, 0x2e, 0x68, 0x61, 0x73, 0x68, 0x69, 0x63, 0x6f, 0x72, 0x70, 0x2e, 0x77, 0x61, 0x74,
	0x63, 0x68, 0x74, 0x6f, 0x77, 0x65, 0x72, 0x2e, 0x63, 0x6f, 0x6e, 0x74, 0x72, 0x6f, 0x6c, 0x6c,
	0x65, 0x72, 0x2e, 0x6f, 0x70, 0x6c, 0x6f, 0x67, 0x2e, 0x76, 0x31, 0x2e, 0x4f, 0x70, 0x54, 0x79,
	0x70, 0x65, 0x52, 0x0d, 0x6f, 0x70, 0x65, 0x72, 0x61, 0x74, 0x69, 0x6f, 0x6e, 0x54, 0x79, 0x70,
	0x65, 0x12, 0x1d, 0x0a, 0x0a, 0x66, 0x69, 0x65, 0x6c, 0x64, 0x5f, 0x6d, 0x61, 0x73, 0x6b, 0x18,
	0x04, 0x20, 0x01, 0x28, 0x09, 0x52, 0x09, 0x66, 0x69, 0x65, 0x6c, 0x64, 0x4d, 0x61, 0x73, 0x6b,
	0x2a, 0x45, 0x0a, 0x06, 0x4f, 0x70, 0x54, 0x79, 0x70, 0x65, 0x12, 0x0e, 0x0a, 0x0a, 0x55, 0x4e,
	0x4b, 0x4e, 0x4f, 0x57, 0x4e, 0x5f, 0x4f, 0x50, 0x10, 0x00, 0x12, 0x0d, 0x0a, 0x09, 0x43, 0x52,
	0x45, 0x41, 0x54, 0x45, 0x5f, 0x4f, 0x50, 0x10, 0x01, 0x12, 0x0d, 0x0a, 0x09, 0x55, 0x50, 0x44,
	0x41, 0x54, 0x45, 0x5f, 0x4f, 0x50, 0x10, 0x02, 0x12, 0x0d, 0x0a, 0x09, 0x44, 0x45, 0x4c, 0x45,
	0x54, 0x45, 0x5f, 0x4f, 0x50, 0x10, 0x03, 0x42, 0x3c, 0x5a, 0x3a, 0x67, 0x69, 0x74, 0x68, 0x75,
	0x62, 0x2e, 0x63, 0x6f, 0x6d, 0x2f, 0x68, 0x61, 0x73, 0x68, 0x69, 0x63, 0x6f, 0x72, 0x70, 0x2f,
	0x77, 0x61, 0x74, 0x63, 0x68, 0x74, 0x6f, 0x77, 0x65, 0x72, 0x2f, 0x69, 0x6e, 0x74, 0x65, 0x72,
	0x6e, 0x61, 0x6c, 0x2f, 0x6f, 0x70, 0x6c, 0x6f, 0x67, 0x2f, 0x6f, 0x70, 0x6c, 0x6f, 0x67, 0x3b,
	0x6f, 0x70, 0x6c, 0x6f, 0x67, 0x62, 0x06, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x33,
}

var (
	file_internal_oplog_any_proto_rawDescOnce sync.Once
	file_internal_oplog_any_proto_rawDescData = file_internal_oplog_any_proto_rawDesc
)

func file_internal_oplog_any_proto_rawDescGZIP() []byte {
	file_internal_oplog_any_proto_rawDescOnce.Do(func() {
		file_internal_oplog_any_proto_rawDescData = protoimpl.X.CompressGZIP(file_internal_oplog_any_proto_rawDescData)
	})
	return file_internal_oplog_any_proto_rawDescData
}

var file_internal_oplog_any_proto_enumTypes = make([]protoimpl.EnumInfo, 1)
var file_internal_oplog_any_proto_msgTypes = make([]protoimpl.MessageInfo, 1)
var file_internal_oplog_any_proto_goTypes = []interface{}{
	(OpType)(0),          // 0: hashicorp.watchtower.controller.oplog.v1.OpType
	(*AnyOperation)(nil), // 1: hashicorp.watchtower.controller.oplog.v1.AnyOperation
}
var file_internal_oplog_any_proto_depIdxs = []int32{
	0, // 0: hashicorp.watchtower.controller.oplog.v1.AnyOperation.operation_type:type_name -> hashicorp.watchtower.controller.oplog.v1.OpType
	1, // [1:1] is the sub-list for method output_type
	1, // [1:1] is the sub-list for method input_type
	1, // [1:1] is the sub-list for extension type_name
	1, // [1:1] is the sub-list for extension extendee
	0, // [0:1] is the sub-list for field type_name
}

func init() { file_internal_oplog_any_proto_init() }
func file_internal_oplog_any_proto_init() {
	if File_internal_oplog_any_proto != nil {
		return
	}
	if !protoimpl.UnsafeEnabled {
		file_internal_oplog_any_proto_msgTypes[0].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*AnyOperation); i {
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
			RawDescriptor: file_internal_oplog_any_proto_rawDesc,
			NumEnums:      1,
			NumMessages:   1,
			NumExtensions: 0,
			NumServices:   0,
		},
		GoTypes:           file_internal_oplog_any_proto_goTypes,
		DependencyIndexes: file_internal_oplog_any_proto_depIdxs,
		EnumInfos:         file_internal_oplog_any_proto_enumTypes,
		MessageInfos:      file_internal_oplog_any_proto_msgTypes,
	}.Build()
	File_internal_oplog_any_proto = out.File
	file_internal_oplog_any_proto_rawDesc = nil
	file_internal_oplog_any_proto_goTypes = nil
	file_internal_oplog_any_proto_depIdxs = nil
}
