// Code generated by protoc-gen-go. DO NOT EDIT.
// versions:
// 	protoc-gen-go v1.27.1
// 	protoc        v3.17.3
// source: plugin/host_catalog.proto

package proto

import (
	protoreflect "google.golang.org/protobuf/reflect/protoreflect"
	protoimpl "google.golang.org/protobuf/runtime/protoimpl"
	structpb "google.golang.org/protobuf/types/known/structpb"
	reflect "reflect"
	sync "sync"
)

const (
	// Verify that this generated code is sufficiently up-to-date.
	_ = protoimpl.EnforceVersion(20 - protoimpl.MinVersion)
	// Verify that runtime/protoimpl is sufficiently up-to-date.
	_ = protoimpl.EnforceVersion(protoimpl.MaxVersion - 20)
)

// HostCatalog represents a host catalog as passed in to a plugin call.
type HostCatalog struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	// The ID of the host catalog.
	Id string `protobuf:"bytes,10,opt,name=id,proto3" json:"id,omitempty"`
	// Attributes specific to the host catalog.
	Attributes *structpb.Struct `protobuf:"bytes,20,opt,name=attributes,proto3" json:"attributes,omitempty"`
	// A set of secrets specific to the host catalog.
	Secrets *structpb.Struct `protobuf:"bytes,30,opt,name=secrets,proto3" json:"secrets,omitempty"`
}

func (x *HostCatalog) Reset() {
	*x = HostCatalog{}
	if protoimpl.UnsafeEnabled {
		mi := &file_plugin_host_catalog_proto_msgTypes[0]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *HostCatalog) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*HostCatalog) ProtoMessage() {}

func (x *HostCatalog) ProtoReflect() protoreflect.Message {
	mi := &file_plugin_host_catalog_proto_msgTypes[0]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use HostCatalog.ProtoReflect.Descriptor instead.
func (*HostCatalog) Descriptor() ([]byte, []int) {
	return file_plugin_host_catalog_proto_rawDescGZIP(), []int{0}
}

func (x *HostCatalog) GetId() string {
	if x != nil {
		return x.Id
	}
	return ""
}

func (x *HostCatalog) GetAttributes() *structpb.Struct {
	if x != nil {
		return x.Attributes
	}
	return nil
}

func (x *HostCatalog) GetSecrets() *structpb.Struct {
	if x != nil {
		return x.Secrets
	}
	return nil
}

// HostCatalogPersisted represents state persisted between host
// catalog calls. This data is encrypted at-rest by Boundary, but is
// supplied to various plugin calls unencrypted.
type HostCatalogPersisted struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	// The persisted data.
	Data *structpb.Struct `protobuf:"bytes,100,opt,name=data,proto3" json:"data,omitempty"`
}

func (x *HostCatalogPersisted) Reset() {
	*x = HostCatalogPersisted{}
	if protoimpl.UnsafeEnabled {
		mi := &file_plugin_host_catalog_proto_msgTypes[1]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *HostCatalogPersisted) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*HostCatalogPersisted) ProtoMessage() {}

func (x *HostCatalogPersisted) ProtoReflect() protoreflect.Message {
	mi := &file_plugin_host_catalog_proto_msgTypes[1]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use HostCatalogPersisted.ProtoReflect.Descriptor instead.
func (*HostCatalogPersisted) Descriptor() ([]byte, []int) {
	return file_plugin_host_catalog_proto_rawDescGZIP(), []int{1}
}

func (x *HostCatalogPersisted) GetData() *structpb.Struct {
	if x != nil {
		return x.Data
	}
	return nil
}

var File_plugin_host_catalog_proto protoreflect.FileDescriptor

var file_plugin_host_catalog_proto_rawDesc = []byte{
	0x0a, 0x19, 0x70, 0x6c, 0x75, 0x67, 0x69, 0x6e, 0x2f, 0x68, 0x6f, 0x73, 0x74, 0x5f, 0x63, 0x61,
	0x74, 0x61, 0x6c, 0x6f, 0x67, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x12, 0x10, 0x70, 0x6c, 0x75,
	0x67, 0x69, 0x6e, 0x2e, 0x73, 0x64, 0x6b, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x1a, 0x1c, 0x67,
	0x6f, 0x6f, 0x67, 0x6c, 0x65, 0x2f, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x62, 0x75, 0x66, 0x2f, 0x73,
	0x74, 0x72, 0x75, 0x63, 0x74, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x22, 0x89, 0x01, 0x0a, 0x0b,
	0x48, 0x6f, 0x73, 0x74, 0x43, 0x61, 0x74, 0x61, 0x6c, 0x6f, 0x67, 0x12, 0x0e, 0x0a, 0x02, 0x69,
	0x64, 0x18, 0x0a, 0x20, 0x01, 0x28, 0x09, 0x52, 0x02, 0x69, 0x64, 0x12, 0x37, 0x0a, 0x0a, 0x61,
	0x74, 0x74, 0x72, 0x69, 0x62, 0x75, 0x74, 0x65, 0x73, 0x18, 0x14, 0x20, 0x01, 0x28, 0x0b, 0x32,
	0x17, 0x2e, 0x67, 0x6f, 0x6f, 0x67, 0x6c, 0x65, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x62, 0x75,
	0x66, 0x2e, 0x53, 0x74, 0x72, 0x75, 0x63, 0x74, 0x52, 0x0a, 0x61, 0x74, 0x74, 0x72, 0x69, 0x62,
	0x75, 0x74, 0x65, 0x73, 0x12, 0x31, 0x0a, 0x07, 0x73, 0x65, 0x63, 0x72, 0x65, 0x74, 0x73, 0x18,
	0x1e, 0x20, 0x01, 0x28, 0x0b, 0x32, 0x17, 0x2e, 0x67, 0x6f, 0x6f, 0x67, 0x6c, 0x65, 0x2e, 0x70,
	0x72, 0x6f, 0x74, 0x6f, 0x62, 0x75, 0x66, 0x2e, 0x53, 0x74, 0x72, 0x75, 0x63, 0x74, 0x52, 0x07,
	0x73, 0x65, 0x63, 0x72, 0x65, 0x74, 0x73, 0x22, 0x43, 0x0a, 0x14, 0x48, 0x6f, 0x73, 0x74, 0x43,
	0x61, 0x74, 0x61, 0x6c, 0x6f, 0x67, 0x50, 0x65, 0x72, 0x73, 0x69, 0x73, 0x74, 0x65, 0x64, 0x12,
	0x2b, 0x0a, 0x04, 0x64, 0x61, 0x74, 0x61, 0x18, 0x64, 0x20, 0x01, 0x28, 0x0b, 0x32, 0x17, 0x2e,
	0x67, 0x6f, 0x6f, 0x67, 0x6c, 0x65, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x62, 0x75, 0x66, 0x2e,
	0x53, 0x74, 0x72, 0x75, 0x63, 0x74, 0x52, 0x04, 0x64, 0x61, 0x74, 0x61, 0x42, 0x3f, 0x5a, 0x3d,
	0x67, 0x69, 0x74, 0x68, 0x75, 0x62, 0x2e, 0x63, 0x6f, 0x6d, 0x2f, 0x68, 0x61, 0x73, 0x68, 0x69,
	0x63, 0x6f, 0x72, 0x70, 0x2f, 0x62, 0x6f, 0x75, 0x6e, 0x64, 0x61, 0x72, 0x79, 0x2f, 0x69, 0x6e,
	0x74, 0x65, 0x72, 0x6e, 0x61, 0x6c, 0x2f, 0x70, 0x6c, 0x75, 0x67, 0x69, 0x6e, 0x2f, 0x73, 0x64,
	0x6b, 0x2f, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x3b, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x62, 0x06, 0x70,
	0x72, 0x6f, 0x74, 0x6f, 0x33,
}

var (
	file_plugin_host_catalog_proto_rawDescOnce sync.Once
	file_plugin_host_catalog_proto_rawDescData = file_plugin_host_catalog_proto_rawDesc
)

func file_plugin_host_catalog_proto_rawDescGZIP() []byte {
	file_plugin_host_catalog_proto_rawDescOnce.Do(func() {
		file_plugin_host_catalog_proto_rawDescData = protoimpl.X.CompressGZIP(file_plugin_host_catalog_proto_rawDescData)
	})
	return file_plugin_host_catalog_proto_rawDescData
}

var file_plugin_host_catalog_proto_msgTypes = make([]protoimpl.MessageInfo, 2)
var file_plugin_host_catalog_proto_goTypes = []interface{}{
	(*HostCatalog)(nil),          // 0: plugin.sdk.proto.HostCatalog
	(*HostCatalogPersisted)(nil), // 1: plugin.sdk.proto.HostCatalogPersisted
	(*structpb.Struct)(nil),      // 2: google.protobuf.Struct
}
var file_plugin_host_catalog_proto_depIdxs = []int32{
	2, // 0: plugin.sdk.proto.HostCatalog.attributes:type_name -> google.protobuf.Struct
	2, // 1: plugin.sdk.proto.HostCatalog.secrets:type_name -> google.protobuf.Struct
	2, // 2: plugin.sdk.proto.HostCatalogPersisted.data:type_name -> google.protobuf.Struct
	3, // [3:3] is the sub-list for method output_type
	3, // [3:3] is the sub-list for method input_type
	3, // [3:3] is the sub-list for extension type_name
	3, // [3:3] is the sub-list for extension extendee
	0, // [0:3] is the sub-list for field type_name
}

func init() { file_plugin_host_catalog_proto_init() }
func file_plugin_host_catalog_proto_init() {
	if File_plugin_host_catalog_proto != nil {
		return
	}
	if !protoimpl.UnsafeEnabled {
		file_plugin_host_catalog_proto_msgTypes[0].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*HostCatalog); i {
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
		file_plugin_host_catalog_proto_msgTypes[1].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*HostCatalogPersisted); i {
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
			RawDescriptor: file_plugin_host_catalog_proto_rawDesc,
			NumEnums:      0,
			NumMessages:   2,
			NumExtensions: 0,
			NumServices:   0,
		},
		GoTypes:           file_plugin_host_catalog_proto_goTypes,
		DependencyIndexes: file_plugin_host_catalog_proto_depIdxs,
		MessageInfos:      file_plugin_host_catalog_proto_msgTypes,
	}.Build()
	File_plugin_host_catalog_proto = out.File
	file_plugin_host_catalog_proto_rawDesc = nil
	file_plugin_host_catalog_proto_goTypes = nil
	file_plugin_host_catalog_proto_depIdxs = nil
}
