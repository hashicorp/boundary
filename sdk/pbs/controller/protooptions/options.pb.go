// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: BUSL-1.1

// Code generated by protoc-gen-go. DO NOT EDIT.
// versions:
// 	protoc-gen-go v1.30.0
// 	protoc        (unknown)
// source: controller/custom_options/v1/options.proto

package protooptions

import (
	protoreflect "google.golang.org/protobuf/reflect/protoreflect"
	protoimpl "google.golang.org/protobuf/runtime/protoimpl"
	descriptorpb "google.golang.org/protobuf/types/descriptorpb"
	reflect "reflect"
	sync "sync"
)

const (
	// Verify that this generated code is sufficiently up-to-date.
	_ = protoimpl.EnforceVersion(20 - protoimpl.MinVersion)
	// Verify that runtime/protoimpl is sufficiently up-to-date.
	_ = protoimpl.EnforceVersion(protoimpl.MaxVersion - 20)
)

type MaskMapping struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	This string `protobuf:"bytes,1,opt,name=this,proto3" json:"this,omitempty"`
	That string `protobuf:"bytes,2,opt,name=that,proto3" json:"that,omitempty"`
}

func (x *MaskMapping) Reset() {
	*x = MaskMapping{}
	if protoimpl.UnsafeEnabled {
		mi := &file_controller_custom_options_v1_options_proto_msgTypes[0]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *MaskMapping) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*MaskMapping) ProtoMessage() {}

func (x *MaskMapping) ProtoReflect() protoreflect.Message {
	mi := &file_controller_custom_options_v1_options_proto_msgTypes[0]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use MaskMapping.ProtoReflect.Descriptor instead.
func (*MaskMapping) Descriptor() ([]byte, []int) {
	return file_controller_custom_options_v1_options_proto_rawDescGZIP(), []int{0}
}

func (x *MaskMapping) GetThis() string {
	if x != nil {
		return x.This
	}
	return ""
}

func (x *MaskMapping) GetThat() string {
	if x != nil {
		return x.That
	}
	return ""
}

var file_controller_custom_options_v1_options_proto_extTypes = []protoimpl.ExtensionInfo{
	{
		ExtendedType:  (*descriptorpb.FieldOptions)(nil),
		ExtensionType: (*MaskMapping)(nil),
		Field:         85464,
		Name:          "controller.custom_options.v1.mask_mapping",
		Tag:           "bytes,85464,opt,name=mask_mapping",
		Filename:      "controller/custom_options/v1/options.proto",
	},
	{
		ExtendedType:  (*descriptorpb.FieldOptions)(nil),
		ExtensionType: (*bool)(nil),
		Field:         85412,
		Name:          "controller.custom_options.v1.generate_sdk_option",
		Tag:           "varint,85412,opt,name=generate_sdk_option",
		Filename:      "controller/custom_options/v1/options.proto",
	},
	{
		ExtendedType:  (*descriptorpb.FieldOptions)(nil),
		ExtensionType: (*string)(nil),
		Field:         85555,
		Name:          "controller.custom_options.v1.subtype",
		Tag:           "bytes,85555,opt,name=subtype",
		Filename:      "controller/custom_options/v1/options.proto",
	},
	{
		ExtendedType:  (*descriptorpb.FieldOptions)(nil),
		ExtensionType: (*bool)(nil),
		Field:         85556,
		Name:          "controller.custom_options.v1.subtype_source_id",
		Tag:           "varint,85556,opt,name=subtype_source_id",
		Filename:      "controller/custom_options/v1/options.proto",
	},
	{
		ExtendedType:  (*descriptorpb.FileOptions)(nil),
		ExtensionType: (*string)(nil),
		Field:         85556,
		Name:          "controller.custom_options.v1.domain",
		Tag:           "bytes,85556,opt,name=domain",
		Filename:      "controller/custom_options/v1/options.proto",
	},
}

// Extension fields to descriptorpb.FieldOptions.
var (
	// mask_mapping is an option which tags a field with the expected field mask
	// used by a companion proto if applied on the field this option is for.
	// The value of this option should be for the field name itself and not for
	// the json name.
	//
	// optional controller.custom_options.v1.MaskMapping mask_mapping = 85464;
	E_MaskMapping = &file_controller_custom_options_v1_options_proto_extTypes[0]
	// generate_sdk_option is a directive used when generating the SDK to
	// indicate that an option should be created for the field. This also controls
	// API options (DefaultX, WithX functions).
	//
	// optional bool generate_sdk_option = 85412;
	E_GenerateSdkOption = &file_controller_custom_options_v1_options_proto_extTypes[1]
	// subtype is used for oneOf attribute subtypes, to identify that we only need to parse attributes
	// of oneOf once and not for each option when generating the API
	// This will serve as a JSON key, used to transform that into the key the protobuf expects
	//
	// optional string subtype = 85555;
	E_Subtype = &file_controller_custom_options_v1_options_proto_extTypes[2]
	// subtype_source_id is used to indicate that a field provided an id that can be used
	// to determine the subtype of a message.
	//
	// optional bool subtype_source_id = 85556;
	E_SubtypeSourceId = &file_controller_custom_options_v1_options_proto_extTypes[3]
)

// Extension fields to descriptorpb.FileOptions.
var (
	// domain is used to associate the messages in a file with a domain package.
	//
	// optional string domain = 85556;
	E_Domain = &file_controller_custom_options_v1_options_proto_extTypes[4]
)

var File_controller_custom_options_v1_options_proto protoreflect.FileDescriptor

var file_controller_custom_options_v1_options_proto_rawDesc = []byte{
	0x0a, 0x2a, 0x63, 0x6f, 0x6e, 0x74, 0x72, 0x6f, 0x6c, 0x6c, 0x65, 0x72, 0x2f, 0x63, 0x75, 0x73,
	0x74, 0x6f, 0x6d, 0x5f, 0x6f, 0x70, 0x74, 0x69, 0x6f, 0x6e, 0x73, 0x2f, 0x76, 0x31, 0x2f, 0x6f,
	0x70, 0x74, 0x69, 0x6f, 0x6e, 0x73, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x12, 0x1c, 0x63, 0x6f,
	0x6e, 0x74, 0x72, 0x6f, 0x6c, 0x6c, 0x65, 0x72, 0x2e, 0x63, 0x75, 0x73, 0x74, 0x6f, 0x6d, 0x5f,
	0x6f, 0x70, 0x74, 0x69, 0x6f, 0x6e, 0x73, 0x2e, 0x76, 0x31, 0x1a, 0x20, 0x67, 0x6f, 0x6f, 0x67,
	0x6c, 0x65, 0x2f, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x62, 0x75, 0x66, 0x2f, 0x64, 0x65, 0x73, 0x63,
	0x72, 0x69, 0x70, 0x74, 0x6f, 0x72, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x22, 0x35, 0x0a, 0x0b,
	0x4d, 0x61, 0x73, 0x6b, 0x4d, 0x61, 0x70, 0x70, 0x69, 0x6e, 0x67, 0x12, 0x12, 0x0a, 0x04, 0x74,
	0x68, 0x69, 0x73, 0x18, 0x01, 0x20, 0x01, 0x28, 0x09, 0x52, 0x04, 0x74, 0x68, 0x69, 0x73, 0x12,
	0x12, 0x0a, 0x04, 0x74, 0x68, 0x61, 0x74, 0x18, 0x02, 0x20, 0x01, 0x28, 0x09, 0x52, 0x04, 0x74,
	0x68, 0x61, 0x74, 0x3a, 0x6d, 0x0a, 0x0c, 0x6d, 0x61, 0x73, 0x6b, 0x5f, 0x6d, 0x61, 0x70, 0x70,
	0x69, 0x6e, 0x67, 0x12, 0x1d, 0x2e, 0x67, 0x6f, 0x6f, 0x67, 0x6c, 0x65, 0x2e, 0x70, 0x72, 0x6f,
	0x74, 0x6f, 0x62, 0x75, 0x66, 0x2e, 0x46, 0x69, 0x65, 0x6c, 0x64, 0x4f, 0x70, 0x74, 0x69, 0x6f,
	0x6e, 0x73, 0x18, 0xd8, 0x9b, 0x05, 0x20, 0x01, 0x28, 0x0b, 0x32, 0x29, 0x2e, 0x63, 0x6f, 0x6e,
	0x74, 0x72, 0x6f, 0x6c, 0x6c, 0x65, 0x72, 0x2e, 0x63, 0x75, 0x73, 0x74, 0x6f, 0x6d, 0x5f, 0x6f,
	0x70, 0x74, 0x69, 0x6f, 0x6e, 0x73, 0x2e, 0x76, 0x31, 0x2e, 0x4d, 0x61, 0x73, 0x6b, 0x4d, 0x61,
	0x70, 0x70, 0x69, 0x6e, 0x67, 0x52, 0x0b, 0x6d, 0x61, 0x73, 0x6b, 0x4d, 0x61, 0x70, 0x70, 0x69,
	0x6e, 0x67, 0x3a, 0x4f, 0x0a, 0x13, 0x67, 0x65, 0x6e, 0x65, 0x72, 0x61, 0x74, 0x65, 0x5f, 0x73,
	0x64, 0x6b, 0x5f, 0x6f, 0x70, 0x74, 0x69, 0x6f, 0x6e, 0x12, 0x1d, 0x2e, 0x67, 0x6f, 0x6f, 0x67,
	0x6c, 0x65, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x62, 0x75, 0x66, 0x2e, 0x46, 0x69, 0x65, 0x6c,
	0x64, 0x4f, 0x70, 0x74, 0x69, 0x6f, 0x6e, 0x73, 0x18, 0xa4, 0x9b, 0x05, 0x20, 0x01, 0x28, 0x08,
	0x52, 0x11, 0x67, 0x65, 0x6e, 0x65, 0x72, 0x61, 0x74, 0x65, 0x53, 0x64, 0x6b, 0x4f, 0x70, 0x74,
	0x69, 0x6f, 0x6e, 0x3a, 0x39, 0x0a, 0x07, 0x73, 0x75, 0x62, 0x74, 0x79, 0x70, 0x65, 0x12, 0x1d,
	0x2e, 0x67, 0x6f, 0x6f, 0x67, 0x6c, 0x65, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x62, 0x75, 0x66,
	0x2e, 0x46, 0x69, 0x65, 0x6c, 0x64, 0x4f, 0x70, 0x74, 0x69, 0x6f, 0x6e, 0x73, 0x18, 0xb3, 0x9c,
	0x05, 0x20, 0x01, 0x28, 0x09, 0x52, 0x07, 0x73, 0x75, 0x62, 0x74, 0x79, 0x70, 0x65, 0x3a, 0x4b,
	0x0a, 0x11, 0x73, 0x75, 0x62, 0x74, 0x79, 0x70, 0x65, 0x5f, 0x73, 0x6f, 0x75, 0x72, 0x63, 0x65,
	0x5f, 0x69, 0x64, 0x12, 0x1d, 0x2e, 0x67, 0x6f, 0x6f, 0x67, 0x6c, 0x65, 0x2e, 0x70, 0x72, 0x6f,
	0x74, 0x6f, 0x62, 0x75, 0x66, 0x2e, 0x46, 0x69, 0x65, 0x6c, 0x64, 0x4f, 0x70, 0x74, 0x69, 0x6f,
	0x6e, 0x73, 0x18, 0xb4, 0x9c, 0x05, 0x20, 0x01, 0x28, 0x08, 0x52, 0x0f, 0x73, 0x75, 0x62, 0x74,
	0x79, 0x70, 0x65, 0x53, 0x6f, 0x75, 0x72, 0x63, 0x65, 0x49, 0x64, 0x3a, 0x36, 0x0a, 0x06, 0x64,
	0x6f, 0x6d, 0x61, 0x69, 0x6e, 0x12, 0x1c, 0x2e, 0x67, 0x6f, 0x6f, 0x67, 0x6c, 0x65, 0x2e, 0x70,
	0x72, 0x6f, 0x74, 0x6f, 0x62, 0x75, 0x66, 0x2e, 0x46, 0x69, 0x6c, 0x65, 0x4f, 0x70, 0x74, 0x69,
	0x6f, 0x6e, 0x73, 0x18, 0xb4, 0x9c, 0x05, 0x20, 0x01, 0x28, 0x09, 0x52, 0x06, 0x64, 0x6f, 0x6d,
	0x61, 0x69, 0x6e, 0x42, 0x4c, 0x5a, 0x4a, 0x67, 0x69, 0x74, 0x68, 0x75, 0x62, 0x2e, 0x63, 0x6f,
	0x6d, 0x2f, 0x68, 0x61, 0x73, 0x68, 0x69, 0x63, 0x6f, 0x72, 0x70, 0x2f, 0x62, 0x6f, 0x75, 0x6e,
	0x64, 0x61, 0x72, 0x79, 0x2f, 0x73, 0x64, 0x6b, 0x2f, 0x70, 0x62, 0x73, 0x2f, 0x63, 0x6f, 0x6e,
	0x74, 0x72, 0x6f, 0x6c, 0x6c, 0x65, 0x72, 0x2f, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x6f, 0x70, 0x74,
	0x69, 0x6f, 0x6e, 0x73, 0x3b, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x6f, 0x70, 0x74, 0x69, 0x6f, 0x6e,
	0x73, 0x62, 0x06, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x33,
}

var (
	file_controller_custom_options_v1_options_proto_rawDescOnce sync.Once
	file_controller_custom_options_v1_options_proto_rawDescData = file_controller_custom_options_v1_options_proto_rawDesc
)

func file_controller_custom_options_v1_options_proto_rawDescGZIP() []byte {
	file_controller_custom_options_v1_options_proto_rawDescOnce.Do(func() {
		file_controller_custom_options_v1_options_proto_rawDescData = protoimpl.X.CompressGZIP(file_controller_custom_options_v1_options_proto_rawDescData)
	})
	return file_controller_custom_options_v1_options_proto_rawDescData
}

var file_controller_custom_options_v1_options_proto_msgTypes = make([]protoimpl.MessageInfo, 1)
var file_controller_custom_options_v1_options_proto_goTypes = []interface{}{
	(*MaskMapping)(nil),               // 0: controller.custom_options.v1.MaskMapping
	(*descriptorpb.FieldOptions)(nil), // 1: google.protobuf.FieldOptions
	(*descriptorpb.FileOptions)(nil),  // 2: google.protobuf.FileOptions
}
var file_controller_custom_options_v1_options_proto_depIdxs = []int32{
	1, // 0: controller.custom_options.v1.mask_mapping:extendee -> google.protobuf.FieldOptions
	1, // 1: controller.custom_options.v1.generate_sdk_option:extendee -> google.protobuf.FieldOptions
	1, // 2: controller.custom_options.v1.subtype:extendee -> google.protobuf.FieldOptions
	1, // 3: controller.custom_options.v1.subtype_source_id:extendee -> google.protobuf.FieldOptions
	2, // 4: controller.custom_options.v1.domain:extendee -> google.protobuf.FileOptions
	0, // 5: controller.custom_options.v1.mask_mapping:type_name -> controller.custom_options.v1.MaskMapping
	6, // [6:6] is the sub-list for method output_type
	6, // [6:6] is the sub-list for method input_type
	5, // [5:6] is the sub-list for extension type_name
	0, // [0:5] is the sub-list for extension extendee
	0, // [0:0] is the sub-list for field type_name
}

func init() { file_controller_custom_options_v1_options_proto_init() }
func file_controller_custom_options_v1_options_proto_init() {
	if File_controller_custom_options_v1_options_proto != nil {
		return
	}
	if !protoimpl.UnsafeEnabled {
		file_controller_custom_options_v1_options_proto_msgTypes[0].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*MaskMapping); i {
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
			RawDescriptor: file_controller_custom_options_v1_options_proto_rawDesc,
			NumEnums:      0,
			NumMessages:   1,
			NumExtensions: 5,
			NumServices:   0,
		},
		GoTypes:           file_controller_custom_options_v1_options_proto_goTypes,
		DependencyIndexes: file_controller_custom_options_v1_options_proto_depIdxs,
		MessageInfos:      file_controller_custom_options_v1_options_proto_msgTypes,
		ExtensionInfos:    file_controller_custom_options_v1_options_proto_extTypes,
	}.Build()
	File_controller_custom_options_v1_options_proto = out.File
	file_controller_custom_options_v1_options_proto_rawDesc = nil
	file_controller_custom_options_v1_options_proto_goTypes = nil
	file_controller_custom_options_v1_options_proto_depIdxs = nil
}
