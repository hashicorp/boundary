// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

// Code generated by protoc-gen-go. DO NOT EDIT.
// versions:
// 	protoc-gen-go v1.33.0
// 	protoc        (unknown)
// source: controller/api/resources/billing/v1/billing.proto

package billing

import (
	protoreflect "google.golang.org/protobuf/reflect/protoreflect"
	protoimpl "google.golang.org/protobuf/runtime/protoimpl"
	timestamppb "google.golang.org/protobuf/types/known/timestamppb"
	reflect "reflect"
	sync "sync"
)

const (
	// Verify that this generated code is sufficiently up-to-date.
	_ = protoimpl.EnforceVersion(20 - protoimpl.MinVersion)
	// Verify that runtime/protoimpl is sufficiently up-to-date.
	_ = protoimpl.EnforceVersion(protoimpl.MaxVersion - 20)
)

type ActiveUsers struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	// Output only. The number of active users between the start time and end time.
	Count uint32 `protobuf:"varint,1,opt,name=count,proto3" json:"count,omitempty" class:"public"` // @gotags: `class:"public"`
	// Output only. The start time of the active users count, inclusive.
	StartTime *timestamppb.Timestamp `protobuf:"bytes,2,opt,name=start_time,proto3" json:"start_time,omitempty" class:"public"` // @gotags: class:"public"
	// Output only. The end time of the active users count, exclusive.
	EndTime *timestamppb.Timestamp `protobuf:"bytes,3,opt,name=end_time,proto3" json:"end_time,omitempty" class:"public"` // @gotags: class:"public"
}

func (x *ActiveUsers) Reset() {
	*x = ActiveUsers{}
	if protoimpl.UnsafeEnabled {
		mi := &file_controller_api_resources_billing_v1_billing_proto_msgTypes[0]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *ActiveUsers) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*ActiveUsers) ProtoMessage() {}

func (x *ActiveUsers) ProtoReflect() protoreflect.Message {
	mi := &file_controller_api_resources_billing_v1_billing_proto_msgTypes[0]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use ActiveUsers.ProtoReflect.Descriptor instead.
func (*ActiveUsers) Descriptor() ([]byte, []int) {
	return file_controller_api_resources_billing_v1_billing_proto_rawDescGZIP(), []int{0}
}

func (x *ActiveUsers) GetCount() uint32 {
	if x != nil {
		return x.Count
	}
	return 0
}

func (x *ActiveUsers) GetStartTime() *timestamppb.Timestamp {
	if x != nil {
		return x.StartTime
	}
	return nil
}

func (x *ActiveUsers) GetEndTime() *timestamppb.Timestamp {
	if x != nil {
		return x.EndTime
	}
	return nil
}

var File_controller_api_resources_billing_v1_billing_proto protoreflect.FileDescriptor

var file_controller_api_resources_billing_v1_billing_proto_rawDesc = []byte{
	0x0a, 0x31, 0x63, 0x6f, 0x6e, 0x74, 0x72, 0x6f, 0x6c, 0x6c, 0x65, 0x72, 0x2f, 0x61, 0x70, 0x69,
	0x2f, 0x72, 0x65, 0x73, 0x6f, 0x75, 0x72, 0x63, 0x65, 0x73, 0x2f, 0x62, 0x69, 0x6c, 0x6c, 0x69,
	0x6e, 0x67, 0x2f, 0x76, 0x31, 0x2f, 0x62, 0x69, 0x6c, 0x6c, 0x69, 0x6e, 0x67, 0x2e, 0x70, 0x72,
	0x6f, 0x74, 0x6f, 0x12, 0x23, 0x63, 0x6f, 0x6e, 0x74, 0x72, 0x6f, 0x6c, 0x6c, 0x65, 0x72, 0x2e,
	0x61, 0x70, 0x69, 0x2e, 0x72, 0x65, 0x73, 0x6f, 0x75, 0x72, 0x63, 0x65, 0x73, 0x2e, 0x62, 0x69,
	0x6c, 0x6c, 0x69, 0x6e, 0x67, 0x2e, 0x76, 0x31, 0x1a, 0x1f, 0x67, 0x6f, 0x6f, 0x67, 0x6c, 0x65,
	0x2f, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x62, 0x75, 0x66, 0x2f, 0x74, 0x69, 0x6d, 0x65, 0x73, 0x74,
	0x61, 0x6d, 0x70, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x22, 0x97, 0x01, 0x0a, 0x0b, 0x41, 0x63,
	0x74, 0x69, 0x76, 0x65, 0x55, 0x73, 0x65, 0x72, 0x73, 0x12, 0x14, 0x0a, 0x05, 0x63, 0x6f, 0x75,
	0x6e, 0x74, 0x18, 0x01, 0x20, 0x01, 0x28, 0x0d, 0x52, 0x05, 0x63, 0x6f, 0x75, 0x6e, 0x74, 0x12,
	0x3a, 0x0a, 0x0a, 0x73, 0x74, 0x61, 0x72, 0x74, 0x5f, 0x74, 0x69, 0x6d, 0x65, 0x18, 0x02, 0x20,
	0x01, 0x28, 0x0b, 0x32, 0x1a, 0x2e, 0x67, 0x6f, 0x6f, 0x67, 0x6c, 0x65, 0x2e, 0x70, 0x72, 0x6f,
	0x74, 0x6f, 0x62, 0x75, 0x66, 0x2e, 0x54, 0x69, 0x6d, 0x65, 0x73, 0x74, 0x61, 0x6d, 0x70, 0x52,
	0x0a, 0x73, 0x74, 0x61, 0x72, 0x74, 0x5f, 0x74, 0x69, 0x6d, 0x65, 0x12, 0x36, 0x0a, 0x08, 0x65,
	0x6e, 0x64, 0x5f, 0x74, 0x69, 0x6d, 0x65, 0x18, 0x03, 0x20, 0x01, 0x28, 0x0b, 0x32, 0x1a, 0x2e,
	0x67, 0x6f, 0x6f, 0x67, 0x6c, 0x65, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x62, 0x75, 0x66, 0x2e,
	0x54, 0x69, 0x6d, 0x65, 0x73, 0x74, 0x61, 0x6d, 0x70, 0x52, 0x08, 0x65, 0x6e, 0x64, 0x5f, 0x74,
	0x69, 0x6d, 0x65, 0x42, 0x50, 0x5a, 0x4e, 0x67, 0x69, 0x74, 0x68, 0x75, 0x62, 0x2e, 0x63, 0x6f,
	0x6d, 0x2f, 0x68, 0x61, 0x73, 0x68, 0x69, 0x63, 0x6f, 0x72, 0x70, 0x2f, 0x62, 0x6f, 0x75, 0x6e,
	0x64, 0x61, 0x72, 0x79, 0x2f, 0x73, 0x64, 0x6b, 0x2f, 0x70, 0x62, 0x73, 0x2f, 0x63, 0x6f, 0x6e,
	0x74, 0x72, 0x6f, 0x6c, 0x6c, 0x65, 0x72, 0x2f, 0x61, 0x70, 0x69, 0x2f, 0x72, 0x65, 0x73, 0x6f,
	0x75, 0x72, 0x63, 0x65, 0x73, 0x2f, 0x62, 0x69, 0x6c, 0x6c, 0x69, 0x6e, 0x67, 0x3b, 0x62, 0x69,
	0x6c, 0x6c, 0x69, 0x6e, 0x67, 0x62, 0x06, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x33,
}

var (
	file_controller_api_resources_billing_v1_billing_proto_rawDescOnce sync.Once
	file_controller_api_resources_billing_v1_billing_proto_rawDescData = file_controller_api_resources_billing_v1_billing_proto_rawDesc
)

func file_controller_api_resources_billing_v1_billing_proto_rawDescGZIP() []byte {
	file_controller_api_resources_billing_v1_billing_proto_rawDescOnce.Do(func() {
		file_controller_api_resources_billing_v1_billing_proto_rawDescData = protoimpl.X.CompressGZIP(file_controller_api_resources_billing_v1_billing_proto_rawDescData)
	})
	return file_controller_api_resources_billing_v1_billing_proto_rawDescData
}

var file_controller_api_resources_billing_v1_billing_proto_msgTypes = make([]protoimpl.MessageInfo, 1)
var file_controller_api_resources_billing_v1_billing_proto_goTypes = []interface{}{
	(*ActiveUsers)(nil),           // 0: controller.api.resources.billing.v1.ActiveUsers
	(*timestamppb.Timestamp)(nil), // 1: google.protobuf.Timestamp
}
var file_controller_api_resources_billing_v1_billing_proto_depIdxs = []int32{
	1, // 0: controller.api.resources.billing.v1.ActiveUsers.start_time:type_name -> google.protobuf.Timestamp
	1, // 1: controller.api.resources.billing.v1.ActiveUsers.end_time:type_name -> google.protobuf.Timestamp
	2, // [2:2] is the sub-list for method output_type
	2, // [2:2] is the sub-list for method input_type
	2, // [2:2] is the sub-list for extension type_name
	2, // [2:2] is the sub-list for extension extendee
	0, // [0:2] is the sub-list for field type_name
}

func init() { file_controller_api_resources_billing_v1_billing_proto_init() }
func file_controller_api_resources_billing_v1_billing_proto_init() {
	if File_controller_api_resources_billing_v1_billing_proto != nil {
		return
	}
	if !protoimpl.UnsafeEnabled {
		file_controller_api_resources_billing_v1_billing_proto_msgTypes[0].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*ActiveUsers); i {
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
			RawDescriptor: file_controller_api_resources_billing_v1_billing_proto_rawDesc,
			NumEnums:      0,
			NumMessages:   1,
			NumExtensions: 0,
			NumServices:   0,
		},
		GoTypes:           file_controller_api_resources_billing_v1_billing_proto_goTypes,
		DependencyIndexes: file_controller_api_resources_billing_v1_billing_proto_depIdxs,
		MessageInfos:      file_controller_api_resources_billing_v1_billing_proto_msgTypes,
	}.Build()
	File_controller_api_resources_billing_v1_billing_proto = out.File
	file_controller_api_resources_billing_v1_billing_proto_rawDesc = nil
	file_controller_api_resources_billing_v1_billing_proto_goTypes = nil
	file_controller_api_resources_billing_v1_billing_proto_depIdxs = nil
}
