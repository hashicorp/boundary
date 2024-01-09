// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: BUSL-1.1

// Code generated by protoc-gen-go. DO NOT EDIT.
// versions:
// 	protoc-gen-go v1.31.0
// 	protoc        (unknown)
// source: controller/storage/kms/store/v1/data_key_version_destruction_job_progress.proto

package store

import (
	timestamp "github.com/hashicorp/boundary/internal/db/timestamp"
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

type DataKeyVersionDestructionJobProgress struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	// The id of the data key version that is being revoked
	// @inject_tag: `gorm:"not_null"`
	KeyId string `protobuf:"bytes,10,opt,name=key_id,json=keyId,proto3" json:"key_id,omitempty" gorm:"not_null"`
	// Scope id this data key version belongs to.
	// @inject_tag: `gorm:"not_null"`
	ScopeId string `protobuf:"bytes,20,opt,name=scope_id,json=scopeId,proto3" json:"scope_id,omitempty" gorm:"not_null"`
	// create_time from the RDBMS
	// @inject_tag: `gorm:"not_null"`
	CreateTime *timestamp.Timestamp `protobuf:"bytes,30,opt,name=create_time,json=createTime,proto3" json:"create_time,omitempty" gorm:"not_null"`
	// The status of this data key version destruction job
	// One of "pending", "running" or "completed"
	// @inject_tag: `gorm:"not_null"`
	Status string `protobuf:"bytes,40,opt,name=status,proto3" json:"status,omitempty" gorm:"not_null"`
	// The number of rows that have been rewrapped
	// @inject_tag: `gorm:"not_null"`
	CompletedCount int64 `protobuf:"varint,50,opt,name=completed_count,json=completedCount,proto3" json:"completed_count,omitempty" gorm:"not_null"`
	// The total number of rows that need rewrapping
	// @inject_tag: `gorm:"not_null"`
	TotalCount int64 `protobuf:"varint,60,opt,name=total_count,json=totalCount,proto3" json:"total_count,omitempty" gorm:"not_null"`
}

func (x *DataKeyVersionDestructionJobProgress) Reset() {
	*x = DataKeyVersionDestructionJobProgress{}
	if protoimpl.UnsafeEnabled {
		mi := &file_controller_storage_kms_store_v1_data_key_version_destruction_job_progress_proto_msgTypes[0]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *DataKeyVersionDestructionJobProgress) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*DataKeyVersionDestructionJobProgress) ProtoMessage() {}

func (x *DataKeyVersionDestructionJobProgress) ProtoReflect() protoreflect.Message {
	mi := &file_controller_storage_kms_store_v1_data_key_version_destruction_job_progress_proto_msgTypes[0]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use DataKeyVersionDestructionJobProgress.ProtoReflect.Descriptor instead.
func (*DataKeyVersionDestructionJobProgress) Descriptor() ([]byte, []int) {
	return file_controller_storage_kms_store_v1_data_key_version_destruction_job_progress_proto_rawDescGZIP(), []int{0}
}

func (x *DataKeyVersionDestructionJobProgress) GetKeyId() string {
	if x != nil {
		return x.KeyId
	}
	return ""
}

func (x *DataKeyVersionDestructionJobProgress) GetScopeId() string {
	if x != nil {
		return x.ScopeId
	}
	return ""
}

func (x *DataKeyVersionDestructionJobProgress) GetCreateTime() *timestamp.Timestamp {
	if x != nil {
		return x.CreateTime
	}
	return nil
}

func (x *DataKeyVersionDestructionJobProgress) GetStatus() string {
	if x != nil {
		return x.Status
	}
	return ""
}

func (x *DataKeyVersionDestructionJobProgress) GetCompletedCount() int64 {
	if x != nil {
		return x.CompletedCount
	}
	return 0
}

func (x *DataKeyVersionDestructionJobProgress) GetTotalCount() int64 {
	if x != nil {
		return x.TotalCount
	}
	return 0
}

var File_controller_storage_kms_store_v1_data_key_version_destruction_job_progress_proto protoreflect.FileDescriptor

var file_controller_storage_kms_store_v1_data_key_version_destruction_job_progress_proto_rawDesc = []byte{
	0x0a, 0x4f, 0x63, 0x6f, 0x6e, 0x74, 0x72, 0x6f, 0x6c, 0x6c, 0x65, 0x72, 0x2f, 0x73, 0x74, 0x6f,
	0x72, 0x61, 0x67, 0x65, 0x2f, 0x6b, 0x6d, 0x73, 0x2f, 0x73, 0x74, 0x6f, 0x72, 0x65, 0x2f, 0x76,
	0x31, 0x2f, 0x64, 0x61, 0x74, 0x61, 0x5f, 0x6b, 0x65, 0x79, 0x5f, 0x76, 0x65, 0x72, 0x73, 0x69,
	0x6f, 0x6e, 0x5f, 0x64, 0x65, 0x73, 0x74, 0x72, 0x75, 0x63, 0x74, 0x69, 0x6f, 0x6e, 0x5f, 0x6a,
	0x6f, 0x62, 0x5f, 0x70, 0x72, 0x6f, 0x67, 0x72, 0x65, 0x73, 0x73, 0x2e, 0x70, 0x72, 0x6f, 0x74,
	0x6f, 0x12, 0x1f, 0x63, 0x6f, 0x6e, 0x74, 0x72, 0x6f, 0x6c, 0x6c, 0x65, 0x72, 0x2e, 0x73, 0x74,
	0x6f, 0x72, 0x61, 0x67, 0x65, 0x2e, 0x6b, 0x6d, 0x73, 0x2e, 0x73, 0x74, 0x6f, 0x72, 0x65, 0x2e,
	0x76, 0x31, 0x1a, 0x2f, 0x63, 0x6f, 0x6e, 0x74, 0x72, 0x6f, 0x6c, 0x6c, 0x65, 0x72, 0x2f, 0x73,
	0x74, 0x6f, 0x72, 0x61, 0x67, 0x65, 0x2f, 0x74, 0x69, 0x6d, 0x65, 0x73, 0x74, 0x61, 0x6d, 0x70,
	0x2f, 0x76, 0x31, 0x2f, 0x74, 0x69, 0x6d, 0x65, 0x73, 0x74, 0x61, 0x6d, 0x70, 0x2e, 0x70, 0x72,
	0x6f, 0x74, 0x6f, 0x22, 0x87, 0x02, 0x0a, 0x24, 0x44, 0x61, 0x74, 0x61, 0x4b, 0x65, 0x79, 0x56,
	0x65, 0x72, 0x73, 0x69, 0x6f, 0x6e, 0x44, 0x65, 0x73, 0x74, 0x72, 0x75, 0x63, 0x74, 0x69, 0x6f,
	0x6e, 0x4a, 0x6f, 0x62, 0x50, 0x72, 0x6f, 0x67, 0x72, 0x65, 0x73, 0x73, 0x12, 0x15, 0x0a, 0x06,
	0x6b, 0x65, 0x79, 0x5f, 0x69, 0x64, 0x18, 0x0a, 0x20, 0x01, 0x28, 0x09, 0x52, 0x05, 0x6b, 0x65,
	0x79, 0x49, 0x64, 0x12, 0x19, 0x0a, 0x08, 0x73, 0x63, 0x6f, 0x70, 0x65, 0x5f, 0x69, 0x64, 0x18,
	0x14, 0x20, 0x01, 0x28, 0x09, 0x52, 0x07, 0x73, 0x63, 0x6f, 0x70, 0x65, 0x49, 0x64, 0x12, 0x4b,
	0x0a, 0x0b, 0x63, 0x72, 0x65, 0x61, 0x74, 0x65, 0x5f, 0x74, 0x69, 0x6d, 0x65, 0x18, 0x1e, 0x20,
	0x01, 0x28, 0x0b, 0x32, 0x2a, 0x2e, 0x63, 0x6f, 0x6e, 0x74, 0x72, 0x6f, 0x6c, 0x6c, 0x65, 0x72,
	0x2e, 0x73, 0x74, 0x6f, 0x72, 0x61, 0x67, 0x65, 0x2e, 0x74, 0x69, 0x6d, 0x65, 0x73, 0x74, 0x61,
	0x6d, 0x70, 0x2e, 0x76, 0x31, 0x2e, 0x54, 0x69, 0x6d, 0x65, 0x73, 0x74, 0x61, 0x6d, 0x70, 0x52,
	0x0a, 0x63, 0x72, 0x65, 0x61, 0x74, 0x65, 0x54, 0x69, 0x6d, 0x65, 0x12, 0x16, 0x0a, 0x06, 0x73,
	0x74, 0x61, 0x74, 0x75, 0x73, 0x18, 0x28, 0x20, 0x01, 0x28, 0x09, 0x52, 0x06, 0x73, 0x74, 0x61,
	0x74, 0x75, 0x73, 0x12, 0x27, 0x0a, 0x0f, 0x63, 0x6f, 0x6d, 0x70, 0x6c, 0x65, 0x74, 0x65, 0x64,
	0x5f, 0x63, 0x6f, 0x75, 0x6e, 0x74, 0x18, 0x32, 0x20, 0x01, 0x28, 0x03, 0x52, 0x0e, 0x63, 0x6f,
	0x6d, 0x70, 0x6c, 0x65, 0x74, 0x65, 0x64, 0x43, 0x6f, 0x75, 0x6e, 0x74, 0x12, 0x1f, 0x0a, 0x0b,
	0x74, 0x6f, 0x74, 0x61, 0x6c, 0x5f, 0x63, 0x6f, 0x75, 0x6e, 0x74, 0x18, 0x3c, 0x20, 0x01, 0x28,
	0x03, 0x52, 0x0a, 0x74, 0x6f, 0x74, 0x61, 0x6c, 0x43, 0x6f, 0x75, 0x6e, 0x74, 0x42, 0x38, 0x5a,
	0x36, 0x67, 0x69, 0x74, 0x68, 0x75, 0x62, 0x2e, 0x63, 0x6f, 0x6d, 0x2f, 0x68, 0x61, 0x73, 0x68,
	0x69, 0x63, 0x6f, 0x72, 0x70, 0x2f, 0x62, 0x6f, 0x75, 0x6e, 0x64, 0x61, 0x72, 0x79, 0x2f, 0x69,
	0x6e, 0x74, 0x65, 0x72, 0x6e, 0x61, 0x6c, 0x2f, 0x6b, 0x6d, 0x73, 0x2f, 0x73, 0x74, 0x6f, 0x72,
	0x65, 0x3b, 0x73, 0x74, 0x6f, 0x72, 0x65, 0x62, 0x06, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x33,
}

var (
	file_controller_storage_kms_store_v1_data_key_version_destruction_job_progress_proto_rawDescOnce sync.Once
	file_controller_storage_kms_store_v1_data_key_version_destruction_job_progress_proto_rawDescData = file_controller_storage_kms_store_v1_data_key_version_destruction_job_progress_proto_rawDesc
)

func file_controller_storage_kms_store_v1_data_key_version_destruction_job_progress_proto_rawDescGZIP() []byte {
	file_controller_storage_kms_store_v1_data_key_version_destruction_job_progress_proto_rawDescOnce.Do(func() {
		file_controller_storage_kms_store_v1_data_key_version_destruction_job_progress_proto_rawDescData = protoimpl.X.CompressGZIP(file_controller_storage_kms_store_v1_data_key_version_destruction_job_progress_proto_rawDescData)
	})
	return file_controller_storage_kms_store_v1_data_key_version_destruction_job_progress_proto_rawDescData
}

var file_controller_storage_kms_store_v1_data_key_version_destruction_job_progress_proto_msgTypes = make([]protoimpl.MessageInfo, 1)
var file_controller_storage_kms_store_v1_data_key_version_destruction_job_progress_proto_goTypes = []interface{}{
	(*DataKeyVersionDestructionJobProgress)(nil), // 0: controller.storage.kms.store.v1.DataKeyVersionDestructionJobProgress
	(*timestamp.Timestamp)(nil),                  // 1: controller.storage.timestamp.v1.Timestamp
}
var file_controller_storage_kms_store_v1_data_key_version_destruction_job_progress_proto_depIdxs = []int32{
	1, // 0: controller.storage.kms.store.v1.DataKeyVersionDestructionJobProgress.create_time:type_name -> controller.storage.timestamp.v1.Timestamp
	1, // [1:1] is the sub-list for method output_type
	1, // [1:1] is the sub-list for method input_type
	1, // [1:1] is the sub-list for extension type_name
	1, // [1:1] is the sub-list for extension extendee
	0, // [0:1] is the sub-list for field type_name
}

func init() {
	file_controller_storage_kms_store_v1_data_key_version_destruction_job_progress_proto_init()
}
func file_controller_storage_kms_store_v1_data_key_version_destruction_job_progress_proto_init() {
	if File_controller_storage_kms_store_v1_data_key_version_destruction_job_progress_proto != nil {
		return
	}
	if !protoimpl.UnsafeEnabled {
		file_controller_storage_kms_store_v1_data_key_version_destruction_job_progress_proto_msgTypes[0].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*DataKeyVersionDestructionJobProgress); i {
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
			RawDescriptor: file_controller_storage_kms_store_v1_data_key_version_destruction_job_progress_proto_rawDesc,
			NumEnums:      0,
			NumMessages:   1,
			NumExtensions: 0,
			NumServices:   0,
		},
		GoTypes:           file_controller_storage_kms_store_v1_data_key_version_destruction_job_progress_proto_goTypes,
		DependencyIndexes: file_controller_storage_kms_store_v1_data_key_version_destruction_job_progress_proto_depIdxs,
		MessageInfos:      file_controller_storage_kms_store_v1_data_key_version_destruction_job_progress_proto_msgTypes,
	}.Build()
	File_controller_storage_kms_store_v1_data_key_version_destruction_job_progress_proto = out.File
	file_controller_storage_kms_store_v1_data_key_version_destruction_job_progress_proto_rawDesc = nil
	file_controller_storage_kms_store_v1_data_key_version_destruction_job_progress_proto_goTypes = nil
	file_controller_storage_kms_store_v1_data_key_version_destruction_job_progress_proto_depIdxs = nil
}
