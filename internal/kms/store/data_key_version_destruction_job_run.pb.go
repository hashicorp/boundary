// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

// Code generated by protoc-gen-go. DO NOT EDIT.
// versions:
// 	protoc-gen-go v1.30.0
// 	protoc        (unknown)
// source: controller/storage/kms/store/v1/data_key_version_destruction_job_run.proto

package store

import (
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

// DataKeyVersionDestructionJobRun is used to read and write
// data from the kms_data_key_version_destruction_job_run table.
type DataKeyVersionDestructionJobRun struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	// key_id is the private id of the data key version being destroyed.
	// @inject_tag: `gorm:"primary_key"`
	KeyId string `protobuf:"bytes,10,opt,name=key_id,json=keyId,proto3" json:"key_id,omitempty" gorm:"primary_key"`
	// table_name is the table name that is being rewrapped by this run.
	// @inject_tag: `gorm:"primary_key"`
	TableName string `protobuf:"bytes,20,opt,name=table_name,json=tableName,proto3" json:"table_name,omitempty" gorm:"primary_key"`
	// total_count is the total number of rows that need to be rewrapped
	// in this table.
	// @inject_tag: `gorm:"not_null"`
	TotalCount int64 `protobuf:"varint,30,opt,name=total_count,json=totalCount,proto3" json:"total_count,omitempty" gorm:"not_null"`
	// completed_count is the number of rows that have completed rewrapping.
	// @inject_tag: `gorm:"not_null"`
	CompletedCount int64 `protobuf:"varint,40,opt,name=completed_count,json=completedCount,proto3" json:"completed_count,omitempty" gorm:"not_null"`
	// is_running defines whether this run is currently running. Only
	// one run is allowed to be running at a time.
	// @inject_tag: `gorm:"not_null"`
	IsRunning bool `protobuf:"varint,50,opt,name=is_running,json=isRunning,proto3" json:"is_running,omitempty" gorm:"not_null"`
}

func (x *DataKeyVersionDestructionJobRun) Reset() {
	*x = DataKeyVersionDestructionJobRun{}
	if protoimpl.UnsafeEnabled {
		mi := &file_controller_storage_kms_store_v1_data_key_version_destruction_job_run_proto_msgTypes[0]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *DataKeyVersionDestructionJobRun) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*DataKeyVersionDestructionJobRun) ProtoMessage() {}

func (x *DataKeyVersionDestructionJobRun) ProtoReflect() protoreflect.Message {
	mi := &file_controller_storage_kms_store_v1_data_key_version_destruction_job_run_proto_msgTypes[0]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use DataKeyVersionDestructionJobRun.ProtoReflect.Descriptor instead.
func (*DataKeyVersionDestructionJobRun) Descriptor() ([]byte, []int) {
	return file_controller_storage_kms_store_v1_data_key_version_destruction_job_run_proto_rawDescGZIP(), []int{0}
}

func (x *DataKeyVersionDestructionJobRun) GetKeyId() string {
	if x != nil {
		return x.KeyId
	}
	return ""
}

func (x *DataKeyVersionDestructionJobRun) GetTableName() string {
	if x != nil {
		return x.TableName
	}
	return ""
}

func (x *DataKeyVersionDestructionJobRun) GetTotalCount() int64 {
	if x != nil {
		return x.TotalCount
	}
	return 0
}

func (x *DataKeyVersionDestructionJobRun) GetCompletedCount() int64 {
	if x != nil {
		return x.CompletedCount
	}
	return 0
}

func (x *DataKeyVersionDestructionJobRun) GetIsRunning() bool {
	if x != nil {
		return x.IsRunning
	}
	return false
}

var File_controller_storage_kms_store_v1_data_key_version_destruction_job_run_proto protoreflect.FileDescriptor

var file_controller_storage_kms_store_v1_data_key_version_destruction_job_run_proto_rawDesc = []byte{
	0x0a, 0x4a, 0x63, 0x6f, 0x6e, 0x74, 0x72, 0x6f, 0x6c, 0x6c, 0x65, 0x72, 0x2f, 0x73, 0x74, 0x6f,
	0x72, 0x61, 0x67, 0x65, 0x2f, 0x6b, 0x6d, 0x73, 0x2f, 0x73, 0x74, 0x6f, 0x72, 0x65, 0x2f, 0x76,
	0x31, 0x2f, 0x64, 0x61, 0x74, 0x61, 0x5f, 0x6b, 0x65, 0x79, 0x5f, 0x76, 0x65, 0x72, 0x73, 0x69,
	0x6f, 0x6e, 0x5f, 0x64, 0x65, 0x73, 0x74, 0x72, 0x75, 0x63, 0x74, 0x69, 0x6f, 0x6e, 0x5f, 0x6a,
	0x6f, 0x62, 0x5f, 0x72, 0x75, 0x6e, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x12, 0x1f, 0x63, 0x6f,
	0x6e, 0x74, 0x72, 0x6f, 0x6c, 0x6c, 0x65, 0x72, 0x2e, 0x73, 0x74, 0x6f, 0x72, 0x61, 0x67, 0x65,
	0x2e, 0x6b, 0x6d, 0x73, 0x2e, 0x73, 0x74, 0x6f, 0x72, 0x65, 0x2e, 0x76, 0x31, 0x22, 0xc0, 0x01,
	0x0a, 0x1f, 0x44, 0x61, 0x74, 0x61, 0x4b, 0x65, 0x79, 0x56, 0x65, 0x72, 0x73, 0x69, 0x6f, 0x6e,
	0x44, 0x65, 0x73, 0x74, 0x72, 0x75, 0x63, 0x74, 0x69, 0x6f, 0x6e, 0x4a, 0x6f, 0x62, 0x52, 0x75,
	0x6e, 0x12, 0x15, 0x0a, 0x06, 0x6b, 0x65, 0x79, 0x5f, 0x69, 0x64, 0x18, 0x0a, 0x20, 0x01, 0x28,
	0x09, 0x52, 0x05, 0x6b, 0x65, 0x79, 0x49, 0x64, 0x12, 0x1d, 0x0a, 0x0a, 0x74, 0x61, 0x62, 0x6c,
	0x65, 0x5f, 0x6e, 0x61, 0x6d, 0x65, 0x18, 0x14, 0x20, 0x01, 0x28, 0x09, 0x52, 0x09, 0x74, 0x61,
	0x62, 0x6c, 0x65, 0x4e, 0x61, 0x6d, 0x65, 0x12, 0x1f, 0x0a, 0x0b, 0x74, 0x6f, 0x74, 0x61, 0x6c,
	0x5f, 0x63, 0x6f, 0x75, 0x6e, 0x74, 0x18, 0x1e, 0x20, 0x01, 0x28, 0x03, 0x52, 0x0a, 0x74, 0x6f,
	0x74, 0x61, 0x6c, 0x43, 0x6f, 0x75, 0x6e, 0x74, 0x12, 0x27, 0x0a, 0x0f, 0x63, 0x6f, 0x6d, 0x70,
	0x6c, 0x65, 0x74, 0x65, 0x64, 0x5f, 0x63, 0x6f, 0x75, 0x6e, 0x74, 0x18, 0x28, 0x20, 0x01, 0x28,
	0x03, 0x52, 0x0e, 0x63, 0x6f, 0x6d, 0x70, 0x6c, 0x65, 0x74, 0x65, 0x64, 0x43, 0x6f, 0x75, 0x6e,
	0x74, 0x12, 0x1d, 0x0a, 0x0a, 0x69, 0x73, 0x5f, 0x72, 0x75, 0x6e, 0x6e, 0x69, 0x6e, 0x67, 0x18,
	0x32, 0x20, 0x01, 0x28, 0x08, 0x52, 0x09, 0x69, 0x73, 0x52, 0x75, 0x6e, 0x6e, 0x69, 0x6e, 0x67,
	0x42, 0x38, 0x5a, 0x36, 0x67, 0x69, 0x74, 0x68, 0x75, 0x62, 0x2e, 0x63, 0x6f, 0x6d, 0x2f, 0x68,
	0x61, 0x73, 0x68, 0x69, 0x63, 0x6f, 0x72, 0x70, 0x2f, 0x62, 0x6f, 0x75, 0x6e, 0x64, 0x61, 0x72,
	0x79, 0x2f, 0x69, 0x6e, 0x74, 0x65, 0x72, 0x6e, 0x61, 0x6c, 0x2f, 0x6b, 0x6d, 0x73, 0x2f, 0x73,
	0x74, 0x6f, 0x72, 0x65, 0x3b, 0x73, 0x74, 0x6f, 0x72, 0x65, 0x62, 0x06, 0x70, 0x72, 0x6f, 0x74,
	0x6f, 0x33,
}

var (
	file_controller_storage_kms_store_v1_data_key_version_destruction_job_run_proto_rawDescOnce sync.Once
	file_controller_storage_kms_store_v1_data_key_version_destruction_job_run_proto_rawDescData = file_controller_storage_kms_store_v1_data_key_version_destruction_job_run_proto_rawDesc
)

func file_controller_storage_kms_store_v1_data_key_version_destruction_job_run_proto_rawDescGZIP() []byte {
	file_controller_storage_kms_store_v1_data_key_version_destruction_job_run_proto_rawDescOnce.Do(func() {
		file_controller_storage_kms_store_v1_data_key_version_destruction_job_run_proto_rawDescData = protoimpl.X.CompressGZIP(file_controller_storage_kms_store_v1_data_key_version_destruction_job_run_proto_rawDescData)
	})
	return file_controller_storage_kms_store_v1_data_key_version_destruction_job_run_proto_rawDescData
}

var file_controller_storage_kms_store_v1_data_key_version_destruction_job_run_proto_msgTypes = make([]protoimpl.MessageInfo, 1)
var file_controller_storage_kms_store_v1_data_key_version_destruction_job_run_proto_goTypes = []interface{}{
	(*DataKeyVersionDestructionJobRun)(nil), // 0: controller.storage.kms.store.v1.DataKeyVersionDestructionJobRun
}
var file_controller_storage_kms_store_v1_data_key_version_destruction_job_run_proto_depIdxs = []int32{
	0, // [0:0] is the sub-list for method output_type
	0, // [0:0] is the sub-list for method input_type
	0, // [0:0] is the sub-list for extension type_name
	0, // [0:0] is the sub-list for extension extendee
	0, // [0:0] is the sub-list for field type_name
}

func init() { file_controller_storage_kms_store_v1_data_key_version_destruction_job_run_proto_init() }
func file_controller_storage_kms_store_v1_data_key_version_destruction_job_run_proto_init() {
	if File_controller_storage_kms_store_v1_data_key_version_destruction_job_run_proto != nil {
		return
	}
	if !protoimpl.UnsafeEnabled {
		file_controller_storage_kms_store_v1_data_key_version_destruction_job_run_proto_msgTypes[0].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*DataKeyVersionDestructionJobRun); i {
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
			RawDescriptor: file_controller_storage_kms_store_v1_data_key_version_destruction_job_run_proto_rawDesc,
			NumEnums:      0,
			NumMessages:   1,
			NumExtensions: 0,
			NumServices:   0,
		},
		GoTypes:           file_controller_storage_kms_store_v1_data_key_version_destruction_job_run_proto_goTypes,
		DependencyIndexes: file_controller_storage_kms_store_v1_data_key_version_destruction_job_run_proto_depIdxs,
		MessageInfos:      file_controller_storage_kms_store_v1_data_key_version_destruction_job_run_proto_msgTypes,
	}.Build()
	File_controller_storage_kms_store_v1_data_key_version_destruction_job_run_proto = out.File
	file_controller_storage_kms_store_v1_data_key_version_destruction_job_run_proto_rawDesc = nil
	file_controller_storage_kms_store_v1_data_key_version_destruction_job_run_proto_goTypes = nil
	file_controller_storage_kms_store_v1_data_key_version_destruction_job_run_proto_depIdxs = nil
}
