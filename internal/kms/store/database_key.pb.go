// Code generated by protoc-gen-go. DO NOT EDIT.
// versions:
// 	protoc-gen-go v1.25.0-devel
// 	protoc        v3.12.4
// source: controller/storage/kms/store/v1/database_key.proto

package store

import (
	timestamp "github.com/hashicorp/boundary/internal/db/timestamp"
	_ "github.com/hashicorp/boundary/internal/gen/controller/protooptions"
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

type DatabaseKey struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	// private_id is used to access the key via an API
	// @inject_tag: gorm:"primary_key"
	PrivateId string `protobuf:"bytes,10,opt,name=private_id,json=privateId,proto3" json:"private_id,omitempty" gorm:"primary_key"`
	// root key id for the key
	// @inject_tag: `gorm:"default:null"`
	RootKeyId string `protobuf:"bytes,20,opt,name=root_key_id,json=rootKeyId,proto3" json:"root_key_id,omitempty" gorm:"default:null"`
	// create_time from the RDBMS
	// @inject_tag: `gorm:"default:current_timestamp"`
	CreateTime *timestamp.Timestamp `protobuf:"bytes,30,opt,name=create_time,json=createTime,proto3" json:"create_time,omitempty" gorm:"default:current_timestamp"`
}

func (x *DatabaseKey) Reset() {
	*x = DatabaseKey{}
	if protoimpl.UnsafeEnabled {
		mi := &file_controller_storage_kms_store_v1_database_key_proto_msgTypes[0]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *DatabaseKey) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*DatabaseKey) ProtoMessage() {}

func (x *DatabaseKey) ProtoReflect() protoreflect.Message {
	mi := &file_controller_storage_kms_store_v1_database_key_proto_msgTypes[0]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use DatabaseKey.ProtoReflect.Descriptor instead.
func (*DatabaseKey) Descriptor() ([]byte, []int) {
	return file_controller_storage_kms_store_v1_database_key_proto_rawDescGZIP(), []int{0}
}

func (x *DatabaseKey) GetPrivateId() string {
	if x != nil {
		return x.PrivateId
	}
	return ""
}

func (x *DatabaseKey) GetRootKeyId() string {
	if x != nil {
		return x.RootKeyId
	}
	return ""
}

func (x *DatabaseKey) GetCreateTime() *timestamp.Timestamp {
	if x != nil {
		return x.CreateTime
	}
	return nil
}

type DatabaseKeyVersion struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	// private_id is used to access the key version via an API
	// @inject_tag: gorm:"primary_key"
	PrivateId string `protobuf:"bytes,10,opt,name=private_id,json=privateId,proto3" json:"private_id,omitempty" gorm:"primary_key"`
	// database id for the key version
	// @inject_tag: `gorm:"default:null"`
	DatabaseKeyId string `protobuf:"bytes,20,opt,name=database_key_id,json=databaseKeyId,proto3" json:"database_key_id,omitempty" gorm:"default:null"`
	// root_key_version_id of the version of the root key data.
	// @inject_tag: `gorm:"default:null"`
	RootKeyVersionId string `protobuf:"bytes,30,opt,name=root_key_version_id,json=rootKeyVersionId,proto3" json:"root_key_version_id,omitempty" gorm:"default:null"`
	// plain-text of the key data.  we are NOT storing this plain-text key
	// in the db.
	// @inject_tag: `gorm:"-" wrapping:"pt,key_data"`
	Key []byte `protobuf:"bytes,40,opt,name=key,proto3" json:"key,omitempty" gorm:"-" wrapping:"pt,key_data"`
	// ciphertext key data stored in the database
	// @inject_tag: `gorm:"column:key;not_null" wrapping:"ct,key_data"`
	CtKey []byte `protobuf:"bytes,50,opt,name=ct_key,json=ctKey,proto3" json:"ct_key,omitempty" gorm:"column:key;not_null" wrapping:"ct,key_data"`
	// version of the key data.  This is not used for optimistic locking, since
	// key versions are immutable.  It's just the version of the key.
	// @inject_tag: `gorm:"default:null"`
	Version uint32 `protobuf:"varint,60,opt,name=version,proto3" json:"version,omitempty" gorm:"default:null"`
	// create_time from the RDBMS
	// @inject_tag: `gorm:"default:current_timestamp"`
	CreateTime *timestamp.Timestamp `protobuf:"bytes,70,opt,name=create_time,json=createTime,proto3" json:"create_time,omitempty" gorm:"default:current_timestamp"`
}

func (x *DatabaseKeyVersion) Reset() {
	*x = DatabaseKeyVersion{}
	if protoimpl.UnsafeEnabled {
		mi := &file_controller_storage_kms_store_v1_database_key_proto_msgTypes[1]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *DatabaseKeyVersion) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*DatabaseKeyVersion) ProtoMessage() {}

func (x *DatabaseKeyVersion) ProtoReflect() protoreflect.Message {
	mi := &file_controller_storage_kms_store_v1_database_key_proto_msgTypes[1]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use DatabaseKeyVersion.ProtoReflect.Descriptor instead.
func (*DatabaseKeyVersion) Descriptor() ([]byte, []int) {
	return file_controller_storage_kms_store_v1_database_key_proto_rawDescGZIP(), []int{1}
}

func (x *DatabaseKeyVersion) GetPrivateId() string {
	if x != nil {
		return x.PrivateId
	}
	return ""
}

func (x *DatabaseKeyVersion) GetDatabaseKeyId() string {
	if x != nil {
		return x.DatabaseKeyId
	}
	return ""
}

func (x *DatabaseKeyVersion) GetRootKeyVersionId() string {
	if x != nil {
		return x.RootKeyVersionId
	}
	return ""
}

func (x *DatabaseKeyVersion) GetKey() []byte {
	if x != nil {
		return x.Key
	}
	return nil
}

func (x *DatabaseKeyVersion) GetCtKey() []byte {
	if x != nil {
		return x.CtKey
	}
	return nil
}

func (x *DatabaseKeyVersion) GetVersion() uint32 {
	if x != nil {
		return x.Version
	}
	return 0
}

func (x *DatabaseKeyVersion) GetCreateTime() *timestamp.Timestamp {
	if x != nil {
		return x.CreateTime
	}
	return nil
}

var File_controller_storage_kms_store_v1_database_key_proto protoreflect.FileDescriptor

var file_controller_storage_kms_store_v1_database_key_proto_rawDesc = []byte{
	0x0a, 0x32, 0x63, 0x6f, 0x6e, 0x74, 0x72, 0x6f, 0x6c, 0x6c, 0x65, 0x72, 0x2f, 0x73, 0x74, 0x6f,
	0x72, 0x61, 0x67, 0x65, 0x2f, 0x6b, 0x6d, 0x73, 0x2f, 0x73, 0x74, 0x6f, 0x72, 0x65, 0x2f, 0x76,
	0x31, 0x2f, 0x64, 0x61, 0x74, 0x61, 0x62, 0x61, 0x73, 0x65, 0x5f, 0x6b, 0x65, 0x79, 0x2e, 0x70,
	0x72, 0x6f, 0x74, 0x6f, 0x12, 0x1f, 0x63, 0x6f, 0x6e, 0x74, 0x72, 0x6f, 0x6c, 0x6c, 0x65, 0x72,
	0x2e, 0x73, 0x74, 0x6f, 0x72, 0x61, 0x67, 0x65, 0x2e, 0x6b, 0x6d, 0x73, 0x2e, 0x73, 0x74, 0x6f,
	0x72, 0x65, 0x2e, 0x76, 0x31, 0x1a, 0x2f, 0x63, 0x6f, 0x6e, 0x74, 0x72, 0x6f, 0x6c, 0x6c, 0x65,
	0x72, 0x2f, 0x73, 0x74, 0x6f, 0x72, 0x61, 0x67, 0x65, 0x2f, 0x74, 0x69, 0x6d, 0x65, 0x73, 0x74,
	0x61, 0x6d, 0x70, 0x2f, 0x76, 0x31, 0x2f, 0x74, 0x69, 0x6d, 0x65, 0x73, 0x74, 0x61, 0x6d, 0x70,
	0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x1a, 0x2a, 0x63, 0x6f, 0x6e, 0x74, 0x72, 0x6f, 0x6c, 0x6c,
	0x65, 0x72, 0x2f, 0x63, 0x75, 0x73, 0x74, 0x6f, 0x6d, 0x5f, 0x6f, 0x70, 0x74, 0x69, 0x6f, 0x6e,
	0x73, 0x2f, 0x76, 0x31, 0x2f, 0x6f, 0x70, 0x74, 0x69, 0x6f, 0x6e, 0x73, 0x2e, 0x70, 0x72, 0x6f,
	0x74, 0x6f, 0x22, 0x99, 0x01, 0x0a, 0x0b, 0x44, 0x61, 0x74, 0x61, 0x62, 0x61, 0x73, 0x65, 0x4b,
	0x65, 0x79, 0x12, 0x1d, 0x0a, 0x0a, 0x70, 0x72, 0x69, 0x76, 0x61, 0x74, 0x65, 0x5f, 0x69, 0x64,
	0x18, 0x0a, 0x20, 0x01, 0x28, 0x09, 0x52, 0x09, 0x70, 0x72, 0x69, 0x76, 0x61, 0x74, 0x65, 0x49,
	0x64, 0x12, 0x1e, 0x0a, 0x0b, 0x72, 0x6f, 0x6f, 0x74, 0x5f, 0x6b, 0x65, 0x79, 0x5f, 0x69, 0x64,
	0x18, 0x14, 0x20, 0x01, 0x28, 0x09, 0x52, 0x09, 0x72, 0x6f, 0x6f, 0x74, 0x4b, 0x65, 0x79, 0x49,
	0x64, 0x12, 0x4b, 0x0a, 0x0b, 0x63, 0x72, 0x65, 0x61, 0x74, 0x65, 0x5f, 0x74, 0x69, 0x6d, 0x65,
	0x18, 0x1e, 0x20, 0x01, 0x28, 0x0b, 0x32, 0x2a, 0x2e, 0x63, 0x6f, 0x6e, 0x74, 0x72, 0x6f, 0x6c,
	0x6c, 0x65, 0x72, 0x2e, 0x73, 0x74, 0x6f, 0x72, 0x61, 0x67, 0x65, 0x2e, 0x74, 0x69, 0x6d, 0x65,
	0x73, 0x74, 0x61, 0x6d, 0x70, 0x2e, 0x76, 0x31, 0x2e, 0x54, 0x69, 0x6d, 0x65, 0x73, 0x74, 0x61,
	0x6d, 0x70, 0x52, 0x0a, 0x63, 0x72, 0x65, 0x61, 0x74, 0x65, 0x54, 0x69, 0x6d, 0x65, 0x22, 0x9a,
	0x02, 0x0a, 0x12, 0x44, 0x61, 0x74, 0x61, 0x62, 0x61, 0x73, 0x65, 0x4b, 0x65, 0x79, 0x56, 0x65,
	0x72, 0x73, 0x69, 0x6f, 0x6e, 0x12, 0x1d, 0x0a, 0x0a, 0x70, 0x72, 0x69, 0x76, 0x61, 0x74, 0x65,
	0x5f, 0x69, 0x64, 0x18, 0x0a, 0x20, 0x01, 0x28, 0x09, 0x52, 0x09, 0x70, 0x72, 0x69, 0x76, 0x61,
	0x74, 0x65, 0x49, 0x64, 0x12, 0x26, 0x0a, 0x0f, 0x64, 0x61, 0x74, 0x61, 0x62, 0x61, 0x73, 0x65,
	0x5f, 0x6b, 0x65, 0x79, 0x5f, 0x69, 0x64, 0x18, 0x14, 0x20, 0x01, 0x28, 0x09, 0x52, 0x0d, 0x64,
	0x61, 0x74, 0x61, 0x62, 0x61, 0x73, 0x65, 0x4b, 0x65, 0x79, 0x49, 0x64, 0x12, 0x2d, 0x0a, 0x13,
	0x72, 0x6f, 0x6f, 0x74, 0x5f, 0x6b, 0x65, 0x79, 0x5f, 0x76, 0x65, 0x72, 0x73, 0x69, 0x6f, 0x6e,
	0x5f, 0x69, 0x64, 0x18, 0x1e, 0x20, 0x01, 0x28, 0x09, 0x52, 0x10, 0x72, 0x6f, 0x6f, 0x74, 0x4b,
	0x65, 0x79, 0x56, 0x65, 0x72, 0x73, 0x69, 0x6f, 0x6e, 0x49, 0x64, 0x12, 0x10, 0x0a, 0x03, 0x6b,
	0x65, 0x79, 0x18, 0x28, 0x20, 0x01, 0x28, 0x0c, 0x52, 0x03, 0x6b, 0x65, 0x79, 0x12, 0x15, 0x0a,
	0x06, 0x63, 0x74, 0x5f, 0x6b, 0x65, 0x79, 0x18, 0x32, 0x20, 0x01, 0x28, 0x0c, 0x52, 0x05, 0x63,
	0x74, 0x4b, 0x65, 0x79, 0x12, 0x18, 0x0a, 0x07, 0x76, 0x65, 0x72, 0x73, 0x69, 0x6f, 0x6e, 0x18,
	0x3c, 0x20, 0x01, 0x28, 0x0d, 0x52, 0x07, 0x76, 0x65, 0x72, 0x73, 0x69, 0x6f, 0x6e, 0x12, 0x4b,
	0x0a, 0x0b, 0x63, 0x72, 0x65, 0x61, 0x74, 0x65, 0x5f, 0x74, 0x69, 0x6d, 0x65, 0x18, 0x46, 0x20,
	0x01, 0x28, 0x0b, 0x32, 0x2a, 0x2e, 0x63, 0x6f, 0x6e, 0x74, 0x72, 0x6f, 0x6c, 0x6c, 0x65, 0x72,
	0x2e, 0x73, 0x74, 0x6f, 0x72, 0x61, 0x67, 0x65, 0x2e, 0x74, 0x69, 0x6d, 0x65, 0x73, 0x74, 0x61,
	0x6d, 0x70, 0x2e, 0x76, 0x31, 0x2e, 0x54, 0x69, 0x6d, 0x65, 0x73, 0x74, 0x61, 0x6d, 0x70, 0x52,
	0x0a, 0x63, 0x72, 0x65, 0x61, 0x74, 0x65, 0x54, 0x69, 0x6d, 0x65, 0x42, 0x38, 0x5a, 0x36, 0x67,
	0x69, 0x74, 0x68, 0x75, 0x62, 0x2e, 0x63, 0x6f, 0x6d, 0x2f, 0x68, 0x61, 0x73, 0x68, 0x69, 0x63,
	0x6f, 0x72, 0x70, 0x2f, 0x62, 0x6f, 0x75, 0x6e, 0x64, 0x61, 0x72, 0x79, 0x2f, 0x69, 0x6e, 0x74,
	0x65, 0x72, 0x6e, 0x61, 0x6c, 0x2f, 0x6b, 0x6d, 0x73, 0x2f, 0x73, 0x74, 0x6f, 0x72, 0x65, 0x3b,
	0x73, 0x74, 0x6f, 0x72, 0x65, 0x62, 0x06, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x33,
}

var (
	file_controller_storage_kms_store_v1_database_key_proto_rawDescOnce sync.Once
	file_controller_storage_kms_store_v1_database_key_proto_rawDescData = file_controller_storage_kms_store_v1_database_key_proto_rawDesc
)

func file_controller_storage_kms_store_v1_database_key_proto_rawDescGZIP() []byte {
	file_controller_storage_kms_store_v1_database_key_proto_rawDescOnce.Do(func() {
		file_controller_storage_kms_store_v1_database_key_proto_rawDescData = protoimpl.X.CompressGZIP(file_controller_storage_kms_store_v1_database_key_proto_rawDescData)
	})
	return file_controller_storage_kms_store_v1_database_key_proto_rawDescData
}

var file_controller_storage_kms_store_v1_database_key_proto_msgTypes = make([]protoimpl.MessageInfo, 2)
var file_controller_storage_kms_store_v1_database_key_proto_goTypes = []interface{}{
	(*DatabaseKey)(nil),         // 0: controller.storage.kms.store.v1.DatabaseKey
	(*DatabaseKeyVersion)(nil),  // 1: controller.storage.kms.store.v1.DatabaseKeyVersion
	(*timestamp.Timestamp)(nil), // 2: controller.storage.timestamp.v1.Timestamp
}
var file_controller_storage_kms_store_v1_database_key_proto_depIdxs = []int32{
	2, // 0: controller.storage.kms.store.v1.DatabaseKey.create_time:type_name -> controller.storage.timestamp.v1.Timestamp
	2, // 1: controller.storage.kms.store.v1.DatabaseKeyVersion.create_time:type_name -> controller.storage.timestamp.v1.Timestamp
	2, // [2:2] is the sub-list for method output_type
	2, // [2:2] is the sub-list for method input_type
	2, // [2:2] is the sub-list for extension type_name
	2, // [2:2] is the sub-list for extension extendee
	0, // [0:2] is the sub-list for field type_name
}

func init() { file_controller_storage_kms_store_v1_database_key_proto_init() }
func file_controller_storage_kms_store_v1_database_key_proto_init() {
	if File_controller_storage_kms_store_v1_database_key_proto != nil {
		return
	}
	if !protoimpl.UnsafeEnabled {
		file_controller_storage_kms_store_v1_database_key_proto_msgTypes[0].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*DatabaseKey); i {
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
		file_controller_storage_kms_store_v1_database_key_proto_msgTypes[1].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*DatabaseKeyVersion); i {
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
			RawDescriptor: file_controller_storage_kms_store_v1_database_key_proto_rawDesc,
			NumEnums:      0,
			NumMessages:   2,
			NumExtensions: 0,
			NumServices:   0,
		},
		GoTypes:           file_controller_storage_kms_store_v1_database_key_proto_goTypes,
		DependencyIndexes: file_controller_storage_kms_store_v1_database_key_proto_depIdxs,
		MessageInfos:      file_controller_storage_kms_store_v1_database_key_proto_msgTypes,
	}.Build()
	File_controller_storage_kms_store_v1_database_key_proto = out.File
	file_controller_storage_kms_store_v1_database_key_proto_rawDesc = nil
	file_controller_storage_kms_store_v1_database_key_proto_goTypes = nil
	file_controller_storage_kms_store_v1_database_key_proto_depIdxs = nil
}
