// Code generated by protoc-gen-go. DO NOT EDIT.
// versions:
// 	protoc-gen-go v1.25.0
// 	protoc        v3.12.4
// source: controller/storage/kms/store/v1/external_config.proto

package store

import (
	proto "github.com/golang/protobuf/proto"
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

// This is a compile-time assertion that a sufficiently up-to-date version
// of the legacy proto package is being used.
const _ = proto.ProtoPackageIsVersion4

type ExternalConfig struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	// private_id is used to access the config via an API
	// @inject_tag: gorm:"primary_key"
	PrivateId string `protobuf:"bytes,1,opt,name=private_id,json=privateId,proto3" json:"private_id,omitempty" gorm:"primary_key"`
	// scope id for the config
	// @inject_tag: `gorm:"default:null"`
	ScopeId string `protobuf:"bytes,2,opt,name=scope_id,json=scopeId,proto3" json:"scope_id,omitempty" gorm:"default:null"`
	// type of the external kms' config
	// @inject_tag: `gorm:"default:null"`
	Type string `protobuf:"bytes,3,opt,name=type,proto3" json:"type,omitempty" gorm:"default:null"`
	// plain-text of the config data.  we are NOT storing this plain-text config
	// in the db.
	// @inject_tag: `gorm:"-" wrapping:"pt,config_data"`
	Config string `protobuf:"bytes,4,opt,name=config,proto3" json:"config,omitempty" gorm:"-" wrapping:"pt,config_data"`
	// ciphertext config data stored in the database
	// @inject_tag: `gorm:"column:config;not_null" wrapping:"ct,config_data"`
	CtConfig []byte `protobuf:"bytes,5,opt,name=ct_config,json=ctConfig,proto3" json:"ct_config,omitempty" gorm:"column:config;not_null" wrapping:"ct,config_data"`
	// version allows optimistic locking of the config
	// @inject_tag: `gorm:"default:null"`
	Version uint32 `protobuf:"varint,6,opt,name=version,proto3" json:"version,omitempty" gorm:"default:null"`
	// create_time from the RDBMS
	// @inject_tag: `gorm:"default:current_timestamp"`
	CreateTime *timestamp.Timestamp `protobuf:"bytes,7,opt,name=create_time,json=createTime,proto3" json:"create_time,omitempty" gorm:"default:current_timestamp"`
	// update_time from the RDBMS
	// @inject_tag: `gorm:"default:current_timestamp"`
	UpdateTime *timestamp.Timestamp `protobuf:"bytes,8,opt,name=update_time,json=updateTime,proto3" json:"update_time,omitempty" gorm:"default:current_timestamp"`
}

func (x *ExternalConfig) Reset() {
	*x = ExternalConfig{}
	if protoimpl.UnsafeEnabled {
		mi := &file_controller_storage_kms_store_v1_external_config_proto_msgTypes[0]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *ExternalConfig) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*ExternalConfig) ProtoMessage() {}

func (x *ExternalConfig) ProtoReflect() protoreflect.Message {
	mi := &file_controller_storage_kms_store_v1_external_config_proto_msgTypes[0]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use ExternalConfig.ProtoReflect.Descriptor instead.
func (*ExternalConfig) Descriptor() ([]byte, []int) {
	return file_controller_storage_kms_store_v1_external_config_proto_rawDescGZIP(), []int{0}
}

func (x *ExternalConfig) GetPrivateId() string {
	if x != nil {
		return x.PrivateId
	}
	return ""
}

func (x *ExternalConfig) GetScopeId() string {
	if x != nil {
		return x.ScopeId
	}
	return ""
}

func (x *ExternalConfig) GetType() string {
	if x != nil {
		return x.Type
	}
	return ""
}

func (x *ExternalConfig) GetConfig() string {
	if x != nil {
		return x.Config
	}
	return ""
}

func (x *ExternalConfig) GetCtConfig() []byte {
	if x != nil {
		return x.CtConfig
	}
	return nil
}

func (x *ExternalConfig) GetVersion() uint32 {
	if x != nil {
		return x.Version
	}
	return 0
}

func (x *ExternalConfig) GetCreateTime() *timestamp.Timestamp {
	if x != nil {
		return x.CreateTime
	}
	return nil
}

func (x *ExternalConfig) GetUpdateTime() *timestamp.Timestamp {
	if x != nil {
		return x.UpdateTime
	}
	return nil
}

var File_controller_storage_kms_store_v1_external_config_proto protoreflect.FileDescriptor

var file_controller_storage_kms_store_v1_external_config_proto_rawDesc = []byte{
	0x0a, 0x35, 0x63, 0x6f, 0x6e, 0x74, 0x72, 0x6f, 0x6c, 0x6c, 0x65, 0x72, 0x2f, 0x73, 0x74, 0x6f,
	0x72, 0x61, 0x67, 0x65, 0x2f, 0x6b, 0x6d, 0x73, 0x2f, 0x73, 0x74, 0x6f, 0x72, 0x65, 0x2f, 0x76,
	0x31, 0x2f, 0x65, 0x78, 0x74, 0x65, 0x72, 0x6e, 0x61, 0x6c, 0x5f, 0x63, 0x6f, 0x6e, 0x66, 0x69,
	0x67, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x12, 0x1f, 0x63, 0x6f, 0x6e, 0x74, 0x72, 0x6f, 0x6c,
	0x6c, 0x65, 0x72, 0x2e, 0x73, 0x74, 0x6f, 0x72, 0x61, 0x67, 0x65, 0x2e, 0x6b, 0x6d, 0x73, 0x2e,
	0x73, 0x74, 0x6f, 0x72, 0x65, 0x2e, 0x76, 0x31, 0x1a, 0x2f, 0x63, 0x6f, 0x6e, 0x74, 0x72, 0x6f,
	0x6c, 0x6c, 0x65, 0x72, 0x2f, 0x73, 0x74, 0x6f, 0x72, 0x61, 0x67, 0x65, 0x2f, 0x74, 0x69, 0x6d,
	0x65, 0x73, 0x74, 0x61, 0x6d, 0x70, 0x2f, 0x76, 0x31, 0x2f, 0x74, 0x69, 0x6d, 0x65, 0x73, 0x74,
	0x61, 0x6d, 0x70, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x1a, 0x2a, 0x63, 0x6f, 0x6e, 0x74, 0x72,
	0x6f, 0x6c, 0x6c, 0x65, 0x72, 0x2f, 0x63, 0x75, 0x73, 0x74, 0x6f, 0x6d, 0x5f, 0x6f, 0x70, 0x74,
	0x69, 0x6f, 0x6e, 0x73, 0x2f, 0x76, 0x31, 0x2f, 0x6f, 0x70, 0x74, 0x69, 0x6f, 0x6e, 0x73, 0x2e,
	0x70, 0x72, 0x6f, 0x74, 0x6f, 0x22, 0xc7, 0x02, 0x0a, 0x0e, 0x45, 0x78, 0x74, 0x65, 0x72, 0x6e,
	0x61, 0x6c, 0x43, 0x6f, 0x6e, 0x66, 0x69, 0x67, 0x12, 0x1d, 0x0a, 0x0a, 0x70, 0x72, 0x69, 0x76,
	0x61, 0x74, 0x65, 0x5f, 0x69, 0x64, 0x18, 0x01, 0x20, 0x01, 0x28, 0x09, 0x52, 0x09, 0x70, 0x72,
	0x69, 0x76, 0x61, 0x74, 0x65, 0x49, 0x64, 0x12, 0x19, 0x0a, 0x08, 0x73, 0x63, 0x6f, 0x70, 0x65,
	0x5f, 0x69, 0x64, 0x18, 0x02, 0x20, 0x01, 0x28, 0x09, 0x52, 0x07, 0x73, 0x63, 0x6f, 0x70, 0x65,
	0x49, 0x64, 0x12, 0x12, 0x0a, 0x04, 0x74, 0x79, 0x70, 0x65, 0x18, 0x03, 0x20, 0x01, 0x28, 0x09,
	0x52, 0x04, 0x74, 0x79, 0x70, 0x65, 0x12, 0x16, 0x0a, 0x06, 0x63, 0x6f, 0x6e, 0x66, 0x69, 0x67,
	0x18, 0x04, 0x20, 0x01, 0x28, 0x09, 0x52, 0x06, 0x63, 0x6f, 0x6e, 0x66, 0x69, 0x67, 0x12, 0x1b,
	0x0a, 0x09, 0x63, 0x74, 0x5f, 0x63, 0x6f, 0x6e, 0x66, 0x69, 0x67, 0x18, 0x05, 0x20, 0x01, 0x28,
	0x0c, 0x52, 0x08, 0x63, 0x74, 0x43, 0x6f, 0x6e, 0x66, 0x69, 0x67, 0x12, 0x18, 0x0a, 0x07, 0x76,
	0x65, 0x72, 0x73, 0x69, 0x6f, 0x6e, 0x18, 0x06, 0x20, 0x01, 0x28, 0x0d, 0x52, 0x07, 0x76, 0x65,
	0x72, 0x73, 0x69, 0x6f, 0x6e, 0x12, 0x4b, 0x0a, 0x0b, 0x63, 0x72, 0x65, 0x61, 0x74, 0x65, 0x5f,
	0x74, 0x69, 0x6d, 0x65, 0x18, 0x07, 0x20, 0x01, 0x28, 0x0b, 0x32, 0x2a, 0x2e, 0x63, 0x6f, 0x6e,
	0x74, 0x72, 0x6f, 0x6c, 0x6c, 0x65, 0x72, 0x2e, 0x73, 0x74, 0x6f, 0x72, 0x61, 0x67, 0x65, 0x2e,
	0x74, 0x69, 0x6d, 0x65, 0x73, 0x74, 0x61, 0x6d, 0x70, 0x2e, 0x76, 0x31, 0x2e, 0x54, 0x69, 0x6d,
	0x65, 0x73, 0x74, 0x61, 0x6d, 0x70, 0x52, 0x0a, 0x63, 0x72, 0x65, 0x61, 0x74, 0x65, 0x54, 0x69,
	0x6d, 0x65, 0x12, 0x4b, 0x0a, 0x0b, 0x75, 0x70, 0x64, 0x61, 0x74, 0x65, 0x5f, 0x74, 0x69, 0x6d,
	0x65, 0x18, 0x08, 0x20, 0x01, 0x28, 0x0b, 0x32, 0x2a, 0x2e, 0x63, 0x6f, 0x6e, 0x74, 0x72, 0x6f,
	0x6c, 0x6c, 0x65, 0x72, 0x2e, 0x73, 0x74, 0x6f, 0x72, 0x61, 0x67, 0x65, 0x2e, 0x74, 0x69, 0x6d,
	0x65, 0x73, 0x74, 0x61, 0x6d, 0x70, 0x2e, 0x76, 0x31, 0x2e, 0x54, 0x69, 0x6d, 0x65, 0x73, 0x74,
	0x61, 0x6d, 0x70, 0x52, 0x0a, 0x75, 0x70, 0x64, 0x61, 0x74, 0x65, 0x54, 0x69, 0x6d, 0x65, 0x42,
	0x38, 0x5a, 0x36, 0x67, 0x69, 0x74, 0x68, 0x75, 0x62, 0x2e, 0x63, 0x6f, 0x6d, 0x2f, 0x68, 0x61,
	0x73, 0x68, 0x69, 0x63, 0x6f, 0x72, 0x70, 0x2f, 0x62, 0x6f, 0x75, 0x6e, 0x64, 0x61, 0x72, 0x79,
	0x2f, 0x69, 0x6e, 0x74, 0x65, 0x72, 0x6e, 0x61, 0x6c, 0x2f, 0x6b, 0x6d, 0x73, 0x2f, 0x73, 0x74,
	0x6f, 0x72, 0x65, 0x3b, 0x73, 0x74, 0x6f, 0x72, 0x65, 0x62, 0x06, 0x70, 0x72, 0x6f, 0x74, 0x6f,
	0x33,
}

var (
	file_controller_storage_kms_store_v1_external_config_proto_rawDescOnce sync.Once
	file_controller_storage_kms_store_v1_external_config_proto_rawDescData = file_controller_storage_kms_store_v1_external_config_proto_rawDesc
)

func file_controller_storage_kms_store_v1_external_config_proto_rawDescGZIP() []byte {
	file_controller_storage_kms_store_v1_external_config_proto_rawDescOnce.Do(func() {
		file_controller_storage_kms_store_v1_external_config_proto_rawDescData = protoimpl.X.CompressGZIP(file_controller_storage_kms_store_v1_external_config_proto_rawDescData)
	})
	return file_controller_storage_kms_store_v1_external_config_proto_rawDescData
}

var file_controller_storage_kms_store_v1_external_config_proto_msgTypes = make([]protoimpl.MessageInfo, 1)
var file_controller_storage_kms_store_v1_external_config_proto_goTypes = []interface{}{
	(*ExternalConfig)(nil),      // 0: controller.storage.kms.store.v1.ExternalConfig
	(*timestamp.Timestamp)(nil), // 1: controller.storage.timestamp.v1.Timestamp
}
var file_controller_storage_kms_store_v1_external_config_proto_depIdxs = []int32{
	1, // 0: controller.storage.kms.store.v1.ExternalConfig.create_time:type_name -> controller.storage.timestamp.v1.Timestamp
	1, // 1: controller.storage.kms.store.v1.ExternalConfig.update_time:type_name -> controller.storage.timestamp.v1.Timestamp
	2, // [2:2] is the sub-list for method output_type
	2, // [2:2] is the sub-list for method input_type
	2, // [2:2] is the sub-list for extension type_name
	2, // [2:2] is the sub-list for extension extendee
	0, // [0:2] is the sub-list for field type_name
}

func init() { file_controller_storage_kms_store_v1_external_config_proto_init() }
func file_controller_storage_kms_store_v1_external_config_proto_init() {
	if File_controller_storage_kms_store_v1_external_config_proto != nil {
		return
	}
	if !protoimpl.UnsafeEnabled {
		file_controller_storage_kms_store_v1_external_config_proto_msgTypes[0].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*ExternalConfig); i {
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
			RawDescriptor: file_controller_storage_kms_store_v1_external_config_proto_rawDesc,
			NumEnums:      0,
			NumMessages:   1,
			NumExtensions: 0,
			NumServices:   0,
		},
		GoTypes:           file_controller_storage_kms_store_v1_external_config_proto_goTypes,
		DependencyIndexes: file_controller_storage_kms_store_v1_external_config_proto_depIdxs,
		MessageInfos:      file_controller_storage_kms_store_v1_external_config_proto_msgTypes,
	}.Build()
	File_controller_storage_kms_store_v1_external_config_proto = out.File
	file_controller_storage_kms_store_v1_external_config_proto_rawDesc = nil
	file_controller_storage_kms_store_v1_external_config_proto_goTypes = nil
	file_controller_storage_kms_store_v1_external_config_proto_depIdxs = nil
}
