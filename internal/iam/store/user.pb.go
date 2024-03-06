// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: BUSL-1.1

// Code generated by protoc-gen-go. DO NOT EDIT.
// versions:
// 	protoc-gen-go v1.33.0
// 	protoc        (unknown)
// source: controller/storage/iam/store/v1/user.proto

package store

import (
	timestamp "github.com/hashicorp/boundary/internal/db/timestamp"
	_ "github.com/hashicorp/boundary/sdk/pbs/controller/protooptions"
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

type User struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	// public_id is used to access the User via an API
	// @inject_tag: gorm:"primary_key"
	PublicId string `protobuf:"bytes,10,opt,name=public_id,json=publicId,proto3" json:"public_id,omitempty" gorm:"primary_key"`
	// scope id for the user
	// @inject_tag: `gorm:"default:null"`
	ScopeId string `protobuf:"bytes,20,opt,name=scope_id,json=scopeId,proto3" json:"scope_id,omitempty" gorm:"default:null"`
	// name is the optional friendly name used to
	// access the User via an API
	// @inject_tag: `gorm:"default:null"`
	Name string `protobuf:"bytes,30,opt,name=name,proto3" json:"name,omitempty" gorm:"default:null"`
	// description of the user
	// @inject_tag: `gorm:"default:null"`
	Description string `protobuf:"bytes,40,opt,name=description,proto3" json:"description,omitempty" gorm:"default:null"`
	// create_time from the RDBMS
	// @inject_tag: `gorm:"default:current_timestamp"`
	CreateTime *timestamp.Timestamp `protobuf:"bytes,50,opt,name=create_time,json=createTime,proto3" json:"create_time,omitempty" gorm:"default:current_timestamp"`
	// update_time from the RDBMS
	// @inject_tag: `gorm:"default:current_timestamp"`
	UpdateTime *timestamp.Timestamp `protobuf:"bytes,60,opt,name=update_time,json=updateTime,proto3" json:"update_time,omitempty" gorm:"default:current_timestamp"`
	// version allows optimistic locking of the user
	// @inject_tag: `gorm:"default:null"`
	Version uint32 `protobuf:"varint,70,opt,name=version,proto3" json:"version,omitempty" gorm:"default:null"`
	// Output only. login_name is a string that maps to the user's account "login
	// name" from the scope's primary auth method
	// @inject_tag: `gorm:"->"`
	LoginName string `protobuf:"bytes,90,opt,name=login_name,proto3" json:"login_name,omitempty" gorm:"->"`
	// Output only. full_name is a string that maps to the user's account name
	// from the scope's primary auth method
	// @inject_tag: `gorm:"->"`
	FullName string `protobuf:"bytes,100,opt,name=full_name,proto3" json:"full_name,omitempty" gorm:"->"`
	// Output only. email is a string that maps to the user's account email from
	// the scope's primary auth method
	// @inject_tag: `gorm:"->"`
	Email string `protobuf:"bytes,110,opt,name=email,proto3" json:"email,omitempty" gorm:"->"`
	// Output only. primary_account_id is a string that maps to the user's account
	// public_id from the scope's primary auth method
	// @inject_tag: `gorm:"->"`
	PrimaryAccountId string `protobuf:"bytes,120,opt,name=primary_account_id,proto3" json:"primary_account_id,omitempty" gorm:"->"`
}

func (x *User) Reset() {
	*x = User{}
	if protoimpl.UnsafeEnabled {
		mi := &file_controller_storage_iam_store_v1_user_proto_msgTypes[0]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *User) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*User) ProtoMessage() {}

func (x *User) ProtoReflect() protoreflect.Message {
	mi := &file_controller_storage_iam_store_v1_user_proto_msgTypes[0]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use User.ProtoReflect.Descriptor instead.
func (*User) Descriptor() ([]byte, []int) {
	return file_controller_storage_iam_store_v1_user_proto_rawDescGZIP(), []int{0}
}

func (x *User) GetPublicId() string {
	if x != nil {
		return x.PublicId
	}
	return ""
}

func (x *User) GetScopeId() string {
	if x != nil {
		return x.ScopeId
	}
	return ""
}

func (x *User) GetName() string {
	if x != nil {
		return x.Name
	}
	return ""
}

func (x *User) GetDescription() string {
	if x != nil {
		return x.Description
	}
	return ""
}

func (x *User) GetCreateTime() *timestamp.Timestamp {
	if x != nil {
		return x.CreateTime
	}
	return nil
}

func (x *User) GetUpdateTime() *timestamp.Timestamp {
	if x != nil {
		return x.UpdateTime
	}
	return nil
}

func (x *User) GetVersion() uint32 {
	if x != nil {
		return x.Version
	}
	return 0
}

func (x *User) GetLoginName() string {
	if x != nil {
		return x.LoginName
	}
	return ""
}

func (x *User) GetFullName() string {
	if x != nil {
		return x.FullName
	}
	return ""
}

func (x *User) GetEmail() string {
	if x != nil {
		return x.Email
	}
	return ""
}

func (x *User) GetPrimaryAccountId() string {
	if x != nil {
		return x.PrimaryAccountId
	}
	return ""
}

var File_controller_storage_iam_store_v1_user_proto protoreflect.FileDescriptor

var file_controller_storage_iam_store_v1_user_proto_rawDesc = []byte{
	0x0a, 0x2a, 0x63, 0x6f, 0x6e, 0x74, 0x72, 0x6f, 0x6c, 0x6c, 0x65, 0x72, 0x2f, 0x73, 0x74, 0x6f,
	0x72, 0x61, 0x67, 0x65, 0x2f, 0x69, 0x61, 0x6d, 0x2f, 0x73, 0x74, 0x6f, 0x72, 0x65, 0x2f, 0x76,
	0x31, 0x2f, 0x75, 0x73, 0x65, 0x72, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x12, 0x1f, 0x63, 0x6f,
	0x6e, 0x74, 0x72, 0x6f, 0x6c, 0x6c, 0x65, 0x72, 0x2e, 0x73, 0x74, 0x6f, 0x72, 0x61, 0x67, 0x65,
	0x2e, 0x69, 0x61, 0x6d, 0x2e, 0x73, 0x74, 0x6f, 0x72, 0x65, 0x2e, 0x76, 0x31, 0x1a, 0x2a, 0x63,
	0x6f, 0x6e, 0x74, 0x72, 0x6f, 0x6c, 0x6c, 0x65, 0x72, 0x2f, 0x63, 0x75, 0x73, 0x74, 0x6f, 0x6d,
	0x5f, 0x6f, 0x70, 0x74, 0x69, 0x6f, 0x6e, 0x73, 0x2f, 0x76, 0x31, 0x2f, 0x6f, 0x70, 0x74, 0x69,
	0x6f, 0x6e, 0x73, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x1a, 0x2f, 0x63, 0x6f, 0x6e, 0x74, 0x72,
	0x6f, 0x6c, 0x6c, 0x65, 0x72, 0x2f, 0x73, 0x74, 0x6f, 0x72, 0x61, 0x67, 0x65, 0x2f, 0x74, 0x69,
	0x6d, 0x65, 0x73, 0x74, 0x61, 0x6d, 0x70, 0x2f, 0x76, 0x31, 0x2f, 0x74, 0x69, 0x6d, 0x65, 0x73,
	0x74, 0x61, 0x6d, 0x70, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x22, 0xde, 0x03, 0x0a, 0x04, 0x55,
	0x73, 0x65, 0x72, 0x12, 0x1b, 0x0a, 0x09, 0x70, 0x75, 0x62, 0x6c, 0x69, 0x63, 0x5f, 0x69, 0x64,
	0x18, 0x0a, 0x20, 0x01, 0x28, 0x09, 0x52, 0x08, 0x70, 0x75, 0x62, 0x6c, 0x69, 0x63, 0x49, 0x64,
	0x12, 0x19, 0x0a, 0x08, 0x73, 0x63, 0x6f, 0x70, 0x65, 0x5f, 0x69, 0x64, 0x18, 0x14, 0x20, 0x01,
	0x28, 0x09, 0x52, 0x07, 0x73, 0x63, 0x6f, 0x70, 0x65, 0x49, 0x64, 0x12, 0x24, 0x0a, 0x04, 0x6e,
	0x61, 0x6d, 0x65, 0x18, 0x1e, 0x20, 0x01, 0x28, 0x09, 0x42, 0x10, 0xc2, 0xdd, 0x29, 0x0c, 0x0a,
	0x04, 0x6e, 0x61, 0x6d, 0x65, 0x12, 0x04, 0x6e, 0x61, 0x6d, 0x65, 0x52, 0x04, 0x6e, 0x61, 0x6d,
	0x65, 0x12, 0x40, 0x0a, 0x0b, 0x64, 0x65, 0x73, 0x63, 0x72, 0x69, 0x70, 0x74, 0x69, 0x6f, 0x6e,
	0x18, 0x28, 0x20, 0x01, 0x28, 0x09, 0x42, 0x1e, 0xc2, 0xdd, 0x29, 0x1a, 0x0a, 0x0b, 0x64, 0x65,
	0x73, 0x63, 0x72, 0x69, 0x70, 0x74, 0x69, 0x6f, 0x6e, 0x12, 0x0b, 0x64, 0x65, 0x73, 0x63, 0x72,
	0x69, 0x70, 0x74, 0x69, 0x6f, 0x6e, 0x52, 0x0b, 0x64, 0x65, 0x73, 0x63, 0x72, 0x69, 0x70, 0x74,
	0x69, 0x6f, 0x6e, 0x12, 0x4b, 0x0a, 0x0b, 0x63, 0x72, 0x65, 0x61, 0x74, 0x65, 0x5f, 0x74, 0x69,
	0x6d, 0x65, 0x18, 0x32, 0x20, 0x01, 0x28, 0x0b, 0x32, 0x2a, 0x2e, 0x63, 0x6f, 0x6e, 0x74, 0x72,
	0x6f, 0x6c, 0x6c, 0x65, 0x72, 0x2e, 0x73, 0x74, 0x6f, 0x72, 0x61, 0x67, 0x65, 0x2e, 0x74, 0x69,
	0x6d, 0x65, 0x73, 0x74, 0x61, 0x6d, 0x70, 0x2e, 0x76, 0x31, 0x2e, 0x54, 0x69, 0x6d, 0x65, 0x73,
	0x74, 0x61, 0x6d, 0x70, 0x52, 0x0a, 0x63, 0x72, 0x65, 0x61, 0x74, 0x65, 0x54, 0x69, 0x6d, 0x65,
	0x12, 0x4b, 0x0a, 0x0b, 0x75, 0x70, 0x64, 0x61, 0x74, 0x65, 0x5f, 0x74, 0x69, 0x6d, 0x65, 0x18,
	0x3c, 0x20, 0x01, 0x28, 0x0b, 0x32, 0x2a, 0x2e, 0x63, 0x6f, 0x6e, 0x74, 0x72, 0x6f, 0x6c, 0x6c,
	0x65, 0x72, 0x2e, 0x73, 0x74, 0x6f, 0x72, 0x61, 0x67, 0x65, 0x2e, 0x74, 0x69, 0x6d, 0x65, 0x73,
	0x74, 0x61, 0x6d, 0x70, 0x2e, 0x76, 0x31, 0x2e, 0x54, 0x69, 0x6d, 0x65, 0x73, 0x74, 0x61, 0x6d,
	0x70, 0x52, 0x0a, 0x75, 0x70, 0x64, 0x61, 0x74, 0x65, 0x54, 0x69, 0x6d, 0x65, 0x12, 0x18, 0x0a,
	0x07, 0x76, 0x65, 0x72, 0x73, 0x69, 0x6f, 0x6e, 0x18, 0x46, 0x20, 0x01, 0x28, 0x0d, 0x52, 0x07,
	0x76, 0x65, 0x72, 0x73, 0x69, 0x6f, 0x6e, 0x12, 0x1e, 0x0a, 0x0a, 0x6c, 0x6f, 0x67, 0x69, 0x6e,
	0x5f, 0x6e, 0x61, 0x6d, 0x65, 0x18, 0x5a, 0x20, 0x01, 0x28, 0x09, 0x52, 0x0a, 0x6c, 0x6f, 0x67,
	0x69, 0x6e, 0x5f, 0x6e, 0x61, 0x6d, 0x65, 0x12, 0x1c, 0x0a, 0x09, 0x66, 0x75, 0x6c, 0x6c, 0x5f,
	0x6e, 0x61, 0x6d, 0x65, 0x18, 0x64, 0x20, 0x01, 0x28, 0x09, 0x52, 0x09, 0x66, 0x75, 0x6c, 0x6c,
	0x5f, 0x6e, 0x61, 0x6d, 0x65, 0x12, 0x14, 0x0a, 0x05, 0x65, 0x6d, 0x61, 0x69, 0x6c, 0x18, 0x6e,
	0x20, 0x01, 0x28, 0x09, 0x52, 0x05, 0x65, 0x6d, 0x61, 0x69, 0x6c, 0x12, 0x2e, 0x0a, 0x12, 0x70,
	0x72, 0x69, 0x6d, 0x61, 0x72, 0x79, 0x5f, 0x61, 0x63, 0x63, 0x6f, 0x75, 0x6e, 0x74, 0x5f, 0x69,
	0x64, 0x18, 0x78, 0x20, 0x01, 0x28, 0x09, 0x52, 0x12, 0x70, 0x72, 0x69, 0x6d, 0x61, 0x72, 0x79,
	0x5f, 0x61, 0x63, 0x63, 0x6f, 0x75, 0x6e, 0x74, 0x5f, 0x69, 0x64, 0x42, 0x38, 0x5a, 0x36, 0x67,
	0x69, 0x74, 0x68, 0x75, 0x62, 0x2e, 0x63, 0x6f, 0x6d, 0x2f, 0x68, 0x61, 0x73, 0x68, 0x69, 0x63,
	0x6f, 0x72, 0x70, 0x2f, 0x62, 0x6f, 0x75, 0x6e, 0x64, 0x61, 0x72, 0x79, 0x2f, 0x69, 0x6e, 0x74,
	0x65, 0x72, 0x6e, 0x61, 0x6c, 0x2f, 0x69, 0x61, 0x6d, 0x2f, 0x73, 0x74, 0x6f, 0x72, 0x65, 0x3b,
	0x73, 0x74, 0x6f, 0x72, 0x65, 0x62, 0x06, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x33,
}

var (
	file_controller_storage_iam_store_v1_user_proto_rawDescOnce sync.Once
	file_controller_storage_iam_store_v1_user_proto_rawDescData = file_controller_storage_iam_store_v1_user_proto_rawDesc
)

func file_controller_storage_iam_store_v1_user_proto_rawDescGZIP() []byte {
	file_controller_storage_iam_store_v1_user_proto_rawDescOnce.Do(func() {
		file_controller_storage_iam_store_v1_user_proto_rawDescData = protoimpl.X.CompressGZIP(file_controller_storage_iam_store_v1_user_proto_rawDescData)
	})
	return file_controller_storage_iam_store_v1_user_proto_rawDescData
}

var file_controller_storage_iam_store_v1_user_proto_msgTypes = make([]protoimpl.MessageInfo, 1)
var file_controller_storage_iam_store_v1_user_proto_goTypes = []interface{}{
	(*User)(nil),                // 0: controller.storage.iam.store.v1.User
	(*timestamp.Timestamp)(nil), // 1: controller.storage.timestamp.v1.Timestamp
}
var file_controller_storage_iam_store_v1_user_proto_depIdxs = []int32{
	1, // 0: controller.storage.iam.store.v1.User.create_time:type_name -> controller.storage.timestamp.v1.Timestamp
	1, // 1: controller.storage.iam.store.v1.User.update_time:type_name -> controller.storage.timestamp.v1.Timestamp
	2, // [2:2] is the sub-list for method output_type
	2, // [2:2] is the sub-list for method input_type
	2, // [2:2] is the sub-list for extension type_name
	2, // [2:2] is the sub-list for extension extendee
	0, // [0:2] is the sub-list for field type_name
}

func init() { file_controller_storage_iam_store_v1_user_proto_init() }
func file_controller_storage_iam_store_v1_user_proto_init() {
	if File_controller_storage_iam_store_v1_user_proto != nil {
		return
	}
	if !protoimpl.UnsafeEnabled {
		file_controller_storage_iam_store_v1_user_proto_msgTypes[0].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*User); i {
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
			RawDescriptor: file_controller_storage_iam_store_v1_user_proto_rawDesc,
			NumEnums:      0,
			NumMessages:   1,
			NumExtensions: 0,
			NumServices:   0,
		},
		GoTypes:           file_controller_storage_iam_store_v1_user_proto_goTypes,
		DependencyIndexes: file_controller_storage_iam_store_v1_user_proto_depIdxs,
		MessageInfos:      file_controller_storage_iam_store_v1_user_proto_msgTypes,
	}.Build()
	File_controller_storage_iam_store_v1_user_proto = out.File
	file_controller_storage_iam_store_v1_user_proto_rawDesc = nil
	file_controller_storage_iam_store_v1_user_proto_goTypes = nil
	file_controller_storage_iam_store_v1_user_proto_depIdxs = nil
}
