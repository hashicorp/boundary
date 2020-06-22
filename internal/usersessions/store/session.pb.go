// Code generated by protoc-gen-go. DO NOT EDIT.
// versions:
// 	protoc-gen-go v1.24.0
// 	protoc        v3.12.3
// source: controller/storage/usersessions/store/v1/session.proto

package store

import (
	proto "github.com/golang/protobuf/proto"
	timestamp "github.com/hashicorp/watchtower/internal/db/timestamp"
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

type Session struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	// public_id is used to access the Session via an API
	// @inject_tag: gorm:"primary_key"
	PublicId string `protobuf:"bytes,1,opt,name=public_id,json=publicId,proto3" json:"public_id,omitempty" gorm:"primary_key"`
	// create_time from the RDBMS
	// @inject_tag: `gorm:"default:current_timestamp"`
	CreateTime *timestamp.Timestamp `protobuf:"bytes,2,opt,name=create_time,json=createTime,proto3" json:"create_time,omitempty" gorm:"default:current_timestamp"`
	// update_time from the RDBMS
	// @inject_tag: `gorm:"default:current_timestamp"`
	UpdateTime *timestamp.Timestamp `protobuf:"bytes,3,opt,name=update_time,json=updateTime,proto3" json:"update_time,omitempty" gorm:"default:current_timestamp"`
	// last_access_time indicates the last time the session token was used on the watchtower API.
	// @inject_tag: `gorm:"default:current_timestamp"`
	LastAccessTime *timestamp.Timestamp `protobuf:"bytes,4,opt,name=last_access_time,json=lastAccessTime,proto3" json:"last_access_time,omitempty" gorm:"default:current_timestamp"`
	// expiration_time indicates when this session will expire.
	// If null a default duration and create_time is used to calculate expiration.
	// @inject_tag: `gorm:"default:null"`
	ExpirationTime *timestamp.Timestamp `protobuf:"bytes,5,opt,name=expiration_time,json=expirationTime,proto3" json:"expiration_time,omitempty" gorm:"default:null"`
	// token is the field stored by the client and used
	// @inject_tag: `gorm:"default:not_null"`
	Token string `protobuf:"bytes,6,opt,name=token,proto3" json:"token,omitempty" gorm:"default:not_null"`
	// The iam_scope_id of the owning scope and must be set.
	// @inject_tag: `gorm:"default:not_null"`
	ScopeId string `protobuf:"bytes,7,opt,name=scope_id,json=scopeId,proto3" json:"scope_id,omitempty" gorm:"default:not_null"`
	// iam_user_id is the public id for the iam user this session is for.
	// @inject_tag: `gorm:"default:not_null"`
	IamUserId string `protobuf:"bytes,8,opt,name=iam_user_id,json=iamUserId,proto3" json:"iam_user_id,omitempty" gorm:"default:not_null"`
	// user id is the public id for the iam user this session is for.
	// @inject_tag: `gorm:"default:not_null"`
	AuthMethodId string `protobuf:"bytes,9,opt,name=auth_method_id,json=authMethodId,proto3" json:"auth_method_id,omitempty" gorm:"default:not_null"`
}

func (x *Session) Reset() {
	*x = Session{}
	if protoimpl.UnsafeEnabled {
		mi := &file_controller_storage_usersessions_store_v1_session_proto_msgTypes[0]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *Session) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*Session) ProtoMessage() {}

func (x *Session) ProtoReflect() protoreflect.Message {
	mi := &file_controller_storage_usersessions_store_v1_session_proto_msgTypes[0]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use Session.ProtoReflect.Descriptor instead.
func (*Session) Descriptor() ([]byte, []int) {
	return file_controller_storage_usersessions_store_v1_session_proto_rawDescGZIP(), []int{0}
}

func (x *Session) GetPublicId() string {
	if x != nil {
		return x.PublicId
	}
	return ""
}

func (x *Session) GetCreateTime() *timestamp.Timestamp {
	if x != nil {
		return x.CreateTime
	}
	return nil
}

func (x *Session) GetUpdateTime() *timestamp.Timestamp {
	if x != nil {
		return x.UpdateTime
	}
	return nil
}

func (x *Session) GetLastAccessTime() *timestamp.Timestamp {
	if x != nil {
		return x.LastAccessTime
	}
	return nil
}

func (x *Session) GetExpirationTime() *timestamp.Timestamp {
	if x != nil {
		return x.ExpirationTime
	}
	return nil
}

func (x *Session) GetToken() string {
	if x != nil {
		return x.Token
	}
	return ""
}

func (x *Session) GetScopeId() string {
	if x != nil {
		return x.ScopeId
	}
	return ""
}

func (x *Session) GetIamUserId() string {
	if x != nil {
		return x.IamUserId
	}
	return ""
}

func (x *Session) GetAuthMethodId() string {
	if x != nil {
		return x.AuthMethodId
	}
	return ""
}

var File_controller_storage_usersessions_store_v1_session_proto protoreflect.FileDescriptor

var file_controller_storage_usersessions_store_v1_session_proto_rawDesc = []byte{
	0x0a, 0x36, 0x63, 0x6f, 0x6e, 0x74, 0x72, 0x6f, 0x6c, 0x6c, 0x65, 0x72, 0x2f, 0x73, 0x74, 0x6f,
	0x72, 0x61, 0x67, 0x65, 0x2f, 0x75, 0x73, 0x65, 0x72, 0x73, 0x65, 0x73, 0x73, 0x69, 0x6f, 0x6e,
	0x73, 0x2f, 0x73, 0x74, 0x6f, 0x72, 0x65, 0x2f, 0x76, 0x31, 0x2f, 0x73, 0x65, 0x73, 0x73, 0x69,
	0x6f, 0x6e, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x12, 0x28, 0x63, 0x6f, 0x6e, 0x74, 0x72, 0x6f,
	0x6c, 0x6c, 0x65, 0x72, 0x2e, 0x73, 0x74, 0x6f, 0x72, 0x61, 0x67, 0x65, 0x2e, 0x75, 0x73, 0x65,
	0x72, 0x73, 0x65, 0x73, 0x73, 0x69, 0x6f, 0x6e, 0x73, 0x2e, 0x73, 0x74, 0x6f, 0x72, 0x65, 0x2e,
	0x76, 0x31, 0x1a, 0x2f, 0x63, 0x6f, 0x6e, 0x74, 0x72, 0x6f, 0x6c, 0x6c, 0x65, 0x72, 0x2f, 0x73,
	0x74, 0x6f, 0x72, 0x61, 0x67, 0x65, 0x2f, 0x74, 0x69, 0x6d, 0x65, 0x73, 0x74, 0x61, 0x6d, 0x70,
	0x2f, 0x76, 0x31, 0x2f, 0x74, 0x69, 0x6d, 0x65, 0x73, 0x74, 0x61, 0x6d, 0x70, 0x2e, 0x70, 0x72,
	0x6f, 0x74, 0x6f, 0x22, 0xe2, 0x03, 0x0a, 0x07, 0x53, 0x65, 0x73, 0x73, 0x69, 0x6f, 0x6e, 0x12,
	0x1b, 0x0a, 0x09, 0x70, 0x75, 0x62, 0x6c, 0x69, 0x63, 0x5f, 0x69, 0x64, 0x18, 0x01, 0x20, 0x01,
	0x28, 0x09, 0x52, 0x08, 0x70, 0x75, 0x62, 0x6c, 0x69, 0x63, 0x49, 0x64, 0x12, 0x4b, 0x0a, 0x0b,
	0x63, 0x72, 0x65, 0x61, 0x74, 0x65, 0x5f, 0x74, 0x69, 0x6d, 0x65, 0x18, 0x02, 0x20, 0x01, 0x28,
	0x0b, 0x32, 0x2a, 0x2e, 0x63, 0x6f, 0x6e, 0x74, 0x72, 0x6f, 0x6c, 0x6c, 0x65, 0x72, 0x2e, 0x73,
	0x74, 0x6f, 0x72, 0x61, 0x67, 0x65, 0x2e, 0x74, 0x69, 0x6d, 0x65, 0x73, 0x74, 0x61, 0x6d, 0x70,
	0x2e, 0x76, 0x31, 0x2e, 0x54, 0x69, 0x6d, 0x65, 0x73, 0x74, 0x61, 0x6d, 0x70, 0x52, 0x0a, 0x63,
	0x72, 0x65, 0x61, 0x74, 0x65, 0x54, 0x69, 0x6d, 0x65, 0x12, 0x4b, 0x0a, 0x0b, 0x75, 0x70, 0x64,
	0x61, 0x74, 0x65, 0x5f, 0x74, 0x69, 0x6d, 0x65, 0x18, 0x03, 0x20, 0x01, 0x28, 0x0b, 0x32, 0x2a,
	0x2e, 0x63, 0x6f, 0x6e, 0x74, 0x72, 0x6f, 0x6c, 0x6c, 0x65, 0x72, 0x2e, 0x73, 0x74, 0x6f, 0x72,
	0x61, 0x67, 0x65, 0x2e, 0x74, 0x69, 0x6d, 0x65, 0x73, 0x74, 0x61, 0x6d, 0x70, 0x2e, 0x76, 0x31,
	0x2e, 0x54, 0x69, 0x6d, 0x65, 0x73, 0x74, 0x61, 0x6d, 0x70, 0x52, 0x0a, 0x75, 0x70, 0x64, 0x61,
	0x74, 0x65, 0x54, 0x69, 0x6d, 0x65, 0x12, 0x54, 0x0a, 0x10, 0x6c, 0x61, 0x73, 0x74, 0x5f, 0x61,
	0x63, 0x63, 0x65, 0x73, 0x73, 0x5f, 0x74, 0x69, 0x6d, 0x65, 0x18, 0x04, 0x20, 0x01, 0x28, 0x0b,
	0x32, 0x2a, 0x2e, 0x63, 0x6f, 0x6e, 0x74, 0x72, 0x6f, 0x6c, 0x6c, 0x65, 0x72, 0x2e, 0x73, 0x74,
	0x6f, 0x72, 0x61, 0x67, 0x65, 0x2e, 0x74, 0x69, 0x6d, 0x65, 0x73, 0x74, 0x61, 0x6d, 0x70, 0x2e,
	0x76, 0x31, 0x2e, 0x54, 0x69, 0x6d, 0x65, 0x73, 0x74, 0x61, 0x6d, 0x70, 0x52, 0x0e, 0x6c, 0x61,
	0x73, 0x74, 0x41, 0x63, 0x63, 0x65, 0x73, 0x73, 0x54, 0x69, 0x6d, 0x65, 0x12, 0x53, 0x0a, 0x0f,
	0x65, 0x78, 0x70, 0x69, 0x72, 0x61, 0x74, 0x69, 0x6f, 0x6e, 0x5f, 0x74, 0x69, 0x6d, 0x65, 0x18,
	0x05, 0x20, 0x01, 0x28, 0x0b, 0x32, 0x2a, 0x2e, 0x63, 0x6f, 0x6e, 0x74, 0x72, 0x6f, 0x6c, 0x6c,
	0x65, 0x72, 0x2e, 0x73, 0x74, 0x6f, 0x72, 0x61, 0x67, 0x65, 0x2e, 0x74, 0x69, 0x6d, 0x65, 0x73,
	0x74, 0x61, 0x6d, 0x70, 0x2e, 0x76, 0x31, 0x2e, 0x54, 0x69, 0x6d, 0x65, 0x73, 0x74, 0x61, 0x6d,
	0x70, 0x52, 0x0e, 0x65, 0x78, 0x70, 0x69, 0x72, 0x61, 0x74, 0x69, 0x6f, 0x6e, 0x54, 0x69, 0x6d,
	0x65, 0x12, 0x14, 0x0a, 0x05, 0x74, 0x6f, 0x6b, 0x65, 0x6e, 0x18, 0x06, 0x20, 0x01, 0x28, 0x09,
	0x52, 0x05, 0x74, 0x6f, 0x6b, 0x65, 0x6e, 0x12, 0x19, 0x0a, 0x08, 0x73, 0x63, 0x6f, 0x70, 0x65,
	0x5f, 0x69, 0x64, 0x18, 0x07, 0x20, 0x01, 0x28, 0x09, 0x52, 0x07, 0x73, 0x63, 0x6f, 0x70, 0x65,
	0x49, 0x64, 0x12, 0x1e, 0x0a, 0x0b, 0x69, 0x61, 0x6d, 0x5f, 0x75, 0x73, 0x65, 0x72, 0x5f, 0x69,
	0x64, 0x18, 0x08, 0x20, 0x01, 0x28, 0x09, 0x52, 0x09, 0x69, 0x61, 0x6d, 0x55, 0x73, 0x65, 0x72,
	0x49, 0x64, 0x12, 0x24, 0x0a, 0x0e, 0x61, 0x75, 0x74, 0x68, 0x5f, 0x6d, 0x65, 0x74, 0x68, 0x6f,
	0x64, 0x5f, 0x69, 0x64, 0x18, 0x09, 0x20, 0x01, 0x28, 0x09, 0x52, 0x0c, 0x61, 0x75, 0x74, 0x68,
	0x4d, 0x65, 0x74, 0x68, 0x6f, 0x64, 0x49, 0x64, 0x42, 0x43, 0x5a, 0x41, 0x67, 0x69, 0x74, 0x68,
	0x75, 0x62, 0x2e, 0x63, 0x6f, 0x6d, 0x2f, 0x68, 0x61, 0x73, 0x68, 0x69, 0x63, 0x6f, 0x72, 0x70,
	0x2f, 0x77, 0x61, 0x74, 0x63, 0x68, 0x74, 0x6f, 0x77, 0x65, 0x72, 0x2f, 0x69, 0x6e, 0x74, 0x65,
	0x72, 0x6e, 0x61, 0x6c, 0x2f, 0x75, 0x73, 0x65, 0x72, 0x73, 0x65, 0x73, 0x73, 0x69, 0x6f, 0x6e,
	0x73, 0x2f, 0x73, 0x74, 0x6f, 0x72, 0x65, 0x3b, 0x73, 0x74, 0x6f, 0x72, 0x65, 0x62, 0x06, 0x70,
	0x72, 0x6f, 0x74, 0x6f, 0x33,
}

var (
	file_controller_storage_usersessions_store_v1_session_proto_rawDescOnce sync.Once
	file_controller_storage_usersessions_store_v1_session_proto_rawDescData = file_controller_storage_usersessions_store_v1_session_proto_rawDesc
)

func file_controller_storage_usersessions_store_v1_session_proto_rawDescGZIP() []byte {
	file_controller_storage_usersessions_store_v1_session_proto_rawDescOnce.Do(func() {
		file_controller_storage_usersessions_store_v1_session_proto_rawDescData = protoimpl.X.CompressGZIP(file_controller_storage_usersessions_store_v1_session_proto_rawDescData)
	})
	return file_controller_storage_usersessions_store_v1_session_proto_rawDescData
}

var file_controller_storage_usersessions_store_v1_session_proto_msgTypes = make([]protoimpl.MessageInfo, 1)
var file_controller_storage_usersessions_store_v1_session_proto_goTypes = []interface{}{
	(*Session)(nil),             // 0: controller.storage.usersessions.store.v1.Session
	(*timestamp.Timestamp)(nil), // 1: controller.storage.timestamp.v1.Timestamp
}
var file_controller_storage_usersessions_store_v1_session_proto_depIdxs = []int32{
	1, // 0: controller.storage.usersessions.store.v1.Session.create_time:type_name -> controller.storage.timestamp.v1.Timestamp
	1, // 1: controller.storage.usersessions.store.v1.Session.update_time:type_name -> controller.storage.timestamp.v1.Timestamp
	1, // 2: controller.storage.usersessions.store.v1.Session.last_access_time:type_name -> controller.storage.timestamp.v1.Timestamp
	1, // 3: controller.storage.usersessions.store.v1.Session.expiration_time:type_name -> controller.storage.timestamp.v1.Timestamp
	4, // [4:4] is the sub-list for method output_type
	4, // [4:4] is the sub-list for method input_type
	4, // [4:4] is the sub-list for extension type_name
	4, // [4:4] is the sub-list for extension extendee
	0, // [0:4] is the sub-list for field type_name
}

func init() { file_controller_storage_usersessions_store_v1_session_proto_init() }
func file_controller_storage_usersessions_store_v1_session_proto_init() {
	if File_controller_storage_usersessions_store_v1_session_proto != nil {
		return
	}
	if !protoimpl.UnsafeEnabled {
		file_controller_storage_usersessions_store_v1_session_proto_msgTypes[0].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*Session); i {
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
			RawDescriptor: file_controller_storage_usersessions_store_v1_session_proto_rawDesc,
			NumEnums:      0,
			NumMessages:   1,
			NumExtensions: 0,
			NumServices:   0,
		},
		GoTypes:           file_controller_storage_usersessions_store_v1_session_proto_goTypes,
		DependencyIndexes: file_controller_storage_usersessions_store_v1_session_proto_depIdxs,
		MessageInfos:      file_controller_storage_usersessions_store_v1_session_proto_msgTypes,
	}.Build()
	File_controller_storage_usersessions_store_v1_session_proto = out.File
	file_controller_storage_usersessions_store_v1_session_proto_rawDesc = nil
	file_controller_storage_usersessions_store_v1_session_proto_goTypes = nil
	file_controller_storage_usersessions_store_v1_session_proto_depIdxs = nil
}
