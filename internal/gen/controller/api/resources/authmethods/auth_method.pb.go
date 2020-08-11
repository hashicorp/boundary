// Code generated by protoc-gen-go. DO NOT EDIT.
// versions:
// 	protoc-gen-go v1.25.0
// 	protoc        v3.12.4
// source: controller/api/resources/authmethods/v1/auth_method.proto

package authmethods

import (
	proto "github.com/golang/protobuf/proto"
	_struct "github.com/golang/protobuf/ptypes/struct"
	timestamp "github.com/golang/protobuf/ptypes/timestamp"
	wrappers "github.com/golang/protobuf/ptypes/wrappers"
	scopes "github.com/hashicorp/boundary/internal/gen/controller/api/resources/scopes"
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

// AuthMethod contains all fields related to a AuthMethod resource
type AuthMethod struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	// The ID of the AuthMethod
	// Output only.
	Id string `protobuf:"bytes,1,opt,name=id,proto3" json:"id,omitempty"`
	// Scope information for this resource
	// Output only.
	Scope *scopes.ScopeInfo `protobuf:"bytes,2,opt,name=scope,proto3" json:"scope,omitempty"`
	// Optional name for identification purposes
	Name *wrappers.StringValue `protobuf:"bytes,3,opt,name=name,proto3" json:"name,omitempty"`
	// Optional user-set description for identification purposes
	Description *wrappers.StringValue `protobuf:"bytes,4,opt,name=description,proto3" json:"description,omitempty"`
	// The time this resource was created
	// Output only.
	CreatedTime *timestamp.Timestamp `protobuf:"bytes,5,opt,name=created_time,proto3" json:"created_time,omitempty"`
	// The time this resource was last updated.
	// Output only.
	UpdatedTime *timestamp.Timestamp `protobuf:"bytes,6,opt,name=updated_time,proto3" json:"updated_time,omitempty"`
	// The version can be used in subsequent write requests to ensure this resource
	// has not changed and to fail the write if it has.
	// Output only.
	Version uint32 `protobuf:"varint,7,opt,name=version,proto3" json:"version,omitempty"`
	// The auth method type.  This can be "password" or "oidc".
	Type string `protobuf:"bytes,8,opt,name=type,proto3" json:"type,omitempty"`
	// The attributes that are applied for the specific Auth Method type.
	Attributes *_struct.Struct `protobuf:"bytes,9,opt,name=attributes,proto3" json:"attributes,omitempty"`
}

func (x *AuthMethod) Reset() {
	*x = AuthMethod{}
	if protoimpl.UnsafeEnabled {
		mi := &file_controller_api_resources_authmethods_v1_auth_method_proto_msgTypes[0]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *AuthMethod) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*AuthMethod) ProtoMessage() {}

func (x *AuthMethod) ProtoReflect() protoreflect.Message {
	mi := &file_controller_api_resources_authmethods_v1_auth_method_proto_msgTypes[0]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use AuthMethod.ProtoReflect.Descriptor instead.
func (*AuthMethod) Descriptor() ([]byte, []int) {
	return file_controller_api_resources_authmethods_v1_auth_method_proto_rawDescGZIP(), []int{0}
}

func (x *AuthMethod) GetId() string {
	if x != nil {
		return x.Id
	}
	return ""
}

func (x *AuthMethod) GetScope() *scopes.ScopeInfo {
	if x != nil {
		return x.Scope
	}
	return nil
}

func (x *AuthMethod) GetName() *wrappers.StringValue {
	if x != nil {
		return x.Name
	}
	return nil
}

func (x *AuthMethod) GetDescription() *wrappers.StringValue {
	if x != nil {
		return x.Description
	}
	return nil
}

func (x *AuthMethod) GetCreatedTime() *timestamp.Timestamp {
	if x != nil {
		return x.CreatedTime
	}
	return nil
}

func (x *AuthMethod) GetUpdatedTime() *timestamp.Timestamp {
	if x != nil {
		return x.UpdatedTime
	}
	return nil
}

func (x *AuthMethod) GetVersion() uint32 {
	if x != nil {
		return x.Version
	}
	return 0
}

func (x *AuthMethod) GetType() string {
	if x != nil {
		return x.Type
	}
	return ""
}

func (x *AuthMethod) GetAttributes() *_struct.Struct {
	if x != nil {
		return x.Attributes
	}
	return nil
}

type PasswordAuthMethodAttributes struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	// The minimum length allowed for user names for accounts in this auth method.
	MinUserNameLength uint32 `protobuf:"varint,1,opt,name=min_user_name_length,json=minUserNameLength,proto3" json:"min_user_name_length,omitempty"`
	// The minimum length allowed for passwords for accounts in this auth method.
	MinPasswordLength uint32 `protobuf:"varint,2,opt,name=min_password_length,json=minPasswordLength,proto3" json:"min_password_length,omitempty"`
}

func (x *PasswordAuthMethodAttributes) Reset() {
	*x = PasswordAuthMethodAttributes{}
	if protoimpl.UnsafeEnabled {
		mi := &file_controller_api_resources_authmethods_v1_auth_method_proto_msgTypes[1]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *PasswordAuthMethodAttributes) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*PasswordAuthMethodAttributes) ProtoMessage() {}

func (x *PasswordAuthMethodAttributes) ProtoReflect() protoreflect.Message {
	mi := &file_controller_api_resources_authmethods_v1_auth_method_proto_msgTypes[1]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use PasswordAuthMethodAttributes.ProtoReflect.Descriptor instead.
func (*PasswordAuthMethodAttributes) Descriptor() ([]byte, []int) {
	return file_controller_api_resources_authmethods_v1_auth_method_proto_rawDescGZIP(), []int{1}
}

func (x *PasswordAuthMethodAttributes) GetMinUserNameLength() uint32 {
	if x != nil {
		return x.MinUserNameLength
	}
	return 0
}

func (x *PasswordAuthMethodAttributes) GetMinPasswordLength() uint32 {
	if x != nil {
		return x.MinPasswordLength
	}
	return 0
}

var File_controller_api_resources_authmethods_v1_auth_method_proto protoreflect.FileDescriptor

var file_controller_api_resources_authmethods_v1_auth_method_proto_rawDesc = []byte{
	0x0a, 0x39, 0x63, 0x6f, 0x6e, 0x74, 0x72, 0x6f, 0x6c, 0x6c, 0x65, 0x72, 0x2f, 0x61, 0x70, 0x69,
	0x2f, 0x72, 0x65, 0x73, 0x6f, 0x75, 0x72, 0x63, 0x65, 0x73, 0x2f, 0x61, 0x75, 0x74, 0x68, 0x6d,
	0x65, 0x74, 0x68, 0x6f, 0x64, 0x73, 0x2f, 0x76, 0x31, 0x2f, 0x61, 0x75, 0x74, 0x68, 0x5f, 0x6d,
	0x65, 0x74, 0x68, 0x6f, 0x64, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x12, 0x27, 0x63, 0x6f, 0x6e,
	0x74, 0x72, 0x6f, 0x6c, 0x6c, 0x65, 0x72, 0x2e, 0x61, 0x70, 0x69, 0x2e, 0x72, 0x65, 0x73, 0x6f,
	0x75, 0x72, 0x63, 0x65, 0x73, 0x2e, 0x61, 0x75, 0x74, 0x68, 0x6d, 0x65, 0x74, 0x68, 0x6f, 0x64,
	0x73, 0x2e, 0x76, 0x31, 0x1a, 0x1f, 0x67, 0x6f, 0x6f, 0x67, 0x6c, 0x65, 0x2f, 0x70, 0x72, 0x6f,
	0x74, 0x6f, 0x62, 0x75, 0x66, 0x2f, 0x74, 0x69, 0x6d, 0x65, 0x73, 0x74, 0x61, 0x6d, 0x70, 0x2e,
	0x70, 0x72, 0x6f, 0x74, 0x6f, 0x1a, 0x1e, 0x67, 0x6f, 0x6f, 0x67, 0x6c, 0x65, 0x2f, 0x70, 0x72,
	0x6f, 0x74, 0x6f, 0x62, 0x75, 0x66, 0x2f, 0x77, 0x72, 0x61, 0x70, 0x70, 0x65, 0x72, 0x73, 0x2e,
	0x70, 0x72, 0x6f, 0x74, 0x6f, 0x1a, 0x1c, 0x67, 0x6f, 0x6f, 0x67, 0x6c, 0x65, 0x2f, 0x70, 0x72,
	0x6f, 0x74, 0x6f, 0x62, 0x75, 0x66, 0x2f, 0x73, 0x74, 0x72, 0x75, 0x63, 0x74, 0x2e, 0x70, 0x72,
	0x6f, 0x74, 0x6f, 0x1a, 0x2e, 0x63, 0x6f, 0x6e, 0x74, 0x72, 0x6f, 0x6c, 0x6c, 0x65, 0x72, 0x2f,
	0x61, 0x70, 0x69, 0x2f, 0x72, 0x65, 0x73, 0x6f, 0x75, 0x72, 0x63, 0x65, 0x73, 0x2f, 0x73, 0x63,
	0x6f, 0x70, 0x65, 0x73, 0x2f, 0x76, 0x31, 0x2f, 0x73, 0x63, 0x6f, 0x70, 0x65, 0x2e, 0x70, 0x72,
	0x6f, 0x74, 0x6f, 0x1a, 0x2a, 0x63, 0x6f, 0x6e, 0x74, 0x72, 0x6f, 0x6c, 0x6c, 0x65, 0x72, 0x2f,
	0x63, 0x75, 0x73, 0x74, 0x6f, 0x6d, 0x5f, 0x6f, 0x70, 0x74, 0x69, 0x6f, 0x6e, 0x73, 0x2f, 0x76,
	0x31, 0x2f, 0x6f, 0x70, 0x74, 0x69, 0x6f, 0x6e, 0x73, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x22,
	0x80, 0x04, 0x0a, 0x0a, 0x41, 0x75, 0x74, 0x68, 0x4d, 0x65, 0x74, 0x68, 0x6f, 0x64, 0x12, 0x0e,
	0x0a, 0x02, 0x69, 0x64, 0x18, 0x01, 0x20, 0x01, 0x28, 0x09, 0x52, 0x02, 0x69, 0x64, 0x12, 0x43,
	0x0a, 0x05, 0x73, 0x63, 0x6f, 0x70, 0x65, 0x18, 0x02, 0x20, 0x01, 0x28, 0x0b, 0x32, 0x2d, 0x2e,
	0x63, 0x6f, 0x6e, 0x74, 0x72, 0x6f, 0x6c, 0x6c, 0x65, 0x72, 0x2e, 0x61, 0x70, 0x69, 0x2e, 0x72,
	0x65, 0x73, 0x6f, 0x75, 0x72, 0x63, 0x65, 0x73, 0x2e, 0x73, 0x63, 0x6f, 0x70, 0x65, 0x73, 0x2e,
	0x76, 0x31, 0x2e, 0x53, 0x63, 0x6f, 0x70, 0x65, 0x49, 0x6e, 0x66, 0x6f, 0x52, 0x05, 0x73, 0x63,
	0x6f, 0x70, 0x65, 0x12, 0x46, 0x0a, 0x04, 0x6e, 0x61, 0x6d, 0x65, 0x18, 0x03, 0x20, 0x01, 0x28,
	0x0b, 0x32, 0x1c, 0x2e, 0x67, 0x6f, 0x6f, 0x67, 0x6c, 0x65, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f,
	0x62, 0x75, 0x66, 0x2e, 0x53, 0x74, 0x72, 0x69, 0x6e, 0x67, 0x56, 0x61, 0x6c, 0x75, 0x65, 0x42,
	0x14, 0xa0, 0xda, 0x29, 0x01, 0xc2, 0xdd, 0x29, 0x0c, 0x0a, 0x04, 0x6e, 0x61, 0x6d, 0x65, 0x12,
	0x04, 0x6e, 0x61, 0x6d, 0x65, 0x52, 0x04, 0x6e, 0x61, 0x6d, 0x65, 0x12, 0x62, 0x0a, 0x0b, 0x64,
	0x65, 0x73, 0x63, 0x72, 0x69, 0x70, 0x74, 0x69, 0x6f, 0x6e, 0x18, 0x04, 0x20, 0x01, 0x28, 0x0b,
	0x32, 0x1c, 0x2e, 0x67, 0x6f, 0x6f, 0x67, 0x6c, 0x65, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x62,
	0x75, 0x66, 0x2e, 0x53, 0x74, 0x72, 0x69, 0x6e, 0x67, 0x56, 0x61, 0x6c, 0x75, 0x65, 0x42, 0x22,
	0xa0, 0xda, 0x29, 0x01, 0xc2, 0xdd, 0x29, 0x1a, 0x0a, 0x0b, 0x64, 0x65, 0x73, 0x63, 0x72, 0x69,
	0x70, 0x74, 0x69, 0x6f, 0x6e, 0x12, 0x0b, 0x64, 0x65, 0x73, 0x63, 0x72, 0x69, 0x70, 0x74, 0x69,
	0x6f, 0x6e, 0x52, 0x0b, 0x64, 0x65, 0x73, 0x63, 0x72, 0x69, 0x70, 0x74, 0x69, 0x6f, 0x6e, 0x12,
	0x3e, 0x0a, 0x0c, 0x63, 0x72, 0x65, 0x61, 0x74, 0x65, 0x64, 0x5f, 0x74, 0x69, 0x6d, 0x65, 0x18,
	0x05, 0x20, 0x01, 0x28, 0x0b, 0x32, 0x1a, 0x2e, 0x67, 0x6f, 0x6f, 0x67, 0x6c, 0x65, 0x2e, 0x70,
	0x72, 0x6f, 0x74, 0x6f, 0x62, 0x75, 0x66, 0x2e, 0x54, 0x69, 0x6d, 0x65, 0x73, 0x74, 0x61, 0x6d,
	0x70, 0x52, 0x0c, 0x63, 0x72, 0x65, 0x61, 0x74, 0x65, 0x64, 0x5f, 0x74, 0x69, 0x6d, 0x65, 0x12,
	0x3e, 0x0a, 0x0c, 0x75, 0x70, 0x64, 0x61, 0x74, 0x65, 0x64, 0x5f, 0x74, 0x69, 0x6d, 0x65, 0x18,
	0x06, 0x20, 0x01, 0x28, 0x0b, 0x32, 0x1a, 0x2e, 0x67, 0x6f, 0x6f, 0x67, 0x6c, 0x65, 0x2e, 0x70,
	0x72, 0x6f, 0x74, 0x6f, 0x62, 0x75, 0x66, 0x2e, 0x54, 0x69, 0x6d, 0x65, 0x73, 0x74, 0x61, 0x6d,
	0x70, 0x52, 0x0c, 0x75, 0x70, 0x64, 0x61, 0x74, 0x65, 0x64, 0x5f, 0x74, 0x69, 0x6d, 0x65, 0x12,
	0x18, 0x0a, 0x07, 0x76, 0x65, 0x72, 0x73, 0x69, 0x6f, 0x6e, 0x18, 0x07, 0x20, 0x01, 0x28, 0x0d,
	0x52, 0x07, 0x76, 0x65, 0x72, 0x73, 0x69, 0x6f, 0x6e, 0x12, 0x18, 0x0a, 0x04, 0x74, 0x79, 0x70,
	0x65, 0x18, 0x08, 0x20, 0x01, 0x28, 0x09, 0x42, 0x04, 0xa0, 0xda, 0x29, 0x01, 0x52, 0x04, 0x74,
	0x79, 0x70, 0x65, 0x12, 0x3d, 0x0a, 0x0a, 0x61, 0x74, 0x74, 0x72, 0x69, 0x62, 0x75, 0x74, 0x65,
	0x73, 0x18, 0x09, 0x20, 0x01, 0x28, 0x0b, 0x32, 0x17, 0x2e, 0x67, 0x6f, 0x6f, 0x67, 0x6c, 0x65,
	0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x62, 0x75, 0x66, 0x2e, 0x53, 0x74, 0x72, 0x75, 0x63, 0x74,
	0x42, 0x04, 0xa0, 0xda, 0x29, 0x01, 0x52, 0x0a, 0x61, 0x74, 0x74, 0x72, 0x69, 0x62, 0x75, 0x74,
	0x65, 0x73, 0x22, 0x8b, 0x01, 0x0a, 0x1c, 0x50, 0x61, 0x73, 0x73, 0x77, 0x6f, 0x72, 0x64, 0x41,
	0x75, 0x74, 0x68, 0x4d, 0x65, 0x74, 0x68, 0x6f, 0x64, 0x41, 0x74, 0x74, 0x72, 0x69, 0x62, 0x75,
	0x74, 0x65, 0x73, 0x12, 0x35, 0x0a, 0x14, 0x6d, 0x69, 0x6e, 0x5f, 0x75, 0x73, 0x65, 0x72, 0x5f,
	0x6e, 0x61, 0x6d, 0x65, 0x5f, 0x6c, 0x65, 0x6e, 0x67, 0x74, 0x68, 0x18, 0x01, 0x20, 0x01, 0x28,
	0x0d, 0x42, 0x04, 0xa0, 0xda, 0x29, 0x01, 0x52, 0x11, 0x6d, 0x69, 0x6e, 0x55, 0x73, 0x65, 0x72,
	0x4e, 0x61, 0x6d, 0x65, 0x4c, 0x65, 0x6e, 0x67, 0x74, 0x68, 0x12, 0x34, 0x0a, 0x13, 0x6d, 0x69,
	0x6e, 0x5f, 0x70, 0x61, 0x73, 0x73, 0x77, 0x6f, 0x72, 0x64, 0x5f, 0x6c, 0x65, 0x6e, 0x67, 0x74,
	0x68, 0x18, 0x02, 0x20, 0x01, 0x28, 0x0d, 0x42, 0x04, 0xa0, 0xda, 0x29, 0x01, 0x52, 0x11, 0x6d,
	0x69, 0x6e, 0x50, 0x61, 0x73, 0x73, 0x77, 0x6f, 0x72, 0x64, 0x4c, 0x65, 0x6e, 0x67, 0x74, 0x68,
	0x42, 0x5d, 0x5a, 0x5b, 0x67, 0x69, 0x74, 0x68, 0x75, 0x62, 0x2e, 0x63, 0x6f, 0x6d, 0x2f, 0x68,
	0x61, 0x73, 0x68, 0x69, 0x63, 0x6f, 0x72, 0x70, 0x2f, 0x62, 0x6f, 0x75, 0x6e, 0x64, 0x61, 0x72,
	0x79, 0x2f, 0x69, 0x6e, 0x74, 0x65, 0x72, 0x6e, 0x61, 0x6c, 0x2f, 0x67, 0x65, 0x6e, 0x2f, 0x63,
	0x6f, 0x6e, 0x74, 0x72, 0x6f, 0x6c, 0x6c, 0x65, 0x72, 0x2f, 0x61, 0x70, 0x69, 0x2f, 0x72, 0x65,
	0x73, 0x6f, 0x75, 0x72, 0x63, 0x65, 0x73, 0x2f, 0x61, 0x75, 0x74, 0x68, 0x6d, 0x65, 0x74, 0x68,
	0x6f, 0x64, 0x73, 0x3b, 0x61, 0x75, 0x74, 0x68, 0x6d, 0x65, 0x74, 0x68, 0x6f, 0x64, 0x73, 0x62,
	0x06, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x33,
}

var (
	file_controller_api_resources_authmethods_v1_auth_method_proto_rawDescOnce sync.Once
	file_controller_api_resources_authmethods_v1_auth_method_proto_rawDescData = file_controller_api_resources_authmethods_v1_auth_method_proto_rawDesc
)

func file_controller_api_resources_authmethods_v1_auth_method_proto_rawDescGZIP() []byte {
	file_controller_api_resources_authmethods_v1_auth_method_proto_rawDescOnce.Do(func() {
		file_controller_api_resources_authmethods_v1_auth_method_proto_rawDescData = protoimpl.X.CompressGZIP(file_controller_api_resources_authmethods_v1_auth_method_proto_rawDescData)
	})
	return file_controller_api_resources_authmethods_v1_auth_method_proto_rawDescData
}

var file_controller_api_resources_authmethods_v1_auth_method_proto_msgTypes = make([]protoimpl.MessageInfo, 2)
var file_controller_api_resources_authmethods_v1_auth_method_proto_goTypes = []interface{}{
	(*AuthMethod)(nil),                   // 0: controller.api.resources.authmethods.v1.AuthMethod
	(*PasswordAuthMethodAttributes)(nil), // 1: controller.api.resources.authmethods.v1.PasswordAuthMethodAttributes
	(*scopes.ScopeInfo)(nil),             // 2: controller.api.resources.scopes.v1.ScopeInfo
	(*wrappers.StringValue)(nil),         // 3: google.protobuf.StringValue
	(*timestamp.Timestamp)(nil),          // 4: google.protobuf.Timestamp
	(*_struct.Struct)(nil),               // 5: google.protobuf.Struct
}
var file_controller_api_resources_authmethods_v1_auth_method_proto_depIdxs = []int32{
	2, // 0: controller.api.resources.authmethods.v1.AuthMethod.scope:type_name -> controller.api.resources.scopes.v1.ScopeInfo
	3, // 1: controller.api.resources.authmethods.v1.AuthMethod.name:type_name -> google.protobuf.StringValue
	3, // 2: controller.api.resources.authmethods.v1.AuthMethod.description:type_name -> google.protobuf.StringValue
	4, // 3: controller.api.resources.authmethods.v1.AuthMethod.created_time:type_name -> google.protobuf.Timestamp
	4, // 4: controller.api.resources.authmethods.v1.AuthMethod.updated_time:type_name -> google.protobuf.Timestamp
	5, // 5: controller.api.resources.authmethods.v1.AuthMethod.attributes:type_name -> google.protobuf.Struct
	6, // [6:6] is the sub-list for method output_type
	6, // [6:6] is the sub-list for method input_type
	6, // [6:6] is the sub-list for extension type_name
	6, // [6:6] is the sub-list for extension extendee
	0, // [0:6] is the sub-list for field type_name
}

func init() { file_controller_api_resources_authmethods_v1_auth_method_proto_init() }
func file_controller_api_resources_authmethods_v1_auth_method_proto_init() {
	if File_controller_api_resources_authmethods_v1_auth_method_proto != nil {
		return
	}
	if !protoimpl.UnsafeEnabled {
		file_controller_api_resources_authmethods_v1_auth_method_proto_msgTypes[0].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*AuthMethod); i {
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
		file_controller_api_resources_authmethods_v1_auth_method_proto_msgTypes[1].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*PasswordAuthMethodAttributes); i {
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
			RawDescriptor: file_controller_api_resources_authmethods_v1_auth_method_proto_rawDesc,
			NumEnums:      0,
			NumMessages:   2,
			NumExtensions: 0,
			NumServices:   0,
		},
		GoTypes:           file_controller_api_resources_authmethods_v1_auth_method_proto_goTypes,
		DependencyIndexes: file_controller_api_resources_authmethods_v1_auth_method_proto_depIdxs,
		MessageInfos:      file_controller_api_resources_authmethods_v1_auth_method_proto_msgTypes,
	}.Build()
	File_controller_api_resources_authmethods_v1_auth_method_proto = out.File
	file_controller_api_resources_authmethods_v1_auth_method_proto_rawDesc = nil
	file_controller_api_resources_authmethods_v1_auth_method_proto_goTypes = nil
	file_controller_api_resources_authmethods_v1_auth_method_proto_depIdxs = nil
}
