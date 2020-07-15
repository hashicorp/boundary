// Code generated by protoc-gen-go. DO NOT EDIT.
// versions:
// 	protoc-gen-go v1.24.0
// 	protoc        v3.12.3
// source: controller/api/services/v1/authenticate_service.proto

package services

import (
	context "context"
	proto "github.com/golang/protobuf/proto"
	_struct "github.com/golang/protobuf/ptypes/struct"
	_ "github.com/grpc-ecosystem/grpc-gateway/protoc-gen-swagger/options"
	authtokens "github.com/hashicorp/watchtower/internal/gen/controller/api/resources/authtokens"
	_ "google.golang.org/genproto/googleapis/api/annotations"
	grpc "google.golang.org/grpc"
	codes "google.golang.org/grpc/codes"
	status "google.golang.org/grpc/status"
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

// The layout of the struct for "credentials" field in AuthenticateRequest.  This message isn't
// directly referenced anywhere but is used here to define the expected field names and types.
type PasswordCredentials struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	Name     string `protobuf:"bytes,1,opt,name=name,proto3" json:"name,omitempty"`
	Password string `protobuf:"bytes,2,opt,name=password,proto3" json:"password,omitempty"`
}

func (x *PasswordCredentials) Reset() {
	*x = PasswordCredentials{}
	if protoimpl.UnsafeEnabled {
		mi := &file_controller_api_services_v1_authenticate_service_proto_msgTypes[0]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *PasswordCredentials) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*PasswordCredentials) ProtoMessage() {}

func (x *PasswordCredentials) ProtoReflect() protoreflect.Message {
	mi := &file_controller_api_services_v1_authenticate_service_proto_msgTypes[0]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use PasswordCredentials.ProtoReflect.Descriptor instead.
func (*PasswordCredentials) Descriptor() ([]byte, []int) {
	return file_controller_api_services_v1_authenticate_service_proto_rawDescGZIP(), []int{0}
}

func (x *PasswordCredentials) GetName() string {
	if x != nil {
		return x.Name
	}
	return ""
}

func (x *PasswordCredentials) GetPassword() string {
	if x != nil {
		return x.Password
	}
	return ""
}

type AuthenticateRequest struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	OrgId string `protobuf:"bytes,1,opt,name=org_id,json=orgId,proto3" json:"org_id,omitempty"`
	// The id to the authmethod in the system being used for authentication.  The auth method must be in the org
	// being logged in to.
	AuthMethodId string `protobuf:"bytes,2,opt,name=auth_method_id,json=authMethodId,proto3" json:"auth_method_id,omitempty"`
	// This can be "cookie" or "token".  If not provided, "token" will be used.  For now only type "token" is returned.
	TokenType string `protobuf:"bytes,3,opt,name=token_type,json=tokenType,proto3" json:"token_type,omitempty"`
	// credentials are the different possible credential names depending on what type of auth method is used.
	// For password auth method: should include only "name" and "password".
	Credentials *_struct.Struct `protobuf:"bytes,8,opt,name=credentials,proto3" json:"credentials,omitempty"`
}

func (x *AuthenticateRequest) Reset() {
	*x = AuthenticateRequest{}
	if protoimpl.UnsafeEnabled {
		mi := &file_controller_api_services_v1_authenticate_service_proto_msgTypes[1]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *AuthenticateRequest) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*AuthenticateRequest) ProtoMessage() {}

func (x *AuthenticateRequest) ProtoReflect() protoreflect.Message {
	mi := &file_controller_api_services_v1_authenticate_service_proto_msgTypes[1]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use AuthenticateRequest.ProtoReflect.Descriptor instead.
func (*AuthenticateRequest) Descriptor() ([]byte, []int) {
	return file_controller_api_services_v1_authenticate_service_proto_rawDescGZIP(), []int{1}
}

func (x *AuthenticateRequest) GetOrgId() string {
	if x != nil {
		return x.OrgId
	}
	return ""
}

func (x *AuthenticateRequest) GetAuthMethodId() string {
	if x != nil {
		return x.AuthMethodId
	}
	return ""
}

func (x *AuthenticateRequest) GetTokenType() string {
	if x != nil {
		return x.TokenType
	}
	return ""
}

func (x *AuthenticateRequest) GetCredentials() *_struct.Struct {
	if x != nil {
		return x.Credentials
	}
	return nil
}

type AuthenticateResponse struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	Item *authtokens.AuthToken `protobuf:"bytes,1,opt,name=item,proto3" json:"item,omitempty"`
}

func (x *AuthenticateResponse) Reset() {
	*x = AuthenticateResponse{}
	if protoimpl.UnsafeEnabled {
		mi := &file_controller_api_services_v1_authenticate_service_proto_msgTypes[2]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *AuthenticateResponse) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*AuthenticateResponse) ProtoMessage() {}

func (x *AuthenticateResponse) ProtoReflect() protoreflect.Message {
	mi := &file_controller_api_services_v1_authenticate_service_proto_msgTypes[2]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use AuthenticateResponse.ProtoReflect.Descriptor instead.
func (*AuthenticateResponse) Descriptor() ([]byte, []int) {
	return file_controller_api_services_v1_authenticate_service_proto_rawDescGZIP(), []int{2}
}

func (x *AuthenticateResponse) GetItem() *authtokens.AuthToken {
	if x != nil {
		return x.Item
	}
	return nil
}

type DeauthenticateRequest struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	OrgId string `protobuf:"bytes,1,opt,name=org_id,json=orgId,proto3" json:"org_id,omitempty"`
}

func (x *DeauthenticateRequest) Reset() {
	*x = DeauthenticateRequest{}
	if protoimpl.UnsafeEnabled {
		mi := &file_controller_api_services_v1_authenticate_service_proto_msgTypes[3]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *DeauthenticateRequest) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*DeauthenticateRequest) ProtoMessage() {}

func (x *DeauthenticateRequest) ProtoReflect() protoreflect.Message {
	mi := &file_controller_api_services_v1_authenticate_service_proto_msgTypes[3]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use DeauthenticateRequest.ProtoReflect.Descriptor instead.
func (*DeauthenticateRequest) Descriptor() ([]byte, []int) {
	return file_controller_api_services_v1_authenticate_service_proto_rawDescGZIP(), []int{3}
}

func (x *DeauthenticateRequest) GetOrgId() string {
	if x != nil {
		return x.OrgId
	}
	return ""
}

type DeauthenticateResponse struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields
}

func (x *DeauthenticateResponse) Reset() {
	*x = DeauthenticateResponse{}
	if protoimpl.UnsafeEnabled {
		mi := &file_controller_api_services_v1_authenticate_service_proto_msgTypes[4]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *DeauthenticateResponse) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*DeauthenticateResponse) ProtoMessage() {}

func (x *DeauthenticateResponse) ProtoReflect() protoreflect.Message {
	mi := &file_controller_api_services_v1_authenticate_service_proto_msgTypes[4]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use DeauthenticateResponse.ProtoReflect.Descriptor instead.
func (*DeauthenticateResponse) Descriptor() ([]byte, []int) {
	return file_controller_api_services_v1_authenticate_service_proto_rawDescGZIP(), []int{4}
}

var File_controller_api_services_v1_authenticate_service_proto protoreflect.FileDescriptor

var file_controller_api_services_v1_authenticate_service_proto_rawDesc = []byte{
	0x0a, 0x35, 0x63, 0x6f, 0x6e, 0x74, 0x72, 0x6f, 0x6c, 0x6c, 0x65, 0x72, 0x2f, 0x61, 0x70, 0x69,
	0x2f, 0x73, 0x65, 0x72, 0x76, 0x69, 0x63, 0x65, 0x73, 0x2f, 0x76, 0x31, 0x2f, 0x61, 0x75, 0x74,
	0x68, 0x65, 0x6e, 0x74, 0x69, 0x63, 0x61, 0x74, 0x65, 0x5f, 0x73, 0x65, 0x72, 0x76, 0x69, 0x63,
	0x65, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x12, 0x1a, 0x63, 0x6f, 0x6e, 0x74, 0x72, 0x6f, 0x6c,
	0x6c, 0x65, 0x72, 0x2e, 0x61, 0x70, 0x69, 0x2e, 0x73, 0x65, 0x72, 0x76, 0x69, 0x63, 0x65, 0x73,
	0x2e, 0x76, 0x31, 0x1a, 0x2c, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x63, 0x2d, 0x67, 0x65, 0x6e, 0x2d,
	0x73, 0x77, 0x61, 0x67, 0x67, 0x65, 0x72, 0x2f, 0x6f, 0x70, 0x74, 0x69, 0x6f, 0x6e, 0x73, 0x2f,
	0x61, 0x6e, 0x6e, 0x6f, 0x74, 0x61, 0x74, 0x69, 0x6f, 0x6e, 0x73, 0x2e, 0x70, 0x72, 0x6f, 0x74,
	0x6f, 0x1a, 0x1c, 0x67, 0x6f, 0x6f, 0x67, 0x6c, 0x65, 0x2f, 0x61, 0x70, 0x69, 0x2f, 0x61, 0x6e,
	0x6e, 0x6f, 0x74, 0x61, 0x74, 0x69, 0x6f, 0x6e, 0x73, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x1a,
	0x1c, 0x67, 0x6f, 0x6f, 0x67, 0x6c, 0x65, 0x2f, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x62, 0x75, 0x66,
	0x2f, 0x73, 0x74, 0x72, 0x75, 0x63, 0x74, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x1a, 0x37, 0x63,
	0x6f, 0x6e, 0x74, 0x72, 0x6f, 0x6c, 0x6c, 0x65, 0x72, 0x2f, 0x61, 0x70, 0x69, 0x2f, 0x72, 0x65,
	0x73, 0x6f, 0x75, 0x72, 0x63, 0x65, 0x73, 0x2f, 0x61, 0x75, 0x74, 0x68, 0x74, 0x6f, 0x6b, 0x65,
	0x6e, 0x73, 0x2f, 0x76, 0x31, 0x2f, 0x61, 0x75, 0x74, 0x68, 0x5f, 0x74, 0x6f, 0x6b, 0x65, 0x6e,
	0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x22, 0x45, 0x0a, 0x13, 0x50, 0x61, 0x73, 0x73, 0x77, 0x6f,
	0x72, 0x64, 0x43, 0x72, 0x65, 0x64, 0x65, 0x6e, 0x74, 0x69, 0x61, 0x6c, 0x73, 0x12, 0x12, 0x0a,
	0x04, 0x6e, 0x61, 0x6d, 0x65, 0x18, 0x01, 0x20, 0x01, 0x28, 0x09, 0x52, 0x04, 0x6e, 0x61, 0x6d,
	0x65, 0x12, 0x1a, 0x0a, 0x08, 0x70, 0x61, 0x73, 0x73, 0x77, 0x6f, 0x72, 0x64, 0x18, 0x02, 0x20,
	0x01, 0x28, 0x09, 0x52, 0x08, 0x70, 0x61, 0x73, 0x73, 0x77, 0x6f, 0x72, 0x64, 0x22, 0xac, 0x01,
	0x0a, 0x13, 0x41, 0x75, 0x74, 0x68, 0x65, 0x6e, 0x74, 0x69, 0x63, 0x61, 0x74, 0x65, 0x52, 0x65,
	0x71, 0x75, 0x65, 0x73, 0x74, 0x12, 0x15, 0x0a, 0x06, 0x6f, 0x72, 0x67, 0x5f, 0x69, 0x64, 0x18,
	0x01, 0x20, 0x01, 0x28, 0x09, 0x52, 0x05, 0x6f, 0x72, 0x67, 0x49, 0x64, 0x12, 0x24, 0x0a, 0x0e,
	0x61, 0x75, 0x74, 0x68, 0x5f, 0x6d, 0x65, 0x74, 0x68, 0x6f, 0x64, 0x5f, 0x69, 0x64, 0x18, 0x02,
	0x20, 0x01, 0x28, 0x09, 0x52, 0x0c, 0x61, 0x75, 0x74, 0x68, 0x4d, 0x65, 0x74, 0x68, 0x6f, 0x64,
	0x49, 0x64, 0x12, 0x1d, 0x0a, 0x0a, 0x74, 0x6f, 0x6b, 0x65, 0x6e, 0x5f, 0x74, 0x79, 0x70, 0x65,
	0x18, 0x03, 0x20, 0x01, 0x28, 0x09, 0x52, 0x09, 0x74, 0x6f, 0x6b, 0x65, 0x6e, 0x54, 0x79, 0x70,
	0x65, 0x12, 0x39, 0x0a, 0x0b, 0x63, 0x72, 0x65, 0x64, 0x65, 0x6e, 0x74, 0x69, 0x61, 0x6c, 0x73,
	0x18, 0x08, 0x20, 0x01, 0x28, 0x0b, 0x32, 0x17, 0x2e, 0x67, 0x6f, 0x6f, 0x67, 0x6c, 0x65, 0x2e,
	0x70, 0x72, 0x6f, 0x74, 0x6f, 0x62, 0x75, 0x66, 0x2e, 0x53, 0x74, 0x72, 0x75, 0x63, 0x74, 0x52,
	0x0b, 0x63, 0x72, 0x65, 0x64, 0x65, 0x6e, 0x74, 0x69, 0x61, 0x6c, 0x73, 0x22, 0x5d, 0x0a, 0x14,
	0x41, 0x75, 0x74, 0x68, 0x65, 0x6e, 0x74, 0x69, 0x63, 0x61, 0x74, 0x65, 0x52, 0x65, 0x73, 0x70,
	0x6f, 0x6e, 0x73, 0x65, 0x12, 0x45, 0x0a, 0x04, 0x69, 0x74, 0x65, 0x6d, 0x18, 0x01, 0x20, 0x01,
	0x28, 0x0b, 0x32, 0x31, 0x2e, 0x63, 0x6f, 0x6e, 0x74, 0x72, 0x6f, 0x6c, 0x6c, 0x65, 0x72, 0x2e,
	0x61, 0x70, 0x69, 0x2e, 0x72, 0x65, 0x73, 0x6f, 0x75, 0x72, 0x63, 0x65, 0x73, 0x2e, 0x61, 0x75,
	0x74, 0x68, 0x74, 0x6f, 0x6b, 0x65, 0x6e, 0x73, 0x2e, 0x76, 0x31, 0x2e, 0x41, 0x75, 0x74, 0x68,
	0x54, 0x6f, 0x6b, 0x65, 0x6e, 0x52, 0x04, 0x69, 0x74, 0x65, 0x6d, 0x22, 0x2e, 0x0a, 0x15, 0x44,
	0x65, 0x61, 0x75, 0x74, 0x68, 0x65, 0x6e, 0x74, 0x69, 0x63, 0x61, 0x74, 0x65, 0x52, 0x65, 0x71,
	0x75, 0x65, 0x73, 0x74, 0x12, 0x15, 0x0a, 0x06, 0x6f, 0x72, 0x67, 0x5f, 0x69, 0x64, 0x18, 0x01,
	0x20, 0x01, 0x28, 0x09, 0x52, 0x05, 0x6f, 0x72, 0x67, 0x49, 0x64, 0x22, 0x18, 0x0a, 0x16, 0x44,
	0x65, 0x61, 0x75, 0x74, 0x68, 0x65, 0x6e, 0x74, 0x69, 0x63, 0x61, 0x74, 0x65, 0x52, 0x65, 0x73,
	0x70, 0x6f, 0x6e, 0x73, 0x65, 0x32, 0xff, 0x03, 0x0a, 0x15, 0x41, 0x75, 0x74, 0x68, 0x65, 0x6e,
	0x74, 0x69, 0x63, 0x61, 0x74, 0x69, 0x6f, 0x6e, 0x53, 0x65, 0x72, 0x76, 0x69, 0x63, 0x65, 0x12,
	0x89, 0x02, 0x0a, 0x0c, 0x41, 0x75, 0x74, 0x68, 0x65, 0x6e, 0x74, 0x69, 0x63, 0x61, 0x74, 0x65,
	0x12, 0x2f, 0x2e, 0x63, 0x6f, 0x6e, 0x74, 0x72, 0x6f, 0x6c, 0x6c, 0x65, 0x72, 0x2e, 0x61, 0x70,
	0x69, 0x2e, 0x73, 0x65, 0x72, 0x76, 0x69, 0x63, 0x65, 0x73, 0x2e, 0x76, 0x31, 0x2e, 0x41, 0x75,
	0x74, 0x68, 0x65, 0x6e, 0x74, 0x69, 0x63, 0x61, 0x74, 0x65, 0x52, 0x65, 0x71, 0x75, 0x65, 0x73,
	0x74, 0x1a, 0x30, 0x2e, 0x63, 0x6f, 0x6e, 0x74, 0x72, 0x6f, 0x6c, 0x6c, 0x65, 0x72, 0x2e, 0x61,
	0x70, 0x69, 0x2e, 0x73, 0x65, 0x72, 0x76, 0x69, 0x63, 0x65, 0x73, 0x2e, 0x76, 0x31, 0x2e, 0x41,
	0x75, 0x74, 0x68, 0x65, 0x6e, 0x74, 0x69, 0x63, 0x61, 0x74, 0x65, 0x52, 0x65, 0x73, 0x70, 0x6f,
	0x6e, 0x73, 0x65, 0x22, 0x95, 0x01, 0x82, 0xd3, 0xe4, 0x93, 0x02, 0x47, 0x22, 0x3c, 0x2f, 0x76,
	0x31, 0x2f, 0x6f, 0x72, 0x67, 0x73, 0x2f, 0x7b, 0x6f, 0x72, 0x67, 0x5f, 0x69, 0x64, 0x7d, 0x2f,
	0x61, 0x75, 0x74, 0x68, 0x2d, 0x6d, 0x65, 0x74, 0x68, 0x6f, 0x64, 0x73, 0x2f, 0x7b, 0x61, 0x75,
	0x74, 0x68, 0x5f, 0x6d, 0x65, 0x74, 0x68, 0x6f, 0x64, 0x5f, 0x69, 0x64, 0x7d, 0x3a, 0x61, 0x75,
	0x74, 0x68, 0x65, 0x6e, 0x74, 0x69, 0x63, 0x61, 0x74, 0x65, 0x3a, 0x01, 0x2a, 0x62, 0x04, 0x69,
	0x74, 0x65, 0x6d, 0x92, 0x41, 0x45, 0x12, 0x43, 0x41, 0x75, 0x74, 0x68, 0x65, 0x6e, 0x74, 0x69,
	0x63, 0x61, 0x74, 0x65, 0x20, 0x61, 0x20, 0x75, 0x73, 0x65, 0x72, 0x20, 0x74, 0x6f, 0x20, 0x61,
	0x6e, 0x20, 0x4f, 0x72, 0x67, 0x20, 0x61, 0x6e, 0x64, 0x20, 0x72, 0x65, 0x74, 0x72, 0x69, 0x65,
	0x76, 0x65, 0x20, 0x61, 0x6e, 0x20, 0x61, 0x75, 0x74, 0x68, 0x65, 0x6e, 0x74, 0x69, 0x63, 0x61,
	0x74, 0x69, 0x6f, 0x6e, 0x20, 0x74, 0x6f, 0x6b, 0x65, 0x6e, 0x2e, 0x12, 0xd9, 0x01, 0x0a, 0x0e,
	0x44, 0x65, 0x61, 0x75, 0x74, 0x68, 0x65, 0x6e, 0x74, 0x69, 0x63, 0x61, 0x74, 0x65, 0x12, 0x31,
	0x2e, 0x63, 0x6f, 0x6e, 0x74, 0x72, 0x6f, 0x6c, 0x6c, 0x65, 0x72, 0x2e, 0x61, 0x70, 0x69, 0x2e,
	0x73, 0x65, 0x72, 0x76, 0x69, 0x63, 0x65, 0x73, 0x2e, 0x76, 0x31, 0x2e, 0x44, 0x65, 0x61, 0x75,
	0x74, 0x68, 0x65, 0x6e, 0x74, 0x69, 0x63, 0x61, 0x74, 0x65, 0x52, 0x65, 0x71, 0x75, 0x65, 0x73,
	0x74, 0x1a, 0x32, 0x2e, 0x63, 0x6f, 0x6e, 0x74, 0x72, 0x6f, 0x6c, 0x6c, 0x65, 0x72, 0x2e, 0x61,
	0x70, 0x69, 0x2e, 0x73, 0x65, 0x72, 0x76, 0x69, 0x63, 0x65, 0x73, 0x2e, 0x76, 0x31, 0x2e, 0x44,
	0x65, 0x61, 0x75, 0x74, 0x68, 0x65, 0x6e, 0x74, 0x69, 0x63, 0x61, 0x74, 0x65, 0x52, 0x65, 0x73,
	0x70, 0x6f, 0x6e, 0x73, 0x65, 0x22, 0x60, 0x82, 0xd3, 0xe4, 0x93, 0x02, 0x22, 0x22, 0x20, 0x2f,
	0x76, 0x31, 0x2f, 0x6f, 0x72, 0x67, 0x73, 0x2f, 0x7b, 0x6f, 0x72, 0x67, 0x5f, 0x69, 0x64, 0x7d,
	0x3a, 0x64, 0x65, 0x61, 0x75, 0x74, 0x68, 0x65, 0x6e, 0x74, 0x69, 0x63, 0x61, 0x74, 0x65, 0x92,
	0x41, 0x35, 0x12, 0x33, 0x44, 0x65, 0x61, 0x75, 0x74, 0x68, 0x65, 0x6e, 0x74, 0x69, 0x63, 0x61,
	0x74, 0x65, 0x20, 0x61, 0x6e, 0x20, 0x61, 0x75, 0x74, 0x68, 0x65, 0x6e, 0x74, 0x69, 0x63, 0x61,
	0x74, 0x69, 0x6f, 0x6e, 0x20, 0x74, 0x6f, 0x6b, 0x65, 0x6e, 0x20, 0x66, 0x72, 0x6f, 0x6d, 0x20,
	0x61, 0x6e, 0x20, 0x4f, 0x72, 0x67, 0x2e, 0x42, 0x4f, 0x5a, 0x4d, 0x67, 0x69, 0x74, 0x68, 0x75,
	0x62, 0x2e, 0x63, 0x6f, 0x6d, 0x2f, 0x68, 0x61, 0x73, 0x68, 0x69, 0x63, 0x6f, 0x72, 0x70, 0x2f,
	0x77, 0x61, 0x74, 0x63, 0x68, 0x74, 0x6f, 0x77, 0x65, 0x72, 0x2f, 0x69, 0x6e, 0x74, 0x65, 0x72,
	0x6e, 0x61, 0x6c, 0x2f, 0x67, 0x65, 0x6e, 0x2f, 0x63, 0x6f, 0x6e, 0x74, 0x72, 0x6f, 0x6c, 0x6c,
	0x65, 0x72, 0x2f, 0x61, 0x70, 0x69, 0x2f, 0x73, 0x65, 0x72, 0x76, 0x69, 0x63, 0x65, 0x73, 0x3b,
	0x73, 0x65, 0x72, 0x76, 0x69, 0x63, 0x65, 0x73, 0x62, 0x06, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x33,
}

var (
	file_controller_api_services_v1_authenticate_service_proto_rawDescOnce sync.Once
	file_controller_api_services_v1_authenticate_service_proto_rawDescData = file_controller_api_services_v1_authenticate_service_proto_rawDesc
)

func file_controller_api_services_v1_authenticate_service_proto_rawDescGZIP() []byte {
	file_controller_api_services_v1_authenticate_service_proto_rawDescOnce.Do(func() {
		file_controller_api_services_v1_authenticate_service_proto_rawDescData = protoimpl.X.CompressGZIP(file_controller_api_services_v1_authenticate_service_proto_rawDescData)
	})
	return file_controller_api_services_v1_authenticate_service_proto_rawDescData
}

var file_controller_api_services_v1_authenticate_service_proto_msgTypes = make([]protoimpl.MessageInfo, 5)
var file_controller_api_services_v1_authenticate_service_proto_goTypes = []interface{}{
	(*PasswordCredentials)(nil),    // 0: controller.api.services.v1.PasswordCredentials
	(*AuthenticateRequest)(nil),    // 1: controller.api.services.v1.AuthenticateRequest
	(*AuthenticateResponse)(nil),   // 2: controller.api.services.v1.AuthenticateResponse
	(*DeauthenticateRequest)(nil),  // 3: controller.api.services.v1.DeauthenticateRequest
	(*DeauthenticateResponse)(nil), // 4: controller.api.services.v1.DeauthenticateResponse
	(*_struct.Struct)(nil),         // 5: google.protobuf.Struct
	(*authtokens.AuthToken)(nil),   // 6: controller.api.resources.authtokens.v1.AuthToken
}
var file_controller_api_services_v1_authenticate_service_proto_depIdxs = []int32{
	5, // 0: controller.api.services.v1.AuthenticateRequest.credentials:type_name -> google.protobuf.Struct
	6, // 1: controller.api.services.v1.AuthenticateResponse.item:type_name -> controller.api.resources.authtokens.v1.AuthToken
	1, // 2: controller.api.services.v1.AuthenticationService.Authenticate:input_type -> controller.api.services.v1.AuthenticateRequest
	3, // 3: controller.api.services.v1.AuthenticationService.Deauthenticate:input_type -> controller.api.services.v1.DeauthenticateRequest
	2, // 4: controller.api.services.v1.AuthenticationService.Authenticate:output_type -> controller.api.services.v1.AuthenticateResponse
	4, // 5: controller.api.services.v1.AuthenticationService.Deauthenticate:output_type -> controller.api.services.v1.DeauthenticateResponse
	4, // [4:6] is the sub-list for method output_type
	2, // [2:4] is the sub-list for method input_type
	2, // [2:2] is the sub-list for extension type_name
	2, // [2:2] is the sub-list for extension extendee
	0, // [0:2] is the sub-list for field type_name
}

func init() { file_controller_api_services_v1_authenticate_service_proto_init() }
func file_controller_api_services_v1_authenticate_service_proto_init() {
	if File_controller_api_services_v1_authenticate_service_proto != nil {
		return
	}
	if !protoimpl.UnsafeEnabled {
		file_controller_api_services_v1_authenticate_service_proto_msgTypes[0].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*PasswordCredentials); i {
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
		file_controller_api_services_v1_authenticate_service_proto_msgTypes[1].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*AuthenticateRequest); i {
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
		file_controller_api_services_v1_authenticate_service_proto_msgTypes[2].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*AuthenticateResponse); i {
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
		file_controller_api_services_v1_authenticate_service_proto_msgTypes[3].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*DeauthenticateRequest); i {
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
		file_controller_api_services_v1_authenticate_service_proto_msgTypes[4].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*DeauthenticateResponse); i {
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
			RawDescriptor: file_controller_api_services_v1_authenticate_service_proto_rawDesc,
			NumEnums:      0,
			NumMessages:   5,
			NumExtensions: 0,
			NumServices:   1,
		},
		GoTypes:           file_controller_api_services_v1_authenticate_service_proto_goTypes,
		DependencyIndexes: file_controller_api_services_v1_authenticate_service_proto_depIdxs,
		MessageInfos:      file_controller_api_services_v1_authenticate_service_proto_msgTypes,
	}.Build()
	File_controller_api_services_v1_authenticate_service_proto = out.File
	file_controller_api_services_v1_authenticate_service_proto_rawDesc = nil
	file_controller_api_services_v1_authenticate_service_proto_goTypes = nil
	file_controller_api_services_v1_authenticate_service_proto_depIdxs = nil
}

// Reference imports to suppress errors if they are not otherwise used.
var _ context.Context
var _ grpc.ClientConnInterface

// This is a compile-time assertion to ensure that this generated file
// is compatible with the grpc package it is being compiled against.
const _ = grpc.SupportPackageIsVersion6

// AuthenticationServiceClient is the client API for AuthenticationService service.
//
// For semantics around ctx use and closing/ending streaming RPCs, please refer to https://godoc.org/google.golang.org/grpc#ClientConn.NewStream.
type AuthenticationServiceClient interface {
	// Authenticate validates credentials provided and returns an auth token.
	Authenticate(ctx context.Context, in *AuthenticateRequest, opts ...grpc.CallOption) (*AuthenticateResponse, error)
	// Logout terminates a user's current session.
	Deauthenticate(ctx context.Context, in *DeauthenticateRequest, opts ...grpc.CallOption) (*DeauthenticateResponse, error)
}

type authenticationServiceClient struct {
	cc grpc.ClientConnInterface
}

func NewAuthenticationServiceClient(cc grpc.ClientConnInterface) AuthenticationServiceClient {
	return &authenticationServiceClient{cc}
}

func (c *authenticationServiceClient) Authenticate(ctx context.Context, in *AuthenticateRequest, opts ...grpc.CallOption) (*AuthenticateResponse, error) {
	out := new(AuthenticateResponse)
	err := c.cc.Invoke(ctx, "/controller.api.services.v1.AuthenticationService/Authenticate", in, out, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (c *authenticationServiceClient) Deauthenticate(ctx context.Context, in *DeauthenticateRequest, opts ...grpc.CallOption) (*DeauthenticateResponse, error) {
	out := new(DeauthenticateResponse)
	err := c.cc.Invoke(ctx, "/controller.api.services.v1.AuthenticationService/Deauthenticate", in, out, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

// AuthenticationServiceServer is the server API for AuthenticationService service.
type AuthenticationServiceServer interface {
	// Authenticate validates credentials provided and returns an auth token.
	Authenticate(context.Context, *AuthenticateRequest) (*AuthenticateResponse, error)
	// Logout terminates a user's current session.
	Deauthenticate(context.Context, *DeauthenticateRequest) (*DeauthenticateResponse, error)
}

// UnimplementedAuthenticationServiceServer can be embedded to have forward compatible implementations.
type UnimplementedAuthenticationServiceServer struct {
}

func (*UnimplementedAuthenticationServiceServer) Authenticate(context.Context, *AuthenticateRequest) (*AuthenticateResponse, error) {
	return nil, status.Errorf(codes.Unimplemented, "method Authenticate not implemented")
}
func (*UnimplementedAuthenticationServiceServer) Deauthenticate(context.Context, *DeauthenticateRequest) (*DeauthenticateResponse, error) {
	return nil, status.Errorf(codes.Unimplemented, "method Deauthenticate not implemented")
}

func RegisterAuthenticationServiceServer(s *grpc.Server, srv AuthenticationServiceServer) {
	s.RegisterService(&_AuthenticationService_serviceDesc, srv)
}

func _AuthenticationService_Authenticate_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(AuthenticateRequest)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(AuthenticationServiceServer).Authenticate(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: "/controller.api.services.v1.AuthenticationService/Authenticate",
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(AuthenticationServiceServer).Authenticate(ctx, req.(*AuthenticateRequest))
	}
	return interceptor(ctx, in, info, handler)
}

func _AuthenticationService_Deauthenticate_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(DeauthenticateRequest)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(AuthenticationServiceServer).Deauthenticate(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: "/controller.api.services.v1.AuthenticationService/Deauthenticate",
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(AuthenticationServiceServer).Deauthenticate(ctx, req.(*DeauthenticateRequest))
	}
	return interceptor(ctx, in, info, handler)
}

var _AuthenticationService_serviceDesc = grpc.ServiceDesc{
	ServiceName: "controller.api.services.v1.AuthenticationService",
	HandlerType: (*AuthenticationServiceServer)(nil),
	Methods: []grpc.MethodDesc{
		{
			MethodName: "Authenticate",
			Handler:    _AuthenticationService_Authenticate_Handler,
		},
		{
			MethodName: "Deauthenticate",
			Handler:    _AuthenticationService_Deauthenticate_Handler,
		},
	},
	Streams:  []grpc.StreamDesc{},
	Metadata: "controller/api/services/v1/authenticate_service.proto",
}
