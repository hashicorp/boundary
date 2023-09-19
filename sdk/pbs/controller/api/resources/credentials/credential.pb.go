// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

// Code generated by protoc-gen-go. DO NOT EDIT.
// versions:
// 	protoc-gen-go v1.31.0
// 	protoc        (unknown)
// source: controller/api/resources/credentials/v1/credential.proto

package credentials

import (
	scopes "github.com/hashicorp/boundary/sdk/pbs/controller/api/resources/scopes"
	_ "github.com/hashicorp/boundary/sdk/pbs/controller/protooptions"
	_ "google.golang.org/genproto/googleapis/api/visibility"
	protoreflect "google.golang.org/protobuf/reflect/protoreflect"
	protoimpl "google.golang.org/protobuf/runtime/protoimpl"
	structpb "google.golang.org/protobuf/types/known/structpb"
	timestamppb "google.golang.org/protobuf/types/known/timestamppb"
	wrapperspb "google.golang.org/protobuf/types/known/wrapperspb"
	reflect "reflect"
	sync "sync"
)

const (
	// Verify that this generated code is sufficiently up-to-date.
	_ = protoimpl.EnforceVersion(20 - protoimpl.MinVersion)
	// Verify that runtime/protoimpl is sufficiently up-to-date.
	_ = protoimpl.EnforceVersion(protoimpl.MaxVersion - 20)
)

// Credential contains all fields related to an Credential resource
type Credential struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	// Output only. The ID of the Credential.
	Id string `protobuf:"bytes,10,opt,name=id,proto3" json:"id,omitempty" class:"public"` // @gotags: `class:"public"`
	// The ID of the Credential Store of which this Credential is a part.
	CredentialStoreId string `protobuf:"bytes,20,opt,name=credential_store_id,proto3" json:"credential_store_id,omitempty" class:"public"` // @gotags: `class:"public"`
	// Output only. Scope information for this Credential.
	Scope *scopes.ScopeInfo `protobuf:"bytes,30,opt,name=scope,proto3" json:"scope,omitempty"`
	// Optional name for identification purposes.
	Name *wrapperspb.StringValue `protobuf:"bytes,40,opt,name=name,proto3" json:"name,omitempty" class:"public"` // @gotags: `class:"public"`
	// Optional user-set description for identification purposes.
	Description *wrapperspb.StringValue `protobuf:"bytes,50,opt,name=description,proto3" json:"description,omitempty" class:"public"` // @gotags: `class:"public"`
	// Output only. The time this resource was created.
	CreatedTime *timestamppb.Timestamp `protobuf:"bytes,60,opt,name=created_time,proto3" json:"created_time,omitempty" class:"public"` // @gotags: `class:"public"`
	// Output only. The time this resource was last updated.
	UpdatedTime *timestamppb.Timestamp `protobuf:"bytes,70,opt,name=updated_time,proto3" json:"updated_time,omitempty" class:"public"` // @gotags: `class:"public"`
	// Version is used in mutation requests, after the initial creation, to ensure this resource has not changed.
	// The mutation will fail if the version does not match the latest known good version.
	Version uint32 `protobuf:"varint,80,opt,name=version,proto3" json:"version,omitempty" class:"public"` // @gotags: `class:"public"`
	// The Credential type.
	Type string `protobuf:"bytes,90,opt,name=type,proto3" json:"type,omitempty" class:"public"` // @gotags: `class:"public"`
	// Types that are assignable to Attrs:
	//
	//	*Credential_Attributes
	//	*Credential_UsernamePasswordAttributes
	//	*Credential_SshPrivateKeyAttributes
	//	*Credential_JsonAttributes
	Attrs isCredential_Attrs `protobuf_oneof:"attrs"`
	// Output only. The available actions on this resource for this user.
	AuthorizedActions []string `protobuf:"bytes,300,rep,name=authorized_actions,proto3" json:"authorized_actions,omitempty" class:"public"` // @gotags: `class:"public"`
}

func (x *Credential) Reset() {
	*x = Credential{}
	if protoimpl.UnsafeEnabled {
		mi := &file_controller_api_resources_credentials_v1_credential_proto_msgTypes[0]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *Credential) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*Credential) ProtoMessage() {}

func (x *Credential) ProtoReflect() protoreflect.Message {
	mi := &file_controller_api_resources_credentials_v1_credential_proto_msgTypes[0]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use Credential.ProtoReflect.Descriptor instead.
func (*Credential) Descriptor() ([]byte, []int) {
	return file_controller_api_resources_credentials_v1_credential_proto_rawDescGZIP(), []int{0}
}

func (x *Credential) GetId() string {
	if x != nil {
		return x.Id
	}
	return ""
}

func (x *Credential) GetCredentialStoreId() string {
	if x != nil {
		return x.CredentialStoreId
	}
	return ""
}

func (x *Credential) GetScope() *scopes.ScopeInfo {
	if x != nil {
		return x.Scope
	}
	return nil
}

func (x *Credential) GetName() *wrapperspb.StringValue {
	if x != nil {
		return x.Name
	}
	return nil
}

func (x *Credential) GetDescription() *wrapperspb.StringValue {
	if x != nil {
		return x.Description
	}
	return nil
}

func (x *Credential) GetCreatedTime() *timestamppb.Timestamp {
	if x != nil {
		return x.CreatedTime
	}
	return nil
}

func (x *Credential) GetUpdatedTime() *timestamppb.Timestamp {
	if x != nil {
		return x.UpdatedTime
	}
	return nil
}

func (x *Credential) GetVersion() uint32 {
	if x != nil {
		return x.Version
	}
	return 0
}

func (x *Credential) GetType() string {
	if x != nil {
		return x.Type
	}
	return ""
}

func (m *Credential) GetAttrs() isCredential_Attrs {
	if m != nil {
		return m.Attrs
	}
	return nil
}

func (x *Credential) GetAttributes() *structpb.Struct {
	if x, ok := x.GetAttrs().(*Credential_Attributes); ok {
		return x.Attributes
	}
	return nil
}

func (x *Credential) GetUsernamePasswordAttributes() *UsernamePasswordAttributes {
	if x, ok := x.GetAttrs().(*Credential_UsernamePasswordAttributes); ok {
		return x.UsernamePasswordAttributes
	}
	return nil
}

func (x *Credential) GetSshPrivateKeyAttributes() *SshPrivateKeyAttributes {
	if x, ok := x.GetAttrs().(*Credential_SshPrivateKeyAttributes); ok {
		return x.SshPrivateKeyAttributes
	}
	return nil
}

func (x *Credential) GetJsonAttributes() *JsonAttributes {
	if x, ok := x.GetAttrs().(*Credential_JsonAttributes); ok {
		return x.JsonAttributes
	}
	return nil
}

func (x *Credential) GetAuthorizedActions() []string {
	if x != nil {
		return x.AuthorizedActions
	}
	return nil
}

type isCredential_Attrs interface {
	isCredential_Attrs()
}

type Credential_Attributes struct {
	// The attributes that are applicable for the specific Credential type.
	Attributes *structpb.Struct `protobuf:"bytes,100,opt,name=attributes,proto3,oneof"`
}

type Credential_UsernamePasswordAttributes struct {
	UsernamePasswordAttributes *UsernamePasswordAttributes `protobuf:"bytes,101,opt,name=username_password_attributes,json=usernamePasswordAttributes,proto3,oneof"`
}

type Credential_SshPrivateKeyAttributes struct {
	SshPrivateKeyAttributes *SshPrivateKeyAttributes `protobuf:"bytes,102,opt,name=ssh_private_key_attributes,json=sshPrivateKeyAttributes,proto3,oneof"`
}

type Credential_JsonAttributes struct {
	JsonAttributes *JsonAttributes `protobuf:"bytes,103,opt,name=json_attributes,json=jsonAttributes,proto3,oneof"`
}

func (*Credential_Attributes) isCredential_Attrs() {}

func (*Credential_UsernamePasswordAttributes) isCredential_Attrs() {}

func (*Credential_SshPrivateKeyAttributes) isCredential_Attrs() {}

func (*Credential_JsonAttributes) isCredential_Attrs() {}

// The attributes of a UsernamePassword Credential.
type UsernamePasswordAttributes struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	// The username associated with the credential.
	Username *wrapperspb.StringValue `protobuf:"bytes,10,opt,name=username,proto3" json:"username,omitempty" class:"public"` // @gotags: `class:"public"`
	// Input only. The password associated with the credential.
	Password *wrapperspb.StringValue `protobuf:"bytes,20,opt,name=password,proto3" json:"password,omitempty" class:"secret"` // @gotags: `class:"secret"`
	// Output only. The hmac value of the password.
	PasswordHmac string `protobuf:"bytes,30,opt,name=password_hmac,proto3" json:"password_hmac,omitempty" class:"public"` // @gotags: `class:"public"`
}

func (x *UsernamePasswordAttributes) Reset() {
	*x = UsernamePasswordAttributes{}
	if protoimpl.UnsafeEnabled {
		mi := &file_controller_api_resources_credentials_v1_credential_proto_msgTypes[1]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *UsernamePasswordAttributes) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*UsernamePasswordAttributes) ProtoMessage() {}

func (x *UsernamePasswordAttributes) ProtoReflect() protoreflect.Message {
	mi := &file_controller_api_resources_credentials_v1_credential_proto_msgTypes[1]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use UsernamePasswordAttributes.ProtoReflect.Descriptor instead.
func (*UsernamePasswordAttributes) Descriptor() ([]byte, []int) {
	return file_controller_api_resources_credentials_v1_credential_proto_rawDescGZIP(), []int{1}
}

func (x *UsernamePasswordAttributes) GetUsername() *wrapperspb.StringValue {
	if x != nil {
		return x.Username
	}
	return nil
}

func (x *UsernamePasswordAttributes) GetPassword() *wrapperspb.StringValue {
	if x != nil {
		return x.Password
	}
	return nil
}

func (x *UsernamePasswordAttributes) GetPasswordHmac() string {
	if x != nil {
		return x.PasswordHmac
	}
	return ""
}

// The attributes of a SshPrivateKey Credential.
type SshPrivateKeyAttributes struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	// The username associated with the credential.
	Username *wrapperspb.StringValue `protobuf:"bytes,10,opt,name=username,proto3" json:"username,omitempty" class:"public"` // @gotags: `class:"public"`
	// Input only. The SSH private key associated with the credential.
	PrivateKey *wrapperspb.StringValue `protobuf:"bytes,20,opt,name=private_key,proto3" json:"private_key,omitempty" class:"secret"` // @gotags: `class:"secret"`
	// Output only. The hmac value of the SSH private key.
	PrivateKeyHmac string `protobuf:"bytes,30,opt,name=private_key_hmac,proto3" json:"private_key_hmac,omitempty" class:"public"` // @gotags: `class:"public"`
	// Input only. The passphrase for the SSH private key associated with the credential.
	PrivateKeyPassphrase *wrapperspb.StringValue `protobuf:"bytes,40,opt,name=private_key_passphrase,proto3" json:"private_key_passphrase,omitempty" class:"secret"` // @gotags: `class:"secret"`
	// Output only. The hmac value of the SSH private key passphrase.
	PrivateKeyPassphraseHmac string `protobuf:"bytes,50,opt,name=private_key_passphrase_hmac,proto3" json:"private_key_passphrase_hmac,omitempty" class:"public"` // @gotags: `class:"public"`
}

func (x *SshPrivateKeyAttributes) Reset() {
	*x = SshPrivateKeyAttributes{}
	if protoimpl.UnsafeEnabled {
		mi := &file_controller_api_resources_credentials_v1_credential_proto_msgTypes[2]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *SshPrivateKeyAttributes) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*SshPrivateKeyAttributes) ProtoMessage() {}

func (x *SshPrivateKeyAttributes) ProtoReflect() protoreflect.Message {
	mi := &file_controller_api_resources_credentials_v1_credential_proto_msgTypes[2]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use SshPrivateKeyAttributes.ProtoReflect.Descriptor instead.
func (*SshPrivateKeyAttributes) Descriptor() ([]byte, []int) {
	return file_controller_api_resources_credentials_v1_credential_proto_rawDescGZIP(), []int{2}
}

func (x *SshPrivateKeyAttributes) GetUsername() *wrapperspb.StringValue {
	if x != nil {
		return x.Username
	}
	return nil
}

func (x *SshPrivateKeyAttributes) GetPrivateKey() *wrapperspb.StringValue {
	if x != nil {
		return x.PrivateKey
	}
	return nil
}

func (x *SshPrivateKeyAttributes) GetPrivateKeyHmac() string {
	if x != nil {
		return x.PrivateKeyHmac
	}
	return ""
}

func (x *SshPrivateKeyAttributes) GetPrivateKeyPassphrase() *wrapperspb.StringValue {
	if x != nil {
		return x.PrivateKeyPassphrase
	}
	return nil
}

func (x *SshPrivateKeyAttributes) GetPrivateKeyPassphraseHmac() string {
	if x != nil {
		return x.PrivateKeyPassphraseHmac
	}
	return ""
}

// The attributes of a JSON Credential.
type JsonAttributes struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	// Input only. The secret associated with the credential.
	Object *structpb.Struct `protobuf:"bytes,10,opt,name=object,proto3" json:"object,omitempty" class:"secret"` // @gotags: `class:"secret"`
	// Output only. The hmac value of the object.
	ObjectHmac string `protobuf:"bytes,20,opt,name=object_hmac,proto3" json:"object_hmac,omitempty" class:"public"` // @gotags: `class:"public"`
}

func (x *JsonAttributes) Reset() {
	*x = JsonAttributes{}
	if protoimpl.UnsafeEnabled {
		mi := &file_controller_api_resources_credentials_v1_credential_proto_msgTypes[3]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *JsonAttributes) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*JsonAttributes) ProtoMessage() {}

func (x *JsonAttributes) ProtoReflect() protoreflect.Message {
	mi := &file_controller_api_resources_credentials_v1_credential_proto_msgTypes[3]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use JsonAttributes.ProtoReflect.Descriptor instead.
func (*JsonAttributes) Descriptor() ([]byte, []int) {
	return file_controller_api_resources_credentials_v1_credential_proto_rawDescGZIP(), []int{3}
}

func (x *JsonAttributes) GetObject() *structpb.Struct {
	if x != nil {
		return x.Object
	}
	return nil
}

func (x *JsonAttributes) GetObjectHmac() string {
	if x != nil {
		return x.ObjectHmac
	}
	return ""
}

var File_controller_api_resources_credentials_v1_credential_proto protoreflect.FileDescriptor

var file_controller_api_resources_credentials_v1_credential_proto_rawDesc = []byte{
	0x0a, 0x38, 0x63, 0x6f, 0x6e, 0x74, 0x72, 0x6f, 0x6c, 0x6c, 0x65, 0x72, 0x2f, 0x61, 0x70, 0x69,
	0x2f, 0x72, 0x65, 0x73, 0x6f, 0x75, 0x72, 0x63, 0x65, 0x73, 0x2f, 0x63, 0x72, 0x65, 0x64, 0x65,
	0x6e, 0x74, 0x69, 0x61, 0x6c, 0x73, 0x2f, 0x76, 0x31, 0x2f, 0x63, 0x72, 0x65, 0x64, 0x65, 0x6e,
	0x74, 0x69, 0x61, 0x6c, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x12, 0x27, 0x63, 0x6f, 0x6e, 0x74,
	0x72, 0x6f, 0x6c, 0x6c, 0x65, 0x72, 0x2e, 0x61, 0x70, 0x69, 0x2e, 0x72, 0x65, 0x73, 0x6f, 0x75,
	0x72, 0x63, 0x65, 0x73, 0x2e, 0x63, 0x72, 0x65, 0x64, 0x65, 0x6e, 0x74, 0x69, 0x61, 0x6c, 0x73,
	0x2e, 0x76, 0x31, 0x1a, 0x2e, 0x63, 0x6f, 0x6e, 0x74, 0x72, 0x6f, 0x6c, 0x6c, 0x65, 0x72, 0x2f,
	0x61, 0x70, 0x69, 0x2f, 0x72, 0x65, 0x73, 0x6f, 0x75, 0x72, 0x63, 0x65, 0x73, 0x2f, 0x73, 0x63,
	0x6f, 0x70, 0x65, 0x73, 0x2f, 0x76, 0x31, 0x2f, 0x73, 0x63, 0x6f, 0x70, 0x65, 0x2e, 0x70, 0x72,
	0x6f, 0x74, 0x6f, 0x1a, 0x2a, 0x63, 0x6f, 0x6e, 0x74, 0x72, 0x6f, 0x6c, 0x6c, 0x65, 0x72, 0x2f,
	0x63, 0x75, 0x73, 0x74, 0x6f, 0x6d, 0x5f, 0x6f, 0x70, 0x74, 0x69, 0x6f, 0x6e, 0x73, 0x2f, 0x76,
	0x31, 0x2f, 0x6f, 0x70, 0x74, 0x69, 0x6f, 0x6e, 0x73, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x1a,
	0x1b, 0x67, 0x6f, 0x6f, 0x67, 0x6c, 0x65, 0x2f, 0x61, 0x70, 0x69, 0x2f, 0x76, 0x69, 0x73, 0x69,
	0x62, 0x69, 0x6c, 0x69, 0x74, 0x79, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x1a, 0x1c, 0x67, 0x6f,
	0x6f, 0x67, 0x6c, 0x65, 0x2f, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x62, 0x75, 0x66, 0x2f, 0x73, 0x74,
	0x72, 0x75, 0x63, 0x74, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x1a, 0x1f, 0x67, 0x6f, 0x6f, 0x67,
	0x6c, 0x65, 0x2f, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x62, 0x75, 0x66, 0x2f, 0x74, 0x69, 0x6d, 0x65,
	0x73, 0x74, 0x61, 0x6d, 0x70, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x1a, 0x1e, 0x67, 0x6f, 0x6f,
	0x67, 0x6c, 0x65, 0x2f, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x62, 0x75, 0x66, 0x2f, 0x77, 0x72, 0x61,
	0x70, 0x70, 0x65, 0x72, 0x73, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x22, 0xd6, 0x08, 0x0a, 0x0a,
	0x43, 0x72, 0x65, 0x64, 0x65, 0x6e, 0x74, 0x69, 0x61, 0x6c, 0x12, 0x0e, 0x0a, 0x02, 0x69, 0x64,
	0x18, 0x0a, 0x20, 0x01, 0x28, 0x09, 0x52, 0x02, 0x69, 0x64, 0x12, 0x30, 0x0a, 0x13, 0x63, 0x72,
	0x65, 0x64, 0x65, 0x6e, 0x74, 0x69, 0x61, 0x6c, 0x5f, 0x73, 0x74, 0x6f, 0x72, 0x65, 0x5f, 0x69,
	0x64, 0x18, 0x14, 0x20, 0x01, 0x28, 0x09, 0x52, 0x13, 0x63, 0x72, 0x65, 0x64, 0x65, 0x6e, 0x74,
	0x69, 0x61, 0x6c, 0x5f, 0x73, 0x74, 0x6f, 0x72, 0x65, 0x5f, 0x69, 0x64, 0x12, 0x43, 0x0a, 0x05,
	0x73, 0x63, 0x6f, 0x70, 0x65, 0x18, 0x1e, 0x20, 0x01, 0x28, 0x0b, 0x32, 0x2d, 0x2e, 0x63, 0x6f,
	0x6e, 0x74, 0x72, 0x6f, 0x6c, 0x6c, 0x65, 0x72, 0x2e, 0x61, 0x70, 0x69, 0x2e, 0x72, 0x65, 0x73,
	0x6f, 0x75, 0x72, 0x63, 0x65, 0x73, 0x2e, 0x73, 0x63, 0x6f, 0x70, 0x65, 0x73, 0x2e, 0x76, 0x31,
	0x2e, 0x53, 0x63, 0x6f, 0x70, 0x65, 0x49, 0x6e, 0x66, 0x6f, 0x52, 0x05, 0x73, 0x63, 0x6f, 0x70,
	0x65, 0x12, 0x46, 0x0a, 0x04, 0x6e, 0x61, 0x6d, 0x65, 0x18, 0x28, 0x20, 0x01, 0x28, 0x0b, 0x32,
	0x1c, 0x2e, 0x67, 0x6f, 0x6f, 0x67, 0x6c, 0x65, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x62, 0x75,
	0x66, 0x2e, 0x53, 0x74, 0x72, 0x69, 0x6e, 0x67, 0x56, 0x61, 0x6c, 0x75, 0x65, 0x42, 0x14, 0xa0,
	0xda, 0x29, 0x01, 0xc2, 0xdd, 0x29, 0x0c, 0x0a, 0x04, 0x6e, 0x61, 0x6d, 0x65, 0x12, 0x04, 0x4e,
	0x61, 0x6d, 0x65, 0x52, 0x04, 0x6e, 0x61, 0x6d, 0x65, 0x12, 0x62, 0x0a, 0x0b, 0x64, 0x65, 0x73,
	0x63, 0x72, 0x69, 0x70, 0x74, 0x69, 0x6f, 0x6e, 0x18, 0x32, 0x20, 0x01, 0x28, 0x0b, 0x32, 0x1c,
	0x2e, 0x67, 0x6f, 0x6f, 0x67, 0x6c, 0x65, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x62, 0x75, 0x66,
	0x2e, 0x53, 0x74, 0x72, 0x69, 0x6e, 0x67, 0x56, 0x61, 0x6c, 0x75, 0x65, 0x42, 0x22, 0xa0, 0xda,
	0x29, 0x01, 0xc2, 0xdd, 0x29, 0x1a, 0x0a, 0x0b, 0x64, 0x65, 0x73, 0x63, 0x72, 0x69, 0x70, 0x74,
	0x69, 0x6f, 0x6e, 0x12, 0x0b, 0x44, 0x65, 0x73, 0x63, 0x72, 0x69, 0x70, 0x74, 0x69, 0x6f, 0x6e,
	0x52, 0x0b, 0x64, 0x65, 0x73, 0x63, 0x72, 0x69, 0x70, 0x74, 0x69, 0x6f, 0x6e, 0x12, 0x3e, 0x0a,
	0x0c, 0x63, 0x72, 0x65, 0x61, 0x74, 0x65, 0x64, 0x5f, 0x74, 0x69, 0x6d, 0x65, 0x18, 0x3c, 0x20,
	0x01, 0x28, 0x0b, 0x32, 0x1a, 0x2e, 0x67, 0x6f, 0x6f, 0x67, 0x6c, 0x65, 0x2e, 0x70, 0x72, 0x6f,
	0x74, 0x6f, 0x62, 0x75, 0x66, 0x2e, 0x54, 0x69, 0x6d, 0x65, 0x73, 0x74, 0x61, 0x6d, 0x70, 0x52,
	0x0c, 0x63, 0x72, 0x65, 0x61, 0x74, 0x65, 0x64, 0x5f, 0x74, 0x69, 0x6d, 0x65, 0x12, 0x3e, 0x0a,
	0x0c, 0x75, 0x70, 0x64, 0x61, 0x74, 0x65, 0x64, 0x5f, 0x74, 0x69, 0x6d, 0x65, 0x18, 0x46, 0x20,
	0x01, 0x28, 0x0b, 0x32, 0x1a, 0x2e, 0x67, 0x6f, 0x6f, 0x67, 0x6c, 0x65, 0x2e, 0x70, 0x72, 0x6f,
	0x74, 0x6f, 0x62, 0x75, 0x66, 0x2e, 0x54, 0x69, 0x6d, 0x65, 0x73, 0x74, 0x61, 0x6d, 0x70, 0x52,
	0x0c, 0x75, 0x70, 0x64, 0x61, 0x74, 0x65, 0x64, 0x5f, 0x74, 0x69, 0x6d, 0x65, 0x12, 0x18, 0x0a,
	0x07, 0x76, 0x65, 0x72, 0x73, 0x69, 0x6f, 0x6e, 0x18, 0x50, 0x20, 0x01, 0x28, 0x0d, 0x52, 0x07,
	0x76, 0x65, 0x72, 0x73, 0x69, 0x6f, 0x6e, 0x12, 0x12, 0x0a, 0x04, 0x74, 0x79, 0x70, 0x65, 0x18,
	0x5a, 0x20, 0x01, 0x28, 0x09, 0x52, 0x04, 0x74, 0x79, 0x70, 0x65, 0x12, 0x4a, 0x0a, 0x0a, 0x61,
	0x74, 0x74, 0x72, 0x69, 0x62, 0x75, 0x74, 0x65, 0x73, 0x18, 0x64, 0x20, 0x01, 0x28, 0x0b, 0x32,
	0x17, 0x2e, 0x67, 0x6f, 0x6f, 0x67, 0x6c, 0x65, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x62, 0x75,
	0x66, 0x2e, 0x53, 0x74, 0x72, 0x75, 0x63, 0x74, 0x42, 0x0f, 0xa0, 0xda, 0x29, 0x01, 0x9a, 0xe3,
	0x29, 0x07, 0x64, 0x65, 0x66, 0x61, 0x75, 0x6c, 0x74, 0x48, 0x00, 0x52, 0x0a, 0x61, 0x74, 0x74,
	0x72, 0x69, 0x62, 0x75, 0x74, 0x65, 0x73, 0x12, 0xb2, 0x01, 0x0a, 0x1c, 0x75, 0x73, 0x65, 0x72,
	0x6e, 0x61, 0x6d, 0x65, 0x5f, 0x70, 0x61, 0x73, 0x73, 0x77, 0x6f, 0x72, 0x64, 0x5f, 0x61, 0x74,
	0x74, 0x72, 0x69, 0x62, 0x75, 0x74, 0x65, 0x73, 0x18, 0x65, 0x20, 0x01, 0x28, 0x0b, 0x32, 0x43,
	0x2e, 0x63, 0x6f, 0x6e, 0x74, 0x72, 0x6f, 0x6c, 0x6c, 0x65, 0x72, 0x2e, 0x61, 0x70, 0x69, 0x2e,
	0x72, 0x65, 0x73, 0x6f, 0x75, 0x72, 0x63, 0x65, 0x73, 0x2e, 0x63, 0x72, 0x65, 0x64, 0x65, 0x6e,
	0x74, 0x69, 0x61, 0x6c, 0x73, 0x2e, 0x76, 0x31, 0x2e, 0x55, 0x73, 0x65, 0x72, 0x6e, 0x61, 0x6d,
	0x65, 0x50, 0x61, 0x73, 0x73, 0x77, 0x6f, 0x72, 0x64, 0x41, 0x74, 0x74, 0x72, 0x69, 0x62, 0x75,
	0x74, 0x65, 0x73, 0x42, 0x29, 0xa0, 0xda, 0x29, 0x01, 0x9a, 0xe3, 0x29, 0x11, 0x75, 0x73, 0x65,
	0x72, 0x6e, 0x61, 0x6d, 0x65, 0x5f, 0x70, 0x61, 0x73, 0x73, 0x77, 0x6f, 0x72, 0x64, 0xfa, 0xd2,
	0xe4, 0x93, 0x02, 0x0a, 0x12, 0x08, 0x49, 0x4e, 0x54, 0x45, 0x52, 0x4e, 0x41, 0x4c, 0x48, 0x00,
	0x52, 0x1a, 0x75, 0x73, 0x65, 0x72, 0x6e, 0x61, 0x6d, 0x65, 0x50, 0x61, 0x73, 0x73, 0x77, 0x6f,
	0x72, 0x64, 0x41, 0x74, 0x74, 0x72, 0x69, 0x62, 0x75, 0x74, 0x65, 0x73, 0x12, 0xa8, 0x01, 0x0a,
	0x1a, 0x73, 0x73, 0x68, 0x5f, 0x70, 0x72, 0x69, 0x76, 0x61, 0x74, 0x65, 0x5f, 0x6b, 0x65, 0x79,
	0x5f, 0x61, 0x74, 0x74, 0x72, 0x69, 0x62, 0x75, 0x74, 0x65, 0x73, 0x18, 0x66, 0x20, 0x01, 0x28,
	0x0b, 0x32, 0x40, 0x2e, 0x63, 0x6f, 0x6e, 0x74, 0x72, 0x6f, 0x6c, 0x6c, 0x65, 0x72, 0x2e, 0x61,
	0x70, 0x69, 0x2e, 0x72, 0x65, 0x73, 0x6f, 0x75, 0x72, 0x63, 0x65, 0x73, 0x2e, 0x63, 0x72, 0x65,
	0x64, 0x65, 0x6e, 0x74, 0x69, 0x61, 0x6c, 0x73, 0x2e, 0x76, 0x31, 0x2e, 0x53, 0x73, 0x68, 0x50,
	0x72, 0x69, 0x76, 0x61, 0x74, 0x65, 0x4b, 0x65, 0x79, 0x41, 0x74, 0x74, 0x72, 0x69, 0x62, 0x75,
	0x74, 0x65, 0x73, 0x42, 0x27, 0xa0, 0xda, 0x29, 0x01, 0x9a, 0xe3, 0x29, 0x0f, 0x73, 0x73, 0x68,
	0x5f, 0x70, 0x72, 0x69, 0x76, 0x61, 0x74, 0x65, 0x5f, 0x6b, 0x65, 0x79, 0xfa, 0xd2, 0xe4, 0x93,
	0x02, 0x0a, 0x12, 0x08, 0x49, 0x4e, 0x54, 0x45, 0x52, 0x4e, 0x41, 0x4c, 0x48, 0x00, 0x52, 0x17,
	0x73, 0x73, 0x68, 0x50, 0x72, 0x69, 0x76, 0x61, 0x74, 0x65, 0x4b, 0x65, 0x79, 0x41, 0x74, 0x74,
	0x72, 0x69, 0x62, 0x75, 0x74, 0x65, 0x73, 0x12, 0x80, 0x01, 0x0a, 0x0f, 0x6a, 0x73, 0x6f, 0x6e,
	0x5f, 0x61, 0x74, 0x74, 0x72, 0x69, 0x62, 0x75, 0x74, 0x65, 0x73, 0x18, 0x67, 0x20, 0x01, 0x28,
	0x0b, 0x32, 0x37, 0x2e, 0x63, 0x6f, 0x6e, 0x74, 0x72, 0x6f, 0x6c, 0x6c, 0x65, 0x72, 0x2e, 0x61,
	0x70, 0x69, 0x2e, 0x72, 0x65, 0x73, 0x6f, 0x75, 0x72, 0x63, 0x65, 0x73, 0x2e, 0x63, 0x72, 0x65,
	0x64, 0x65, 0x6e, 0x74, 0x69, 0x61, 0x6c, 0x73, 0x2e, 0x76, 0x31, 0x2e, 0x4a, 0x73, 0x6f, 0x6e,
	0x41, 0x74, 0x74, 0x72, 0x69, 0x62, 0x75, 0x74, 0x65, 0x73, 0x42, 0x1c, 0xa0, 0xda, 0x29, 0x01,
	0x9a, 0xe3, 0x29, 0x04, 0x6a, 0x73, 0x6f, 0x6e, 0xfa, 0xd2, 0xe4, 0x93, 0x02, 0x0a, 0x12, 0x08,
	0x49, 0x4e, 0x54, 0x45, 0x52, 0x4e, 0x41, 0x4c, 0x48, 0x00, 0x52, 0x0e, 0x6a, 0x73, 0x6f, 0x6e,
	0x41, 0x74, 0x74, 0x72, 0x69, 0x62, 0x75, 0x74, 0x65, 0x73, 0x12, 0x2f, 0x0a, 0x12, 0x61, 0x75,
	0x74, 0x68, 0x6f, 0x72, 0x69, 0x7a, 0x65, 0x64, 0x5f, 0x61, 0x63, 0x74, 0x69, 0x6f, 0x6e, 0x73,
	0x18, 0xac, 0x02, 0x20, 0x03, 0x28, 0x09, 0x52, 0x12, 0x61, 0x75, 0x74, 0x68, 0x6f, 0x72, 0x69,
	0x7a, 0x65, 0x64, 0x5f, 0x61, 0x63, 0x74, 0x69, 0x6f, 0x6e, 0x73, 0x42, 0x07, 0x0a, 0x05, 0x61,
	0x74, 0x74, 0x72, 0x73, 0x22, 0xb6, 0x02, 0x0a, 0x1a, 0x55, 0x73, 0x65, 0x72, 0x6e, 0x61, 0x6d,
	0x65, 0x50, 0x61, 0x73, 0x73, 0x77, 0x6f, 0x72, 0x64, 0x41, 0x74, 0x74, 0x72, 0x69, 0x62, 0x75,
	0x74, 0x65, 0x73, 0x12, 0x61, 0x0a, 0x08, 0x75, 0x73, 0x65, 0x72, 0x6e, 0x61, 0x6d, 0x65, 0x18,
	0x0a, 0x20, 0x01, 0x28, 0x0b, 0x32, 0x1c, 0x2e, 0x67, 0x6f, 0x6f, 0x67, 0x6c, 0x65, 0x2e, 0x70,
	0x72, 0x6f, 0x74, 0x6f, 0x62, 0x75, 0x66, 0x2e, 0x53, 0x74, 0x72, 0x69, 0x6e, 0x67, 0x56, 0x61,
	0x6c, 0x75, 0x65, 0x42, 0x27, 0xa0, 0xda, 0x29, 0x01, 0xc2, 0xdd, 0x29, 0x1f, 0x0a, 0x13, 0x61,
	0x74, 0x74, 0x72, 0x69, 0x62, 0x75, 0x74, 0x65, 0x73, 0x2e, 0x75, 0x73, 0x65, 0x72, 0x6e, 0x61,
	0x6d, 0x65, 0x12, 0x08, 0x55, 0x73, 0x65, 0x72, 0x6e, 0x61, 0x6d, 0x65, 0x52, 0x08, 0x75, 0x73,
	0x65, 0x72, 0x6e, 0x61, 0x6d, 0x65, 0x12, 0x61, 0x0a, 0x08, 0x70, 0x61, 0x73, 0x73, 0x77, 0x6f,
	0x72, 0x64, 0x18, 0x14, 0x20, 0x01, 0x28, 0x0b, 0x32, 0x1c, 0x2e, 0x67, 0x6f, 0x6f, 0x67, 0x6c,
	0x65, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x62, 0x75, 0x66, 0x2e, 0x53, 0x74, 0x72, 0x69, 0x6e,
	0x67, 0x56, 0x61, 0x6c, 0x75, 0x65, 0x42, 0x27, 0xa0, 0xda, 0x29, 0x01, 0xc2, 0xdd, 0x29, 0x1f,
	0x0a, 0x13, 0x61, 0x74, 0x74, 0x72, 0x69, 0x62, 0x75, 0x74, 0x65, 0x73, 0x2e, 0x70, 0x61, 0x73,
	0x73, 0x77, 0x6f, 0x72, 0x64, 0x12, 0x08, 0x50, 0x61, 0x73, 0x73, 0x77, 0x6f, 0x72, 0x64, 0x52,
	0x08, 0x70, 0x61, 0x73, 0x73, 0x77, 0x6f, 0x72, 0x64, 0x12, 0x52, 0x0a, 0x0d, 0x70, 0x61, 0x73,
	0x73, 0x77, 0x6f, 0x72, 0x64, 0x5f, 0x68, 0x6d, 0x61, 0x63, 0x18, 0x1e, 0x20, 0x01, 0x28, 0x09,
	0x42, 0x2c, 0xc2, 0xdd, 0x29, 0x28, 0x0a, 0x18, 0x61, 0x74, 0x74, 0x72, 0x69, 0x62, 0x75, 0x74,
	0x65, 0x73, 0x2e, 0x70, 0x61, 0x73, 0x73, 0x77, 0x6f, 0x72, 0x64, 0x5f, 0x68, 0x6d, 0x61, 0x63,
	0x12, 0x0c, 0x50, 0x61, 0x73, 0x73, 0x77, 0x6f, 0x72, 0x64, 0x48, 0x6d, 0x61, 0x63, 0x52, 0x0d,
	0x70, 0x61, 0x73, 0x73, 0x77, 0x6f, 0x72, 0x64, 0x5f, 0x68, 0x6d, 0x61, 0x63, 0x22, 0xee, 0x04,
	0x0a, 0x17, 0x53, 0x73, 0x68, 0x50, 0x72, 0x69, 0x76, 0x61, 0x74, 0x65, 0x4b, 0x65, 0x79, 0x41,
	0x74, 0x74, 0x72, 0x69, 0x62, 0x75, 0x74, 0x65, 0x73, 0x12, 0x61, 0x0a, 0x08, 0x75, 0x73, 0x65,
	0x72, 0x6e, 0x61, 0x6d, 0x65, 0x18, 0x0a, 0x20, 0x01, 0x28, 0x0b, 0x32, 0x1c, 0x2e, 0x67, 0x6f,
	0x6f, 0x67, 0x6c, 0x65, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x62, 0x75, 0x66, 0x2e, 0x53, 0x74,
	0x72, 0x69, 0x6e, 0x67, 0x56, 0x61, 0x6c, 0x75, 0x65, 0x42, 0x27, 0xa0, 0xda, 0x29, 0x01, 0xc2,
	0xdd, 0x29, 0x1f, 0x0a, 0x13, 0x61, 0x74, 0x74, 0x72, 0x69, 0x62, 0x75, 0x74, 0x65, 0x73, 0x2e,
	0x75, 0x73, 0x65, 0x72, 0x6e, 0x61, 0x6d, 0x65, 0x12, 0x08, 0x55, 0x73, 0x65, 0x72, 0x6e, 0x61,
	0x6d, 0x65, 0x52, 0x08, 0x75, 0x73, 0x65, 0x72, 0x6e, 0x61, 0x6d, 0x65, 0x12, 0x6c, 0x0a, 0x0b,
	0x70, 0x72, 0x69, 0x76, 0x61, 0x74, 0x65, 0x5f, 0x6b, 0x65, 0x79, 0x18, 0x14, 0x20, 0x01, 0x28,
	0x0b, 0x32, 0x1c, 0x2e, 0x67, 0x6f, 0x6f, 0x67, 0x6c, 0x65, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f,
	0x62, 0x75, 0x66, 0x2e, 0x53, 0x74, 0x72, 0x69, 0x6e, 0x67, 0x56, 0x61, 0x6c, 0x75, 0x65, 0x42,
	0x2c, 0xa0, 0xda, 0x29, 0x01, 0xc2, 0xdd, 0x29, 0x24, 0x0a, 0x16, 0x61, 0x74, 0x74, 0x72, 0x69,
	0x62, 0x75, 0x74, 0x65, 0x73, 0x2e, 0x70, 0x72, 0x69, 0x76, 0x61, 0x74, 0x65, 0x5f, 0x6b, 0x65,
	0x79, 0x12, 0x0a, 0x50, 0x72, 0x69, 0x76, 0x61, 0x74, 0x65, 0x4b, 0x65, 0x79, 0x52, 0x0b, 0x70,
	0x72, 0x69, 0x76, 0x61, 0x74, 0x65, 0x5f, 0x6b, 0x65, 0x79, 0x12, 0x5d, 0x0a, 0x10, 0x70, 0x72,
	0x69, 0x76, 0x61, 0x74, 0x65, 0x5f, 0x6b, 0x65, 0x79, 0x5f, 0x68, 0x6d, 0x61, 0x63, 0x18, 0x1e,
	0x20, 0x01, 0x28, 0x09, 0x42, 0x31, 0xc2, 0xdd, 0x29, 0x2d, 0x0a, 0x1b, 0x61, 0x74, 0x74, 0x72,
	0x69, 0x62, 0x75, 0x74, 0x65, 0x73, 0x2e, 0x70, 0x72, 0x69, 0x76, 0x61, 0x74, 0x65, 0x5f, 0x6b,
	0x65, 0x79, 0x5f, 0x68, 0x6d, 0x61, 0x63, 0x12, 0x0e, 0x50, 0x72, 0x69, 0x76, 0x61, 0x74, 0x65,
	0x4b, 0x65, 0x79, 0x48, 0x6d, 0x61, 0x63, 0x52, 0x10, 0x70, 0x72, 0x69, 0x76, 0x61, 0x74, 0x65,
	0x5f, 0x6b, 0x65, 0x79, 0x5f, 0x68, 0x6d, 0x61, 0x63, 0x12, 0x97, 0x01, 0x0a, 0x16, 0x70, 0x72,
	0x69, 0x76, 0x61, 0x74, 0x65, 0x5f, 0x6b, 0x65, 0x79, 0x5f, 0x70, 0x61, 0x73, 0x73, 0x70, 0x68,
	0x72, 0x61, 0x73, 0x65, 0x18, 0x28, 0x20, 0x01, 0x28, 0x0b, 0x32, 0x1c, 0x2e, 0x67, 0x6f, 0x6f,
	0x67, 0x6c, 0x65, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x62, 0x75, 0x66, 0x2e, 0x53, 0x74, 0x72,
	0x69, 0x6e, 0x67, 0x56, 0x61, 0x6c, 0x75, 0x65, 0x42, 0x41, 0xa0, 0xda, 0x29, 0x01, 0xc2, 0xdd,
	0x29, 0x39, 0x0a, 0x21, 0x61, 0x74, 0x74, 0x72, 0x69, 0x62, 0x75, 0x74, 0x65, 0x73, 0x2e, 0x70,
	0x72, 0x69, 0x76, 0x61, 0x74, 0x65, 0x5f, 0x6b, 0x65, 0x79, 0x5f, 0x70, 0x61, 0x73, 0x73, 0x70,
	0x68, 0x72, 0x61, 0x73, 0x65, 0x12, 0x14, 0x50, 0x72, 0x69, 0x76, 0x61, 0x74, 0x65, 0x4b, 0x65,
	0x79, 0x50, 0x61, 0x73, 0x73, 0x70, 0x68, 0x72, 0x61, 0x73, 0x65, 0x52, 0x16, 0x70, 0x72, 0x69,
	0x76, 0x61, 0x74, 0x65, 0x5f, 0x6b, 0x65, 0x79, 0x5f, 0x70, 0x61, 0x73, 0x73, 0x70, 0x68, 0x72,
	0x61, 0x73, 0x65, 0x12, 0x88, 0x01, 0x0a, 0x1b, 0x70, 0x72, 0x69, 0x76, 0x61, 0x74, 0x65, 0x5f,
	0x6b, 0x65, 0x79, 0x5f, 0x70, 0x61, 0x73, 0x73, 0x70, 0x68, 0x72, 0x61, 0x73, 0x65, 0x5f, 0x68,
	0x6d, 0x61, 0x63, 0x18, 0x32, 0x20, 0x01, 0x28, 0x09, 0x42, 0x46, 0xc2, 0xdd, 0x29, 0x42, 0x0a,
	0x26, 0x61, 0x74, 0x74, 0x72, 0x69, 0x62, 0x75, 0x74, 0x65, 0x73, 0x2e, 0x70, 0x72, 0x69, 0x76,
	0x61, 0x74, 0x65, 0x5f, 0x6b, 0x65, 0x79, 0x5f, 0x70, 0x61, 0x73, 0x73, 0x70, 0x68, 0x72, 0x61,
	0x73, 0x65, 0x5f, 0x68, 0x6d, 0x61, 0x63, 0x12, 0x18, 0x50, 0x72, 0x69, 0x76, 0x61, 0x74, 0x65,
	0x4b, 0x65, 0x79, 0x50, 0x61, 0x73, 0x73, 0x70, 0x68, 0x72, 0x61, 0x73, 0x65, 0x48, 0x6d, 0x61,
	0x63, 0x52, 0x1b, 0x70, 0x72, 0x69, 0x76, 0x61, 0x74, 0x65, 0x5f, 0x6b, 0x65, 0x79, 0x5f, 0x70,
	0x61, 0x73, 0x73, 0x70, 0x68, 0x72, 0x61, 0x73, 0x65, 0x5f, 0x68, 0x6d, 0x61, 0x63, 0x22, 0xb2,
	0x01, 0x0a, 0x0e, 0x4a, 0x73, 0x6f, 0x6e, 0x41, 0x74, 0x74, 0x72, 0x69, 0x62, 0x75, 0x74, 0x65,
	0x73, 0x12, 0x54, 0x0a, 0x06, 0x6f, 0x62, 0x6a, 0x65, 0x63, 0x74, 0x18, 0x0a, 0x20, 0x01, 0x28,
	0x0b, 0x32, 0x17, 0x2e, 0x67, 0x6f, 0x6f, 0x67, 0x6c, 0x65, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f,
	0x62, 0x75, 0x66, 0x2e, 0x53, 0x74, 0x72, 0x75, 0x63, 0x74, 0x42, 0x23, 0xa0, 0xda, 0x29, 0x01,
	0xc2, 0xdd, 0x29, 0x1b, 0x0a, 0x11, 0x61, 0x74, 0x74, 0x72, 0x69, 0x62, 0x75, 0x74, 0x65, 0x73,
	0x2e, 0x6f, 0x62, 0x6a, 0x65, 0x63, 0x74, 0x12, 0x06, 0x4f, 0x62, 0x6a, 0x65, 0x63, 0x74, 0x52,
	0x06, 0x6f, 0x62, 0x6a, 0x65, 0x63, 0x74, 0x12, 0x4a, 0x0a, 0x0b, 0x6f, 0x62, 0x6a, 0x65, 0x63,
	0x74, 0x5f, 0x68, 0x6d, 0x61, 0x63, 0x18, 0x14, 0x20, 0x01, 0x28, 0x09, 0x42, 0x28, 0xc2, 0xdd,
	0x29, 0x24, 0x0a, 0x16, 0x61, 0x74, 0x74, 0x72, 0x69, 0x62, 0x75, 0x74, 0x65, 0x73, 0x2e, 0x6f,
	0x62, 0x6a, 0x65, 0x63, 0x74, 0x5f, 0x68, 0x6d, 0x61, 0x63, 0x12, 0x0a, 0x4f, 0x62, 0x6a, 0x65,
	0x63, 0x74, 0x48, 0x6d, 0x61, 0x63, 0x52, 0x0b, 0x6f, 0x62, 0x6a, 0x65, 0x63, 0x74, 0x5f, 0x68,
	0x6d, 0x61, 0x63, 0x42, 0x58, 0x5a, 0x56, 0x67, 0x69, 0x74, 0x68, 0x75, 0x62, 0x2e, 0x63, 0x6f,
	0x6d, 0x2f, 0x68, 0x61, 0x73, 0x68, 0x69, 0x63, 0x6f, 0x72, 0x70, 0x2f, 0x62, 0x6f, 0x75, 0x6e,
	0x64, 0x61, 0x72, 0x79, 0x2f, 0x73, 0x64, 0x6b, 0x2f, 0x70, 0x62, 0x73, 0x2f, 0x63, 0x6f, 0x6e,
	0x74, 0x72, 0x6f, 0x6c, 0x6c, 0x65, 0x72, 0x2f, 0x61, 0x70, 0x69, 0x2f, 0x72, 0x65, 0x73, 0x6f,
	0x75, 0x72, 0x63, 0x65, 0x73, 0x2f, 0x63, 0x72, 0x65, 0x64, 0x65, 0x6e, 0x74, 0x69, 0x61, 0x6c,
	0x73, 0x3b, 0x63, 0x72, 0x65, 0x64, 0x65, 0x6e, 0x74, 0x69, 0x61, 0x6c, 0x73, 0x62, 0x06, 0x70,
	0x72, 0x6f, 0x74, 0x6f, 0x33,
}

var (
	file_controller_api_resources_credentials_v1_credential_proto_rawDescOnce sync.Once
	file_controller_api_resources_credentials_v1_credential_proto_rawDescData = file_controller_api_resources_credentials_v1_credential_proto_rawDesc
)

func file_controller_api_resources_credentials_v1_credential_proto_rawDescGZIP() []byte {
	file_controller_api_resources_credentials_v1_credential_proto_rawDescOnce.Do(func() {
		file_controller_api_resources_credentials_v1_credential_proto_rawDescData = protoimpl.X.CompressGZIP(file_controller_api_resources_credentials_v1_credential_proto_rawDescData)
	})
	return file_controller_api_resources_credentials_v1_credential_proto_rawDescData
}

var file_controller_api_resources_credentials_v1_credential_proto_msgTypes = make([]protoimpl.MessageInfo, 4)
var file_controller_api_resources_credentials_v1_credential_proto_goTypes = []interface{}{
	(*Credential)(nil),                 // 0: controller.api.resources.credentials.v1.Credential
	(*UsernamePasswordAttributes)(nil), // 1: controller.api.resources.credentials.v1.UsernamePasswordAttributes
	(*SshPrivateKeyAttributes)(nil),    // 2: controller.api.resources.credentials.v1.SshPrivateKeyAttributes
	(*JsonAttributes)(nil),             // 3: controller.api.resources.credentials.v1.JsonAttributes
	(*scopes.ScopeInfo)(nil),           // 4: controller.api.resources.scopes.v1.ScopeInfo
	(*wrapperspb.StringValue)(nil),     // 5: google.protobuf.StringValue
	(*timestamppb.Timestamp)(nil),      // 6: google.protobuf.Timestamp
	(*structpb.Struct)(nil),            // 7: google.protobuf.Struct
}
var file_controller_api_resources_credentials_v1_credential_proto_depIdxs = []int32{
	4,  // 0: controller.api.resources.credentials.v1.Credential.scope:type_name -> controller.api.resources.scopes.v1.ScopeInfo
	5,  // 1: controller.api.resources.credentials.v1.Credential.name:type_name -> google.protobuf.StringValue
	5,  // 2: controller.api.resources.credentials.v1.Credential.description:type_name -> google.protobuf.StringValue
	6,  // 3: controller.api.resources.credentials.v1.Credential.created_time:type_name -> google.protobuf.Timestamp
	6,  // 4: controller.api.resources.credentials.v1.Credential.updated_time:type_name -> google.protobuf.Timestamp
	7,  // 5: controller.api.resources.credentials.v1.Credential.attributes:type_name -> google.protobuf.Struct
	1,  // 6: controller.api.resources.credentials.v1.Credential.username_password_attributes:type_name -> controller.api.resources.credentials.v1.UsernamePasswordAttributes
	2,  // 7: controller.api.resources.credentials.v1.Credential.ssh_private_key_attributes:type_name -> controller.api.resources.credentials.v1.SshPrivateKeyAttributes
	3,  // 8: controller.api.resources.credentials.v1.Credential.json_attributes:type_name -> controller.api.resources.credentials.v1.JsonAttributes
	5,  // 9: controller.api.resources.credentials.v1.UsernamePasswordAttributes.username:type_name -> google.protobuf.StringValue
	5,  // 10: controller.api.resources.credentials.v1.UsernamePasswordAttributes.password:type_name -> google.protobuf.StringValue
	5,  // 11: controller.api.resources.credentials.v1.SshPrivateKeyAttributes.username:type_name -> google.protobuf.StringValue
	5,  // 12: controller.api.resources.credentials.v1.SshPrivateKeyAttributes.private_key:type_name -> google.protobuf.StringValue
	5,  // 13: controller.api.resources.credentials.v1.SshPrivateKeyAttributes.private_key_passphrase:type_name -> google.protobuf.StringValue
	7,  // 14: controller.api.resources.credentials.v1.JsonAttributes.object:type_name -> google.protobuf.Struct
	15, // [15:15] is the sub-list for method output_type
	15, // [15:15] is the sub-list for method input_type
	15, // [15:15] is the sub-list for extension type_name
	15, // [15:15] is the sub-list for extension extendee
	0,  // [0:15] is the sub-list for field type_name
}

func init() { file_controller_api_resources_credentials_v1_credential_proto_init() }
func file_controller_api_resources_credentials_v1_credential_proto_init() {
	if File_controller_api_resources_credentials_v1_credential_proto != nil {
		return
	}
	if !protoimpl.UnsafeEnabled {
		file_controller_api_resources_credentials_v1_credential_proto_msgTypes[0].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*Credential); i {
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
		file_controller_api_resources_credentials_v1_credential_proto_msgTypes[1].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*UsernamePasswordAttributes); i {
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
		file_controller_api_resources_credentials_v1_credential_proto_msgTypes[2].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*SshPrivateKeyAttributes); i {
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
		file_controller_api_resources_credentials_v1_credential_proto_msgTypes[3].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*JsonAttributes); i {
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
	file_controller_api_resources_credentials_v1_credential_proto_msgTypes[0].OneofWrappers = []interface{}{
		(*Credential_Attributes)(nil),
		(*Credential_UsernamePasswordAttributes)(nil),
		(*Credential_SshPrivateKeyAttributes)(nil),
		(*Credential_JsonAttributes)(nil),
	}
	type x struct{}
	out := protoimpl.TypeBuilder{
		File: protoimpl.DescBuilder{
			GoPackagePath: reflect.TypeOf(x{}).PkgPath(),
			RawDescriptor: file_controller_api_resources_credentials_v1_credential_proto_rawDesc,
			NumEnums:      0,
			NumMessages:   4,
			NumExtensions: 0,
			NumServices:   0,
		},
		GoTypes:           file_controller_api_resources_credentials_v1_credential_proto_goTypes,
		DependencyIndexes: file_controller_api_resources_credentials_v1_credential_proto_depIdxs,
		MessageInfos:      file_controller_api_resources_credentials_v1_credential_proto_msgTypes,
	}.Build()
	File_controller_api_resources_credentials_v1_credential_proto = out.File
	file_controller_api_resources_credentials_v1_credential_proto_rawDesc = nil
	file_controller_api_resources_credentials_v1_credential_proto_goTypes = nil
	file_controller_api_resources_credentials_v1_credential_proto_depIdxs = nil
}
