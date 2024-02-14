// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

// Code generated by protoc-gen-go. DO NOT EDIT.
// versions:
// 	protoc-gen-go v1.32.0
// 	protoc        (unknown)
// source: controller/api/resources/aliases/v1/alias.proto

package aliases

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

// Alias contains all fields related to an Alias resource
type Alias struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	// Output only. The ID of the Alias.
	Id string `protobuf:"bytes,10,opt,name=id,proto3" json:"id,omitempty" class:"public" eventstream:"observation"` // @gotags: `class:"public" eventstream:"observation"`
	// The ID of the scope of which this Alias is a part.
	ScopeId string `protobuf:"bytes,20,opt,name=scope_id,proto3" json:"scope_id,omitempty" class:"public" eventstream:"observation"` // @gotags: `class:"public" eventstream:"observation"`
	// Output only. Scope information for this Alias.
	Scope *scopes.ScopeInfo `protobuf:"bytes,30,opt,name=scope,proto3" json:"scope,omitempty"`
	// Optional user-set name for identification purposes.
	Name *wrapperspb.StringValue `protobuf:"bytes,40,opt,name=name,proto3" json:"name,omitempty" class:"public"` // @gotags: `class:"public"`
	// Optional user-set descripton for identification purposes.
	Description *wrapperspb.StringValue `protobuf:"bytes,50,opt,name=description,proto3" json:"description,omitempty" class:"public"` // @gotags: `class:"public"`
	// Output only. The time this resource was created.
	CreatedTime *timestamppb.Timestamp `protobuf:"bytes,60,opt,name=created_time,proto3" json:"created_time,omitempty" class:"public" eventstream:"observation"` // @gotags: `class:"public" eventstream:"observation"`
	// Output only. The time this resource was last updated.
	UpdatedTime *timestamppb.Timestamp `protobuf:"bytes,70,opt,name=updated_time,proto3" json:"updated_time,omitempty" class:"public" eventstream:"observation"` // @gotags: `class:"public" eventstream:"observation"`
	// Version is used in mutation requests, after the initial creation, to ensure this resource has not changed.
	// The mutation will fail if the version does not match the latest known good version.
	Version uint32 `protobuf:"varint,80,opt,name=version,proto3" json:"version,omitempty" class:"public"` // @gotags: `class:"public"`
	// Required value of the alias. This is the value referenced by the user that
	// is resolved to the destination id.
	Value string `protobuf:"bytes,90,opt,name=value,proto3" json:"value,omitempty" class:"public"` // @gotags: `class:"public"`
	// destination_id is the id of the resource that this Alias points to.
	DestinationId *wrapperspb.StringValue `protobuf:"bytes,100,opt,name=destination_id,proto3" json:"destination_id,omitempty" class:"public" eventstream:"observation"` // @gotags: `class:"public" eventstream:"observation"`
	// type is the type of the alias.
	Type string `protobuf:"bytes,110,opt,name=type,proto3" json:"type,omitempty" class:"public" eventstream:"observation"` // @gotags: `class:"public" eventstream:"observation"`
	// Types that are assignable to Attrs:
	//
	//	*Alias_Attributes
	//	*Alias_TargetAliasAttributes
	Attrs isAlias_Attrs `protobuf_oneof:"attrs"`
	// Output only. The available actions on this resource for this user.
	AuthorizedActions []string `protobuf:"bytes,300,rep,name=authorized_actions,proto3" json:"authorized_actions,omitempty" class:"public"` // @gotags: `class:"public"`
}

func (x *Alias) Reset() {
	*x = Alias{}
	if protoimpl.UnsafeEnabled {
		mi := &file_controller_api_resources_aliases_v1_alias_proto_msgTypes[0]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *Alias) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*Alias) ProtoMessage() {}

func (x *Alias) ProtoReflect() protoreflect.Message {
	mi := &file_controller_api_resources_aliases_v1_alias_proto_msgTypes[0]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use Alias.ProtoReflect.Descriptor instead.
func (*Alias) Descriptor() ([]byte, []int) {
	return file_controller_api_resources_aliases_v1_alias_proto_rawDescGZIP(), []int{0}
}

func (x *Alias) GetId() string {
	if x != nil {
		return x.Id
	}
	return ""
}

func (x *Alias) GetScopeId() string {
	if x != nil {
		return x.ScopeId
	}
	return ""
}

func (x *Alias) GetScope() *scopes.ScopeInfo {
	if x != nil {
		return x.Scope
	}
	return nil
}

func (x *Alias) GetName() *wrapperspb.StringValue {
	if x != nil {
		return x.Name
	}
	return nil
}

func (x *Alias) GetDescription() *wrapperspb.StringValue {
	if x != nil {
		return x.Description
	}
	return nil
}

func (x *Alias) GetCreatedTime() *timestamppb.Timestamp {
	if x != nil {
		return x.CreatedTime
	}
	return nil
}

func (x *Alias) GetUpdatedTime() *timestamppb.Timestamp {
	if x != nil {
		return x.UpdatedTime
	}
	return nil
}

func (x *Alias) GetVersion() uint32 {
	if x != nil {
		return x.Version
	}
	return 0
}

func (x *Alias) GetValue() string {
	if x != nil {
		return x.Value
	}
	return ""
}

func (x *Alias) GetDestinationId() *wrapperspb.StringValue {
	if x != nil {
		return x.DestinationId
	}
	return nil
}

func (x *Alias) GetType() string {
	if x != nil {
		return x.Type
	}
	return ""
}

func (m *Alias) GetAttrs() isAlias_Attrs {
	if m != nil {
		return m.Attrs
	}
	return nil
}

func (x *Alias) GetAttributes() *structpb.Struct {
	if x, ok := x.GetAttrs().(*Alias_Attributes); ok {
		return x.Attributes
	}
	return nil
}

func (x *Alias) GetTargetAliasAttributes() *TargetAliasAttributes {
	if x, ok := x.GetAttrs().(*Alias_TargetAliasAttributes); ok {
		return x.TargetAliasAttributes
	}
	return nil
}

func (x *Alias) GetAuthorizedActions() []string {
	if x != nil {
		return x.AuthorizedActions
	}
	return nil
}

type isAlias_Attrs interface {
	isAlias_Attrs()
}

type Alias_Attributes struct {
	// The attributes that are applicable for the specific Alias type.
	Attributes *structpb.Struct `protobuf:"bytes,120,opt,name=attributes,proto3,oneof"`
}

type Alias_TargetAliasAttributes struct {
	TargetAliasAttributes *TargetAliasAttributes `protobuf:"bytes,121,opt,name=target_alias_attributes,json=targetAliasAttributes,proto3,oneof"`
}

func (*Alias_Attributes) isAlias_Attrs() {}

func (*Alias_TargetAliasAttributes) isAlias_Attrs() {}

// Attributes associated only with Aliases with type "target".
type TargetAliasAttributes struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	AuthorizeSessionArguments *AuthorizeSessionArguments `protobuf:"bytes,1,opt,name=authorize_session_arguments,proto3" json:"authorize_session_arguments,omitempty" class:"public"` // @gotags: `class:"public"`
}

func (x *TargetAliasAttributes) Reset() {
	*x = TargetAliasAttributes{}
	if protoimpl.UnsafeEnabled {
		mi := &file_controller_api_resources_aliases_v1_alias_proto_msgTypes[1]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *TargetAliasAttributes) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*TargetAliasAttributes) ProtoMessage() {}

func (x *TargetAliasAttributes) ProtoReflect() protoreflect.Message {
	mi := &file_controller_api_resources_aliases_v1_alias_proto_msgTypes[1]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use TargetAliasAttributes.ProtoReflect.Descriptor instead.
func (*TargetAliasAttributes) Descriptor() ([]byte, []int) {
	return file_controller_api_resources_aliases_v1_alias_proto_rawDescGZIP(), []int{1}
}

func (x *TargetAliasAttributes) GetAuthorizeSessionArguments() *AuthorizeSessionArguments {
	if x != nil {
		return x.AuthorizeSessionArguments
	}
	return nil
}

type AuthorizeSessionArguments struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	// host_id is the id of the host that the session will be authorized for.
	// When specified authorizing a session using this alias will have the same
	// effect of authorizing a session to the aliase's destination_id and passing
	// in this value through the -host-id flag. If the host-id flag is also
	// specified when calling authorize-session an error will be returned unless
	// the provided host-id matches this value.
	HostId string `protobuf:"bytes,100,opt,name=host_id,json=login_name,proto3" json:"host_id,omitempty" class:"public"` // @gotags: `class:"public"`
}

func (x *AuthorizeSessionArguments) Reset() {
	*x = AuthorizeSessionArguments{}
	if protoimpl.UnsafeEnabled {
		mi := &file_controller_api_resources_aliases_v1_alias_proto_msgTypes[2]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *AuthorizeSessionArguments) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*AuthorizeSessionArguments) ProtoMessage() {}

func (x *AuthorizeSessionArguments) ProtoReflect() protoreflect.Message {
	mi := &file_controller_api_resources_aliases_v1_alias_proto_msgTypes[2]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use AuthorizeSessionArguments.ProtoReflect.Descriptor instead.
func (*AuthorizeSessionArguments) Descriptor() ([]byte, []int) {
	return file_controller_api_resources_aliases_v1_alias_proto_rawDescGZIP(), []int{2}
}

func (x *AuthorizeSessionArguments) GetHostId() string {
	if x != nil {
		return x.HostId
	}
	return ""
}

var File_controller_api_resources_aliases_v1_alias_proto protoreflect.FileDescriptor

var file_controller_api_resources_aliases_v1_alias_proto_rawDesc = []byte{
	0x0a, 0x2f, 0x63, 0x6f, 0x6e, 0x74, 0x72, 0x6f, 0x6c, 0x6c, 0x65, 0x72, 0x2f, 0x61, 0x70, 0x69,
	0x2f, 0x72, 0x65, 0x73, 0x6f, 0x75, 0x72, 0x63, 0x65, 0x73, 0x2f, 0x61, 0x6c, 0x69, 0x61, 0x73,
	0x65, 0x73, 0x2f, 0x76, 0x31, 0x2f, 0x61, 0x6c, 0x69, 0x61, 0x73, 0x2e, 0x70, 0x72, 0x6f, 0x74,
	0x6f, 0x12, 0x23, 0x63, 0x6f, 0x6e, 0x74, 0x72, 0x6f, 0x6c, 0x6c, 0x65, 0x72, 0x2e, 0x61, 0x70,
	0x69, 0x2e, 0x72, 0x65, 0x73, 0x6f, 0x75, 0x72, 0x63, 0x65, 0x73, 0x2e, 0x61, 0x6c, 0x69, 0x61,
	0x73, 0x65, 0x73, 0x2e, 0x76, 0x31, 0x1a, 0x2e, 0x63, 0x6f, 0x6e, 0x74, 0x72, 0x6f, 0x6c, 0x6c,
	0x65, 0x72, 0x2f, 0x61, 0x70, 0x69, 0x2f, 0x72, 0x65, 0x73, 0x6f, 0x75, 0x72, 0x63, 0x65, 0x73,
	0x2f, 0x73, 0x63, 0x6f, 0x70, 0x65, 0x73, 0x2f, 0x76, 0x31, 0x2f, 0x73, 0x63, 0x6f, 0x70, 0x65,
	0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x1a, 0x2a, 0x63, 0x6f, 0x6e, 0x74, 0x72, 0x6f, 0x6c, 0x6c,
	0x65, 0x72, 0x2f, 0x63, 0x75, 0x73, 0x74, 0x6f, 0x6d, 0x5f, 0x6f, 0x70, 0x74, 0x69, 0x6f, 0x6e,
	0x73, 0x2f, 0x76, 0x31, 0x2f, 0x6f, 0x70, 0x74, 0x69, 0x6f, 0x6e, 0x73, 0x2e, 0x70, 0x72, 0x6f,
	0x74, 0x6f, 0x1a, 0x1b, 0x67, 0x6f, 0x6f, 0x67, 0x6c, 0x65, 0x2f, 0x61, 0x70, 0x69, 0x2f, 0x76,
	0x69, 0x73, 0x69, 0x62, 0x69, 0x6c, 0x69, 0x74, 0x79, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x1a,
	0x1c, 0x67, 0x6f, 0x6f, 0x67, 0x6c, 0x65, 0x2f, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x62, 0x75, 0x66,
	0x2f, 0x73, 0x74, 0x72, 0x75, 0x63, 0x74, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x1a, 0x1f, 0x67,
	0x6f, 0x6f, 0x67, 0x6c, 0x65, 0x2f, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x62, 0x75, 0x66, 0x2f, 0x74,
	0x69, 0x6d, 0x65, 0x73, 0x74, 0x61, 0x6d, 0x70, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x1a, 0x1e,
	0x67, 0x6f, 0x6f, 0x67, 0x6c, 0x65, 0x2f, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x62, 0x75, 0x66, 0x2f,
	0x77, 0x72, 0x61, 0x70, 0x70, 0x65, 0x72, 0x73, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x22, 0x8c,
	0x07, 0x0a, 0x05, 0x41, 0x6c, 0x69, 0x61, 0x73, 0x12, 0x0e, 0x0a, 0x02, 0x69, 0x64, 0x18, 0x0a,
	0x20, 0x01, 0x28, 0x09, 0x52, 0x02, 0x69, 0x64, 0x12, 0x1a, 0x0a, 0x08, 0x73, 0x63, 0x6f, 0x70,
	0x65, 0x5f, 0x69, 0x64, 0x18, 0x14, 0x20, 0x01, 0x28, 0x09, 0x52, 0x08, 0x73, 0x63, 0x6f, 0x70,
	0x65, 0x5f, 0x69, 0x64, 0x12, 0x43, 0x0a, 0x05, 0x73, 0x63, 0x6f, 0x70, 0x65, 0x18, 0x1e, 0x20,
	0x01, 0x28, 0x0b, 0x32, 0x2d, 0x2e, 0x63, 0x6f, 0x6e, 0x74, 0x72, 0x6f, 0x6c, 0x6c, 0x65, 0x72,
	0x2e, 0x61, 0x70, 0x69, 0x2e, 0x72, 0x65, 0x73, 0x6f, 0x75, 0x72, 0x63, 0x65, 0x73, 0x2e, 0x73,
	0x63, 0x6f, 0x70, 0x65, 0x73, 0x2e, 0x76, 0x31, 0x2e, 0x53, 0x63, 0x6f, 0x70, 0x65, 0x49, 0x6e,
	0x66, 0x6f, 0x52, 0x05, 0x73, 0x63, 0x6f, 0x70, 0x65, 0x12, 0x46, 0x0a, 0x04, 0x6e, 0x61, 0x6d,
	0x65, 0x18, 0x28, 0x20, 0x01, 0x28, 0x0b, 0x32, 0x1c, 0x2e, 0x67, 0x6f, 0x6f, 0x67, 0x6c, 0x65,
	0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x62, 0x75, 0x66, 0x2e, 0x53, 0x74, 0x72, 0x69, 0x6e, 0x67,
	0x56, 0x61, 0x6c, 0x75, 0x65, 0x42, 0x14, 0xa0, 0xda, 0x29, 0x01, 0xc2, 0xdd, 0x29, 0x0c, 0x0a,
	0x04, 0x6e, 0x61, 0x6d, 0x65, 0x12, 0x04, 0x4e, 0x61, 0x6d, 0x65, 0x52, 0x04, 0x6e, 0x61, 0x6d,
	0x65, 0x12, 0x62, 0x0a, 0x0b, 0x64, 0x65, 0x73, 0x63, 0x72, 0x69, 0x70, 0x74, 0x69, 0x6f, 0x6e,
	0x18, 0x32, 0x20, 0x01, 0x28, 0x0b, 0x32, 0x1c, 0x2e, 0x67, 0x6f, 0x6f, 0x67, 0x6c, 0x65, 0x2e,
	0x70, 0x72, 0x6f, 0x74, 0x6f, 0x62, 0x75, 0x66, 0x2e, 0x53, 0x74, 0x72, 0x69, 0x6e, 0x67, 0x56,
	0x61, 0x6c, 0x75, 0x65, 0x42, 0x22, 0xa0, 0xda, 0x29, 0x01, 0xc2, 0xdd, 0x29, 0x1a, 0x0a, 0x0b,
	0x64, 0x65, 0x73, 0x63, 0x72, 0x69, 0x70, 0x74, 0x69, 0x6f, 0x6e, 0x12, 0x0b, 0x44, 0x65, 0x73,
	0x63, 0x72, 0x69, 0x70, 0x74, 0x69, 0x6f, 0x6e, 0x52, 0x0b, 0x64, 0x65, 0x73, 0x63, 0x72, 0x69,
	0x70, 0x74, 0x69, 0x6f, 0x6e, 0x12, 0x3e, 0x0a, 0x0c, 0x63, 0x72, 0x65, 0x61, 0x74, 0x65, 0x64,
	0x5f, 0x74, 0x69, 0x6d, 0x65, 0x18, 0x3c, 0x20, 0x01, 0x28, 0x0b, 0x32, 0x1a, 0x2e, 0x67, 0x6f,
	0x6f, 0x67, 0x6c, 0x65, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x62, 0x75, 0x66, 0x2e, 0x54, 0x69,
	0x6d, 0x65, 0x73, 0x74, 0x61, 0x6d, 0x70, 0x52, 0x0c, 0x63, 0x72, 0x65, 0x61, 0x74, 0x65, 0x64,
	0x5f, 0x74, 0x69, 0x6d, 0x65, 0x12, 0x3e, 0x0a, 0x0c, 0x75, 0x70, 0x64, 0x61, 0x74, 0x65, 0x64,
	0x5f, 0x74, 0x69, 0x6d, 0x65, 0x18, 0x46, 0x20, 0x01, 0x28, 0x0b, 0x32, 0x1a, 0x2e, 0x67, 0x6f,
	0x6f, 0x67, 0x6c, 0x65, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x62, 0x75, 0x66, 0x2e, 0x54, 0x69,
	0x6d, 0x65, 0x73, 0x74, 0x61, 0x6d, 0x70, 0x52, 0x0c, 0x75, 0x70, 0x64, 0x61, 0x74, 0x65, 0x64,
	0x5f, 0x74, 0x69, 0x6d, 0x65, 0x12, 0x18, 0x0a, 0x07, 0x76, 0x65, 0x72, 0x73, 0x69, 0x6f, 0x6e,
	0x18, 0x50, 0x20, 0x01, 0x28, 0x0d, 0x52, 0x07, 0x76, 0x65, 0x72, 0x73, 0x69, 0x6f, 0x6e, 0x12,
	0x2c, 0x0a, 0x05, 0x76, 0x61, 0x6c, 0x75, 0x65, 0x18, 0x5a, 0x20, 0x01, 0x28, 0x09, 0x42, 0x16,
	0xa0, 0xda, 0x29, 0x01, 0xc2, 0xdd, 0x29, 0x0e, 0x0a, 0x05, 0x76, 0x61, 0x6c, 0x75, 0x65, 0x12,
	0x05, 0x56, 0x61, 0x6c, 0x75, 0x65, 0x52, 0x05, 0x76, 0x61, 0x6c, 0x75, 0x65, 0x12, 0x6d, 0x0a,
	0x0e, 0x64, 0x65, 0x73, 0x74, 0x69, 0x6e, 0x61, 0x74, 0x69, 0x6f, 0x6e, 0x5f, 0x69, 0x64, 0x18,
	0x64, 0x20, 0x01, 0x28, 0x0b, 0x32, 0x1c, 0x2e, 0x67, 0x6f, 0x6f, 0x67, 0x6c, 0x65, 0x2e, 0x70,
	0x72, 0x6f, 0x74, 0x6f, 0x62, 0x75, 0x66, 0x2e, 0x53, 0x74, 0x72, 0x69, 0x6e, 0x67, 0x56, 0x61,
	0x6c, 0x75, 0x65, 0x42, 0x27, 0xa0, 0xda, 0x29, 0x01, 0xc2, 0xdd, 0x29, 0x1f, 0x0a, 0x0e, 0x64,
	0x65, 0x73, 0x74, 0x69, 0x6e, 0x61, 0x74, 0x69, 0x6f, 0x6e, 0x5f, 0x69, 0x64, 0x12, 0x0d, 0x44,
	0x65, 0x73, 0x74, 0x69, 0x6e, 0x61, 0x74, 0x69, 0x6f, 0x6e, 0x49, 0x64, 0x52, 0x0e, 0x64, 0x65,
	0x73, 0x74, 0x69, 0x6e, 0x61, 0x74, 0x69, 0x6f, 0x6e, 0x5f, 0x69, 0x64, 0x12, 0x12, 0x0a, 0x04,
	0x74, 0x79, 0x70, 0x65, 0x18, 0x6e, 0x20, 0x01, 0x28, 0x09, 0x52, 0x04, 0x74, 0x79, 0x70, 0x65,
	0x12, 0x4a, 0x0a, 0x0a, 0x61, 0x74, 0x74, 0x72, 0x69, 0x62, 0x75, 0x74, 0x65, 0x73, 0x18, 0x78,
	0x20, 0x01, 0x28, 0x0b, 0x32, 0x17, 0x2e, 0x67, 0x6f, 0x6f, 0x67, 0x6c, 0x65, 0x2e, 0x70, 0x72,
	0x6f, 0x74, 0x6f, 0x62, 0x75, 0x66, 0x2e, 0x53, 0x74, 0x72, 0x75, 0x63, 0x74, 0x42, 0x0f, 0xa0,
	0xda, 0x29, 0x01, 0x9a, 0xe3, 0x29, 0x07, 0x64, 0x65, 0x66, 0x61, 0x75, 0x6c, 0x74, 0x48, 0x00,
	0x52, 0x0a, 0x61, 0x74, 0x74, 0x72, 0x69, 0x62, 0x75, 0x74, 0x65, 0x73, 0x12, 0x94, 0x01, 0x0a,
	0x17, 0x74, 0x61, 0x72, 0x67, 0x65, 0x74, 0x5f, 0x61, 0x6c, 0x69, 0x61, 0x73, 0x5f, 0x61, 0x74,
	0x74, 0x72, 0x69, 0x62, 0x75, 0x74, 0x65, 0x73, 0x18, 0x79, 0x20, 0x01, 0x28, 0x0b, 0x32, 0x3a,
	0x2e, 0x63, 0x6f, 0x6e, 0x74, 0x72, 0x6f, 0x6c, 0x6c, 0x65, 0x72, 0x2e, 0x61, 0x70, 0x69, 0x2e,
	0x72, 0x65, 0x73, 0x6f, 0x75, 0x72, 0x63, 0x65, 0x73, 0x2e, 0x61, 0x6c, 0x69, 0x61, 0x73, 0x65,
	0x73, 0x2e, 0x76, 0x31, 0x2e, 0x54, 0x61, 0x72, 0x67, 0x65, 0x74, 0x41, 0x6c, 0x69, 0x61, 0x73,
	0x41, 0x74, 0x74, 0x72, 0x69, 0x62, 0x75, 0x74, 0x65, 0x73, 0x42, 0x1e, 0xa0, 0xda, 0x29, 0x01,
	0x9a, 0xe3, 0x29, 0x06, 0x74, 0x61, 0x72, 0x67, 0x65, 0x74, 0xfa, 0xd2, 0xe4, 0x93, 0x02, 0x0a,
	0x12, 0x08, 0x49, 0x4e, 0x54, 0x45, 0x52, 0x4e, 0x41, 0x4c, 0x48, 0x00, 0x52, 0x15, 0x74, 0x61,
	0x72, 0x67, 0x65, 0x74, 0x41, 0x6c, 0x69, 0x61, 0x73, 0x41, 0x74, 0x74, 0x72, 0x69, 0x62, 0x75,
	0x74, 0x65, 0x73, 0x12, 0x2f, 0x0a, 0x12, 0x61, 0x75, 0x74, 0x68, 0x6f, 0x72, 0x69, 0x7a, 0x65,
	0x64, 0x5f, 0x61, 0x63, 0x74, 0x69, 0x6f, 0x6e, 0x73, 0x18, 0xac, 0x02, 0x20, 0x03, 0x28, 0x09,
	0x52, 0x12, 0x61, 0x75, 0x74, 0x68, 0x6f, 0x72, 0x69, 0x7a, 0x65, 0x64, 0x5f, 0x61, 0x63, 0x74,
	0x69, 0x6f, 0x6e, 0x73, 0x42, 0x07, 0x0a, 0x05, 0x61, 0x74, 0x74, 0x72, 0x73, 0x22, 0x9a, 0x01,
	0x0a, 0x15, 0x54, 0x61, 0x72, 0x67, 0x65, 0x74, 0x41, 0x6c, 0x69, 0x61, 0x73, 0x41, 0x74, 0x74,
	0x72, 0x69, 0x62, 0x75, 0x74, 0x65, 0x73, 0x12, 0x80, 0x01, 0x0a, 0x1b, 0x61, 0x75, 0x74, 0x68,
	0x6f, 0x72, 0x69, 0x7a, 0x65, 0x5f, 0x73, 0x65, 0x73, 0x73, 0x69, 0x6f, 0x6e, 0x5f, 0x61, 0x72,
	0x67, 0x75, 0x6d, 0x65, 0x6e, 0x74, 0x73, 0x18, 0x01, 0x20, 0x01, 0x28, 0x0b, 0x32, 0x3e, 0x2e,
	0x63, 0x6f, 0x6e, 0x74, 0x72, 0x6f, 0x6c, 0x6c, 0x65, 0x72, 0x2e, 0x61, 0x70, 0x69, 0x2e, 0x72,
	0x65, 0x73, 0x6f, 0x75, 0x72, 0x63, 0x65, 0x73, 0x2e, 0x61, 0x6c, 0x69, 0x61, 0x73, 0x65, 0x73,
	0x2e, 0x76, 0x31, 0x2e, 0x41, 0x75, 0x74, 0x68, 0x6f, 0x72, 0x69, 0x7a, 0x65, 0x53, 0x65, 0x73,
	0x73, 0x69, 0x6f, 0x6e, 0x41, 0x72, 0x67, 0x75, 0x6d, 0x65, 0x6e, 0x74, 0x73, 0x52, 0x1b, 0x61,
	0x75, 0x74, 0x68, 0x6f, 0x72, 0x69, 0x7a, 0x65, 0x5f, 0x73, 0x65, 0x73, 0x73, 0x69, 0x6f, 0x6e,
	0x5f, 0x61, 0x72, 0x67, 0x75, 0x6d, 0x65, 0x6e, 0x74, 0x73, 0x22, 0x7a, 0x0a, 0x19, 0x41, 0x75,
	0x74, 0x68, 0x6f, 0x72, 0x69, 0x7a, 0x65, 0x53, 0x65, 0x73, 0x73, 0x69, 0x6f, 0x6e, 0x41, 0x72,
	0x67, 0x75, 0x6d, 0x65, 0x6e, 0x74, 0x73, 0x12, 0x5d, 0x0a, 0x07, 0x68, 0x6f, 0x73, 0x74, 0x5f,
	0x69, 0x64, 0x18, 0x64, 0x20, 0x01, 0x28, 0x09, 0x42, 0x40, 0xa0, 0xda, 0x29, 0x01, 0xc2, 0xdd,
	0x29, 0x38, 0x0a, 0x2e, 0x61, 0x74, 0x74, 0x72, 0x69, 0x62, 0x75, 0x74, 0x65, 0x73, 0x2e, 0x61,
	0x75, 0x74, 0x68, 0x6f, 0x72, 0x69, 0x7a, 0x65, 0x5f, 0x73, 0x65, 0x73, 0x73, 0x69, 0x6f, 0x6e,
	0x5f, 0x61, 0x72, 0x67, 0x75, 0x6d, 0x65, 0x6e, 0x74, 0x73, 0x2e, 0x68, 0x6f, 0x73, 0x74, 0x5f,
	0x69, 0x64, 0x12, 0x06, 0x48, 0x6f, 0x73, 0x74, 0x49, 0x64, 0x52, 0x0a, 0x6c, 0x6f, 0x67, 0x69,
	0x6e, 0x5f, 0x6e, 0x61, 0x6d, 0x65, 0x42, 0x50, 0x5a, 0x4e, 0x67, 0x69, 0x74, 0x68, 0x75, 0x62,
	0x2e, 0x63, 0x6f, 0x6d, 0x2f, 0x68, 0x61, 0x73, 0x68, 0x69, 0x63, 0x6f, 0x72, 0x70, 0x2f, 0x62,
	0x6f, 0x75, 0x6e, 0x64, 0x61, 0x72, 0x79, 0x2f, 0x73, 0x64, 0x6b, 0x2f, 0x70, 0x62, 0x73, 0x2f,
	0x63, 0x6f, 0x6e, 0x74, 0x72, 0x6f, 0x6c, 0x6c, 0x65, 0x72, 0x2f, 0x61, 0x70, 0x69, 0x2f, 0x72,
	0x65, 0x73, 0x6f, 0x75, 0x72, 0x63, 0x65, 0x73, 0x2f, 0x61, 0x6c, 0x69, 0x61, 0x73, 0x65, 0x73,
	0x3b, 0x61, 0x6c, 0x69, 0x61, 0x73, 0x65, 0x73, 0x62, 0x06, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x33,
}

var (
	file_controller_api_resources_aliases_v1_alias_proto_rawDescOnce sync.Once
	file_controller_api_resources_aliases_v1_alias_proto_rawDescData = file_controller_api_resources_aliases_v1_alias_proto_rawDesc
)

func file_controller_api_resources_aliases_v1_alias_proto_rawDescGZIP() []byte {
	file_controller_api_resources_aliases_v1_alias_proto_rawDescOnce.Do(func() {
		file_controller_api_resources_aliases_v1_alias_proto_rawDescData = protoimpl.X.CompressGZIP(file_controller_api_resources_aliases_v1_alias_proto_rawDescData)
	})
	return file_controller_api_resources_aliases_v1_alias_proto_rawDescData
}

var file_controller_api_resources_aliases_v1_alias_proto_msgTypes = make([]protoimpl.MessageInfo, 3)
var file_controller_api_resources_aliases_v1_alias_proto_goTypes = []interface{}{
	(*Alias)(nil),                     // 0: controller.api.resources.aliases.v1.Alias
	(*TargetAliasAttributes)(nil),     // 1: controller.api.resources.aliases.v1.TargetAliasAttributes
	(*AuthorizeSessionArguments)(nil), // 2: controller.api.resources.aliases.v1.AuthorizeSessionArguments
	(*scopes.ScopeInfo)(nil),          // 3: controller.api.resources.scopes.v1.ScopeInfo
	(*wrapperspb.StringValue)(nil),    // 4: google.protobuf.StringValue
	(*timestamppb.Timestamp)(nil),     // 5: google.protobuf.Timestamp
	(*structpb.Struct)(nil),           // 6: google.protobuf.Struct
}
var file_controller_api_resources_aliases_v1_alias_proto_depIdxs = []int32{
	3, // 0: controller.api.resources.aliases.v1.Alias.scope:type_name -> controller.api.resources.scopes.v1.ScopeInfo
	4, // 1: controller.api.resources.aliases.v1.Alias.name:type_name -> google.protobuf.StringValue
	4, // 2: controller.api.resources.aliases.v1.Alias.description:type_name -> google.protobuf.StringValue
	5, // 3: controller.api.resources.aliases.v1.Alias.created_time:type_name -> google.protobuf.Timestamp
	5, // 4: controller.api.resources.aliases.v1.Alias.updated_time:type_name -> google.protobuf.Timestamp
	4, // 5: controller.api.resources.aliases.v1.Alias.destination_id:type_name -> google.protobuf.StringValue
	6, // 6: controller.api.resources.aliases.v1.Alias.attributes:type_name -> google.protobuf.Struct
	1, // 7: controller.api.resources.aliases.v1.Alias.target_alias_attributes:type_name -> controller.api.resources.aliases.v1.TargetAliasAttributes
	2, // 8: controller.api.resources.aliases.v1.TargetAliasAttributes.authorize_session_arguments:type_name -> controller.api.resources.aliases.v1.AuthorizeSessionArguments
	9, // [9:9] is the sub-list for method output_type
	9, // [9:9] is the sub-list for method input_type
	9, // [9:9] is the sub-list for extension type_name
	9, // [9:9] is the sub-list for extension extendee
	0, // [0:9] is the sub-list for field type_name
}

func init() { file_controller_api_resources_aliases_v1_alias_proto_init() }
func file_controller_api_resources_aliases_v1_alias_proto_init() {
	if File_controller_api_resources_aliases_v1_alias_proto != nil {
		return
	}
	if !protoimpl.UnsafeEnabled {
		file_controller_api_resources_aliases_v1_alias_proto_msgTypes[0].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*Alias); i {
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
		file_controller_api_resources_aliases_v1_alias_proto_msgTypes[1].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*TargetAliasAttributes); i {
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
		file_controller_api_resources_aliases_v1_alias_proto_msgTypes[2].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*AuthorizeSessionArguments); i {
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
	file_controller_api_resources_aliases_v1_alias_proto_msgTypes[0].OneofWrappers = []interface{}{
		(*Alias_Attributes)(nil),
		(*Alias_TargetAliasAttributes)(nil),
	}
	type x struct{}
	out := protoimpl.TypeBuilder{
		File: protoimpl.DescBuilder{
			GoPackagePath: reflect.TypeOf(x{}).PkgPath(),
			RawDescriptor: file_controller_api_resources_aliases_v1_alias_proto_rawDesc,
			NumEnums:      0,
			NumMessages:   3,
			NumExtensions: 0,
			NumServices:   0,
		},
		GoTypes:           file_controller_api_resources_aliases_v1_alias_proto_goTypes,
		DependencyIndexes: file_controller_api_resources_aliases_v1_alias_proto_depIdxs,
		MessageInfos:      file_controller_api_resources_aliases_v1_alias_proto_msgTypes,
	}.Build()
	File_controller_api_resources_aliases_v1_alias_proto = out.File
	file_controller_api_resources_aliases_v1_alias_proto_rawDesc = nil
	file_controller_api_resources_aliases_v1_alias_proto_goTypes = nil
	file_controller_api_resources_aliases_v1_alias_proto_depIdxs = nil
}
