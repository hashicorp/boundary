// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

// Code generated by protoc-gen-go. DO NOT EDIT.
// versions:
// 	protoc-gen-go v1.36.1
// 	protoc        (unknown)
// source: controller/api/resources/managedgroups/v1/managed_group.proto

package managedgroups

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

// ManagedGroup contains all fields related to an ManagedGroup resource
type ManagedGroup struct {
	state protoimpl.MessageState `protogen:"open.v1"`
	// Output only. The ID of the ManagedGroup.
	Id string `protobuf:"bytes,10,opt,name=id,proto3" json:"id,omitempty" class:"public" eventstream:"observation"` // @gotags: `class:"public" eventstream:"observation"`
	// Output only. Scope information for the ManagedGroup.
	Scope *scopes.ScopeInfo `protobuf:"bytes,20,opt,name=scope,proto3" json:"scope,omitempty"`
	// Optional name for identification purposes.
	Name *wrapperspb.StringValue `protobuf:"bytes,30,opt,name=name,proto3" json:"name,omitempty" class:"public"` // @gotags: `class:"public"`
	// Optional user-set description for identification purposes.
	Description *wrapperspb.StringValue `protobuf:"bytes,40,opt,name=description,proto3" json:"description,omitempty" class:"public"` // @gotags: `class:"public"`
	// Output only. The time this resource was created.
	CreatedTime *timestamppb.Timestamp `protobuf:"bytes,50,opt,name=created_time,proto3" json:"created_time,omitempty" class:"public" eventstream:"observation"` // @gotags: `class:"public" eventstream:"observation"`
	// Output only. The time this resource was last updated.
	UpdatedTime *timestamppb.Timestamp `protobuf:"bytes,60,opt,name=updated_time,proto3" json:"updated_time,omitempty" class:"public" eventstream:"observation"` // @gotags: `class:"public" eventstream:"observation"`
	// Version is used in mutation requests, after the initial creation, to ensure this resource has not changed.
	// The mutation will fail if the version does not match the latest known good version.
	Version uint32 `protobuf:"varint,70,opt,name=version,proto3" json:"version,omitempty" class:"public"` // @gotags: `class:"public"`
	// The type of this ManagedGroup.
	Type string `protobuf:"bytes,80,opt,name=type,proto3" json:"type,omitempty" class:"public" eventstream:"observation"` // @gotags: `class:"public" eventstream:"observation"`
	// The ID of the Auth Method that is associated with this ManagedGroup.
	AuthMethodId string `protobuf:"bytes,90,opt,name=auth_method_id,proto3" json:"auth_method_id,omitempty" class:"public" eventstream:"observation"` // @gotags: `class:"public" eventstream:"observation"`
	// Types that are valid to be assigned to Attrs:
	//
	//	*ManagedGroup_Attributes
	//	*ManagedGroup_OidcManagedGroupAttributes
	//	*ManagedGroup_LdapManagedGroupAttributes
	Attrs isManagedGroup_Attrs `protobuf_oneof:"attrs"`
	// Output only. The IDs of the current set of members (accounts) that are associated with this ManagedGroup.
	MemberIds []string `protobuf:"bytes,110,rep,name=member_ids,proto3" json:"member_ids,omitempty" class:"public" eventstream:"observation"` // @gotags: `class:"public" eventstream:"observation"`
	// Output only. The available actions on this resource for this user.
	AuthorizedActions []string `protobuf:"bytes,300,rep,name=authorized_actions,proto3" json:"authorized_actions,omitempty" class:"public"` // @gotags: `class:"public"`
	unknownFields     protoimpl.UnknownFields
	sizeCache         protoimpl.SizeCache
}

func (x *ManagedGroup) Reset() {
	*x = ManagedGroup{}
	mi := &file_controller_api_resources_managedgroups_v1_managed_group_proto_msgTypes[0]
	ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
	ms.StoreMessageInfo(mi)
}

func (x *ManagedGroup) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*ManagedGroup) ProtoMessage() {}

func (x *ManagedGroup) ProtoReflect() protoreflect.Message {
	mi := &file_controller_api_resources_managedgroups_v1_managed_group_proto_msgTypes[0]
	if x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use ManagedGroup.ProtoReflect.Descriptor instead.
func (*ManagedGroup) Descriptor() ([]byte, []int) {
	return file_controller_api_resources_managedgroups_v1_managed_group_proto_rawDescGZIP(), []int{0}
}

func (x *ManagedGroup) GetId() string {
	if x != nil {
		return x.Id
	}
	return ""
}

func (x *ManagedGroup) GetScope() *scopes.ScopeInfo {
	if x != nil {
		return x.Scope
	}
	return nil
}

func (x *ManagedGroup) GetName() *wrapperspb.StringValue {
	if x != nil {
		return x.Name
	}
	return nil
}

func (x *ManagedGroup) GetDescription() *wrapperspb.StringValue {
	if x != nil {
		return x.Description
	}
	return nil
}

func (x *ManagedGroup) GetCreatedTime() *timestamppb.Timestamp {
	if x != nil {
		return x.CreatedTime
	}
	return nil
}

func (x *ManagedGroup) GetUpdatedTime() *timestamppb.Timestamp {
	if x != nil {
		return x.UpdatedTime
	}
	return nil
}

func (x *ManagedGroup) GetVersion() uint32 {
	if x != nil {
		return x.Version
	}
	return 0
}

func (x *ManagedGroup) GetType() string {
	if x != nil {
		return x.Type
	}
	return ""
}

func (x *ManagedGroup) GetAuthMethodId() string {
	if x != nil {
		return x.AuthMethodId
	}
	return ""
}

func (x *ManagedGroup) GetAttrs() isManagedGroup_Attrs {
	if x != nil {
		return x.Attrs
	}
	return nil
}

func (x *ManagedGroup) GetAttributes() *structpb.Struct {
	if x != nil {
		if x, ok := x.Attrs.(*ManagedGroup_Attributes); ok {
			return x.Attributes
		}
	}
	return nil
}

func (x *ManagedGroup) GetOidcManagedGroupAttributes() *OidcManagedGroupAttributes {
	if x != nil {
		if x, ok := x.Attrs.(*ManagedGroup_OidcManagedGroupAttributes); ok {
			return x.OidcManagedGroupAttributes
		}
	}
	return nil
}

func (x *ManagedGroup) GetLdapManagedGroupAttributes() *LdapManagedGroupAttributes {
	if x != nil {
		if x, ok := x.Attrs.(*ManagedGroup_LdapManagedGroupAttributes); ok {
			return x.LdapManagedGroupAttributes
		}
	}
	return nil
}

func (x *ManagedGroup) GetMemberIds() []string {
	if x != nil {
		return x.MemberIds
	}
	return nil
}

func (x *ManagedGroup) GetAuthorizedActions() []string {
	if x != nil {
		return x.AuthorizedActions
	}
	return nil
}

type isManagedGroup_Attrs interface {
	isManagedGroup_Attrs()
}

type ManagedGroup_Attributes struct {
	// The attributes that are applicable for the specific ManagedGroup type.
	Attributes *structpb.Struct `protobuf:"bytes,100,opt,name=attributes,proto3,oneof"`
}

type ManagedGroup_OidcManagedGroupAttributes struct {
	OidcManagedGroupAttributes *OidcManagedGroupAttributes `protobuf:"bytes,101,opt,name=oidc_managed_group_attributes,json=oidcManagedGroupAttributes,proto3,oneof"`
}

type ManagedGroup_LdapManagedGroupAttributes struct {
	LdapManagedGroupAttributes *LdapManagedGroupAttributes `protobuf:"bytes,102,opt,name=ldap_managed_group_attributes,json=ldapManagedGroupAttributes,proto3,oneof"`
}

func (*ManagedGroup_Attributes) isManagedGroup_Attrs() {}

func (*ManagedGroup_OidcManagedGroupAttributes) isManagedGroup_Attrs() {}

func (*ManagedGroup_LdapManagedGroupAttributes) isManagedGroup_Attrs() {}

// Attributes associated only with ManagedGroups with type "oidc".
type OidcManagedGroupAttributes struct {
	state protoimpl.MessageState `protogen:"open.v1"`
	// The boolean expression filter to use to determine membership.
	Filter        string `protobuf:"bytes,10,opt,name=filter,proto3" json:"filter,omitempty" class:"public"` // @gotags: `class:"public"`
	unknownFields protoimpl.UnknownFields
	sizeCache     protoimpl.SizeCache
}

func (x *OidcManagedGroupAttributes) Reset() {
	*x = OidcManagedGroupAttributes{}
	mi := &file_controller_api_resources_managedgroups_v1_managed_group_proto_msgTypes[1]
	ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
	ms.StoreMessageInfo(mi)
}

func (x *OidcManagedGroupAttributes) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*OidcManagedGroupAttributes) ProtoMessage() {}

func (x *OidcManagedGroupAttributes) ProtoReflect() protoreflect.Message {
	mi := &file_controller_api_resources_managedgroups_v1_managed_group_proto_msgTypes[1]
	if x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use OidcManagedGroupAttributes.ProtoReflect.Descriptor instead.
func (*OidcManagedGroupAttributes) Descriptor() ([]byte, []int) {
	return file_controller_api_resources_managedgroups_v1_managed_group_proto_rawDescGZIP(), []int{1}
}

func (x *OidcManagedGroupAttributes) GetFilter() string {
	if x != nil {
		return x.Filter
	}
	return ""
}

// Attributes associated only with ManagedGroups with type "ldap".
type LdapManagedGroupAttributes struct {
	state protoimpl.MessageState `protogen:"open.v1"`
	// The list of groups that make up the ManagedGroup
	GroupNames    []string `protobuf:"bytes,100,rep,name=group_names,proto3" json:"group_names,omitempty" class:"public"` // @gotags: `class:"public"`
	unknownFields protoimpl.UnknownFields
	sizeCache     protoimpl.SizeCache
}

func (x *LdapManagedGroupAttributes) Reset() {
	*x = LdapManagedGroupAttributes{}
	mi := &file_controller_api_resources_managedgroups_v1_managed_group_proto_msgTypes[2]
	ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
	ms.StoreMessageInfo(mi)
}

func (x *LdapManagedGroupAttributes) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*LdapManagedGroupAttributes) ProtoMessage() {}

func (x *LdapManagedGroupAttributes) ProtoReflect() protoreflect.Message {
	mi := &file_controller_api_resources_managedgroups_v1_managed_group_proto_msgTypes[2]
	if x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use LdapManagedGroupAttributes.ProtoReflect.Descriptor instead.
func (*LdapManagedGroupAttributes) Descriptor() ([]byte, []int) {
	return file_controller_api_resources_managedgroups_v1_managed_group_proto_rawDescGZIP(), []int{2}
}

func (x *LdapManagedGroupAttributes) GetGroupNames() []string {
	if x != nil {
		return x.GroupNames
	}
	return nil
}

var File_controller_api_resources_managedgroups_v1_managed_group_proto protoreflect.FileDescriptor

var file_controller_api_resources_managedgroups_v1_managed_group_proto_rawDesc = []byte{
	0x0a, 0x3d, 0x63, 0x6f, 0x6e, 0x74, 0x72, 0x6f, 0x6c, 0x6c, 0x65, 0x72, 0x2f, 0x61, 0x70, 0x69,
	0x2f, 0x72, 0x65, 0x73, 0x6f, 0x75, 0x72, 0x63, 0x65, 0x73, 0x2f, 0x6d, 0x61, 0x6e, 0x61, 0x67,
	0x65, 0x64, 0x67, 0x72, 0x6f, 0x75, 0x70, 0x73, 0x2f, 0x76, 0x31, 0x2f, 0x6d, 0x61, 0x6e, 0x61,
	0x67, 0x65, 0x64, 0x5f, 0x67, 0x72, 0x6f, 0x75, 0x70, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x12,
	0x29, 0x63, 0x6f, 0x6e, 0x74, 0x72, 0x6f, 0x6c, 0x6c, 0x65, 0x72, 0x2e, 0x61, 0x70, 0x69, 0x2e,
	0x72, 0x65, 0x73, 0x6f, 0x75, 0x72, 0x63, 0x65, 0x73, 0x2e, 0x6d, 0x61, 0x6e, 0x61, 0x67, 0x65,
	0x64, 0x67, 0x72, 0x6f, 0x75, 0x70, 0x73, 0x2e, 0x76, 0x31, 0x1a, 0x2e, 0x63, 0x6f, 0x6e, 0x74,
	0x72, 0x6f, 0x6c, 0x6c, 0x65, 0x72, 0x2f, 0x61, 0x70, 0x69, 0x2f, 0x72, 0x65, 0x73, 0x6f, 0x75,
	0x72, 0x63, 0x65, 0x73, 0x2f, 0x73, 0x63, 0x6f, 0x70, 0x65, 0x73, 0x2f, 0x76, 0x31, 0x2f, 0x73,
	0x63, 0x6f, 0x70, 0x65, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x1a, 0x2a, 0x63, 0x6f, 0x6e, 0x74,
	0x72, 0x6f, 0x6c, 0x6c, 0x65, 0x72, 0x2f, 0x63, 0x75, 0x73, 0x74, 0x6f, 0x6d, 0x5f, 0x6f, 0x70,
	0x74, 0x69, 0x6f, 0x6e, 0x73, 0x2f, 0x76, 0x31, 0x2f, 0x6f, 0x70, 0x74, 0x69, 0x6f, 0x6e, 0x73,
	0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x1a, 0x1b, 0x67, 0x6f, 0x6f, 0x67, 0x6c, 0x65, 0x2f, 0x61,
	0x70, 0x69, 0x2f, 0x76, 0x69, 0x73, 0x69, 0x62, 0x69, 0x6c, 0x69, 0x74, 0x79, 0x2e, 0x70, 0x72,
	0x6f, 0x74, 0x6f, 0x1a, 0x1c, 0x67, 0x6f, 0x6f, 0x67, 0x6c, 0x65, 0x2f, 0x70, 0x72, 0x6f, 0x74,
	0x6f, 0x62, 0x75, 0x66, 0x2f, 0x73, 0x74, 0x72, 0x75, 0x63, 0x74, 0x2e, 0x70, 0x72, 0x6f, 0x74,
	0x6f, 0x1a, 0x1f, 0x67, 0x6f, 0x6f, 0x67, 0x6c, 0x65, 0x2f, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x62,
	0x75, 0x66, 0x2f, 0x74, 0x69, 0x6d, 0x65, 0x73, 0x74, 0x61, 0x6d, 0x70, 0x2e, 0x70, 0x72, 0x6f,
	0x74, 0x6f, 0x1a, 0x1e, 0x67, 0x6f, 0x6f, 0x67, 0x6c, 0x65, 0x2f, 0x70, 0x72, 0x6f, 0x74, 0x6f,
	0x62, 0x75, 0x66, 0x2f, 0x77, 0x72, 0x61, 0x70, 0x70, 0x65, 0x72, 0x73, 0x2e, 0x70, 0x72, 0x6f,
	0x74, 0x6f, 0x22, 0xe7, 0x07, 0x0a, 0x0c, 0x4d, 0x61, 0x6e, 0x61, 0x67, 0x65, 0x64, 0x47, 0x72,
	0x6f, 0x75, 0x70, 0x12, 0x0e, 0x0a, 0x02, 0x69, 0x64, 0x18, 0x0a, 0x20, 0x01, 0x28, 0x09, 0x52,
	0x02, 0x69, 0x64, 0x12, 0x43, 0x0a, 0x05, 0x73, 0x63, 0x6f, 0x70, 0x65, 0x18, 0x14, 0x20, 0x01,
	0x28, 0x0b, 0x32, 0x2d, 0x2e, 0x63, 0x6f, 0x6e, 0x74, 0x72, 0x6f, 0x6c, 0x6c, 0x65, 0x72, 0x2e,
	0x61, 0x70, 0x69, 0x2e, 0x72, 0x65, 0x73, 0x6f, 0x75, 0x72, 0x63, 0x65, 0x73, 0x2e, 0x73, 0x63,
	0x6f, 0x70, 0x65, 0x73, 0x2e, 0x76, 0x31, 0x2e, 0x53, 0x63, 0x6f, 0x70, 0x65, 0x49, 0x6e, 0x66,
	0x6f, 0x52, 0x05, 0x73, 0x63, 0x6f, 0x70, 0x65, 0x12, 0x46, 0x0a, 0x04, 0x6e, 0x61, 0x6d, 0x65,
	0x18, 0x1e, 0x20, 0x01, 0x28, 0x0b, 0x32, 0x1c, 0x2e, 0x67, 0x6f, 0x6f, 0x67, 0x6c, 0x65, 0x2e,
	0x70, 0x72, 0x6f, 0x74, 0x6f, 0x62, 0x75, 0x66, 0x2e, 0x53, 0x74, 0x72, 0x69, 0x6e, 0x67, 0x56,
	0x61, 0x6c, 0x75, 0x65, 0x42, 0x14, 0xa0, 0xda, 0x29, 0x01, 0xc2, 0xdd, 0x29, 0x0c, 0x0a, 0x04,
	0x6e, 0x61, 0x6d, 0x65, 0x12, 0x04, 0x4e, 0x61, 0x6d, 0x65, 0x52, 0x04, 0x6e, 0x61, 0x6d, 0x65,
	0x12, 0x62, 0x0a, 0x0b, 0x64, 0x65, 0x73, 0x63, 0x72, 0x69, 0x70, 0x74, 0x69, 0x6f, 0x6e, 0x18,
	0x28, 0x20, 0x01, 0x28, 0x0b, 0x32, 0x1c, 0x2e, 0x67, 0x6f, 0x6f, 0x67, 0x6c, 0x65, 0x2e, 0x70,
	0x72, 0x6f, 0x74, 0x6f, 0x62, 0x75, 0x66, 0x2e, 0x53, 0x74, 0x72, 0x69, 0x6e, 0x67, 0x56, 0x61,
	0x6c, 0x75, 0x65, 0x42, 0x22, 0xa0, 0xda, 0x29, 0x01, 0xc2, 0xdd, 0x29, 0x1a, 0x0a, 0x0b, 0x64,
	0x65, 0x73, 0x63, 0x72, 0x69, 0x70, 0x74, 0x69, 0x6f, 0x6e, 0x12, 0x0b, 0x44, 0x65, 0x73, 0x63,
	0x72, 0x69, 0x70, 0x74, 0x69, 0x6f, 0x6e, 0x52, 0x0b, 0x64, 0x65, 0x73, 0x63, 0x72, 0x69, 0x70,
	0x74, 0x69, 0x6f, 0x6e, 0x12, 0x3e, 0x0a, 0x0c, 0x63, 0x72, 0x65, 0x61, 0x74, 0x65, 0x64, 0x5f,
	0x74, 0x69, 0x6d, 0x65, 0x18, 0x32, 0x20, 0x01, 0x28, 0x0b, 0x32, 0x1a, 0x2e, 0x67, 0x6f, 0x6f,
	0x67, 0x6c, 0x65, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x62, 0x75, 0x66, 0x2e, 0x54, 0x69, 0x6d,
	0x65, 0x73, 0x74, 0x61, 0x6d, 0x70, 0x52, 0x0c, 0x63, 0x72, 0x65, 0x61, 0x74, 0x65, 0x64, 0x5f,
	0x74, 0x69, 0x6d, 0x65, 0x12, 0x3e, 0x0a, 0x0c, 0x75, 0x70, 0x64, 0x61, 0x74, 0x65, 0x64, 0x5f,
	0x74, 0x69, 0x6d, 0x65, 0x18, 0x3c, 0x20, 0x01, 0x28, 0x0b, 0x32, 0x1a, 0x2e, 0x67, 0x6f, 0x6f,
	0x67, 0x6c, 0x65, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x62, 0x75, 0x66, 0x2e, 0x54, 0x69, 0x6d,
	0x65, 0x73, 0x74, 0x61, 0x6d, 0x70, 0x52, 0x0c, 0x75, 0x70, 0x64, 0x61, 0x74, 0x65, 0x64, 0x5f,
	0x74, 0x69, 0x6d, 0x65, 0x12, 0x18, 0x0a, 0x07, 0x76, 0x65, 0x72, 0x73, 0x69, 0x6f, 0x6e, 0x18,
	0x46, 0x20, 0x01, 0x28, 0x0d, 0x52, 0x07, 0x76, 0x65, 0x72, 0x73, 0x69, 0x6f, 0x6e, 0x12, 0x12,
	0x0a, 0x04, 0x74, 0x79, 0x70, 0x65, 0x18, 0x50, 0x20, 0x01, 0x28, 0x09, 0x52, 0x04, 0x74, 0x79,
	0x70, 0x65, 0x12, 0x2c, 0x0a, 0x0e, 0x61, 0x75, 0x74, 0x68, 0x5f, 0x6d, 0x65, 0x74, 0x68, 0x6f,
	0x64, 0x5f, 0x69, 0x64, 0x18, 0x5a, 0x20, 0x01, 0x28, 0x09, 0x42, 0x04, 0xa0, 0xe3, 0x29, 0x01,
	0x52, 0x0e, 0x61, 0x75, 0x74, 0x68, 0x5f, 0x6d, 0x65, 0x74, 0x68, 0x6f, 0x64, 0x5f, 0x69, 0x64,
	0x12, 0x4a, 0x0a, 0x0a, 0x61, 0x74, 0x74, 0x72, 0x69, 0x62, 0x75, 0x74, 0x65, 0x73, 0x18, 0x64,
	0x20, 0x01, 0x28, 0x0b, 0x32, 0x17, 0x2e, 0x67, 0x6f, 0x6f, 0x67, 0x6c, 0x65, 0x2e, 0x70, 0x72,
	0x6f, 0x74, 0x6f, 0x62, 0x75, 0x66, 0x2e, 0x53, 0x74, 0x72, 0x75, 0x63, 0x74, 0x42, 0x0f, 0xa0,
	0xda, 0x29, 0x01, 0x9a, 0xe3, 0x29, 0x07, 0x64, 0x65, 0x66, 0x61, 0x75, 0x6c, 0x74, 0x48, 0x00,
	0x52, 0x0a, 0x61, 0x74, 0x74, 0x72, 0x69, 0x62, 0x75, 0x74, 0x65, 0x73, 0x12, 0xa8, 0x01, 0x0a,
	0x1d, 0x6f, 0x69, 0x64, 0x63, 0x5f, 0x6d, 0x61, 0x6e, 0x61, 0x67, 0x65, 0x64, 0x5f, 0x67, 0x72,
	0x6f, 0x75, 0x70, 0x5f, 0x61, 0x74, 0x74, 0x72, 0x69, 0x62, 0x75, 0x74, 0x65, 0x73, 0x18, 0x65,
	0x20, 0x01, 0x28, 0x0b, 0x32, 0x45, 0x2e, 0x63, 0x6f, 0x6e, 0x74, 0x72, 0x6f, 0x6c, 0x6c, 0x65,
	0x72, 0x2e, 0x61, 0x70, 0x69, 0x2e, 0x72, 0x65, 0x73, 0x6f, 0x75, 0x72, 0x63, 0x65, 0x73, 0x2e,
	0x6d, 0x61, 0x6e, 0x61, 0x67, 0x65, 0x64, 0x67, 0x72, 0x6f, 0x75, 0x70, 0x73, 0x2e, 0x76, 0x31,
	0x2e, 0x4f, 0x69, 0x64, 0x63, 0x4d, 0x61, 0x6e, 0x61, 0x67, 0x65, 0x64, 0x47, 0x72, 0x6f, 0x75,
	0x70, 0x41, 0x74, 0x74, 0x72, 0x69, 0x62, 0x75, 0x74, 0x65, 0x73, 0x42, 0x1c, 0xa0, 0xda, 0x29,
	0x01, 0x9a, 0xe3, 0x29, 0x04, 0x6f, 0x69, 0x64, 0x63, 0xfa, 0xd2, 0xe4, 0x93, 0x02, 0x0a, 0x12,
	0x08, 0x49, 0x4e, 0x54, 0x45, 0x52, 0x4e, 0x41, 0x4c, 0x48, 0x00, 0x52, 0x1a, 0x6f, 0x69, 0x64,
	0x63, 0x4d, 0x61, 0x6e, 0x61, 0x67, 0x65, 0x64, 0x47, 0x72, 0x6f, 0x75, 0x70, 0x41, 0x74, 0x74,
	0x72, 0x69, 0x62, 0x75, 0x74, 0x65, 0x73, 0x12, 0xa8, 0x01, 0x0a, 0x1d, 0x6c, 0x64, 0x61, 0x70,
	0x5f, 0x6d, 0x61, 0x6e, 0x61, 0x67, 0x65, 0x64, 0x5f, 0x67, 0x72, 0x6f, 0x75, 0x70, 0x5f, 0x61,
	0x74, 0x74, 0x72, 0x69, 0x62, 0x75, 0x74, 0x65, 0x73, 0x18, 0x66, 0x20, 0x01, 0x28, 0x0b, 0x32,
	0x45, 0x2e, 0x63, 0x6f, 0x6e, 0x74, 0x72, 0x6f, 0x6c, 0x6c, 0x65, 0x72, 0x2e, 0x61, 0x70, 0x69,
	0x2e, 0x72, 0x65, 0x73, 0x6f, 0x75, 0x72, 0x63, 0x65, 0x73, 0x2e, 0x6d, 0x61, 0x6e, 0x61, 0x67,
	0x65, 0x64, 0x67, 0x72, 0x6f, 0x75, 0x70, 0x73, 0x2e, 0x76, 0x31, 0x2e, 0x4c, 0x64, 0x61, 0x70,
	0x4d, 0x61, 0x6e, 0x61, 0x67, 0x65, 0x64, 0x47, 0x72, 0x6f, 0x75, 0x70, 0x41, 0x74, 0x74, 0x72,
	0x69, 0x62, 0x75, 0x74, 0x65, 0x73, 0x42, 0x1c, 0xa0, 0xda, 0x29, 0x01, 0x9a, 0xe3, 0x29, 0x04,
	0x6c, 0x64, 0x61, 0x70, 0xfa, 0xd2, 0xe4, 0x93, 0x02, 0x0a, 0x12, 0x08, 0x49, 0x4e, 0x54, 0x45,
	0x52, 0x4e, 0x41, 0x4c, 0x48, 0x00, 0x52, 0x1a, 0x6c, 0x64, 0x61, 0x70, 0x4d, 0x61, 0x6e, 0x61,
	0x67, 0x65, 0x64, 0x47, 0x72, 0x6f, 0x75, 0x70, 0x41, 0x74, 0x74, 0x72, 0x69, 0x62, 0x75, 0x74,
	0x65, 0x73, 0x12, 0x1e, 0x0a, 0x0a, 0x6d, 0x65, 0x6d, 0x62, 0x65, 0x72, 0x5f, 0x69, 0x64, 0x73,
	0x18, 0x6e, 0x20, 0x03, 0x28, 0x09, 0x52, 0x0a, 0x6d, 0x65, 0x6d, 0x62, 0x65, 0x72, 0x5f, 0x69,
	0x64, 0x73, 0x12, 0x2f, 0x0a, 0x12, 0x61, 0x75, 0x74, 0x68, 0x6f, 0x72, 0x69, 0x7a, 0x65, 0x64,
	0x5f, 0x61, 0x63, 0x74, 0x69, 0x6f, 0x6e, 0x73, 0x18, 0xac, 0x02, 0x20, 0x03, 0x28, 0x09, 0x52,
	0x12, 0x61, 0x75, 0x74, 0x68, 0x6f, 0x72, 0x69, 0x7a, 0x65, 0x64, 0x5f, 0x61, 0x63, 0x74, 0x69,
	0x6f, 0x6e, 0x73, 0x42, 0x07, 0x0a, 0x05, 0x61, 0x74, 0x74, 0x72, 0x73, 0x22, 0x59, 0x0a, 0x1a,
	0x4f, 0x69, 0x64, 0x63, 0x4d, 0x61, 0x6e, 0x61, 0x67, 0x65, 0x64, 0x47, 0x72, 0x6f, 0x75, 0x70,
	0x41, 0x74, 0x74, 0x72, 0x69, 0x62, 0x75, 0x74, 0x65, 0x73, 0x12, 0x3b, 0x0a, 0x06, 0x66, 0x69,
	0x6c, 0x74, 0x65, 0x72, 0x18, 0x0a, 0x20, 0x01, 0x28, 0x09, 0x42, 0x23, 0xa0, 0xda, 0x29, 0x01,
	0xc2, 0xdd, 0x29, 0x1b, 0x0a, 0x11, 0x61, 0x74, 0x74, 0x72, 0x69, 0x62, 0x75, 0x74, 0x65, 0x73,
	0x2e, 0x66, 0x69, 0x6c, 0x74, 0x65, 0x72, 0x12, 0x06, 0x46, 0x69, 0x6c, 0x74, 0x65, 0x72, 0x52,
	0x06, 0x66, 0x69, 0x6c, 0x74, 0x65, 0x72, 0x22, 0x6c, 0x0a, 0x1a, 0x4c, 0x64, 0x61, 0x70, 0x4d,
	0x61, 0x6e, 0x61, 0x67, 0x65, 0x64, 0x47, 0x72, 0x6f, 0x75, 0x70, 0x41, 0x74, 0x74, 0x72, 0x69,
	0x62, 0x75, 0x74, 0x65, 0x73, 0x12, 0x4e, 0x0a, 0x0b, 0x67, 0x72, 0x6f, 0x75, 0x70, 0x5f, 0x6e,
	0x61, 0x6d, 0x65, 0x73, 0x18, 0x64, 0x20, 0x03, 0x28, 0x09, 0x42, 0x2c, 0xa0, 0xda, 0x29, 0x01,
	0xc2, 0xdd, 0x29, 0x24, 0x0a, 0x16, 0x61, 0x74, 0x74, 0x72, 0x69, 0x62, 0x75, 0x74, 0x65, 0x73,
	0x2e, 0x67, 0x72, 0x6f, 0x75, 0x70, 0x5f, 0x6e, 0x61, 0x6d, 0x65, 0x73, 0x12, 0x0a, 0x47, 0x72,
	0x6f, 0x75, 0x70, 0x4e, 0x61, 0x6d, 0x65, 0x73, 0x52, 0x0b, 0x67, 0x72, 0x6f, 0x75, 0x70, 0x5f,
	0x6e, 0x61, 0x6d, 0x65, 0x73, 0x42, 0x5c, 0x5a, 0x5a, 0x67, 0x69, 0x74, 0x68, 0x75, 0x62, 0x2e,
	0x63, 0x6f, 0x6d, 0x2f, 0x68, 0x61, 0x73, 0x68, 0x69, 0x63, 0x6f, 0x72, 0x70, 0x2f, 0x62, 0x6f,
	0x75, 0x6e, 0x64, 0x61, 0x72, 0x79, 0x2f, 0x73, 0x64, 0x6b, 0x2f, 0x70, 0x62, 0x73, 0x2f, 0x63,
	0x6f, 0x6e, 0x74, 0x72, 0x6f, 0x6c, 0x6c, 0x65, 0x72, 0x2f, 0x61, 0x70, 0x69, 0x2f, 0x72, 0x65,
	0x73, 0x6f, 0x75, 0x72, 0x63, 0x65, 0x73, 0x2f, 0x6d, 0x61, 0x6e, 0x61, 0x67, 0x65, 0x64, 0x67,
	0x72, 0x6f, 0x75, 0x70, 0x73, 0x3b, 0x6d, 0x61, 0x6e, 0x61, 0x67, 0x65, 0x64, 0x67, 0x72, 0x6f,
	0x75, 0x70, 0x73, 0x62, 0x06, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x33,
}

var (
	file_controller_api_resources_managedgroups_v1_managed_group_proto_rawDescOnce sync.Once
	file_controller_api_resources_managedgroups_v1_managed_group_proto_rawDescData = file_controller_api_resources_managedgroups_v1_managed_group_proto_rawDesc
)

func file_controller_api_resources_managedgroups_v1_managed_group_proto_rawDescGZIP() []byte {
	file_controller_api_resources_managedgroups_v1_managed_group_proto_rawDescOnce.Do(func() {
		file_controller_api_resources_managedgroups_v1_managed_group_proto_rawDescData = protoimpl.X.CompressGZIP(file_controller_api_resources_managedgroups_v1_managed_group_proto_rawDescData)
	})
	return file_controller_api_resources_managedgroups_v1_managed_group_proto_rawDescData
}

var file_controller_api_resources_managedgroups_v1_managed_group_proto_msgTypes = make([]protoimpl.MessageInfo, 3)
var file_controller_api_resources_managedgroups_v1_managed_group_proto_goTypes = []any{
	(*ManagedGroup)(nil),               // 0: controller.api.resources.managedgroups.v1.ManagedGroup
	(*OidcManagedGroupAttributes)(nil), // 1: controller.api.resources.managedgroups.v1.OidcManagedGroupAttributes
	(*LdapManagedGroupAttributes)(nil), // 2: controller.api.resources.managedgroups.v1.LdapManagedGroupAttributes
	(*scopes.ScopeInfo)(nil),           // 3: controller.api.resources.scopes.v1.ScopeInfo
	(*wrapperspb.StringValue)(nil),     // 4: google.protobuf.StringValue
	(*timestamppb.Timestamp)(nil),      // 5: google.protobuf.Timestamp
	(*structpb.Struct)(nil),            // 6: google.protobuf.Struct
}
var file_controller_api_resources_managedgroups_v1_managed_group_proto_depIdxs = []int32{
	3, // 0: controller.api.resources.managedgroups.v1.ManagedGroup.scope:type_name -> controller.api.resources.scopes.v1.ScopeInfo
	4, // 1: controller.api.resources.managedgroups.v1.ManagedGroup.name:type_name -> google.protobuf.StringValue
	4, // 2: controller.api.resources.managedgroups.v1.ManagedGroup.description:type_name -> google.protobuf.StringValue
	5, // 3: controller.api.resources.managedgroups.v1.ManagedGroup.created_time:type_name -> google.protobuf.Timestamp
	5, // 4: controller.api.resources.managedgroups.v1.ManagedGroup.updated_time:type_name -> google.protobuf.Timestamp
	6, // 5: controller.api.resources.managedgroups.v1.ManagedGroup.attributes:type_name -> google.protobuf.Struct
	1, // 6: controller.api.resources.managedgroups.v1.ManagedGroup.oidc_managed_group_attributes:type_name -> controller.api.resources.managedgroups.v1.OidcManagedGroupAttributes
	2, // 7: controller.api.resources.managedgroups.v1.ManagedGroup.ldap_managed_group_attributes:type_name -> controller.api.resources.managedgroups.v1.LdapManagedGroupAttributes
	8, // [8:8] is the sub-list for method output_type
	8, // [8:8] is the sub-list for method input_type
	8, // [8:8] is the sub-list for extension type_name
	8, // [8:8] is the sub-list for extension extendee
	0, // [0:8] is the sub-list for field type_name
}

func init() { file_controller_api_resources_managedgroups_v1_managed_group_proto_init() }
func file_controller_api_resources_managedgroups_v1_managed_group_proto_init() {
	if File_controller_api_resources_managedgroups_v1_managed_group_proto != nil {
		return
	}
	file_controller_api_resources_managedgroups_v1_managed_group_proto_msgTypes[0].OneofWrappers = []any{
		(*ManagedGroup_Attributes)(nil),
		(*ManagedGroup_OidcManagedGroupAttributes)(nil),
		(*ManagedGroup_LdapManagedGroupAttributes)(nil),
	}
	type x struct{}
	out := protoimpl.TypeBuilder{
		File: protoimpl.DescBuilder{
			GoPackagePath: reflect.TypeOf(x{}).PkgPath(),
			RawDescriptor: file_controller_api_resources_managedgroups_v1_managed_group_proto_rawDesc,
			NumEnums:      0,
			NumMessages:   3,
			NumExtensions: 0,
			NumServices:   0,
		},
		GoTypes:           file_controller_api_resources_managedgroups_v1_managed_group_proto_goTypes,
		DependencyIndexes: file_controller_api_resources_managedgroups_v1_managed_group_proto_depIdxs,
		MessageInfos:      file_controller_api_resources_managedgroups_v1_managed_group_proto_msgTypes,
	}.Build()
	File_controller_api_resources_managedgroups_v1_managed_group_proto = out.File
	file_controller_api_resources_managedgroups_v1_managed_group_proto_rawDesc = nil
	file_controller_api_resources_managedgroups_v1_managed_group_proto_goTypes = nil
	file_controller_api_resources_managedgroups_v1_managed_group_proto_depIdxs = nil
}
