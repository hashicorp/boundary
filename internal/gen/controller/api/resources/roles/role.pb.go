// Code generated by protoc-gen-go. DO NOT EDIT.
// versions:
// 	protoc-gen-go v1.25.0
// 	protoc        v3.12.4
// source: controller/api/resources/roles/v1/role.proto

package roles

import (
	proto "github.com/golang/protobuf/proto"
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

type Principal struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	// The ID of the principal.
	// Output only.
	Id string `protobuf:"bytes,1,opt,name=id,proto3" json:"id,omitempty"`
	// The type of the principal.
	// Output only.
	Type string `protobuf:"bytes,2,opt,name=type,proto3" json:"type,omitempty"`
	// The scope ID of the principal.
	// Output only.
	ScopeId string `protobuf:"bytes,3,opt,name=scope_id,proto3" json:"scope_id,omitempty"`
}

func (x *Principal) Reset() {
	*x = Principal{}
	if protoimpl.UnsafeEnabled {
		mi := &file_controller_api_resources_roles_v1_role_proto_msgTypes[0]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *Principal) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*Principal) ProtoMessage() {}

func (x *Principal) ProtoReflect() protoreflect.Message {
	mi := &file_controller_api_resources_roles_v1_role_proto_msgTypes[0]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use Principal.ProtoReflect.Descriptor instead.
func (*Principal) Descriptor() ([]byte, []int) {
	return file_controller_api_resources_roles_v1_role_proto_rawDescGZIP(), []int{0}
}

func (x *Principal) GetId() string {
	if x != nil {
		return x.Id
	}
	return ""
}

func (x *Principal) GetType() string {
	if x != nil {
		return x.Type
	}
	return ""
}

func (x *Principal) GetScopeId() string {
	if x != nil {
		return x.ScopeId
	}
	return ""
}

type GrantJson struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	// The ID, if set.
	// Output only.
	Id string `protobuf:"bytes,1,opt,name=id,proto3" json:"id,omitempty"`
	// The type, if set.
	// Output only.
	Type string `protobuf:"bytes,2,opt,name=type,proto3" json:"type,omitempty"`
	// The actions.
	// Output only.
	Actions []string `protobuf:"bytes,3,rep,name=actions,proto3" json:"actions,omitempty"`
}

func (x *GrantJson) Reset() {
	*x = GrantJson{}
	if protoimpl.UnsafeEnabled {
		mi := &file_controller_api_resources_roles_v1_role_proto_msgTypes[1]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *GrantJson) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*GrantJson) ProtoMessage() {}

func (x *GrantJson) ProtoReflect() protoreflect.Message {
	mi := &file_controller_api_resources_roles_v1_role_proto_msgTypes[1]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use GrantJson.ProtoReflect.Descriptor instead.
func (*GrantJson) Descriptor() ([]byte, []int) {
	return file_controller_api_resources_roles_v1_role_proto_rawDescGZIP(), []int{1}
}

func (x *GrantJson) GetId() string {
	if x != nil {
		return x.Id
	}
	return ""
}

func (x *GrantJson) GetType() string {
	if x != nil {
		return x.Type
	}
	return ""
}

func (x *GrantJson) GetActions() []string {
	if x != nil {
		return x.Actions
	}
	return nil
}

type Grant struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	// The original user-supplied string.
	// Output only.
	Raw string `protobuf:"bytes,1,opt,name=raw,proto3" json:"raw,omitempty"`
	// The canonically formatted string.
	// Output only.
	Canonical string `protobuf:"bytes,2,opt,name=canonical,proto3" json:"canonical,omitempty"`
	// The JSON representation of the grant.
	// Output only.
	Json *GrantJson `protobuf:"bytes,3,opt,name=json,proto3" json:"json,omitempty"`
}

func (x *Grant) Reset() {
	*x = Grant{}
	if protoimpl.UnsafeEnabled {
		mi := &file_controller_api_resources_roles_v1_role_proto_msgTypes[2]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *Grant) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*Grant) ProtoMessage() {}

func (x *Grant) ProtoReflect() protoreflect.Message {
	mi := &file_controller_api_resources_roles_v1_role_proto_msgTypes[2]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use Grant.ProtoReflect.Descriptor instead.
func (*Grant) Descriptor() ([]byte, []int) {
	return file_controller_api_resources_roles_v1_role_proto_rawDescGZIP(), []int{2}
}

func (x *Grant) GetRaw() string {
	if x != nil {
		return x.Raw
	}
	return ""
}

func (x *Grant) GetCanonical() string {
	if x != nil {
		return x.Canonical
	}
	return ""
}

func (x *Grant) GetJson() *GrantJson {
	if x != nil {
		return x.Json
	}
	return nil
}

// Role contains all fields related to a Role resource
type Role struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	// The ID of the Role
	// Output only.
	Id string `protobuf:"bytes,10,opt,name=id,proto3" json:"id,omitempty"`
	// Scope information for this resource
	// Output only.
	Scope *scopes.ScopeInfo `protobuf:"bytes,20,opt,name=scope,proto3" json:"scope,omitempty"`
	// Optional name for identification purposes
	Name *wrappers.StringValue `protobuf:"bytes,30,opt,name=name,proto3" json:"name,omitempty"`
	// Optional user-set description for identification purposes
	Description *wrappers.StringValue `protobuf:"bytes,40,opt,name=description,proto3" json:"description,omitempty"`
	// The time this resource was created
	// Output only.
	CreatedTime *timestamp.Timestamp `protobuf:"bytes,50,opt,name=created_time,proto3" json:"created_time,omitempty"`
	// The time this resource was last updated.
	// Output only.
	UpdatedTime *timestamp.Timestamp `protobuf:"bytes,60,opt,name=updated_time,proto3" json:"updated_time,omitempty"`
	// The version can be used in subsequent write requests to ensure this resource
	// has not changed and to fail the write if it has.
	// Output only.
	Version uint32 `protobuf:"varint,70,opt,name=version,proto3" json:"version,omitempty"`
	// The scope the grants will apply to. If the role is at the global scope,
	// this can be an org or project. If the role is at an org
	// scope, this can be a project within the org. It is invalid for
	// this to be anything other than the role's scope when the role's scope is
	// a project.
	GrantScopeId *wrappers.StringValue `protobuf:"bytes,80,opt,name=grant_scope_id,proto3" json:"grant_scope_id,omitempty"`
	// The IDs (only) of principals that are assigned to this role.
	// Output only.
	PrincipalIds []string `protobuf:"bytes,90,rep,name=principal_ids,proto3" json:"principal_ids,omitempty"`
	// The principals that are assigned to this role.
	// Output only.
	Principals []*Principal `protobuf:"bytes,100,rep,name=principals,proto3" json:"principals,omitempty"`
	// The grants that this role provides for its principals.
	// Output only.
	GrantStrings []string `protobuf:"bytes,110,rep,name=grant_strings,proto3" json:"grant_strings,omitempty"`
	// The parsed grant information.
	// Output only.
	Grants []*Grant `protobuf:"bytes,120,rep,name=grants,proto3" json:"grants,omitempty"`
}

func (x *Role) Reset() {
	*x = Role{}
	if protoimpl.UnsafeEnabled {
		mi := &file_controller_api_resources_roles_v1_role_proto_msgTypes[3]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *Role) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*Role) ProtoMessage() {}

func (x *Role) ProtoReflect() protoreflect.Message {
	mi := &file_controller_api_resources_roles_v1_role_proto_msgTypes[3]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use Role.ProtoReflect.Descriptor instead.
func (*Role) Descriptor() ([]byte, []int) {
	return file_controller_api_resources_roles_v1_role_proto_rawDescGZIP(), []int{3}
}

func (x *Role) GetId() string {
	if x != nil {
		return x.Id
	}
	return ""
}

func (x *Role) GetScope() *scopes.ScopeInfo {
	if x != nil {
		return x.Scope
	}
	return nil
}

func (x *Role) GetName() *wrappers.StringValue {
	if x != nil {
		return x.Name
	}
	return nil
}

func (x *Role) GetDescription() *wrappers.StringValue {
	if x != nil {
		return x.Description
	}
	return nil
}

func (x *Role) GetCreatedTime() *timestamp.Timestamp {
	if x != nil {
		return x.CreatedTime
	}
	return nil
}

func (x *Role) GetUpdatedTime() *timestamp.Timestamp {
	if x != nil {
		return x.UpdatedTime
	}
	return nil
}

func (x *Role) GetVersion() uint32 {
	if x != nil {
		return x.Version
	}
	return 0
}

func (x *Role) GetGrantScopeId() *wrappers.StringValue {
	if x != nil {
		return x.GrantScopeId
	}
	return nil
}

func (x *Role) GetPrincipalIds() []string {
	if x != nil {
		return x.PrincipalIds
	}
	return nil
}

func (x *Role) GetPrincipals() []*Principal {
	if x != nil {
		return x.Principals
	}
	return nil
}

func (x *Role) GetGrantStrings() []string {
	if x != nil {
		return x.GrantStrings
	}
	return nil
}

func (x *Role) GetGrants() []*Grant {
	if x != nil {
		return x.Grants
	}
	return nil
}

var File_controller_api_resources_roles_v1_role_proto protoreflect.FileDescriptor

var file_controller_api_resources_roles_v1_role_proto_rawDesc = []byte{
	0x0a, 0x2c, 0x63, 0x6f, 0x6e, 0x74, 0x72, 0x6f, 0x6c, 0x6c, 0x65, 0x72, 0x2f, 0x61, 0x70, 0x69,
	0x2f, 0x72, 0x65, 0x73, 0x6f, 0x75, 0x72, 0x63, 0x65, 0x73, 0x2f, 0x72, 0x6f, 0x6c, 0x65, 0x73,
	0x2f, 0x76, 0x31, 0x2f, 0x72, 0x6f, 0x6c, 0x65, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x12, 0x21,
	0x63, 0x6f, 0x6e, 0x74, 0x72, 0x6f, 0x6c, 0x6c, 0x65, 0x72, 0x2e, 0x61, 0x70, 0x69, 0x2e, 0x72,
	0x65, 0x73, 0x6f, 0x75, 0x72, 0x63, 0x65, 0x73, 0x2e, 0x72, 0x6f, 0x6c, 0x65, 0x73, 0x2e, 0x76,
	0x31, 0x1a, 0x1f, 0x67, 0x6f, 0x6f, 0x67, 0x6c, 0x65, 0x2f, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x62,
	0x75, 0x66, 0x2f, 0x74, 0x69, 0x6d, 0x65, 0x73, 0x74, 0x61, 0x6d, 0x70, 0x2e, 0x70, 0x72, 0x6f,
	0x74, 0x6f, 0x1a, 0x1e, 0x67, 0x6f, 0x6f, 0x67, 0x6c, 0x65, 0x2f, 0x70, 0x72, 0x6f, 0x74, 0x6f,
	0x62, 0x75, 0x66, 0x2f, 0x77, 0x72, 0x61, 0x70, 0x70, 0x65, 0x72, 0x73, 0x2e, 0x70, 0x72, 0x6f,
	0x74, 0x6f, 0x1a, 0x2e, 0x63, 0x6f, 0x6e, 0x74, 0x72, 0x6f, 0x6c, 0x6c, 0x65, 0x72, 0x2f, 0x61,
	0x70, 0x69, 0x2f, 0x72, 0x65, 0x73, 0x6f, 0x75, 0x72, 0x63, 0x65, 0x73, 0x2f, 0x73, 0x63, 0x6f,
	0x70, 0x65, 0x73, 0x2f, 0x76, 0x31, 0x2f, 0x73, 0x63, 0x6f, 0x70, 0x65, 0x2e, 0x70, 0x72, 0x6f,
	0x74, 0x6f, 0x1a, 0x2a, 0x63, 0x6f, 0x6e, 0x74, 0x72, 0x6f, 0x6c, 0x6c, 0x65, 0x72, 0x2f, 0x63,
	0x75, 0x73, 0x74, 0x6f, 0x6d, 0x5f, 0x6f, 0x70, 0x74, 0x69, 0x6f, 0x6e, 0x73, 0x2f, 0x76, 0x31,
	0x2f, 0x6f, 0x70, 0x74, 0x69, 0x6f, 0x6e, 0x73, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x22, 0x4b,
	0x0a, 0x09, 0x50, 0x72, 0x69, 0x6e, 0x63, 0x69, 0x70, 0x61, 0x6c, 0x12, 0x0e, 0x0a, 0x02, 0x69,
	0x64, 0x18, 0x01, 0x20, 0x01, 0x28, 0x09, 0x52, 0x02, 0x69, 0x64, 0x12, 0x12, 0x0a, 0x04, 0x74,
	0x79, 0x70, 0x65, 0x18, 0x02, 0x20, 0x01, 0x28, 0x09, 0x52, 0x04, 0x74, 0x79, 0x70, 0x65, 0x12,
	0x1a, 0x0a, 0x08, 0x73, 0x63, 0x6f, 0x70, 0x65, 0x5f, 0x69, 0x64, 0x18, 0x03, 0x20, 0x01, 0x28,
	0x09, 0x52, 0x08, 0x73, 0x63, 0x6f, 0x70, 0x65, 0x5f, 0x69, 0x64, 0x22, 0x49, 0x0a, 0x09, 0x47,
	0x72, 0x61, 0x6e, 0x74, 0x4a, 0x73, 0x6f, 0x6e, 0x12, 0x0e, 0x0a, 0x02, 0x69, 0x64, 0x18, 0x01,
	0x20, 0x01, 0x28, 0x09, 0x52, 0x02, 0x69, 0x64, 0x12, 0x12, 0x0a, 0x04, 0x74, 0x79, 0x70, 0x65,
	0x18, 0x02, 0x20, 0x01, 0x28, 0x09, 0x52, 0x04, 0x74, 0x79, 0x70, 0x65, 0x12, 0x18, 0x0a, 0x07,
	0x61, 0x63, 0x74, 0x69, 0x6f, 0x6e, 0x73, 0x18, 0x03, 0x20, 0x03, 0x28, 0x09, 0x52, 0x07, 0x61,
	0x63, 0x74, 0x69, 0x6f, 0x6e, 0x73, 0x22, 0x79, 0x0a, 0x05, 0x47, 0x72, 0x61, 0x6e, 0x74, 0x12,
	0x10, 0x0a, 0x03, 0x72, 0x61, 0x77, 0x18, 0x01, 0x20, 0x01, 0x28, 0x09, 0x52, 0x03, 0x72, 0x61,
	0x77, 0x12, 0x1c, 0x0a, 0x09, 0x63, 0x61, 0x6e, 0x6f, 0x6e, 0x69, 0x63, 0x61, 0x6c, 0x18, 0x02,
	0x20, 0x01, 0x28, 0x09, 0x52, 0x09, 0x63, 0x61, 0x6e, 0x6f, 0x6e, 0x69, 0x63, 0x61, 0x6c, 0x12,
	0x40, 0x0a, 0x04, 0x6a, 0x73, 0x6f, 0x6e, 0x18, 0x03, 0x20, 0x01, 0x28, 0x0b, 0x32, 0x2c, 0x2e,
	0x63, 0x6f, 0x6e, 0x74, 0x72, 0x6f, 0x6c, 0x6c, 0x65, 0x72, 0x2e, 0x61, 0x70, 0x69, 0x2e, 0x72,
	0x65, 0x73, 0x6f, 0x75, 0x72, 0x63, 0x65, 0x73, 0x2e, 0x72, 0x6f, 0x6c, 0x65, 0x73, 0x2e, 0x76,
	0x31, 0x2e, 0x47, 0x72, 0x61, 0x6e, 0x74, 0x4a, 0x73, 0x6f, 0x6e, 0x52, 0x04, 0x6a, 0x73, 0x6f,
	0x6e, 0x22, 0xeb, 0x05, 0x0a, 0x04, 0x52, 0x6f, 0x6c, 0x65, 0x12, 0x0e, 0x0a, 0x02, 0x69, 0x64,
	0x18, 0x0a, 0x20, 0x01, 0x28, 0x09, 0x52, 0x02, 0x69, 0x64, 0x12, 0x43, 0x0a, 0x05, 0x73, 0x63,
	0x6f, 0x70, 0x65, 0x18, 0x14, 0x20, 0x01, 0x28, 0x0b, 0x32, 0x2d, 0x2e, 0x63, 0x6f, 0x6e, 0x74,
	0x72, 0x6f, 0x6c, 0x6c, 0x65, 0x72, 0x2e, 0x61, 0x70, 0x69, 0x2e, 0x72, 0x65, 0x73, 0x6f, 0x75,
	0x72, 0x63, 0x65, 0x73, 0x2e, 0x73, 0x63, 0x6f, 0x70, 0x65, 0x73, 0x2e, 0x76, 0x31, 0x2e, 0x53,
	0x63, 0x6f, 0x70, 0x65, 0x49, 0x6e, 0x66, 0x6f, 0x52, 0x05, 0x73, 0x63, 0x6f, 0x70, 0x65, 0x12,
	0x46, 0x0a, 0x04, 0x6e, 0x61, 0x6d, 0x65, 0x18, 0x1e, 0x20, 0x01, 0x28, 0x0b, 0x32, 0x1c, 0x2e,
	0x67, 0x6f, 0x6f, 0x67, 0x6c, 0x65, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x62, 0x75, 0x66, 0x2e,
	0x53, 0x74, 0x72, 0x69, 0x6e, 0x67, 0x56, 0x61, 0x6c, 0x75, 0x65, 0x42, 0x14, 0xa0, 0xda, 0x29,
	0x01, 0xc2, 0xdd, 0x29, 0x0c, 0x0a, 0x04, 0x6e, 0x61, 0x6d, 0x65, 0x12, 0x04, 0x6e, 0x61, 0x6d,
	0x65, 0x52, 0x04, 0x6e, 0x61, 0x6d, 0x65, 0x12, 0x62, 0x0a, 0x0b, 0x64, 0x65, 0x73, 0x63, 0x72,
	0x69, 0x70, 0x74, 0x69, 0x6f, 0x6e, 0x18, 0x28, 0x20, 0x01, 0x28, 0x0b, 0x32, 0x1c, 0x2e, 0x67,
	0x6f, 0x6f, 0x67, 0x6c, 0x65, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x62, 0x75, 0x66, 0x2e, 0x53,
	0x74, 0x72, 0x69, 0x6e, 0x67, 0x56, 0x61, 0x6c, 0x75, 0x65, 0x42, 0x22, 0xa0, 0xda, 0x29, 0x01,
	0xc2, 0xdd, 0x29, 0x1a, 0x0a, 0x0b, 0x64, 0x65, 0x73, 0x63, 0x72, 0x69, 0x70, 0x74, 0x69, 0x6f,
	0x6e, 0x12, 0x0b, 0x64, 0x65, 0x73, 0x63, 0x72, 0x69, 0x70, 0x74, 0x69, 0x6f, 0x6e, 0x52, 0x0b,
	0x64, 0x65, 0x73, 0x63, 0x72, 0x69, 0x70, 0x74, 0x69, 0x6f, 0x6e, 0x12, 0x3e, 0x0a, 0x0c, 0x63,
	0x72, 0x65, 0x61, 0x74, 0x65, 0x64, 0x5f, 0x74, 0x69, 0x6d, 0x65, 0x18, 0x32, 0x20, 0x01, 0x28,
	0x0b, 0x32, 0x1a, 0x2e, 0x67, 0x6f, 0x6f, 0x67, 0x6c, 0x65, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f,
	0x62, 0x75, 0x66, 0x2e, 0x54, 0x69, 0x6d, 0x65, 0x73, 0x74, 0x61, 0x6d, 0x70, 0x52, 0x0c, 0x63,
	0x72, 0x65, 0x61, 0x74, 0x65, 0x64, 0x5f, 0x74, 0x69, 0x6d, 0x65, 0x12, 0x3e, 0x0a, 0x0c, 0x75,
	0x70, 0x64, 0x61, 0x74, 0x65, 0x64, 0x5f, 0x74, 0x69, 0x6d, 0x65, 0x18, 0x3c, 0x20, 0x01, 0x28,
	0x0b, 0x32, 0x1a, 0x2e, 0x67, 0x6f, 0x6f, 0x67, 0x6c, 0x65, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f,
	0x62, 0x75, 0x66, 0x2e, 0x54, 0x69, 0x6d, 0x65, 0x73, 0x74, 0x61, 0x6d, 0x70, 0x52, 0x0c, 0x75,
	0x70, 0x64, 0x61, 0x74, 0x65, 0x64, 0x5f, 0x74, 0x69, 0x6d, 0x65, 0x12, 0x18, 0x0a, 0x07, 0x76,
	0x65, 0x72, 0x73, 0x69, 0x6f, 0x6e, 0x18, 0x46, 0x20, 0x01, 0x28, 0x0d, 0x52, 0x07, 0x76, 0x65,
	0x72, 0x73, 0x69, 0x6f, 0x6e, 0x12, 0x6c, 0x0a, 0x0e, 0x67, 0x72, 0x61, 0x6e, 0x74, 0x5f, 0x73,
	0x63, 0x6f, 0x70, 0x65, 0x5f, 0x69, 0x64, 0x18, 0x50, 0x20, 0x01, 0x28, 0x0b, 0x32, 0x1c, 0x2e,
	0x67, 0x6f, 0x6f, 0x67, 0x6c, 0x65, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x62, 0x75, 0x66, 0x2e,
	0x53, 0x74, 0x72, 0x69, 0x6e, 0x67, 0x56, 0x61, 0x6c, 0x75, 0x65, 0x42, 0x26, 0xa0, 0xda, 0x29,
	0x01, 0xc2, 0xdd, 0x29, 0x1e, 0x0a, 0x0e, 0x67, 0x72, 0x61, 0x6e, 0x74, 0x5f, 0x73, 0x63, 0x6f,
	0x70, 0x65, 0x5f, 0x69, 0x64, 0x12, 0x0c, 0x47, 0x72, 0x61, 0x6e, 0x74, 0x53, 0x63, 0x6f, 0x70,
	0x65, 0x49, 0x64, 0x52, 0x0e, 0x67, 0x72, 0x61, 0x6e, 0x74, 0x5f, 0x73, 0x63, 0x6f, 0x70, 0x65,
	0x5f, 0x69, 0x64, 0x12, 0x24, 0x0a, 0x0d, 0x70, 0x72, 0x69, 0x6e, 0x63, 0x69, 0x70, 0x61, 0x6c,
	0x5f, 0x69, 0x64, 0x73, 0x18, 0x5a, 0x20, 0x03, 0x28, 0x09, 0x52, 0x0d, 0x70, 0x72, 0x69, 0x6e,
	0x63, 0x69, 0x70, 0x61, 0x6c, 0x5f, 0x69, 0x64, 0x73, 0x12, 0x4c, 0x0a, 0x0a, 0x70, 0x72, 0x69,
	0x6e, 0x63, 0x69, 0x70, 0x61, 0x6c, 0x73, 0x18, 0x64, 0x20, 0x03, 0x28, 0x0b, 0x32, 0x2c, 0x2e,
	0x63, 0x6f, 0x6e, 0x74, 0x72, 0x6f, 0x6c, 0x6c, 0x65, 0x72, 0x2e, 0x61, 0x70, 0x69, 0x2e, 0x72,
	0x65, 0x73, 0x6f, 0x75, 0x72, 0x63, 0x65, 0x73, 0x2e, 0x72, 0x6f, 0x6c, 0x65, 0x73, 0x2e, 0x76,
	0x31, 0x2e, 0x50, 0x72, 0x69, 0x6e, 0x63, 0x69, 0x70, 0x61, 0x6c, 0x52, 0x0a, 0x70, 0x72, 0x69,
	0x6e, 0x63, 0x69, 0x70, 0x61, 0x6c, 0x73, 0x12, 0x24, 0x0a, 0x0d, 0x67, 0x72, 0x61, 0x6e, 0x74,
	0x5f, 0x73, 0x74, 0x72, 0x69, 0x6e, 0x67, 0x73, 0x18, 0x6e, 0x20, 0x03, 0x28, 0x09, 0x52, 0x0d,
	0x67, 0x72, 0x61, 0x6e, 0x74, 0x5f, 0x73, 0x74, 0x72, 0x69, 0x6e, 0x67, 0x73, 0x12, 0x40, 0x0a,
	0x06, 0x67, 0x72, 0x61, 0x6e, 0x74, 0x73, 0x18, 0x78, 0x20, 0x03, 0x28, 0x0b, 0x32, 0x28, 0x2e,
	0x63, 0x6f, 0x6e, 0x74, 0x72, 0x6f, 0x6c, 0x6c, 0x65, 0x72, 0x2e, 0x61, 0x70, 0x69, 0x2e, 0x72,
	0x65, 0x73, 0x6f, 0x75, 0x72, 0x63, 0x65, 0x73, 0x2e, 0x72, 0x6f, 0x6c, 0x65, 0x73, 0x2e, 0x76,
	0x31, 0x2e, 0x47, 0x72, 0x61, 0x6e, 0x74, 0x52, 0x06, 0x67, 0x72, 0x61, 0x6e, 0x74, 0x73, 0x42,
	0x51, 0x5a, 0x4f, 0x67, 0x69, 0x74, 0x68, 0x75, 0x62, 0x2e, 0x63, 0x6f, 0x6d, 0x2f, 0x68, 0x61,
	0x73, 0x68, 0x69, 0x63, 0x6f, 0x72, 0x70, 0x2f, 0x62, 0x6f, 0x75, 0x6e, 0x64, 0x61, 0x72, 0x79,
	0x2f, 0x69, 0x6e, 0x74, 0x65, 0x72, 0x6e, 0x61, 0x6c, 0x2f, 0x67, 0x65, 0x6e, 0x2f, 0x63, 0x6f,
	0x6e, 0x74, 0x72, 0x6f, 0x6c, 0x6c, 0x65, 0x72, 0x2f, 0x61, 0x70, 0x69, 0x2f, 0x72, 0x65, 0x73,
	0x6f, 0x75, 0x72, 0x63, 0x65, 0x73, 0x2f, 0x72, 0x6f, 0x6c, 0x65, 0x73, 0x3b, 0x72, 0x6f, 0x6c,
	0x65, 0x73, 0x62, 0x06, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x33,
}

var (
	file_controller_api_resources_roles_v1_role_proto_rawDescOnce sync.Once
	file_controller_api_resources_roles_v1_role_proto_rawDescData = file_controller_api_resources_roles_v1_role_proto_rawDesc
)

func file_controller_api_resources_roles_v1_role_proto_rawDescGZIP() []byte {
	file_controller_api_resources_roles_v1_role_proto_rawDescOnce.Do(func() {
		file_controller_api_resources_roles_v1_role_proto_rawDescData = protoimpl.X.CompressGZIP(file_controller_api_resources_roles_v1_role_proto_rawDescData)
	})
	return file_controller_api_resources_roles_v1_role_proto_rawDescData
}

var file_controller_api_resources_roles_v1_role_proto_msgTypes = make([]protoimpl.MessageInfo, 4)
var file_controller_api_resources_roles_v1_role_proto_goTypes = []interface{}{
	(*Principal)(nil),            // 0: controller.api.resources.roles.v1.Principal
	(*GrantJson)(nil),            // 1: controller.api.resources.roles.v1.GrantJson
	(*Grant)(nil),                // 2: controller.api.resources.roles.v1.Grant
	(*Role)(nil),                 // 3: controller.api.resources.roles.v1.Role
	(*scopes.ScopeInfo)(nil),     // 4: controller.api.resources.scopes.v1.ScopeInfo
	(*wrappers.StringValue)(nil), // 5: google.protobuf.StringValue
	(*timestamp.Timestamp)(nil),  // 6: google.protobuf.Timestamp
}
var file_controller_api_resources_roles_v1_role_proto_depIdxs = []int32{
	1, // 0: controller.api.resources.roles.v1.Grant.json:type_name -> controller.api.resources.roles.v1.GrantJson
	4, // 1: controller.api.resources.roles.v1.Role.scope:type_name -> controller.api.resources.scopes.v1.ScopeInfo
	5, // 2: controller.api.resources.roles.v1.Role.name:type_name -> google.protobuf.StringValue
	5, // 3: controller.api.resources.roles.v1.Role.description:type_name -> google.protobuf.StringValue
	6, // 4: controller.api.resources.roles.v1.Role.created_time:type_name -> google.protobuf.Timestamp
	6, // 5: controller.api.resources.roles.v1.Role.updated_time:type_name -> google.protobuf.Timestamp
	5, // 6: controller.api.resources.roles.v1.Role.grant_scope_id:type_name -> google.protobuf.StringValue
	0, // 7: controller.api.resources.roles.v1.Role.principals:type_name -> controller.api.resources.roles.v1.Principal
	2, // 8: controller.api.resources.roles.v1.Role.grants:type_name -> controller.api.resources.roles.v1.Grant
	9, // [9:9] is the sub-list for method output_type
	9, // [9:9] is the sub-list for method input_type
	9, // [9:9] is the sub-list for extension type_name
	9, // [9:9] is the sub-list for extension extendee
	0, // [0:9] is the sub-list for field type_name
}

func init() { file_controller_api_resources_roles_v1_role_proto_init() }
func file_controller_api_resources_roles_v1_role_proto_init() {
	if File_controller_api_resources_roles_v1_role_proto != nil {
		return
	}
	if !protoimpl.UnsafeEnabled {
		file_controller_api_resources_roles_v1_role_proto_msgTypes[0].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*Principal); i {
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
		file_controller_api_resources_roles_v1_role_proto_msgTypes[1].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*GrantJson); i {
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
		file_controller_api_resources_roles_v1_role_proto_msgTypes[2].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*Grant); i {
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
		file_controller_api_resources_roles_v1_role_proto_msgTypes[3].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*Role); i {
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
			RawDescriptor: file_controller_api_resources_roles_v1_role_proto_rawDesc,
			NumEnums:      0,
			NumMessages:   4,
			NumExtensions: 0,
			NumServices:   0,
		},
		GoTypes:           file_controller_api_resources_roles_v1_role_proto_goTypes,
		DependencyIndexes: file_controller_api_resources_roles_v1_role_proto_depIdxs,
		MessageInfos:      file_controller_api_resources_roles_v1_role_proto_msgTypes,
	}.Build()
	File_controller_api_resources_roles_v1_role_proto = out.File
	file_controller_api_resources_roles_v1_role_proto_rawDesc = nil
	file_controller_api_resources_roles_v1_role_proto_goTypes = nil
	file_controller_api_resources_roles_v1_role_proto_depIdxs = nil
}
