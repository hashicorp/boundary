// Code generated by protoc-gen-go. DO NOT EDIT.
// versions:
// 	protoc-gen-go v1.26.0
// 	protoc        v3.15.8
// source: controller/storage/iam/store/v1/principal_role.proto

package store

import (
	timestamp "github.com/hashicorp/boundary/internal/db/timestamp"
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

type UserRole struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	// create_time from the RDBMS
	// @inject_tag: `gorm:"default:current_timestamp"`
	CreateTime *timestamp.Timestamp `protobuf:"bytes,1,opt,name=create_time,json=createTime,proto3" json:"create_time,omitempty" gorm:"default:current_timestamp"`
	// role_id is the role of this principal.
	// @inject_tag: gorm:"primary_key"
	RoleId string `protobuf:"bytes,2,opt,name=role_id,json=roleId,proto3" json:"role_id,omitempty" gorm:"primary_key"`
	// principal_id is the public_id of the user (which is the principal)
	// @inject_tag: gorm:"primary_key"
	PrincipalId string `protobuf:"bytes,3,opt,name=principal_id,json=principalId,proto3" json:"principal_id,omitempty" gorm:"primary_key"`
}

func (x *UserRole) Reset() {
	*x = UserRole{}
	if protoimpl.UnsafeEnabled {
		mi := &file_controller_storage_iam_store_v1_principal_role_proto_msgTypes[0]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *UserRole) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*UserRole) ProtoMessage() {}

func (x *UserRole) ProtoReflect() protoreflect.Message {
	mi := &file_controller_storage_iam_store_v1_principal_role_proto_msgTypes[0]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use UserRole.ProtoReflect.Descriptor instead.
func (*UserRole) Descriptor() ([]byte, []int) {
	return file_controller_storage_iam_store_v1_principal_role_proto_rawDescGZIP(), []int{0}
}

func (x *UserRole) GetCreateTime() *timestamp.Timestamp {
	if x != nil {
		return x.CreateTime
	}
	return nil
}

func (x *UserRole) GetRoleId() string {
	if x != nil {
		return x.RoleId
	}
	return ""
}

func (x *UserRole) GetPrincipalId() string {
	if x != nil {
		return x.PrincipalId
	}
	return ""
}

type GroupRole struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	// create_time from the RDBMS
	// @inject_tag: `gorm:"default:current_timestamp"`
	CreateTime *timestamp.Timestamp `protobuf:"bytes,1,opt,name=create_time,json=createTime,proto3" json:"create_time,omitempty" gorm:"default:current_timestamp"`
	// role_id is the role of this principal.
	// @inject_tag: gorm:"primary_key"
	RoleId string `protobuf:"bytes,2,opt,name=role_id,json=roleId,proto3" json:"role_id,omitempty" gorm:"primary_key"`
	// principal_id is the public_id of the group (which is the principal)
	// @inject_tag: gorm:"primary_key"
	PrincipalId string `protobuf:"bytes,3,opt,name=principal_id,json=principalId,proto3" json:"principal_id,omitempty" gorm:"primary_key"`
}

func (x *GroupRole) Reset() {
	*x = GroupRole{}
	if protoimpl.UnsafeEnabled {
		mi := &file_controller_storage_iam_store_v1_principal_role_proto_msgTypes[1]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *GroupRole) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*GroupRole) ProtoMessage() {}

func (x *GroupRole) ProtoReflect() protoreflect.Message {
	mi := &file_controller_storage_iam_store_v1_principal_role_proto_msgTypes[1]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use GroupRole.ProtoReflect.Descriptor instead.
func (*GroupRole) Descriptor() ([]byte, []int) {
	return file_controller_storage_iam_store_v1_principal_role_proto_rawDescGZIP(), []int{1}
}

func (x *GroupRole) GetCreateTime() *timestamp.Timestamp {
	if x != nil {
		return x.CreateTime
	}
	return nil
}

func (x *GroupRole) GetRoleId() string {
	if x != nil {
		return x.RoleId
	}
	return ""
}

func (x *GroupRole) GetPrincipalId() string {
	if x != nil {
		return x.PrincipalId
	}
	return ""
}

type ManagedGroupRole struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	// create_time from the RDBMS
	// @inject_tag: `gorm:"default:current_timestamp"`
	CreateTime *timestamp.Timestamp `protobuf:"bytes,1,opt,name=create_time,json=createTime,proto3" json:"create_time,omitempty" gorm:"default:current_timestamp"`
	// role_id is the role of this principal.
	// @inject_tag: gorm:"primary_key"
	RoleId string `protobuf:"bytes,2,opt,name=role_id,json=roleId,proto3" json:"role_id,omitempty" gorm:"primary_key"`
	// principal_id is the public_id of the managed group (which is the principal)
	// @inject_tag: gorm:"primary_key"
	PrincipalId string `protobuf:"bytes,3,opt,name=principal_id,json=principalId,proto3" json:"principal_id,omitempty" gorm:"primary_key"`
}

func (x *ManagedGroupRole) Reset() {
	*x = ManagedGroupRole{}
	if protoimpl.UnsafeEnabled {
		mi := &file_controller_storage_iam_store_v1_principal_role_proto_msgTypes[2]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *ManagedGroupRole) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*ManagedGroupRole) ProtoMessage() {}

func (x *ManagedGroupRole) ProtoReflect() protoreflect.Message {
	mi := &file_controller_storage_iam_store_v1_principal_role_proto_msgTypes[2]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use ManagedGroupRole.ProtoReflect.Descriptor instead.
func (*ManagedGroupRole) Descriptor() ([]byte, []int) {
	return file_controller_storage_iam_store_v1_principal_role_proto_rawDescGZIP(), []int{2}
}

func (x *ManagedGroupRole) GetCreateTime() *timestamp.Timestamp {
	if x != nil {
		return x.CreateTime
	}
	return nil
}

func (x *ManagedGroupRole) GetRoleId() string {
	if x != nil {
		return x.RoleId
	}
	return ""
}

func (x *ManagedGroupRole) GetPrincipalId() string {
	if x != nil {
		return x.PrincipalId
	}
	return ""
}

type PrincipalRoleView struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	// create_time from the RDBMS
	// @inject_tag: `gorm:"default:current_timestamp"`
	CreateTime *timestamp.Timestamp `protobuf:"bytes,1,opt,name=create_time,json=createTime,proto3" json:"create_time,omitempty" gorm:"default:current_timestamp"`
	// role_id is the role of this principal.
	// @inject_tag: gorm:"primary_key"
	RoleId string `protobuf:"bytes,2,opt,name=role_id,json=roleId,proto3" json:"role_id,omitempty" gorm:"primary_key"`
	// Principal type (User or Group)
	Type string `protobuf:"bytes,3,opt,name=type,proto3" json:"type,omitempty"`
	// @inject_tag: gorm:"primary_key"
	PrincipalId string `protobuf:"bytes,4,opt,name=principal_id,json=principalId,proto3" json:"principal_id,omitempty" gorm:"primary_key"`
	// principal_scope_id of the principal
	// @inject_tag: `gorm:"default:null"`
	PrincipalScopeId string `protobuf:"bytes,5,opt,name=principal_scope_id,json=principalScopeId,proto3" json:"principal_scope_id,omitempty" gorm:"default:null"`
	// role_scope_id of the role
	// @inject_tag: `gorm:"default:null"`
	RoleScopeId string `protobuf:"bytes,6,opt,name=role_scope_id,json=roleScopeId,proto3" json:"role_scope_id,omitempty" gorm:"default:null"`
	// scoped_principal_id of the principal
	// @inject_tag: `gorm:"default:null"`
	ScopedPrincipalId string `protobuf:"bytes,7,opt,name=scoped_principal_id,json=scopedPrincipalId,proto3" json:"scoped_principal_id,omitempty" gorm:"default:null"`
}

func (x *PrincipalRoleView) Reset() {
	*x = PrincipalRoleView{}
	if protoimpl.UnsafeEnabled {
		mi := &file_controller_storage_iam_store_v1_principal_role_proto_msgTypes[3]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *PrincipalRoleView) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*PrincipalRoleView) ProtoMessage() {}

func (x *PrincipalRoleView) ProtoReflect() protoreflect.Message {
	mi := &file_controller_storage_iam_store_v1_principal_role_proto_msgTypes[3]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use PrincipalRoleView.ProtoReflect.Descriptor instead.
func (*PrincipalRoleView) Descriptor() ([]byte, []int) {
	return file_controller_storage_iam_store_v1_principal_role_proto_rawDescGZIP(), []int{3}
}

func (x *PrincipalRoleView) GetCreateTime() *timestamp.Timestamp {
	if x != nil {
		return x.CreateTime
	}
	return nil
}

func (x *PrincipalRoleView) GetRoleId() string {
	if x != nil {
		return x.RoleId
	}
	return ""
}

func (x *PrincipalRoleView) GetType() string {
	if x != nil {
		return x.Type
	}
	return ""
}

func (x *PrincipalRoleView) GetPrincipalId() string {
	if x != nil {
		return x.PrincipalId
	}
	return ""
}

func (x *PrincipalRoleView) GetPrincipalScopeId() string {
	if x != nil {
		return x.PrincipalScopeId
	}
	return ""
}

func (x *PrincipalRoleView) GetRoleScopeId() string {
	if x != nil {
		return x.RoleScopeId
	}
	return ""
}

func (x *PrincipalRoleView) GetScopedPrincipalId() string {
	if x != nil {
		return x.ScopedPrincipalId
	}
	return ""
}

var File_controller_storage_iam_store_v1_principal_role_proto protoreflect.FileDescriptor

var file_controller_storage_iam_store_v1_principal_role_proto_rawDesc = []byte{
	0x0a, 0x34, 0x63, 0x6f, 0x6e, 0x74, 0x72, 0x6f, 0x6c, 0x6c, 0x65, 0x72, 0x2f, 0x73, 0x74, 0x6f,
	0x72, 0x61, 0x67, 0x65, 0x2f, 0x69, 0x61, 0x6d, 0x2f, 0x73, 0x74, 0x6f, 0x72, 0x65, 0x2f, 0x76,
	0x31, 0x2f, 0x70, 0x72, 0x69, 0x6e, 0x63, 0x69, 0x70, 0x61, 0x6c, 0x5f, 0x72, 0x6f, 0x6c, 0x65,
	0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x12, 0x1f, 0x63, 0x6f, 0x6e, 0x74, 0x72, 0x6f, 0x6c, 0x6c,
	0x65, 0x72, 0x2e, 0x73, 0x74, 0x6f, 0x72, 0x61, 0x67, 0x65, 0x2e, 0x69, 0x61, 0x6d, 0x2e, 0x73,
	0x74, 0x6f, 0x72, 0x65, 0x2e, 0x76, 0x31, 0x1a, 0x2f, 0x63, 0x6f, 0x6e, 0x74, 0x72, 0x6f, 0x6c,
	0x6c, 0x65, 0x72, 0x2f, 0x73, 0x74, 0x6f, 0x72, 0x61, 0x67, 0x65, 0x2f, 0x74, 0x69, 0x6d, 0x65,
	0x73, 0x74, 0x61, 0x6d, 0x70, 0x2f, 0x76, 0x31, 0x2f, 0x74, 0x69, 0x6d, 0x65, 0x73, 0x74, 0x61,
	0x6d, 0x70, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x1a, 0x2b, 0x63, 0x6f, 0x6e, 0x74, 0x72, 0x6f,
	0x6c, 0x6c, 0x65, 0x72, 0x2f, 0x73, 0x74, 0x6f, 0x72, 0x61, 0x67, 0x65, 0x2f, 0x69, 0x61, 0x6d,
	0x2f, 0x73, 0x74, 0x6f, 0x72, 0x65, 0x2f, 0x76, 0x31, 0x2f, 0x73, 0x63, 0x6f, 0x70, 0x65, 0x2e,
	0x70, 0x72, 0x6f, 0x74, 0x6f, 0x22, 0x93, 0x01, 0x0a, 0x08, 0x55, 0x73, 0x65, 0x72, 0x52, 0x6f,
	0x6c, 0x65, 0x12, 0x4b, 0x0a, 0x0b, 0x63, 0x72, 0x65, 0x61, 0x74, 0x65, 0x5f, 0x74, 0x69, 0x6d,
	0x65, 0x18, 0x01, 0x20, 0x01, 0x28, 0x0b, 0x32, 0x2a, 0x2e, 0x63, 0x6f, 0x6e, 0x74, 0x72, 0x6f,
	0x6c, 0x6c, 0x65, 0x72, 0x2e, 0x73, 0x74, 0x6f, 0x72, 0x61, 0x67, 0x65, 0x2e, 0x74, 0x69, 0x6d,
	0x65, 0x73, 0x74, 0x61, 0x6d, 0x70, 0x2e, 0x76, 0x31, 0x2e, 0x54, 0x69, 0x6d, 0x65, 0x73, 0x74,
	0x61, 0x6d, 0x70, 0x52, 0x0a, 0x63, 0x72, 0x65, 0x61, 0x74, 0x65, 0x54, 0x69, 0x6d, 0x65, 0x12,
	0x17, 0x0a, 0x07, 0x72, 0x6f, 0x6c, 0x65, 0x5f, 0x69, 0x64, 0x18, 0x02, 0x20, 0x01, 0x28, 0x09,
	0x52, 0x06, 0x72, 0x6f, 0x6c, 0x65, 0x49, 0x64, 0x12, 0x21, 0x0a, 0x0c, 0x70, 0x72, 0x69, 0x6e,
	0x63, 0x69, 0x70, 0x61, 0x6c, 0x5f, 0x69, 0x64, 0x18, 0x03, 0x20, 0x01, 0x28, 0x09, 0x52, 0x0b,
	0x70, 0x72, 0x69, 0x6e, 0x63, 0x69, 0x70, 0x61, 0x6c, 0x49, 0x64, 0x22, 0x94, 0x01, 0x0a, 0x09,
	0x47, 0x72, 0x6f, 0x75, 0x70, 0x52, 0x6f, 0x6c, 0x65, 0x12, 0x4b, 0x0a, 0x0b, 0x63, 0x72, 0x65,
	0x61, 0x74, 0x65, 0x5f, 0x74, 0x69, 0x6d, 0x65, 0x18, 0x01, 0x20, 0x01, 0x28, 0x0b, 0x32, 0x2a,
	0x2e, 0x63, 0x6f, 0x6e, 0x74, 0x72, 0x6f, 0x6c, 0x6c, 0x65, 0x72, 0x2e, 0x73, 0x74, 0x6f, 0x72,
	0x61, 0x67, 0x65, 0x2e, 0x74, 0x69, 0x6d, 0x65, 0x73, 0x74, 0x61, 0x6d, 0x70, 0x2e, 0x76, 0x31,
	0x2e, 0x54, 0x69, 0x6d, 0x65, 0x73, 0x74, 0x61, 0x6d, 0x70, 0x52, 0x0a, 0x63, 0x72, 0x65, 0x61,
	0x74, 0x65, 0x54, 0x69, 0x6d, 0x65, 0x12, 0x17, 0x0a, 0x07, 0x72, 0x6f, 0x6c, 0x65, 0x5f, 0x69,
	0x64, 0x18, 0x02, 0x20, 0x01, 0x28, 0x09, 0x52, 0x06, 0x72, 0x6f, 0x6c, 0x65, 0x49, 0x64, 0x12,
	0x21, 0x0a, 0x0c, 0x70, 0x72, 0x69, 0x6e, 0x63, 0x69, 0x70, 0x61, 0x6c, 0x5f, 0x69, 0x64, 0x18,
	0x03, 0x20, 0x01, 0x28, 0x09, 0x52, 0x0b, 0x70, 0x72, 0x69, 0x6e, 0x63, 0x69, 0x70, 0x61, 0x6c,
	0x49, 0x64, 0x22, 0x9b, 0x01, 0x0a, 0x10, 0x4d, 0x61, 0x6e, 0x61, 0x67, 0x65, 0x64, 0x47, 0x72,
	0x6f, 0x75, 0x70, 0x52, 0x6f, 0x6c, 0x65, 0x12, 0x4b, 0x0a, 0x0b, 0x63, 0x72, 0x65, 0x61, 0x74,
	0x65, 0x5f, 0x74, 0x69, 0x6d, 0x65, 0x18, 0x01, 0x20, 0x01, 0x28, 0x0b, 0x32, 0x2a, 0x2e, 0x63,
	0x6f, 0x6e, 0x74, 0x72, 0x6f, 0x6c, 0x6c, 0x65, 0x72, 0x2e, 0x73, 0x74, 0x6f, 0x72, 0x61, 0x67,
	0x65, 0x2e, 0x74, 0x69, 0x6d, 0x65, 0x73, 0x74, 0x61, 0x6d, 0x70, 0x2e, 0x76, 0x31, 0x2e, 0x54,
	0x69, 0x6d, 0x65, 0x73, 0x74, 0x61, 0x6d, 0x70, 0x52, 0x0a, 0x63, 0x72, 0x65, 0x61, 0x74, 0x65,
	0x54, 0x69, 0x6d, 0x65, 0x12, 0x17, 0x0a, 0x07, 0x72, 0x6f, 0x6c, 0x65, 0x5f, 0x69, 0x64, 0x18,
	0x02, 0x20, 0x01, 0x28, 0x09, 0x52, 0x06, 0x72, 0x6f, 0x6c, 0x65, 0x49, 0x64, 0x12, 0x21, 0x0a,
	0x0c, 0x70, 0x72, 0x69, 0x6e, 0x63, 0x69, 0x70, 0x61, 0x6c, 0x5f, 0x69, 0x64, 0x18, 0x03, 0x20,
	0x01, 0x28, 0x09, 0x52, 0x0b, 0x70, 0x72, 0x69, 0x6e, 0x63, 0x69, 0x70, 0x61, 0x6c, 0x49, 0x64,
	0x22, 0xb2, 0x02, 0x0a, 0x11, 0x50, 0x72, 0x69, 0x6e, 0x63, 0x69, 0x70, 0x61, 0x6c, 0x52, 0x6f,
	0x6c, 0x65, 0x56, 0x69, 0x65, 0x77, 0x12, 0x4b, 0x0a, 0x0b, 0x63, 0x72, 0x65, 0x61, 0x74, 0x65,
	0x5f, 0x74, 0x69, 0x6d, 0x65, 0x18, 0x01, 0x20, 0x01, 0x28, 0x0b, 0x32, 0x2a, 0x2e, 0x63, 0x6f,
	0x6e, 0x74, 0x72, 0x6f, 0x6c, 0x6c, 0x65, 0x72, 0x2e, 0x73, 0x74, 0x6f, 0x72, 0x61, 0x67, 0x65,
	0x2e, 0x74, 0x69, 0x6d, 0x65, 0x73, 0x74, 0x61, 0x6d, 0x70, 0x2e, 0x76, 0x31, 0x2e, 0x54, 0x69,
	0x6d, 0x65, 0x73, 0x74, 0x61, 0x6d, 0x70, 0x52, 0x0a, 0x63, 0x72, 0x65, 0x61, 0x74, 0x65, 0x54,
	0x69, 0x6d, 0x65, 0x12, 0x17, 0x0a, 0x07, 0x72, 0x6f, 0x6c, 0x65, 0x5f, 0x69, 0x64, 0x18, 0x02,
	0x20, 0x01, 0x28, 0x09, 0x52, 0x06, 0x72, 0x6f, 0x6c, 0x65, 0x49, 0x64, 0x12, 0x12, 0x0a, 0x04,
	0x74, 0x79, 0x70, 0x65, 0x18, 0x03, 0x20, 0x01, 0x28, 0x09, 0x52, 0x04, 0x74, 0x79, 0x70, 0x65,
	0x12, 0x21, 0x0a, 0x0c, 0x70, 0x72, 0x69, 0x6e, 0x63, 0x69, 0x70, 0x61, 0x6c, 0x5f, 0x69, 0x64,
	0x18, 0x04, 0x20, 0x01, 0x28, 0x09, 0x52, 0x0b, 0x70, 0x72, 0x69, 0x6e, 0x63, 0x69, 0x70, 0x61,
	0x6c, 0x49, 0x64, 0x12, 0x2c, 0x0a, 0x12, 0x70, 0x72, 0x69, 0x6e, 0x63, 0x69, 0x70, 0x61, 0x6c,
	0x5f, 0x73, 0x63, 0x6f, 0x70, 0x65, 0x5f, 0x69, 0x64, 0x18, 0x05, 0x20, 0x01, 0x28, 0x09, 0x52,
	0x10, 0x70, 0x72, 0x69, 0x6e, 0x63, 0x69, 0x70, 0x61, 0x6c, 0x53, 0x63, 0x6f, 0x70, 0x65, 0x49,
	0x64, 0x12, 0x22, 0x0a, 0x0d, 0x72, 0x6f, 0x6c, 0x65, 0x5f, 0x73, 0x63, 0x6f, 0x70, 0x65, 0x5f,
	0x69, 0x64, 0x18, 0x06, 0x20, 0x01, 0x28, 0x09, 0x52, 0x0b, 0x72, 0x6f, 0x6c, 0x65, 0x53, 0x63,
	0x6f, 0x70, 0x65, 0x49, 0x64, 0x12, 0x2e, 0x0a, 0x13, 0x73, 0x63, 0x6f, 0x70, 0x65, 0x64, 0x5f,
	0x70, 0x72, 0x69, 0x6e, 0x63, 0x69, 0x70, 0x61, 0x6c, 0x5f, 0x69, 0x64, 0x18, 0x07, 0x20, 0x01,
	0x28, 0x09, 0x52, 0x11, 0x73, 0x63, 0x6f, 0x70, 0x65, 0x64, 0x50, 0x72, 0x69, 0x6e, 0x63, 0x69,
	0x70, 0x61, 0x6c, 0x49, 0x64, 0x42, 0x38, 0x5a, 0x36, 0x67, 0x69, 0x74, 0x68, 0x75, 0x62, 0x2e,
	0x63, 0x6f, 0x6d, 0x2f, 0x68, 0x61, 0x73, 0x68, 0x69, 0x63, 0x6f, 0x72, 0x70, 0x2f, 0x62, 0x6f,
	0x75, 0x6e, 0x64, 0x61, 0x72, 0x79, 0x2f, 0x69, 0x6e, 0x74, 0x65, 0x72, 0x6e, 0x61, 0x6c, 0x2f,
	0x69, 0x61, 0x6d, 0x2f, 0x73, 0x74, 0x6f, 0x72, 0x65, 0x3b, 0x73, 0x74, 0x6f, 0x72, 0x65, 0x62,
	0x06, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x33,
}

var (
	file_controller_storage_iam_store_v1_principal_role_proto_rawDescOnce sync.Once
	file_controller_storage_iam_store_v1_principal_role_proto_rawDescData = file_controller_storage_iam_store_v1_principal_role_proto_rawDesc
)

func file_controller_storage_iam_store_v1_principal_role_proto_rawDescGZIP() []byte {
	file_controller_storage_iam_store_v1_principal_role_proto_rawDescOnce.Do(func() {
		file_controller_storage_iam_store_v1_principal_role_proto_rawDescData = protoimpl.X.CompressGZIP(file_controller_storage_iam_store_v1_principal_role_proto_rawDescData)
	})
	return file_controller_storage_iam_store_v1_principal_role_proto_rawDescData
}

var file_controller_storage_iam_store_v1_principal_role_proto_msgTypes = make([]protoimpl.MessageInfo, 4)
var file_controller_storage_iam_store_v1_principal_role_proto_goTypes = []interface{}{
	(*UserRole)(nil),            // 0: controller.storage.iam.store.v1.UserRole
	(*GroupRole)(nil),           // 1: controller.storage.iam.store.v1.GroupRole
	(*ManagedGroupRole)(nil),    // 2: controller.storage.iam.store.v1.ManagedGroupRole
	(*PrincipalRoleView)(nil),   // 3: controller.storage.iam.store.v1.PrincipalRoleView
	(*timestamp.Timestamp)(nil), // 4: controller.storage.timestamp.v1.Timestamp
}
var file_controller_storage_iam_store_v1_principal_role_proto_depIdxs = []int32{
	4, // 0: controller.storage.iam.store.v1.UserRole.create_time:type_name -> controller.storage.timestamp.v1.Timestamp
	4, // 1: controller.storage.iam.store.v1.GroupRole.create_time:type_name -> controller.storage.timestamp.v1.Timestamp
	4, // 2: controller.storage.iam.store.v1.ManagedGroupRole.create_time:type_name -> controller.storage.timestamp.v1.Timestamp
	4, // 3: controller.storage.iam.store.v1.PrincipalRoleView.create_time:type_name -> controller.storage.timestamp.v1.Timestamp
	4, // [4:4] is the sub-list for method output_type
	4, // [4:4] is the sub-list for method input_type
	4, // [4:4] is the sub-list for extension type_name
	4, // [4:4] is the sub-list for extension extendee
	0, // [0:4] is the sub-list for field type_name
}

func init() { file_controller_storage_iam_store_v1_principal_role_proto_init() }
func file_controller_storage_iam_store_v1_principal_role_proto_init() {
	if File_controller_storage_iam_store_v1_principal_role_proto != nil {
		return
	}
	file_controller_storage_iam_store_v1_scope_proto_init()
	if !protoimpl.UnsafeEnabled {
		file_controller_storage_iam_store_v1_principal_role_proto_msgTypes[0].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*UserRole); i {
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
		file_controller_storage_iam_store_v1_principal_role_proto_msgTypes[1].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*GroupRole); i {
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
		file_controller_storage_iam_store_v1_principal_role_proto_msgTypes[2].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*ManagedGroupRole); i {
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
		file_controller_storage_iam_store_v1_principal_role_proto_msgTypes[3].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*PrincipalRoleView); i {
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
			RawDescriptor: file_controller_storage_iam_store_v1_principal_role_proto_rawDesc,
			NumEnums:      0,
			NumMessages:   4,
			NumExtensions: 0,
			NumServices:   0,
		},
		GoTypes:           file_controller_storage_iam_store_v1_principal_role_proto_goTypes,
		DependencyIndexes: file_controller_storage_iam_store_v1_principal_role_proto_depIdxs,
		MessageInfos:      file_controller_storage_iam_store_v1_principal_role_proto_msgTypes,
	}.Build()
	File_controller_storage_iam_store_v1_principal_role_proto = out.File
	file_controller_storage_iam_store_v1_principal_role_proto_rawDesc = nil
	file_controller_storage_iam_store_v1_principal_role_proto_goTypes = nil
	file_controller_storage_iam_store_v1_principal_role_proto_depIdxs = nil
}
