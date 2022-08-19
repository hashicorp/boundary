// Code generated by protoc-gen-go. DO NOT EDIT.
// versions:
// 	protoc-gen-go v1.28.1
// 	protoc        (unknown)
// source: controller/api/services/v1/scope_service.proto

package services

import (
	_ "github.com/grpc-ecosystem/grpc-gateway/v2/protoc-gen-openapiv2/options"
	scopes "github.com/hashicorp/boundary/sdk/pbs/controller/api/resources/scopes"
	_ "google.golang.org/genproto/googleapis/api/annotations"
	protoreflect "google.golang.org/protobuf/reflect/protoreflect"
	protoimpl "google.golang.org/protobuf/runtime/protoimpl"
	fieldmaskpb "google.golang.org/protobuf/types/known/fieldmaskpb"
	reflect "reflect"
	sync "sync"
)

const (
	// Verify that this generated code is sufficiently up-to-date.
	_ = protoimpl.EnforceVersion(20 - protoimpl.MinVersion)
	// Verify that runtime/protoimpl is sufficiently up-to-date.
	_ = protoimpl.EnforceVersion(protoimpl.MaxVersion - 20)
)

type GetScopeRequest struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	Id string `protobuf:"bytes,1,opt,name=id,proto3" json:"id,omitempty"`
}

func (x *GetScopeRequest) Reset() {
	*x = GetScopeRequest{}
	if protoimpl.UnsafeEnabled {
		mi := &file_controller_api_services_v1_scope_service_proto_msgTypes[0]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *GetScopeRequest) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*GetScopeRequest) ProtoMessage() {}

func (x *GetScopeRequest) ProtoReflect() protoreflect.Message {
	mi := &file_controller_api_services_v1_scope_service_proto_msgTypes[0]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use GetScopeRequest.ProtoReflect.Descriptor instead.
func (*GetScopeRequest) Descriptor() ([]byte, []int) {
	return file_controller_api_services_v1_scope_service_proto_rawDescGZIP(), []int{0}
}

func (x *GetScopeRequest) GetId() string {
	if x != nil {
		return x.Id
	}
	return ""
}

type GetScopeResponse struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	Item *scopes.Scope `protobuf:"bytes,1,opt,name=item,proto3" json:"item,omitempty"`
}

func (x *GetScopeResponse) Reset() {
	*x = GetScopeResponse{}
	if protoimpl.UnsafeEnabled {
		mi := &file_controller_api_services_v1_scope_service_proto_msgTypes[1]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *GetScopeResponse) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*GetScopeResponse) ProtoMessage() {}

func (x *GetScopeResponse) ProtoReflect() protoreflect.Message {
	mi := &file_controller_api_services_v1_scope_service_proto_msgTypes[1]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use GetScopeResponse.ProtoReflect.Descriptor instead.
func (*GetScopeResponse) Descriptor() ([]byte, []int) {
	return file_controller_api_services_v1_scope_service_proto_rawDescGZIP(), []int{1}
}

func (x *GetScopeResponse) GetItem() *scopes.Scope {
	if x != nil {
		return x.Item
	}
	return nil
}

type ListScopesRequest struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	ScopeId   string `protobuf:"bytes,1,opt,name=scope_id,json=scopeId,proto3" json:"scope_id,omitempty"`
	Recursive bool   `protobuf:"varint,20,opt,name=recursive,proto3" json:"recursive,omitempty"`
	Filter    string `protobuf:"bytes,30,opt,name=filter,proto3" json:"filter,omitempty"`
}

func (x *ListScopesRequest) Reset() {
	*x = ListScopesRequest{}
	if protoimpl.UnsafeEnabled {
		mi := &file_controller_api_services_v1_scope_service_proto_msgTypes[2]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *ListScopesRequest) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*ListScopesRequest) ProtoMessage() {}

func (x *ListScopesRequest) ProtoReflect() protoreflect.Message {
	mi := &file_controller_api_services_v1_scope_service_proto_msgTypes[2]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use ListScopesRequest.ProtoReflect.Descriptor instead.
func (*ListScopesRequest) Descriptor() ([]byte, []int) {
	return file_controller_api_services_v1_scope_service_proto_rawDescGZIP(), []int{2}
}

func (x *ListScopesRequest) GetScopeId() string {
	if x != nil {
		return x.ScopeId
	}
	return ""
}

func (x *ListScopesRequest) GetRecursive() bool {
	if x != nil {
		return x.Recursive
	}
	return false
}

func (x *ListScopesRequest) GetFilter() string {
	if x != nil {
		return x.Filter
	}
	return ""
}

type ListScopesResponse struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	Items []*scopes.Scope `protobuf:"bytes,1,rep,name=items,proto3" json:"items,omitempty"`
}

func (x *ListScopesResponse) Reset() {
	*x = ListScopesResponse{}
	if protoimpl.UnsafeEnabled {
		mi := &file_controller_api_services_v1_scope_service_proto_msgTypes[3]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *ListScopesResponse) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*ListScopesResponse) ProtoMessage() {}

func (x *ListScopesResponse) ProtoReflect() protoreflect.Message {
	mi := &file_controller_api_services_v1_scope_service_proto_msgTypes[3]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use ListScopesResponse.ProtoReflect.Descriptor instead.
func (*ListScopesResponse) Descriptor() ([]byte, []int) {
	return file_controller_api_services_v1_scope_service_proto_rawDescGZIP(), []int{3}
}

func (x *ListScopesResponse) GetItems() []*scopes.Scope {
	if x != nil {
		return x.Items
	}
	return nil
}

type CreateScopeRequest struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	SkipAdminRoleCreation   bool          `protobuf:"varint,1,opt,name=skip_admin_role_creation,json=skipAdminRoleCreation,proto3" json:"skip_admin_role_creation,omitempty"`
	SkipDefaultRoleCreation bool          `protobuf:"varint,2,opt,name=skip_default_role_creation,json=skipDefaultRoleCreation,proto3" json:"skip_default_role_creation,omitempty"`
	Item                    *scopes.Scope `protobuf:"bytes,3,opt,name=item,proto3" json:"item,omitempty"`
}

func (x *CreateScopeRequest) Reset() {
	*x = CreateScopeRequest{}
	if protoimpl.UnsafeEnabled {
		mi := &file_controller_api_services_v1_scope_service_proto_msgTypes[4]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *CreateScopeRequest) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*CreateScopeRequest) ProtoMessage() {}

func (x *CreateScopeRequest) ProtoReflect() protoreflect.Message {
	mi := &file_controller_api_services_v1_scope_service_proto_msgTypes[4]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use CreateScopeRequest.ProtoReflect.Descriptor instead.
func (*CreateScopeRequest) Descriptor() ([]byte, []int) {
	return file_controller_api_services_v1_scope_service_proto_rawDescGZIP(), []int{4}
}

func (x *CreateScopeRequest) GetSkipAdminRoleCreation() bool {
	if x != nil {
		return x.SkipAdminRoleCreation
	}
	return false
}

func (x *CreateScopeRequest) GetSkipDefaultRoleCreation() bool {
	if x != nil {
		return x.SkipDefaultRoleCreation
	}
	return false
}

func (x *CreateScopeRequest) GetItem() *scopes.Scope {
	if x != nil {
		return x.Item
	}
	return nil
}

type CreateScopeResponse struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	Uri  string        `protobuf:"bytes,1,opt,name=uri,proto3" json:"uri,omitempty"`
	Item *scopes.Scope `protobuf:"bytes,2,opt,name=item,proto3" json:"item,omitempty"`
}

func (x *CreateScopeResponse) Reset() {
	*x = CreateScopeResponse{}
	if protoimpl.UnsafeEnabled {
		mi := &file_controller_api_services_v1_scope_service_proto_msgTypes[5]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *CreateScopeResponse) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*CreateScopeResponse) ProtoMessage() {}

func (x *CreateScopeResponse) ProtoReflect() protoreflect.Message {
	mi := &file_controller_api_services_v1_scope_service_proto_msgTypes[5]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use CreateScopeResponse.ProtoReflect.Descriptor instead.
func (*CreateScopeResponse) Descriptor() ([]byte, []int) {
	return file_controller_api_services_v1_scope_service_proto_rawDescGZIP(), []int{5}
}

func (x *CreateScopeResponse) GetUri() string {
	if x != nil {
		return x.Uri
	}
	return ""
}

func (x *CreateScopeResponse) GetItem() *scopes.Scope {
	if x != nil {
		return x.Item
	}
	return nil
}

type UpdateScopeRequest struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	Id         string                 `protobuf:"bytes,1,opt,name=id,proto3" json:"id,omitempty"`
	Item       *scopes.Scope          `protobuf:"bytes,2,opt,name=item,proto3" json:"item,omitempty"`
	UpdateMask *fieldmaskpb.FieldMask `protobuf:"bytes,3,opt,name=update_mask,proto3" json:"update_mask,omitempty"`
}

func (x *UpdateScopeRequest) Reset() {
	*x = UpdateScopeRequest{}
	if protoimpl.UnsafeEnabled {
		mi := &file_controller_api_services_v1_scope_service_proto_msgTypes[6]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *UpdateScopeRequest) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*UpdateScopeRequest) ProtoMessage() {}

func (x *UpdateScopeRequest) ProtoReflect() protoreflect.Message {
	mi := &file_controller_api_services_v1_scope_service_proto_msgTypes[6]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use UpdateScopeRequest.ProtoReflect.Descriptor instead.
func (*UpdateScopeRequest) Descriptor() ([]byte, []int) {
	return file_controller_api_services_v1_scope_service_proto_rawDescGZIP(), []int{6}
}

func (x *UpdateScopeRequest) GetId() string {
	if x != nil {
		return x.Id
	}
	return ""
}

func (x *UpdateScopeRequest) GetItem() *scopes.Scope {
	if x != nil {
		return x.Item
	}
	return nil
}

func (x *UpdateScopeRequest) GetUpdateMask() *fieldmaskpb.FieldMask {
	if x != nil {
		return x.UpdateMask
	}
	return nil
}

type UpdateScopeResponse struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	Item *scopes.Scope `protobuf:"bytes,1,opt,name=item,proto3" json:"item,omitempty"`
}

func (x *UpdateScopeResponse) Reset() {
	*x = UpdateScopeResponse{}
	if protoimpl.UnsafeEnabled {
		mi := &file_controller_api_services_v1_scope_service_proto_msgTypes[7]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *UpdateScopeResponse) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*UpdateScopeResponse) ProtoMessage() {}

func (x *UpdateScopeResponse) ProtoReflect() protoreflect.Message {
	mi := &file_controller_api_services_v1_scope_service_proto_msgTypes[7]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use UpdateScopeResponse.ProtoReflect.Descriptor instead.
func (*UpdateScopeResponse) Descriptor() ([]byte, []int) {
	return file_controller_api_services_v1_scope_service_proto_rawDescGZIP(), []int{7}
}

func (x *UpdateScopeResponse) GetItem() *scopes.Scope {
	if x != nil {
		return x.Item
	}
	return nil
}

type DeleteScopeRequest struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	Id string `protobuf:"bytes,1,opt,name=id,proto3" json:"id,omitempty"`
}

func (x *DeleteScopeRequest) Reset() {
	*x = DeleteScopeRequest{}
	if protoimpl.UnsafeEnabled {
		mi := &file_controller_api_services_v1_scope_service_proto_msgTypes[8]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *DeleteScopeRequest) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*DeleteScopeRequest) ProtoMessage() {}

func (x *DeleteScopeRequest) ProtoReflect() protoreflect.Message {
	mi := &file_controller_api_services_v1_scope_service_proto_msgTypes[8]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use DeleteScopeRequest.ProtoReflect.Descriptor instead.
func (*DeleteScopeRequest) Descriptor() ([]byte, []int) {
	return file_controller_api_services_v1_scope_service_proto_rawDescGZIP(), []int{8}
}

func (x *DeleteScopeRequest) GetId() string {
	if x != nil {
		return x.Id
	}
	return ""
}

type DeleteScopeResponse struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields
}

func (x *DeleteScopeResponse) Reset() {
	*x = DeleteScopeResponse{}
	if protoimpl.UnsafeEnabled {
		mi := &file_controller_api_services_v1_scope_service_proto_msgTypes[9]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *DeleteScopeResponse) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*DeleteScopeResponse) ProtoMessage() {}

func (x *DeleteScopeResponse) ProtoReflect() protoreflect.Message {
	mi := &file_controller_api_services_v1_scope_service_proto_msgTypes[9]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use DeleteScopeResponse.ProtoReflect.Descriptor instead.
func (*DeleteScopeResponse) Descriptor() ([]byte, []int) {
	return file_controller_api_services_v1_scope_service_proto_rawDescGZIP(), []int{9}
}

var File_controller_api_services_v1_scope_service_proto protoreflect.FileDescriptor

var file_controller_api_services_v1_scope_service_proto_rawDesc = []byte{
	0x0a, 0x2e, 0x63, 0x6f, 0x6e, 0x74, 0x72, 0x6f, 0x6c, 0x6c, 0x65, 0x72, 0x2f, 0x61, 0x70, 0x69,
	0x2f, 0x73, 0x65, 0x72, 0x76, 0x69, 0x63, 0x65, 0x73, 0x2f, 0x76, 0x31, 0x2f, 0x73, 0x63, 0x6f,
	0x70, 0x65, 0x5f, 0x73, 0x65, 0x72, 0x76, 0x69, 0x63, 0x65, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f,
	0x12, 0x1a, 0x63, 0x6f, 0x6e, 0x74, 0x72, 0x6f, 0x6c, 0x6c, 0x65, 0x72, 0x2e, 0x61, 0x70, 0x69,
	0x2e, 0x73, 0x65, 0x72, 0x76, 0x69, 0x63, 0x65, 0x73, 0x2e, 0x76, 0x31, 0x1a, 0x2e, 0x63, 0x6f,
	0x6e, 0x74, 0x72, 0x6f, 0x6c, 0x6c, 0x65, 0x72, 0x2f, 0x61, 0x70, 0x69, 0x2f, 0x72, 0x65, 0x73,
	0x6f, 0x75, 0x72, 0x63, 0x65, 0x73, 0x2f, 0x73, 0x63, 0x6f, 0x70, 0x65, 0x73, 0x2f, 0x76, 0x31,
	0x2f, 0x73, 0x63, 0x6f, 0x70, 0x65, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x1a, 0x1c, 0x67, 0x6f,
	0x6f, 0x67, 0x6c, 0x65, 0x2f, 0x61, 0x70, 0x69, 0x2f, 0x61, 0x6e, 0x6e, 0x6f, 0x74, 0x61, 0x74,
	0x69, 0x6f, 0x6e, 0x73, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x1a, 0x20, 0x67, 0x6f, 0x6f, 0x67,
	0x6c, 0x65, 0x2f, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x62, 0x75, 0x66, 0x2f, 0x66, 0x69, 0x65, 0x6c,
	0x64, 0x5f, 0x6d, 0x61, 0x73, 0x6b, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x1a, 0x2e, 0x70, 0x72,
	0x6f, 0x74, 0x6f, 0x63, 0x2d, 0x67, 0x65, 0x6e, 0x2d, 0x6f, 0x70, 0x65, 0x6e, 0x61, 0x70, 0x69,
	0x76, 0x32, 0x2f, 0x6f, 0x70, 0x74, 0x69, 0x6f, 0x6e, 0x73, 0x2f, 0x61, 0x6e, 0x6e, 0x6f, 0x74,
	0x61, 0x74, 0x69, 0x6f, 0x6e, 0x73, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x22, 0x21, 0x0a, 0x0f,
	0x47, 0x65, 0x74, 0x53, 0x63, 0x6f, 0x70, 0x65, 0x52, 0x65, 0x71, 0x75, 0x65, 0x73, 0x74, 0x12,
	0x0e, 0x0a, 0x02, 0x69, 0x64, 0x18, 0x01, 0x20, 0x01, 0x28, 0x09, 0x52, 0x02, 0x69, 0x64, 0x22,
	0x51, 0x0a, 0x10, 0x47, 0x65, 0x74, 0x53, 0x63, 0x6f, 0x70, 0x65, 0x52, 0x65, 0x73, 0x70, 0x6f,
	0x6e, 0x73, 0x65, 0x12, 0x3d, 0x0a, 0x04, 0x69, 0x74, 0x65, 0x6d, 0x18, 0x01, 0x20, 0x01, 0x28,
	0x0b, 0x32, 0x29, 0x2e, 0x63, 0x6f, 0x6e, 0x74, 0x72, 0x6f, 0x6c, 0x6c, 0x65, 0x72, 0x2e, 0x61,
	0x70, 0x69, 0x2e, 0x72, 0x65, 0x73, 0x6f, 0x75, 0x72, 0x63, 0x65, 0x73, 0x2e, 0x73, 0x63, 0x6f,
	0x70, 0x65, 0x73, 0x2e, 0x76, 0x31, 0x2e, 0x53, 0x63, 0x6f, 0x70, 0x65, 0x52, 0x04, 0x69, 0x74,
	0x65, 0x6d, 0x22, 0x64, 0x0a, 0x11, 0x4c, 0x69, 0x73, 0x74, 0x53, 0x63, 0x6f, 0x70, 0x65, 0x73,
	0x52, 0x65, 0x71, 0x75, 0x65, 0x73, 0x74, 0x12, 0x19, 0x0a, 0x08, 0x73, 0x63, 0x6f, 0x70, 0x65,
	0x5f, 0x69, 0x64, 0x18, 0x01, 0x20, 0x01, 0x28, 0x09, 0x52, 0x07, 0x73, 0x63, 0x6f, 0x70, 0x65,
	0x49, 0x64, 0x12, 0x1c, 0x0a, 0x09, 0x72, 0x65, 0x63, 0x75, 0x72, 0x73, 0x69, 0x76, 0x65, 0x18,
	0x14, 0x20, 0x01, 0x28, 0x08, 0x52, 0x09, 0x72, 0x65, 0x63, 0x75, 0x72, 0x73, 0x69, 0x76, 0x65,
	0x12, 0x16, 0x0a, 0x06, 0x66, 0x69, 0x6c, 0x74, 0x65, 0x72, 0x18, 0x1e, 0x20, 0x01, 0x28, 0x09,
	0x52, 0x06, 0x66, 0x69, 0x6c, 0x74, 0x65, 0x72, 0x22, 0x55, 0x0a, 0x12, 0x4c, 0x69, 0x73, 0x74,
	0x53, 0x63, 0x6f, 0x70, 0x65, 0x73, 0x52, 0x65, 0x73, 0x70, 0x6f, 0x6e, 0x73, 0x65, 0x12, 0x3f,
	0x0a, 0x05, 0x69, 0x74, 0x65, 0x6d, 0x73, 0x18, 0x01, 0x20, 0x03, 0x28, 0x0b, 0x32, 0x29, 0x2e,
	0x63, 0x6f, 0x6e, 0x74, 0x72, 0x6f, 0x6c, 0x6c, 0x65, 0x72, 0x2e, 0x61, 0x70, 0x69, 0x2e, 0x72,
	0x65, 0x73, 0x6f, 0x75, 0x72, 0x63, 0x65, 0x73, 0x2e, 0x73, 0x63, 0x6f, 0x70, 0x65, 0x73, 0x2e,
	0x76, 0x31, 0x2e, 0x53, 0x63, 0x6f, 0x70, 0x65, 0x52, 0x05, 0x69, 0x74, 0x65, 0x6d, 0x73, 0x22,
	0xc9, 0x01, 0x0a, 0x12, 0x43, 0x72, 0x65, 0x61, 0x74, 0x65, 0x53, 0x63, 0x6f, 0x70, 0x65, 0x52,
	0x65, 0x71, 0x75, 0x65, 0x73, 0x74, 0x12, 0x37, 0x0a, 0x18, 0x73, 0x6b, 0x69, 0x70, 0x5f, 0x61,
	0x64, 0x6d, 0x69, 0x6e, 0x5f, 0x72, 0x6f, 0x6c, 0x65, 0x5f, 0x63, 0x72, 0x65, 0x61, 0x74, 0x69,
	0x6f, 0x6e, 0x18, 0x01, 0x20, 0x01, 0x28, 0x08, 0x52, 0x15, 0x73, 0x6b, 0x69, 0x70, 0x41, 0x64,
	0x6d, 0x69, 0x6e, 0x52, 0x6f, 0x6c, 0x65, 0x43, 0x72, 0x65, 0x61, 0x74, 0x69, 0x6f, 0x6e, 0x12,
	0x3b, 0x0a, 0x1a, 0x73, 0x6b, 0x69, 0x70, 0x5f, 0x64, 0x65, 0x66, 0x61, 0x75, 0x6c, 0x74, 0x5f,
	0x72, 0x6f, 0x6c, 0x65, 0x5f, 0x63, 0x72, 0x65, 0x61, 0x74, 0x69, 0x6f, 0x6e, 0x18, 0x02, 0x20,
	0x01, 0x28, 0x08, 0x52, 0x17, 0x73, 0x6b, 0x69, 0x70, 0x44, 0x65, 0x66, 0x61, 0x75, 0x6c, 0x74,
	0x52, 0x6f, 0x6c, 0x65, 0x43, 0x72, 0x65, 0x61, 0x74, 0x69, 0x6f, 0x6e, 0x12, 0x3d, 0x0a, 0x04,
	0x69, 0x74, 0x65, 0x6d, 0x18, 0x03, 0x20, 0x01, 0x28, 0x0b, 0x32, 0x29, 0x2e, 0x63, 0x6f, 0x6e,
	0x74, 0x72, 0x6f, 0x6c, 0x6c, 0x65, 0x72, 0x2e, 0x61, 0x70, 0x69, 0x2e, 0x72, 0x65, 0x73, 0x6f,
	0x75, 0x72, 0x63, 0x65, 0x73, 0x2e, 0x73, 0x63, 0x6f, 0x70, 0x65, 0x73, 0x2e, 0x76, 0x31, 0x2e,
	0x53, 0x63, 0x6f, 0x70, 0x65, 0x52, 0x04, 0x69, 0x74, 0x65, 0x6d, 0x22, 0x66, 0x0a, 0x13, 0x43,
	0x72, 0x65, 0x61, 0x74, 0x65, 0x53, 0x63, 0x6f, 0x70, 0x65, 0x52, 0x65, 0x73, 0x70, 0x6f, 0x6e,
	0x73, 0x65, 0x12, 0x10, 0x0a, 0x03, 0x75, 0x72, 0x69, 0x18, 0x01, 0x20, 0x01, 0x28, 0x09, 0x52,
	0x03, 0x75, 0x72, 0x69, 0x12, 0x3d, 0x0a, 0x04, 0x69, 0x74, 0x65, 0x6d, 0x18, 0x02, 0x20, 0x01,
	0x28, 0x0b, 0x32, 0x29, 0x2e, 0x63, 0x6f, 0x6e, 0x74, 0x72, 0x6f, 0x6c, 0x6c, 0x65, 0x72, 0x2e,
	0x61, 0x70, 0x69, 0x2e, 0x72, 0x65, 0x73, 0x6f, 0x75, 0x72, 0x63, 0x65, 0x73, 0x2e, 0x73, 0x63,
	0x6f, 0x70, 0x65, 0x73, 0x2e, 0x76, 0x31, 0x2e, 0x53, 0x63, 0x6f, 0x70, 0x65, 0x52, 0x04, 0x69,
	0x74, 0x65, 0x6d, 0x22, 0xa1, 0x01, 0x0a, 0x12, 0x55, 0x70, 0x64, 0x61, 0x74, 0x65, 0x53, 0x63,
	0x6f, 0x70, 0x65, 0x52, 0x65, 0x71, 0x75, 0x65, 0x73, 0x74, 0x12, 0x0e, 0x0a, 0x02, 0x69, 0x64,
	0x18, 0x01, 0x20, 0x01, 0x28, 0x09, 0x52, 0x02, 0x69, 0x64, 0x12, 0x3d, 0x0a, 0x04, 0x69, 0x74,
	0x65, 0x6d, 0x18, 0x02, 0x20, 0x01, 0x28, 0x0b, 0x32, 0x29, 0x2e, 0x63, 0x6f, 0x6e, 0x74, 0x72,
	0x6f, 0x6c, 0x6c, 0x65, 0x72, 0x2e, 0x61, 0x70, 0x69, 0x2e, 0x72, 0x65, 0x73, 0x6f, 0x75, 0x72,
	0x63, 0x65, 0x73, 0x2e, 0x73, 0x63, 0x6f, 0x70, 0x65, 0x73, 0x2e, 0x76, 0x31, 0x2e, 0x53, 0x63,
	0x6f, 0x70, 0x65, 0x52, 0x04, 0x69, 0x74, 0x65, 0x6d, 0x12, 0x3c, 0x0a, 0x0b, 0x75, 0x70, 0x64,
	0x61, 0x74, 0x65, 0x5f, 0x6d, 0x61, 0x73, 0x6b, 0x18, 0x03, 0x20, 0x01, 0x28, 0x0b, 0x32, 0x1a,
	0x2e, 0x67, 0x6f, 0x6f, 0x67, 0x6c, 0x65, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x62, 0x75, 0x66,
	0x2e, 0x46, 0x69, 0x65, 0x6c, 0x64, 0x4d, 0x61, 0x73, 0x6b, 0x52, 0x0b, 0x75, 0x70, 0x64, 0x61,
	0x74, 0x65, 0x5f, 0x6d, 0x61, 0x73, 0x6b, 0x22, 0x54, 0x0a, 0x13, 0x55, 0x70, 0x64, 0x61, 0x74,
	0x65, 0x53, 0x63, 0x6f, 0x70, 0x65, 0x52, 0x65, 0x73, 0x70, 0x6f, 0x6e, 0x73, 0x65, 0x12, 0x3d,
	0x0a, 0x04, 0x69, 0x74, 0x65, 0x6d, 0x18, 0x01, 0x20, 0x01, 0x28, 0x0b, 0x32, 0x29, 0x2e, 0x63,
	0x6f, 0x6e, 0x74, 0x72, 0x6f, 0x6c, 0x6c, 0x65, 0x72, 0x2e, 0x61, 0x70, 0x69, 0x2e, 0x72, 0x65,
	0x73, 0x6f, 0x75, 0x72, 0x63, 0x65, 0x73, 0x2e, 0x73, 0x63, 0x6f, 0x70, 0x65, 0x73, 0x2e, 0x76,
	0x31, 0x2e, 0x53, 0x63, 0x6f, 0x70, 0x65, 0x52, 0x04, 0x69, 0x74, 0x65, 0x6d, 0x22, 0x24, 0x0a,
	0x12, 0x44, 0x65, 0x6c, 0x65, 0x74, 0x65, 0x53, 0x63, 0x6f, 0x70, 0x65, 0x52, 0x65, 0x71, 0x75,
	0x65, 0x73, 0x74, 0x12, 0x0e, 0x0a, 0x02, 0x69, 0x64, 0x18, 0x01, 0x20, 0x01, 0x28, 0x09, 0x52,
	0x02, 0x69, 0x64, 0x22, 0x15, 0x0a, 0x13, 0x44, 0x65, 0x6c, 0x65, 0x74, 0x65, 0x53, 0x63, 0x6f,
	0x70, 0x65, 0x52, 0x65, 0x73, 0x70, 0x6f, 0x6e, 0x73, 0x65, 0x32, 0xe6, 0x06, 0x0a, 0x0c, 0x53,
	0x63, 0x6f, 0x70, 0x65, 0x53, 0x65, 0x72, 0x76, 0x69, 0x63, 0x65, 0x12, 0x9d, 0x01, 0x0a, 0x08,
	0x47, 0x65, 0x74, 0x53, 0x63, 0x6f, 0x70, 0x65, 0x12, 0x2b, 0x2e, 0x63, 0x6f, 0x6e, 0x74, 0x72,
	0x6f, 0x6c, 0x6c, 0x65, 0x72, 0x2e, 0x61, 0x70, 0x69, 0x2e, 0x73, 0x65, 0x72, 0x76, 0x69, 0x63,
	0x65, 0x73, 0x2e, 0x76, 0x31, 0x2e, 0x47, 0x65, 0x74, 0x53, 0x63, 0x6f, 0x70, 0x65, 0x52, 0x65,
	0x71, 0x75, 0x65, 0x73, 0x74, 0x1a, 0x2c, 0x2e, 0x63, 0x6f, 0x6e, 0x74, 0x72, 0x6f, 0x6c, 0x6c,
	0x65, 0x72, 0x2e, 0x61, 0x70, 0x69, 0x2e, 0x73, 0x65, 0x72, 0x76, 0x69, 0x63, 0x65, 0x73, 0x2e,
	0x76, 0x31, 0x2e, 0x47, 0x65, 0x74, 0x53, 0x63, 0x6f, 0x70, 0x65, 0x52, 0x65, 0x73, 0x70, 0x6f,
	0x6e, 0x73, 0x65, 0x22, 0x36, 0x92, 0x41, 0x16, 0x12, 0x14, 0x47, 0x65, 0x74, 0x73, 0x20, 0x61,
	0x20, 0x73, 0x69, 0x6e, 0x67, 0x6c, 0x65, 0x20, 0x53, 0x63, 0x6f, 0x70, 0x65, 0x2e, 0x82, 0xd3,
	0xe4, 0x93, 0x02, 0x17, 0x12, 0x0f, 0x2f, 0x76, 0x31, 0x2f, 0x73, 0x63, 0x6f, 0x70, 0x65, 0x73,
	0x2f, 0x7b, 0x69, 0x64, 0x7d, 0x62, 0x04, 0x69, 0x74, 0x65, 0x6d, 0x12, 0xbe, 0x01, 0x0a, 0x0a,
	0x4c, 0x69, 0x73, 0x74, 0x53, 0x63, 0x6f, 0x70, 0x65, 0x73, 0x12, 0x2d, 0x2e, 0x63, 0x6f, 0x6e,
	0x74, 0x72, 0x6f, 0x6c, 0x6c, 0x65, 0x72, 0x2e, 0x61, 0x70, 0x69, 0x2e, 0x73, 0x65, 0x72, 0x76,
	0x69, 0x63, 0x65, 0x73, 0x2e, 0x76, 0x31, 0x2e, 0x4c, 0x69, 0x73, 0x74, 0x53, 0x63, 0x6f, 0x70,
	0x65, 0x73, 0x52, 0x65, 0x71, 0x75, 0x65, 0x73, 0x74, 0x1a, 0x2e, 0x2e, 0x63, 0x6f, 0x6e, 0x74,
	0x72, 0x6f, 0x6c, 0x6c, 0x65, 0x72, 0x2e, 0x61, 0x70, 0x69, 0x2e, 0x73, 0x65, 0x72, 0x76, 0x69,
	0x63, 0x65, 0x73, 0x2e, 0x76, 0x31, 0x2e, 0x4c, 0x69, 0x73, 0x74, 0x53, 0x63, 0x6f, 0x70, 0x65,
	0x73, 0x52, 0x65, 0x73, 0x70, 0x6f, 0x6e, 0x73, 0x65, 0x22, 0x51, 0x92, 0x41, 0x3c, 0x12, 0x3a,
	0x4c, 0x69, 0x73, 0x74, 0x73, 0x20, 0x61, 0x6c, 0x6c, 0x20, 0x53, 0x63, 0x6f, 0x70, 0x65, 0x73,
	0x20, 0x77, 0x69, 0x74, 0x68, 0x69, 0x6e, 0x20, 0x74, 0x68, 0x65, 0x20, 0x53, 0x63, 0x6f, 0x70,
	0x65, 0x20, 0x70, 0x72, 0x6f, 0x76, 0x69, 0x64, 0x65, 0x64, 0x20, 0x69, 0x6e, 0x20, 0x74, 0x68,
	0x65, 0x20, 0x72, 0x65, 0x71, 0x75, 0x65, 0x73, 0x74, 0x2e, 0x82, 0xd3, 0xe4, 0x93, 0x02, 0x0c,
	0x12, 0x0a, 0x2f, 0x76, 0x31, 0x2f, 0x73, 0x63, 0x6f, 0x70, 0x65, 0x73, 0x12, 0xaa, 0x01, 0x0a,
	0x0b, 0x43, 0x72, 0x65, 0x61, 0x74, 0x65, 0x53, 0x63, 0x6f, 0x70, 0x65, 0x12, 0x2e, 0x2e, 0x63,
	0x6f, 0x6e, 0x74, 0x72, 0x6f, 0x6c, 0x6c, 0x65, 0x72, 0x2e, 0x61, 0x70, 0x69, 0x2e, 0x73, 0x65,
	0x72, 0x76, 0x69, 0x63, 0x65, 0x73, 0x2e, 0x76, 0x31, 0x2e, 0x43, 0x72, 0x65, 0x61, 0x74, 0x65,
	0x53, 0x63, 0x6f, 0x70, 0x65, 0x52, 0x65, 0x71, 0x75, 0x65, 0x73, 0x74, 0x1a, 0x2f, 0x2e, 0x63,
	0x6f, 0x6e, 0x74, 0x72, 0x6f, 0x6c, 0x6c, 0x65, 0x72, 0x2e, 0x61, 0x70, 0x69, 0x2e, 0x73, 0x65,
	0x72, 0x76, 0x69, 0x63, 0x65, 0x73, 0x2e, 0x76, 0x31, 0x2e, 0x43, 0x72, 0x65, 0x61, 0x74, 0x65,
	0x53, 0x63, 0x6f, 0x70, 0x65, 0x52, 0x65, 0x73, 0x70, 0x6f, 0x6e, 0x73, 0x65, 0x22, 0x3a, 0x92,
	0x41, 0x19, 0x12, 0x17, 0x43, 0x72, 0x65, 0x61, 0x74, 0x65, 0x73, 0x20, 0x61, 0x20, 0x73, 0x69,
	0x6e, 0x67, 0x6c, 0x65, 0x20, 0x53, 0x63, 0x6f, 0x70, 0x65, 0x2e, 0x82, 0xd3, 0xe4, 0x93, 0x02,
	0x18, 0x22, 0x0a, 0x2f, 0x76, 0x31, 0x2f, 0x73, 0x63, 0x6f, 0x70, 0x65, 0x73, 0x3a, 0x04, 0x69,
	0x74, 0x65, 0x6d, 0x62, 0x04, 0x69, 0x74, 0x65, 0x6d, 0x12, 0xa8, 0x01, 0x0a, 0x0b, 0x55, 0x70,
	0x64, 0x61, 0x74, 0x65, 0x53, 0x63, 0x6f, 0x70, 0x65, 0x12, 0x2e, 0x2e, 0x63, 0x6f, 0x6e, 0x74,
	0x72, 0x6f, 0x6c, 0x6c, 0x65, 0x72, 0x2e, 0x61, 0x70, 0x69, 0x2e, 0x73, 0x65, 0x72, 0x76, 0x69,
	0x63, 0x65, 0x73, 0x2e, 0x76, 0x31, 0x2e, 0x55, 0x70, 0x64, 0x61, 0x74, 0x65, 0x53, 0x63, 0x6f,
	0x70, 0x65, 0x52, 0x65, 0x71, 0x75, 0x65, 0x73, 0x74, 0x1a, 0x2f, 0x2e, 0x63, 0x6f, 0x6e, 0x74,
	0x72, 0x6f, 0x6c, 0x6c, 0x65, 0x72, 0x2e, 0x61, 0x70, 0x69, 0x2e, 0x73, 0x65, 0x72, 0x76, 0x69,
	0x63, 0x65, 0x73, 0x2e, 0x76, 0x31, 0x2e, 0x55, 0x70, 0x64, 0x61, 0x74, 0x65, 0x53, 0x63, 0x6f,
	0x70, 0x65, 0x52, 0x65, 0x73, 0x70, 0x6f, 0x6e, 0x73, 0x65, 0x22, 0x38, 0x92, 0x41, 0x12, 0x12,
	0x10, 0x55, 0x70, 0x64, 0x61, 0x74, 0x65, 0x73, 0x20, 0x61, 0x20, 0x53, 0x63, 0x6f, 0x70, 0x65,
	0x2e, 0x82, 0xd3, 0xe4, 0x93, 0x02, 0x1d, 0x32, 0x0f, 0x2f, 0x76, 0x31, 0x2f, 0x73, 0x63, 0x6f,
	0x70, 0x65, 0x73, 0x2f, 0x7b, 0x69, 0x64, 0x7d, 0x3a, 0x04, 0x69, 0x74, 0x65, 0x6d, 0x62, 0x04,
	0x69, 0x74, 0x65, 0x6d, 0x12, 0x9c, 0x01, 0x0a, 0x0b, 0x44, 0x65, 0x6c, 0x65, 0x74, 0x65, 0x53,
	0x63, 0x6f, 0x70, 0x65, 0x12, 0x2e, 0x2e, 0x63, 0x6f, 0x6e, 0x74, 0x72, 0x6f, 0x6c, 0x6c, 0x65,
	0x72, 0x2e, 0x61, 0x70, 0x69, 0x2e, 0x73, 0x65, 0x72, 0x76, 0x69, 0x63, 0x65, 0x73, 0x2e, 0x76,
	0x31, 0x2e, 0x44, 0x65, 0x6c, 0x65, 0x74, 0x65, 0x53, 0x63, 0x6f, 0x70, 0x65, 0x52, 0x65, 0x71,
	0x75, 0x65, 0x73, 0x74, 0x1a, 0x2f, 0x2e, 0x63, 0x6f, 0x6e, 0x74, 0x72, 0x6f, 0x6c, 0x6c, 0x65,
	0x72, 0x2e, 0x61, 0x70, 0x69, 0x2e, 0x73, 0x65, 0x72, 0x76, 0x69, 0x63, 0x65, 0x73, 0x2e, 0x76,
	0x31, 0x2e, 0x44, 0x65, 0x6c, 0x65, 0x74, 0x65, 0x53, 0x63, 0x6f, 0x70, 0x65, 0x52, 0x65, 0x73,
	0x70, 0x6f, 0x6e, 0x73, 0x65, 0x22, 0x2c, 0x92, 0x41, 0x12, 0x12, 0x10, 0x44, 0x65, 0x6c, 0x65,
	0x74, 0x65, 0x73, 0x20, 0x61, 0x20, 0x53, 0x63, 0x6f, 0x70, 0x65, 0x2e, 0x82, 0xd3, 0xe4, 0x93,
	0x02, 0x11, 0x2a, 0x0f, 0x2f, 0x76, 0x31, 0x2f, 0x73, 0x63, 0x6f, 0x70, 0x65, 0x73, 0x2f, 0x7b,
	0x69, 0x64, 0x7d, 0x42, 0x74, 0x5a, 0x4b, 0x67, 0x69, 0x74, 0x68, 0x75, 0x62, 0x2e, 0x63, 0x6f,
	0x6d, 0x2f, 0x68, 0x61, 0x73, 0x68, 0x69, 0x63, 0x6f, 0x72, 0x70, 0x2f, 0x62, 0x6f, 0x75, 0x6e,
	0x64, 0x61, 0x72, 0x79, 0x2f, 0x69, 0x6e, 0x74, 0x65, 0x72, 0x6e, 0x61, 0x6c, 0x2f, 0x67, 0x65,
	0x6e, 0x2f, 0x63, 0x6f, 0x6e, 0x74, 0x72, 0x6f, 0x6c, 0x6c, 0x65, 0x72, 0x2f, 0x61, 0x70, 0x69,
	0x2f, 0x73, 0x65, 0x72, 0x76, 0x69, 0x63, 0x65, 0x73, 0x3b, 0x73, 0x65, 0x72, 0x76, 0x69, 0x63,
	0x65, 0x73, 0x92, 0x41, 0x24, 0x12, 0x1e, 0x0a, 0x1c, 0x42, 0x6f, 0x75, 0x6e, 0x64, 0x61, 0x72,
	0x79, 0x20, 0x43, 0x6f, 0x6e, 0x74, 0x72, 0x6f, 0x6c, 0x6c, 0x65, 0x72, 0x20, 0x48, 0x54, 0x54,
	0x50, 0x20, 0x41, 0x50, 0x49, 0x2a, 0x02, 0x02, 0x01, 0x62, 0x06, 0x70, 0x72, 0x6f, 0x74, 0x6f,
	0x33,
}

var (
	file_controller_api_services_v1_scope_service_proto_rawDescOnce sync.Once
	file_controller_api_services_v1_scope_service_proto_rawDescData = file_controller_api_services_v1_scope_service_proto_rawDesc
)

func file_controller_api_services_v1_scope_service_proto_rawDescGZIP() []byte {
	file_controller_api_services_v1_scope_service_proto_rawDescOnce.Do(func() {
		file_controller_api_services_v1_scope_service_proto_rawDescData = protoimpl.X.CompressGZIP(file_controller_api_services_v1_scope_service_proto_rawDescData)
	})
	return file_controller_api_services_v1_scope_service_proto_rawDescData
}

var file_controller_api_services_v1_scope_service_proto_msgTypes = make([]protoimpl.MessageInfo, 10)
var file_controller_api_services_v1_scope_service_proto_goTypes = []interface{}{
	(*GetScopeRequest)(nil),       // 0: controller.api.services.v1.GetScopeRequest
	(*GetScopeResponse)(nil),      // 1: controller.api.services.v1.GetScopeResponse
	(*ListScopesRequest)(nil),     // 2: controller.api.services.v1.ListScopesRequest
	(*ListScopesResponse)(nil),    // 3: controller.api.services.v1.ListScopesResponse
	(*CreateScopeRequest)(nil),    // 4: controller.api.services.v1.CreateScopeRequest
	(*CreateScopeResponse)(nil),   // 5: controller.api.services.v1.CreateScopeResponse
	(*UpdateScopeRequest)(nil),    // 6: controller.api.services.v1.UpdateScopeRequest
	(*UpdateScopeResponse)(nil),   // 7: controller.api.services.v1.UpdateScopeResponse
	(*DeleteScopeRequest)(nil),    // 8: controller.api.services.v1.DeleteScopeRequest
	(*DeleteScopeResponse)(nil),   // 9: controller.api.services.v1.DeleteScopeResponse
	(*scopes.Scope)(nil),          // 10: controller.api.resources.scopes.v1.Scope
	(*fieldmaskpb.FieldMask)(nil), // 11: google.protobuf.FieldMask
}
var file_controller_api_services_v1_scope_service_proto_depIdxs = []int32{
	10, // 0: controller.api.services.v1.GetScopeResponse.item:type_name -> controller.api.resources.scopes.v1.Scope
	10, // 1: controller.api.services.v1.ListScopesResponse.items:type_name -> controller.api.resources.scopes.v1.Scope
	10, // 2: controller.api.services.v1.CreateScopeRequest.item:type_name -> controller.api.resources.scopes.v1.Scope
	10, // 3: controller.api.services.v1.CreateScopeResponse.item:type_name -> controller.api.resources.scopes.v1.Scope
	10, // 4: controller.api.services.v1.UpdateScopeRequest.item:type_name -> controller.api.resources.scopes.v1.Scope
	11, // 5: controller.api.services.v1.UpdateScopeRequest.update_mask:type_name -> google.protobuf.FieldMask
	10, // 6: controller.api.services.v1.UpdateScopeResponse.item:type_name -> controller.api.resources.scopes.v1.Scope
	0,  // 7: controller.api.services.v1.ScopeService.GetScope:input_type -> controller.api.services.v1.GetScopeRequest
	2,  // 8: controller.api.services.v1.ScopeService.ListScopes:input_type -> controller.api.services.v1.ListScopesRequest
	4,  // 9: controller.api.services.v1.ScopeService.CreateScope:input_type -> controller.api.services.v1.CreateScopeRequest
	6,  // 10: controller.api.services.v1.ScopeService.UpdateScope:input_type -> controller.api.services.v1.UpdateScopeRequest
	8,  // 11: controller.api.services.v1.ScopeService.DeleteScope:input_type -> controller.api.services.v1.DeleteScopeRequest
	1,  // 12: controller.api.services.v1.ScopeService.GetScope:output_type -> controller.api.services.v1.GetScopeResponse
	3,  // 13: controller.api.services.v1.ScopeService.ListScopes:output_type -> controller.api.services.v1.ListScopesResponse
	5,  // 14: controller.api.services.v1.ScopeService.CreateScope:output_type -> controller.api.services.v1.CreateScopeResponse
	7,  // 15: controller.api.services.v1.ScopeService.UpdateScope:output_type -> controller.api.services.v1.UpdateScopeResponse
	9,  // 16: controller.api.services.v1.ScopeService.DeleteScope:output_type -> controller.api.services.v1.DeleteScopeResponse
	12, // [12:17] is the sub-list for method output_type
	7,  // [7:12] is the sub-list for method input_type
	7,  // [7:7] is the sub-list for extension type_name
	7,  // [7:7] is the sub-list for extension extendee
	0,  // [0:7] is the sub-list for field type_name
}

func init() { file_controller_api_services_v1_scope_service_proto_init() }
func file_controller_api_services_v1_scope_service_proto_init() {
	if File_controller_api_services_v1_scope_service_proto != nil {
		return
	}
	if !protoimpl.UnsafeEnabled {
		file_controller_api_services_v1_scope_service_proto_msgTypes[0].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*GetScopeRequest); i {
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
		file_controller_api_services_v1_scope_service_proto_msgTypes[1].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*GetScopeResponse); i {
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
		file_controller_api_services_v1_scope_service_proto_msgTypes[2].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*ListScopesRequest); i {
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
		file_controller_api_services_v1_scope_service_proto_msgTypes[3].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*ListScopesResponse); i {
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
		file_controller_api_services_v1_scope_service_proto_msgTypes[4].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*CreateScopeRequest); i {
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
		file_controller_api_services_v1_scope_service_proto_msgTypes[5].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*CreateScopeResponse); i {
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
		file_controller_api_services_v1_scope_service_proto_msgTypes[6].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*UpdateScopeRequest); i {
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
		file_controller_api_services_v1_scope_service_proto_msgTypes[7].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*UpdateScopeResponse); i {
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
		file_controller_api_services_v1_scope_service_proto_msgTypes[8].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*DeleteScopeRequest); i {
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
		file_controller_api_services_v1_scope_service_proto_msgTypes[9].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*DeleteScopeResponse); i {
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
			RawDescriptor: file_controller_api_services_v1_scope_service_proto_rawDesc,
			NumEnums:      0,
			NumMessages:   10,
			NumExtensions: 0,
			NumServices:   1,
		},
		GoTypes:           file_controller_api_services_v1_scope_service_proto_goTypes,
		DependencyIndexes: file_controller_api_services_v1_scope_service_proto_depIdxs,
		MessageInfos:      file_controller_api_services_v1_scope_service_proto_msgTypes,
	}.Build()
	File_controller_api_services_v1_scope_service_proto = out.File
	file_controller_api_services_v1_scope_service_proto_rawDesc = nil
	file_controller_api_services_v1_scope_service_proto_goTypes = nil
	file_controller_api_services_v1_scope_service_proto_depIdxs = nil
}
