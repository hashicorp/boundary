// Code generated by protoc-gen-go. DO NOT EDIT.
// versions:
// 	protoc-gen-go v1.28.1
// 	protoc        (unknown)
// source: controller/api/resources/scopes/v1/scope.proto

package scopes

import (
	_ "github.com/hashicorp/boundary/sdk/pbs/controller/protooptions"
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

type ScopeInfo struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	// Output only. The ID of the Scope.
	Id string `protobuf:"bytes,1,opt,name=id,proto3" json:"id,omitempty" class:"public"` // @gotags: `class:"public"`
	// Output only. The type of the Scope.
	Type string `protobuf:"bytes,2,opt,name=type,proto3" json:"type,omitempty" class:"public"` // @gotags: `class:"public"`
	// Output only. The name of the Scope, if any.
	Name string `protobuf:"bytes,3,opt,name=name,proto3" json:"name,omitempty" class:"public"` // @gotags: `class:"public"`
	// Output only. The description of the Scope, if any.
	Description string `protobuf:"bytes,4,opt,name=description,proto3" json:"description,omitempty" class:"public"` // @gotags: `class:"public"`
	// Output only. The ID of the parent Scope, if any. This field will be empty if this is the "global" scope.
	ParentScopeId string `protobuf:"bytes,5,opt,name=parent_scope_id,proto3" json:"parent_scope_id,omitempty" class:"public"` // @gotags: `class:"public"`
}

func (x *ScopeInfo) Reset() {
	*x = ScopeInfo{}
	if protoimpl.UnsafeEnabled {
		mi := &file_controller_api_resources_scopes_v1_scope_proto_msgTypes[0]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *ScopeInfo) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*ScopeInfo) ProtoMessage() {}

func (x *ScopeInfo) ProtoReflect() protoreflect.Message {
	mi := &file_controller_api_resources_scopes_v1_scope_proto_msgTypes[0]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use ScopeInfo.ProtoReflect.Descriptor instead.
func (*ScopeInfo) Descriptor() ([]byte, []int) {
	return file_controller_api_resources_scopes_v1_scope_proto_rawDescGZIP(), []int{0}
}

func (x *ScopeInfo) GetId() string {
	if x != nil {
		return x.Id
	}
	return ""
}

func (x *ScopeInfo) GetType() string {
	if x != nil {
		return x.Type
	}
	return ""
}

func (x *ScopeInfo) GetName() string {
	if x != nil {
		return x.Name
	}
	return ""
}

func (x *ScopeInfo) GetDescription() string {
	if x != nil {
		return x.Description
	}
	return ""
}

func (x *ScopeInfo) GetParentScopeId() string {
	if x != nil {
		return x.ParentScopeId
	}
	return ""
}

// Scope contains all fields related to a Scope resource
type Scope struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	// Output only. The ID of the Scope.
	Id string `protobuf:"bytes,10,opt,name=id,proto3" json:"id,omitempty" class:"public"` // @gotags: `class:"public"`
	// The ID of the Scope this resource is in. If this is the "global" Scope this field will be empty.
	ScopeId string `protobuf:"bytes,20,opt,name=scope_id,proto3" json:"scope_id,omitempty" class:"public"` // @gotags: `class:"public"`
	// Output only. Scope information for this resource.
	Scope *ScopeInfo `protobuf:"bytes,30,opt,name=scope,proto3" json:"scope,omitempty"`
	// Optional name for identification purposes.
	Name *wrapperspb.StringValue `protobuf:"bytes,40,opt,name=name,proto3" json:"name,omitempty" class:"public"` // @gotags: `class:"public"`
	// Optional user-set descripton for identification purposes.
	Description *wrapperspb.StringValue `protobuf:"bytes,50,opt,name=description,proto3" json:"description,omitempty" class:"public"` // @gotags: `class:"public"`
	// Output only. The time this resource was created.
	CreatedTime *timestamppb.Timestamp `protobuf:"bytes,60,opt,name=created_time,proto3" json:"created_time,omitempty" class:"public"` // @gotags: `class:"public"`
	// Output only. The time this resource was last updated.
	UpdatedTime *timestamppb.Timestamp `protobuf:"bytes,70,opt,name=updated_time,proto3" json:"updated_time,omitempty" class:"public"` // @gotags: `class:"public"`
	// Version is used in mutation requests, after the initial creation, to ensure this resource has not changed.
	// The mutation will fail if the version does not match the latest known good version.
	Version uint32 `protobuf:"varint,80,opt,name=version,proto3" json:"version,omitempty" class:"public"` // @gotags: `class:"public"`
	// The type of the resource.
	Type string `protobuf:"bytes,90,opt,name=type,proto3" json:"type,omitempty" class:"public"` // @gotags: `class:"public"`
	// The ID of the primary auth method for this scope.  A primary auth method
	// is allowed to vivify users when new accounts are created and is the source for the users account info
	PrimaryAuthMethodId *wrapperspb.StringValue `protobuf:"bytes,100,opt,name=primary_auth_method_id,proto3" json:"primary_auth_method_id,omitempty" class:"public"` // @gotags: `class:"public"`
	// Output only. The available actions on this resource for this user.
	AuthorizedActions []string `protobuf:"bytes,300,rep,name=authorized_actions,proto3" json:"authorized_actions,omitempty" class:"public"` // @gotags: `class:"public"`
	// Output only. The authorized actions for the scope's collections.
	AuthorizedCollectionActions map[string]*structpb.ListValue `protobuf:"bytes,310,rep,name=authorized_collection_actions,proto3" json:"authorized_collection_actions,omitempty" protobuf_key:"bytes,1,opt,name=key,proto3" protobuf_val:"bytes,2,opt,name=value,proto3"`
}

func (x *Scope) Reset() {
	*x = Scope{}
	if protoimpl.UnsafeEnabled {
		mi := &file_controller_api_resources_scopes_v1_scope_proto_msgTypes[1]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *Scope) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*Scope) ProtoMessage() {}

func (x *Scope) ProtoReflect() protoreflect.Message {
	mi := &file_controller_api_resources_scopes_v1_scope_proto_msgTypes[1]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use Scope.ProtoReflect.Descriptor instead.
func (*Scope) Descriptor() ([]byte, []int) {
	return file_controller_api_resources_scopes_v1_scope_proto_rawDescGZIP(), []int{1}
}

func (x *Scope) GetId() string {
	if x != nil {
		return x.Id
	}
	return ""
}

func (x *Scope) GetScopeId() string {
	if x != nil {
		return x.ScopeId
	}
	return ""
}

func (x *Scope) GetScope() *ScopeInfo {
	if x != nil {
		return x.Scope
	}
	return nil
}

func (x *Scope) GetName() *wrapperspb.StringValue {
	if x != nil {
		return x.Name
	}
	return nil
}

func (x *Scope) GetDescription() *wrapperspb.StringValue {
	if x != nil {
		return x.Description
	}
	return nil
}

func (x *Scope) GetCreatedTime() *timestamppb.Timestamp {
	if x != nil {
		return x.CreatedTime
	}
	return nil
}

func (x *Scope) GetUpdatedTime() *timestamppb.Timestamp {
	if x != nil {
		return x.UpdatedTime
	}
	return nil
}

func (x *Scope) GetVersion() uint32 {
	if x != nil {
		return x.Version
	}
	return 0
}

func (x *Scope) GetType() string {
	if x != nil {
		return x.Type
	}
	return ""
}

func (x *Scope) GetPrimaryAuthMethodId() *wrapperspb.StringValue {
	if x != nil {
		return x.PrimaryAuthMethodId
	}
	return nil
}

func (x *Scope) GetAuthorizedActions() []string {
	if x != nil {
		return x.AuthorizedActions
	}
	return nil
}

func (x *Scope) GetAuthorizedCollectionActions() map[string]*structpb.ListValue {
	if x != nil {
		return x.AuthorizedCollectionActions
	}
	return nil
}

// KeyVersion describes a specific version of a key and holds the actual key material
type KeyVersion struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	// The ID of the key version.
	Id string `protobuf:"bytes,10,opt,name=id,proto3" json:"id,omitempty" class:"public"` // @gotags: `class:"public"`
	// The iteration of the Key that this version represents.
	Version uint32 `protobuf:"varint,20,opt,name=version,proto3" json:"version,omitempty" class:"public"` // @gotags: `class:"public"`
	// When this version was created.
	CreatedTime *timestamppb.Timestamp `protobuf:"bytes,30,opt,name=created_time,proto3" json:"created_time,omitempty" class:"public"` // @gotags: `class:"public"`
}

func (x *KeyVersion) Reset() {
	*x = KeyVersion{}
	if protoimpl.UnsafeEnabled {
		mi := &file_controller_api_resources_scopes_v1_scope_proto_msgTypes[2]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *KeyVersion) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*KeyVersion) ProtoMessage() {}

func (x *KeyVersion) ProtoReflect() protoreflect.Message {
	mi := &file_controller_api_resources_scopes_v1_scope_proto_msgTypes[2]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use KeyVersion.ProtoReflect.Descriptor instead.
func (*KeyVersion) Descriptor() ([]byte, []int) {
	return file_controller_api_resources_scopes_v1_scope_proto_rawDescGZIP(), []int{2}
}

func (x *KeyVersion) GetId() string {
	if x != nil {
		return x.Id
	}
	return ""
}

func (x *KeyVersion) GetVersion() uint32 {
	if x != nil {
		return x.Version
	}
	return 0
}

func (x *KeyVersion) GetCreatedTime() *timestamppb.Timestamp {
	if x != nil {
		return x.CreatedTime
	}
	return nil
}

// Key contains all fields related to a Key in a Scope.
type Key struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	// The ID of the Key.
	Id string `protobuf:"bytes,10,opt,name=id,proto3" json:"id,omitempty" class:"public"` // @gotags: `class:"public"`
	// Scope information for this resource.
	Scope *ScopeInfo `protobuf:"bytes,20,opt,name=scope,proto3" json:"scope,omitempty"`
	// The purpose of the Key.
	Purpose string `protobuf:"bytes,30,opt,name=purpose,proto3" json:"purpose,omitempty" class:"public"` // @gotags: `class:"public"`
	// The time this Key was created.
	CreatedTime *timestamppb.Timestamp `protobuf:"bytes,40,opt,name=created_time,proto3" json:"created_time,omitempty" class:"public"` // @gotags: `class:"public"`
	// The type of the Key.
	Type string `protobuf:"bytes,50,opt,name=type,proto3" json:"type,omitempty" class:"public"` // @gotags: `class:"public"`
	// The versions of the key.
	Versions []*KeyVersion `protobuf:"bytes,60,rep,name=versions,proto3" json:"versions,omitempty"`
}

func (x *Key) Reset() {
	*x = Key{}
	if protoimpl.UnsafeEnabled {
		mi := &file_controller_api_resources_scopes_v1_scope_proto_msgTypes[3]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *Key) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*Key) ProtoMessage() {}

func (x *Key) ProtoReflect() protoreflect.Message {
	mi := &file_controller_api_resources_scopes_v1_scope_proto_msgTypes[3]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use Key.ProtoReflect.Descriptor instead.
func (*Key) Descriptor() ([]byte, []int) {
	return file_controller_api_resources_scopes_v1_scope_proto_rawDescGZIP(), []int{3}
}

func (x *Key) GetId() string {
	if x != nil {
		return x.Id
	}
	return ""
}

func (x *Key) GetScope() *ScopeInfo {
	if x != nil {
		return x.Scope
	}
	return nil
}

func (x *Key) GetPurpose() string {
	if x != nil {
		return x.Purpose
	}
	return ""
}

func (x *Key) GetCreatedTime() *timestamppb.Timestamp {
	if x != nil {
		return x.CreatedTime
	}
	return nil
}

func (x *Key) GetType() string {
	if x != nil {
		return x.Type
	}
	return ""
}

func (x *Key) GetVersions() []*KeyVersion {
	if x != nil {
		return x.Versions
	}
	return nil
}

// KeyVersionDestructionJob holds information about a pending key version destruction job.
type KeyVersionDestructionJob struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	// The ID of the Key version this job relates to.
	KeyVersionId string `protobuf:"bytes,10,opt,name=key_version_id,json=keyVersionId,proto3" json:"key_version_id,omitempty" class:"public"` // @gotags: `class:"public"`
	// Scope information for this resource.
	Scope *ScopeInfo `protobuf:"bytes,20,opt,name=scope,proto3" json:"scope,omitempty"`
	// The current status of the key version destruction job. One of "pending", "running" or "completed".
	Status string `protobuf:"bytes,30,opt,name=status,proto3" json:"status,omitempty" class:"public"` // @gotags: `class:"public"`
	// The time this key version destruction job was created.
	CreatedTime *timestamppb.Timestamp `protobuf:"bytes,40,opt,name=created_time,proto3" json:"created_time,omitempty" class:"public"` // @gotags: `class:"public"`
	// The number of rows that have been successfully re-encrypted with a new key version.
	// All rows must be re-encrypted before the key version can be destroyed.
	CompletedCount int64 `protobuf:"varint,50,opt,name=completed_count,json=completedCount,proto3" json:"completed_count,omitempty" class:"public"` // @gotags: `class:"public"`
	// The total number of rows that need re-encrypting.
	TotalCount int64 `protobuf:"varint,60,opt,name=total_count,json=totalCount,proto3" json:"total_count,omitempty" class:"public"` // @gotags: `class:"public"`
}

func (x *KeyVersionDestructionJob) Reset() {
	*x = KeyVersionDestructionJob{}
	if protoimpl.UnsafeEnabled {
		mi := &file_controller_api_resources_scopes_v1_scope_proto_msgTypes[4]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *KeyVersionDestructionJob) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*KeyVersionDestructionJob) ProtoMessage() {}

func (x *KeyVersionDestructionJob) ProtoReflect() protoreflect.Message {
	mi := &file_controller_api_resources_scopes_v1_scope_proto_msgTypes[4]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use KeyVersionDestructionJob.ProtoReflect.Descriptor instead.
func (*KeyVersionDestructionJob) Descriptor() ([]byte, []int) {
	return file_controller_api_resources_scopes_v1_scope_proto_rawDescGZIP(), []int{4}
}

func (x *KeyVersionDestructionJob) GetKeyVersionId() string {
	if x != nil {
		return x.KeyVersionId
	}
	return ""
}

func (x *KeyVersionDestructionJob) GetScope() *ScopeInfo {
	if x != nil {
		return x.Scope
	}
	return nil
}

func (x *KeyVersionDestructionJob) GetStatus() string {
	if x != nil {
		return x.Status
	}
	return ""
}

func (x *KeyVersionDestructionJob) GetCreatedTime() *timestamppb.Timestamp {
	if x != nil {
		return x.CreatedTime
	}
	return nil
}

func (x *KeyVersionDestructionJob) GetCompletedCount() int64 {
	if x != nil {
		return x.CompletedCount
	}
	return 0
}

func (x *KeyVersionDestructionJob) GetTotalCount() int64 {
	if x != nil {
		return x.TotalCount
	}
	return 0
}

var File_controller_api_resources_scopes_v1_scope_proto protoreflect.FileDescriptor

var file_controller_api_resources_scopes_v1_scope_proto_rawDesc = []byte{
	0x0a, 0x2e, 0x63, 0x6f, 0x6e, 0x74, 0x72, 0x6f, 0x6c, 0x6c, 0x65, 0x72, 0x2f, 0x61, 0x70, 0x69,
	0x2f, 0x72, 0x65, 0x73, 0x6f, 0x75, 0x72, 0x63, 0x65, 0x73, 0x2f, 0x73, 0x63, 0x6f, 0x70, 0x65,
	0x73, 0x2f, 0x76, 0x31, 0x2f, 0x73, 0x63, 0x6f, 0x70, 0x65, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f,
	0x12, 0x22, 0x63, 0x6f, 0x6e, 0x74, 0x72, 0x6f, 0x6c, 0x6c, 0x65, 0x72, 0x2e, 0x61, 0x70, 0x69,
	0x2e, 0x72, 0x65, 0x73, 0x6f, 0x75, 0x72, 0x63, 0x65, 0x73, 0x2e, 0x73, 0x63, 0x6f, 0x70, 0x65,
	0x73, 0x2e, 0x76, 0x31, 0x1a, 0x2a, 0x63, 0x6f, 0x6e, 0x74, 0x72, 0x6f, 0x6c, 0x6c, 0x65, 0x72,
	0x2f, 0x63, 0x75, 0x73, 0x74, 0x6f, 0x6d, 0x5f, 0x6f, 0x70, 0x74, 0x69, 0x6f, 0x6e, 0x73, 0x2f,
	0x76, 0x31, 0x2f, 0x6f, 0x70, 0x74, 0x69, 0x6f, 0x6e, 0x73, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f,
	0x1a, 0x1c, 0x67, 0x6f, 0x6f, 0x67, 0x6c, 0x65, 0x2f, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x62, 0x75,
	0x66, 0x2f, 0x73, 0x74, 0x72, 0x75, 0x63, 0x74, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x1a, 0x1f,
	0x67, 0x6f, 0x6f, 0x67, 0x6c, 0x65, 0x2f, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x62, 0x75, 0x66, 0x2f,
	0x74, 0x69, 0x6d, 0x65, 0x73, 0x74, 0x61, 0x6d, 0x70, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x1a,
	0x1e, 0x67, 0x6f, 0x6f, 0x67, 0x6c, 0x65, 0x2f, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x62, 0x75, 0x66,
	0x2f, 0x77, 0x72, 0x61, 0x70, 0x70, 0x65, 0x72, 0x73, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x22,
	0x8f, 0x01, 0x0a, 0x09, 0x53, 0x63, 0x6f, 0x70, 0x65, 0x49, 0x6e, 0x66, 0x6f, 0x12, 0x0e, 0x0a,
	0x02, 0x69, 0x64, 0x18, 0x01, 0x20, 0x01, 0x28, 0x09, 0x52, 0x02, 0x69, 0x64, 0x12, 0x12, 0x0a,
	0x04, 0x74, 0x79, 0x70, 0x65, 0x18, 0x02, 0x20, 0x01, 0x28, 0x09, 0x52, 0x04, 0x74, 0x79, 0x70,
	0x65, 0x12, 0x12, 0x0a, 0x04, 0x6e, 0x61, 0x6d, 0x65, 0x18, 0x03, 0x20, 0x01, 0x28, 0x09, 0x52,
	0x04, 0x6e, 0x61, 0x6d, 0x65, 0x12, 0x20, 0x0a, 0x0b, 0x64, 0x65, 0x73, 0x63, 0x72, 0x69, 0x70,
	0x74, 0x69, 0x6f, 0x6e, 0x18, 0x04, 0x20, 0x01, 0x28, 0x09, 0x52, 0x0b, 0x64, 0x65, 0x73, 0x63,
	0x72, 0x69, 0x70, 0x74, 0x69, 0x6f, 0x6e, 0x12, 0x28, 0x0a, 0x0f, 0x70, 0x61, 0x72, 0x65, 0x6e,
	0x74, 0x5f, 0x73, 0x63, 0x6f, 0x70, 0x65, 0x5f, 0x69, 0x64, 0x18, 0x05, 0x20, 0x01, 0x28, 0x09,
	0x52, 0x0f, 0x70, 0x61, 0x72, 0x65, 0x6e, 0x74, 0x5f, 0x73, 0x63, 0x6f, 0x70, 0x65, 0x5f, 0x69,
	0x64, 0x22, 0x91, 0x07, 0x0a, 0x05, 0x53, 0x63, 0x6f, 0x70, 0x65, 0x12, 0x0e, 0x0a, 0x02, 0x69,
	0x64, 0x18, 0x0a, 0x20, 0x01, 0x28, 0x09, 0x52, 0x02, 0x69, 0x64, 0x12, 0x1a, 0x0a, 0x08, 0x73,
	0x63, 0x6f, 0x70, 0x65, 0x5f, 0x69, 0x64, 0x18, 0x14, 0x20, 0x01, 0x28, 0x09, 0x52, 0x08, 0x73,
	0x63, 0x6f, 0x70, 0x65, 0x5f, 0x69, 0x64, 0x12, 0x43, 0x0a, 0x05, 0x73, 0x63, 0x6f, 0x70, 0x65,
	0x18, 0x1e, 0x20, 0x01, 0x28, 0x0b, 0x32, 0x2d, 0x2e, 0x63, 0x6f, 0x6e, 0x74, 0x72, 0x6f, 0x6c,
	0x6c, 0x65, 0x72, 0x2e, 0x61, 0x70, 0x69, 0x2e, 0x72, 0x65, 0x73, 0x6f, 0x75, 0x72, 0x63, 0x65,
	0x73, 0x2e, 0x73, 0x63, 0x6f, 0x70, 0x65, 0x73, 0x2e, 0x76, 0x31, 0x2e, 0x53, 0x63, 0x6f, 0x70,
	0x65, 0x49, 0x6e, 0x66, 0x6f, 0x52, 0x05, 0x73, 0x63, 0x6f, 0x70, 0x65, 0x12, 0x46, 0x0a, 0x04,
	0x6e, 0x61, 0x6d, 0x65, 0x18, 0x28, 0x20, 0x01, 0x28, 0x0b, 0x32, 0x1c, 0x2e, 0x67, 0x6f, 0x6f,
	0x67, 0x6c, 0x65, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x62, 0x75, 0x66, 0x2e, 0x53, 0x74, 0x72,
	0x69, 0x6e, 0x67, 0x56, 0x61, 0x6c, 0x75, 0x65, 0x42, 0x14, 0xa0, 0xda, 0x29, 0x01, 0xc2, 0xdd,
	0x29, 0x0c, 0x0a, 0x04, 0x6e, 0x61, 0x6d, 0x65, 0x12, 0x04, 0x6e, 0x61, 0x6d, 0x65, 0x52, 0x04,
	0x6e, 0x61, 0x6d, 0x65, 0x12, 0x62, 0x0a, 0x0b, 0x64, 0x65, 0x73, 0x63, 0x72, 0x69, 0x70, 0x74,
	0x69, 0x6f, 0x6e, 0x18, 0x32, 0x20, 0x01, 0x28, 0x0b, 0x32, 0x1c, 0x2e, 0x67, 0x6f, 0x6f, 0x67,
	0x6c, 0x65, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x62, 0x75, 0x66, 0x2e, 0x53, 0x74, 0x72, 0x69,
	0x6e, 0x67, 0x56, 0x61, 0x6c, 0x75, 0x65, 0x42, 0x22, 0xa0, 0xda, 0x29, 0x01, 0xc2, 0xdd, 0x29,
	0x1a, 0x0a, 0x0b, 0x64, 0x65, 0x73, 0x63, 0x72, 0x69, 0x70, 0x74, 0x69, 0x6f, 0x6e, 0x12, 0x0b,
	0x64, 0x65, 0x73, 0x63, 0x72, 0x69, 0x70, 0x74, 0x69, 0x6f, 0x6e, 0x52, 0x0b, 0x64, 0x65, 0x73,
	0x63, 0x72, 0x69, 0x70, 0x74, 0x69, 0x6f, 0x6e, 0x12, 0x3e, 0x0a, 0x0c, 0x63, 0x72, 0x65, 0x61,
	0x74, 0x65, 0x64, 0x5f, 0x74, 0x69, 0x6d, 0x65, 0x18, 0x3c, 0x20, 0x01, 0x28, 0x0b, 0x32, 0x1a,
	0x2e, 0x67, 0x6f, 0x6f, 0x67, 0x6c, 0x65, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x62, 0x75, 0x66,
	0x2e, 0x54, 0x69, 0x6d, 0x65, 0x73, 0x74, 0x61, 0x6d, 0x70, 0x52, 0x0c, 0x63, 0x72, 0x65, 0x61,
	0x74, 0x65, 0x64, 0x5f, 0x74, 0x69, 0x6d, 0x65, 0x12, 0x3e, 0x0a, 0x0c, 0x75, 0x70, 0x64, 0x61,
	0x74, 0x65, 0x64, 0x5f, 0x74, 0x69, 0x6d, 0x65, 0x18, 0x46, 0x20, 0x01, 0x28, 0x0b, 0x32, 0x1a,
	0x2e, 0x67, 0x6f, 0x6f, 0x67, 0x6c, 0x65, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x62, 0x75, 0x66,
	0x2e, 0x54, 0x69, 0x6d, 0x65, 0x73, 0x74, 0x61, 0x6d, 0x70, 0x52, 0x0c, 0x75, 0x70, 0x64, 0x61,
	0x74, 0x65, 0x64, 0x5f, 0x74, 0x69, 0x6d, 0x65, 0x12, 0x18, 0x0a, 0x07, 0x76, 0x65, 0x72, 0x73,
	0x69, 0x6f, 0x6e, 0x18, 0x50, 0x20, 0x01, 0x28, 0x0d, 0x52, 0x07, 0x76, 0x65, 0x72, 0x73, 0x69,
	0x6f, 0x6e, 0x12, 0x12, 0x0a, 0x04, 0x74, 0x79, 0x70, 0x65, 0x18, 0x5a, 0x20, 0x01, 0x28, 0x09,
	0x52, 0x04, 0x74, 0x79, 0x70, 0x65, 0x12, 0x8b, 0x01, 0x0a, 0x16, 0x70, 0x72, 0x69, 0x6d, 0x61,
	0x72, 0x79, 0x5f, 0x61, 0x75, 0x74, 0x68, 0x5f, 0x6d, 0x65, 0x74, 0x68, 0x6f, 0x64, 0x5f, 0x69,
	0x64, 0x18, 0x64, 0x20, 0x01, 0x28, 0x0b, 0x32, 0x1c, 0x2e, 0x67, 0x6f, 0x6f, 0x67, 0x6c, 0x65,
	0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x62, 0x75, 0x66, 0x2e, 0x53, 0x74, 0x72, 0x69, 0x6e, 0x67,
	0x56, 0x61, 0x6c, 0x75, 0x65, 0x42, 0x35, 0xa0, 0xda, 0x29, 0x01, 0xc2, 0xdd, 0x29, 0x2d, 0x0a,
	0x16, 0x70, 0x72, 0x69, 0x6d, 0x61, 0x72, 0x79, 0x5f, 0x61, 0x75, 0x74, 0x68, 0x5f, 0x6d, 0x65,
	0x74, 0x68, 0x6f, 0x64, 0x5f, 0x69, 0x64, 0x12, 0x13, 0x50, 0x72, 0x69, 0x6d, 0x61, 0x72, 0x79,
	0x41, 0x75, 0x74, 0x68, 0x4d, 0x65, 0x74, 0x68, 0x6f, 0x64, 0x49, 0x64, 0x52, 0x16, 0x70, 0x72,
	0x69, 0x6d, 0x61, 0x72, 0x79, 0x5f, 0x61, 0x75, 0x74, 0x68, 0x5f, 0x6d, 0x65, 0x74, 0x68, 0x6f,
	0x64, 0x5f, 0x69, 0x64, 0x12, 0x2f, 0x0a, 0x12, 0x61, 0x75, 0x74, 0x68, 0x6f, 0x72, 0x69, 0x7a,
	0x65, 0x64, 0x5f, 0x61, 0x63, 0x74, 0x69, 0x6f, 0x6e, 0x73, 0x18, 0xac, 0x02, 0x20, 0x03, 0x28,
	0x09, 0x52, 0x12, 0x61, 0x75, 0x74, 0x68, 0x6f, 0x72, 0x69, 0x7a, 0x65, 0x64, 0x5f, 0x61, 0x63,
	0x74, 0x69, 0x6f, 0x6e, 0x73, 0x12, 0x91, 0x01, 0x0a, 0x1d, 0x61, 0x75, 0x74, 0x68, 0x6f, 0x72,
	0x69, 0x7a, 0x65, 0x64, 0x5f, 0x63, 0x6f, 0x6c, 0x6c, 0x65, 0x63, 0x74, 0x69, 0x6f, 0x6e, 0x5f,
	0x61, 0x63, 0x74, 0x69, 0x6f, 0x6e, 0x73, 0x18, 0xb6, 0x02, 0x20, 0x03, 0x28, 0x0b, 0x32, 0x4a,
	0x2e, 0x63, 0x6f, 0x6e, 0x74, 0x72, 0x6f, 0x6c, 0x6c, 0x65, 0x72, 0x2e, 0x61, 0x70, 0x69, 0x2e,
	0x72, 0x65, 0x73, 0x6f, 0x75, 0x72, 0x63, 0x65, 0x73, 0x2e, 0x73, 0x63, 0x6f, 0x70, 0x65, 0x73,
	0x2e, 0x76, 0x31, 0x2e, 0x53, 0x63, 0x6f, 0x70, 0x65, 0x2e, 0x41, 0x75, 0x74, 0x68, 0x6f, 0x72,
	0x69, 0x7a, 0x65, 0x64, 0x43, 0x6f, 0x6c, 0x6c, 0x65, 0x63, 0x74, 0x69, 0x6f, 0x6e, 0x41, 0x63,
	0x74, 0x69, 0x6f, 0x6e, 0x73, 0x45, 0x6e, 0x74, 0x72, 0x79, 0x52, 0x1d, 0x61, 0x75, 0x74, 0x68,
	0x6f, 0x72, 0x69, 0x7a, 0x65, 0x64, 0x5f, 0x63, 0x6f, 0x6c, 0x6c, 0x65, 0x63, 0x74, 0x69, 0x6f,
	0x6e, 0x5f, 0x61, 0x63, 0x74, 0x69, 0x6f, 0x6e, 0x73, 0x1a, 0x6a, 0x0a, 0x20, 0x41, 0x75, 0x74,
	0x68, 0x6f, 0x72, 0x69, 0x7a, 0x65, 0x64, 0x43, 0x6f, 0x6c, 0x6c, 0x65, 0x63, 0x74, 0x69, 0x6f,
	0x6e, 0x41, 0x63, 0x74, 0x69, 0x6f, 0x6e, 0x73, 0x45, 0x6e, 0x74, 0x72, 0x79, 0x12, 0x10, 0x0a,
	0x03, 0x6b, 0x65, 0x79, 0x18, 0x01, 0x20, 0x01, 0x28, 0x09, 0x52, 0x03, 0x6b, 0x65, 0x79, 0x12,
	0x30, 0x0a, 0x05, 0x76, 0x61, 0x6c, 0x75, 0x65, 0x18, 0x02, 0x20, 0x01, 0x28, 0x0b, 0x32, 0x1a,
	0x2e, 0x67, 0x6f, 0x6f, 0x67, 0x6c, 0x65, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x62, 0x75, 0x66,
	0x2e, 0x4c, 0x69, 0x73, 0x74, 0x56, 0x61, 0x6c, 0x75, 0x65, 0x52, 0x05, 0x76, 0x61, 0x6c, 0x75,
	0x65, 0x3a, 0x02, 0x38, 0x01, 0x22, 0x76, 0x0a, 0x0a, 0x4b, 0x65, 0x79, 0x56, 0x65, 0x72, 0x73,
	0x69, 0x6f, 0x6e, 0x12, 0x0e, 0x0a, 0x02, 0x69, 0x64, 0x18, 0x0a, 0x20, 0x01, 0x28, 0x09, 0x52,
	0x02, 0x69, 0x64, 0x12, 0x18, 0x0a, 0x07, 0x76, 0x65, 0x72, 0x73, 0x69, 0x6f, 0x6e, 0x18, 0x14,
	0x20, 0x01, 0x28, 0x0d, 0x52, 0x07, 0x76, 0x65, 0x72, 0x73, 0x69, 0x6f, 0x6e, 0x12, 0x3e, 0x0a,
	0x0c, 0x63, 0x72, 0x65, 0x61, 0x74, 0x65, 0x64, 0x5f, 0x74, 0x69, 0x6d, 0x65, 0x18, 0x1e, 0x20,
	0x01, 0x28, 0x0b, 0x32, 0x1a, 0x2e, 0x67, 0x6f, 0x6f, 0x67, 0x6c, 0x65, 0x2e, 0x70, 0x72, 0x6f,
	0x74, 0x6f, 0x62, 0x75, 0x66, 0x2e, 0x54, 0x69, 0x6d, 0x65, 0x73, 0x74, 0x61, 0x6d, 0x70, 0x52,
	0x0c, 0x63, 0x72, 0x65, 0x61, 0x74, 0x65, 0x64, 0x5f, 0x74, 0x69, 0x6d, 0x65, 0x22, 0x94, 0x02,
	0x0a, 0x03, 0x4b, 0x65, 0x79, 0x12, 0x0e, 0x0a, 0x02, 0x69, 0x64, 0x18, 0x0a, 0x20, 0x01, 0x28,
	0x09, 0x52, 0x02, 0x69, 0x64, 0x12, 0x43, 0x0a, 0x05, 0x73, 0x63, 0x6f, 0x70, 0x65, 0x18, 0x14,
	0x20, 0x01, 0x28, 0x0b, 0x32, 0x2d, 0x2e, 0x63, 0x6f, 0x6e, 0x74, 0x72, 0x6f, 0x6c, 0x6c, 0x65,
	0x72, 0x2e, 0x61, 0x70, 0x69, 0x2e, 0x72, 0x65, 0x73, 0x6f, 0x75, 0x72, 0x63, 0x65, 0x73, 0x2e,
	0x73, 0x63, 0x6f, 0x70, 0x65, 0x73, 0x2e, 0x76, 0x31, 0x2e, 0x53, 0x63, 0x6f, 0x70, 0x65, 0x49,
	0x6e, 0x66, 0x6f, 0x52, 0x05, 0x73, 0x63, 0x6f, 0x70, 0x65, 0x12, 0x18, 0x0a, 0x07, 0x70, 0x75,
	0x72, 0x70, 0x6f, 0x73, 0x65, 0x18, 0x1e, 0x20, 0x01, 0x28, 0x09, 0x52, 0x07, 0x70, 0x75, 0x72,
	0x70, 0x6f, 0x73, 0x65, 0x12, 0x3e, 0x0a, 0x0c, 0x63, 0x72, 0x65, 0x61, 0x74, 0x65, 0x64, 0x5f,
	0x74, 0x69, 0x6d, 0x65, 0x18, 0x28, 0x20, 0x01, 0x28, 0x0b, 0x32, 0x1a, 0x2e, 0x67, 0x6f, 0x6f,
	0x67, 0x6c, 0x65, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x62, 0x75, 0x66, 0x2e, 0x54, 0x69, 0x6d,
	0x65, 0x73, 0x74, 0x61, 0x6d, 0x70, 0x52, 0x0c, 0x63, 0x72, 0x65, 0x61, 0x74, 0x65, 0x64, 0x5f,
	0x74, 0x69, 0x6d, 0x65, 0x12, 0x12, 0x0a, 0x04, 0x74, 0x79, 0x70, 0x65, 0x18, 0x32, 0x20, 0x01,
	0x28, 0x09, 0x52, 0x04, 0x74, 0x79, 0x70, 0x65, 0x12, 0x4a, 0x0a, 0x08, 0x76, 0x65, 0x72, 0x73,
	0x69, 0x6f, 0x6e, 0x73, 0x18, 0x3c, 0x20, 0x03, 0x28, 0x0b, 0x32, 0x2e, 0x2e, 0x63, 0x6f, 0x6e,
	0x74, 0x72, 0x6f, 0x6c, 0x6c, 0x65, 0x72, 0x2e, 0x61, 0x70, 0x69, 0x2e, 0x72, 0x65, 0x73, 0x6f,
	0x75, 0x72, 0x63, 0x65, 0x73, 0x2e, 0x73, 0x63, 0x6f, 0x70, 0x65, 0x73, 0x2e, 0x76, 0x31, 0x2e,
	0x4b, 0x65, 0x79, 0x56, 0x65, 0x72, 0x73, 0x69, 0x6f, 0x6e, 0x52, 0x08, 0x76, 0x65, 0x72, 0x73,
	0x69, 0x6f, 0x6e, 0x73, 0x22, 0xa7, 0x02, 0x0a, 0x18, 0x4b, 0x65, 0x79, 0x56, 0x65, 0x72, 0x73,
	0x69, 0x6f, 0x6e, 0x44, 0x65, 0x73, 0x74, 0x72, 0x75, 0x63, 0x74, 0x69, 0x6f, 0x6e, 0x4a, 0x6f,
	0x62, 0x12, 0x24, 0x0a, 0x0e, 0x6b, 0x65, 0x79, 0x5f, 0x76, 0x65, 0x72, 0x73, 0x69, 0x6f, 0x6e,
	0x5f, 0x69, 0x64, 0x18, 0x0a, 0x20, 0x01, 0x28, 0x09, 0x52, 0x0c, 0x6b, 0x65, 0x79, 0x56, 0x65,
	0x72, 0x73, 0x69, 0x6f, 0x6e, 0x49, 0x64, 0x12, 0x43, 0x0a, 0x05, 0x73, 0x63, 0x6f, 0x70, 0x65,
	0x18, 0x14, 0x20, 0x01, 0x28, 0x0b, 0x32, 0x2d, 0x2e, 0x63, 0x6f, 0x6e, 0x74, 0x72, 0x6f, 0x6c,
	0x6c, 0x65, 0x72, 0x2e, 0x61, 0x70, 0x69, 0x2e, 0x72, 0x65, 0x73, 0x6f, 0x75, 0x72, 0x63, 0x65,
	0x73, 0x2e, 0x73, 0x63, 0x6f, 0x70, 0x65, 0x73, 0x2e, 0x76, 0x31, 0x2e, 0x53, 0x63, 0x6f, 0x70,
	0x65, 0x49, 0x6e, 0x66, 0x6f, 0x52, 0x05, 0x73, 0x63, 0x6f, 0x70, 0x65, 0x12, 0x16, 0x0a, 0x06,
	0x73, 0x74, 0x61, 0x74, 0x75, 0x73, 0x18, 0x1e, 0x20, 0x01, 0x28, 0x09, 0x52, 0x06, 0x73, 0x74,
	0x61, 0x74, 0x75, 0x73, 0x12, 0x3e, 0x0a, 0x0c, 0x63, 0x72, 0x65, 0x61, 0x74, 0x65, 0x64, 0x5f,
	0x74, 0x69, 0x6d, 0x65, 0x18, 0x28, 0x20, 0x01, 0x28, 0x0b, 0x32, 0x1a, 0x2e, 0x67, 0x6f, 0x6f,
	0x67, 0x6c, 0x65, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x62, 0x75, 0x66, 0x2e, 0x54, 0x69, 0x6d,
	0x65, 0x73, 0x74, 0x61, 0x6d, 0x70, 0x52, 0x0c, 0x63, 0x72, 0x65, 0x61, 0x74, 0x65, 0x64, 0x5f,
	0x74, 0x69, 0x6d, 0x65, 0x12, 0x27, 0x0a, 0x0f, 0x63, 0x6f, 0x6d, 0x70, 0x6c, 0x65, 0x74, 0x65,
	0x64, 0x5f, 0x63, 0x6f, 0x75, 0x6e, 0x74, 0x18, 0x32, 0x20, 0x01, 0x28, 0x03, 0x52, 0x0e, 0x63,
	0x6f, 0x6d, 0x70, 0x6c, 0x65, 0x74, 0x65, 0x64, 0x43, 0x6f, 0x75, 0x6e, 0x74, 0x12, 0x1f, 0x0a,
	0x0b, 0x74, 0x6f, 0x74, 0x61, 0x6c, 0x5f, 0x63, 0x6f, 0x75, 0x6e, 0x74, 0x18, 0x3c, 0x20, 0x01,
	0x28, 0x03, 0x52, 0x0a, 0x74, 0x6f, 0x74, 0x61, 0x6c, 0x43, 0x6f, 0x75, 0x6e, 0x74, 0x42, 0x4e,
	0x5a, 0x4c, 0x67, 0x69, 0x74, 0x68, 0x75, 0x62, 0x2e, 0x63, 0x6f, 0x6d, 0x2f, 0x68, 0x61, 0x73,
	0x68, 0x69, 0x63, 0x6f, 0x72, 0x70, 0x2f, 0x62, 0x6f, 0x75, 0x6e, 0x64, 0x61, 0x72, 0x79, 0x2f,
	0x73, 0x64, 0x6b, 0x2f, 0x70, 0x62, 0x73, 0x2f, 0x63, 0x6f, 0x6e, 0x74, 0x72, 0x6f, 0x6c, 0x6c,
	0x65, 0x72, 0x2f, 0x61, 0x70, 0x69, 0x2f, 0x72, 0x65, 0x73, 0x6f, 0x75, 0x72, 0x63, 0x65, 0x73,
	0x2f, 0x73, 0x63, 0x6f, 0x70, 0x65, 0x73, 0x3b, 0x73, 0x63, 0x6f, 0x70, 0x65, 0x73, 0x62, 0x06,
	0x70, 0x72, 0x6f, 0x74, 0x6f, 0x33,
}

var (
	file_controller_api_resources_scopes_v1_scope_proto_rawDescOnce sync.Once
	file_controller_api_resources_scopes_v1_scope_proto_rawDescData = file_controller_api_resources_scopes_v1_scope_proto_rawDesc
)

func file_controller_api_resources_scopes_v1_scope_proto_rawDescGZIP() []byte {
	file_controller_api_resources_scopes_v1_scope_proto_rawDescOnce.Do(func() {
		file_controller_api_resources_scopes_v1_scope_proto_rawDescData = protoimpl.X.CompressGZIP(file_controller_api_resources_scopes_v1_scope_proto_rawDescData)
	})
	return file_controller_api_resources_scopes_v1_scope_proto_rawDescData
}

var file_controller_api_resources_scopes_v1_scope_proto_msgTypes = make([]protoimpl.MessageInfo, 6)
var file_controller_api_resources_scopes_v1_scope_proto_goTypes = []interface{}{
	(*ScopeInfo)(nil),                // 0: controller.api.resources.scopes.v1.ScopeInfo
	(*Scope)(nil),                    // 1: controller.api.resources.scopes.v1.Scope
	(*KeyVersion)(nil),               // 2: controller.api.resources.scopes.v1.KeyVersion
	(*Key)(nil),                      // 3: controller.api.resources.scopes.v1.Key
	(*KeyVersionDestructionJob)(nil), // 4: controller.api.resources.scopes.v1.KeyVersionDestructionJob
	nil,                              // 5: controller.api.resources.scopes.v1.Scope.AuthorizedCollectionActionsEntry
	(*wrapperspb.StringValue)(nil),   // 6: google.protobuf.StringValue
	(*timestamppb.Timestamp)(nil),    // 7: google.protobuf.Timestamp
	(*structpb.ListValue)(nil),       // 8: google.protobuf.ListValue
}
var file_controller_api_resources_scopes_v1_scope_proto_depIdxs = []int32{
	0,  // 0: controller.api.resources.scopes.v1.Scope.scope:type_name -> controller.api.resources.scopes.v1.ScopeInfo
	6,  // 1: controller.api.resources.scopes.v1.Scope.name:type_name -> google.protobuf.StringValue
	6,  // 2: controller.api.resources.scopes.v1.Scope.description:type_name -> google.protobuf.StringValue
	7,  // 3: controller.api.resources.scopes.v1.Scope.created_time:type_name -> google.protobuf.Timestamp
	7,  // 4: controller.api.resources.scopes.v1.Scope.updated_time:type_name -> google.protobuf.Timestamp
	6,  // 5: controller.api.resources.scopes.v1.Scope.primary_auth_method_id:type_name -> google.protobuf.StringValue
	5,  // 6: controller.api.resources.scopes.v1.Scope.authorized_collection_actions:type_name -> controller.api.resources.scopes.v1.Scope.AuthorizedCollectionActionsEntry
	7,  // 7: controller.api.resources.scopes.v1.KeyVersion.created_time:type_name -> google.protobuf.Timestamp
	0,  // 8: controller.api.resources.scopes.v1.Key.scope:type_name -> controller.api.resources.scopes.v1.ScopeInfo
	7,  // 9: controller.api.resources.scopes.v1.Key.created_time:type_name -> google.protobuf.Timestamp
	2,  // 10: controller.api.resources.scopes.v1.Key.versions:type_name -> controller.api.resources.scopes.v1.KeyVersion
	0,  // 11: controller.api.resources.scopes.v1.KeyVersionDestructionJob.scope:type_name -> controller.api.resources.scopes.v1.ScopeInfo
	7,  // 12: controller.api.resources.scopes.v1.KeyVersionDestructionJob.created_time:type_name -> google.protobuf.Timestamp
	8,  // 13: controller.api.resources.scopes.v1.Scope.AuthorizedCollectionActionsEntry.value:type_name -> google.protobuf.ListValue
	14, // [14:14] is the sub-list for method output_type
	14, // [14:14] is the sub-list for method input_type
	14, // [14:14] is the sub-list for extension type_name
	14, // [14:14] is the sub-list for extension extendee
	0,  // [0:14] is the sub-list for field type_name
}

func init() { file_controller_api_resources_scopes_v1_scope_proto_init() }
func file_controller_api_resources_scopes_v1_scope_proto_init() {
	if File_controller_api_resources_scopes_v1_scope_proto != nil {
		return
	}
	if !protoimpl.UnsafeEnabled {
		file_controller_api_resources_scopes_v1_scope_proto_msgTypes[0].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*ScopeInfo); i {
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
		file_controller_api_resources_scopes_v1_scope_proto_msgTypes[1].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*Scope); i {
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
		file_controller_api_resources_scopes_v1_scope_proto_msgTypes[2].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*KeyVersion); i {
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
		file_controller_api_resources_scopes_v1_scope_proto_msgTypes[3].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*Key); i {
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
		file_controller_api_resources_scopes_v1_scope_proto_msgTypes[4].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*KeyVersionDestructionJob); i {
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
			RawDescriptor: file_controller_api_resources_scopes_v1_scope_proto_rawDesc,
			NumEnums:      0,
			NumMessages:   6,
			NumExtensions: 0,
			NumServices:   0,
		},
		GoTypes:           file_controller_api_resources_scopes_v1_scope_proto_goTypes,
		DependencyIndexes: file_controller_api_resources_scopes_v1_scope_proto_depIdxs,
		MessageInfos:      file_controller_api_resources_scopes_v1_scope_proto_msgTypes,
	}.Build()
	File_controller_api_resources_scopes_v1_scope_proto = out.File
	file_controller_api_resources_scopes_v1_scope_proto_rawDesc = nil
	file_controller_api_resources_scopes_v1_scope_proto_goTypes = nil
	file_controller_api_resources_scopes_v1_scope_proto_depIdxs = nil
}
