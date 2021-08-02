// Code generated by protoc-gen-go. DO NOT EDIT.
// versions:
// 	protoc-gen-go v1.27.1
// 	protoc        v3.15.8
// source: controller/storage/target/store/v1/target.proto

package store

import (
	timestamp "github.com/hashicorp/boundary/internal/db/timestamp"
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

// TargetView is a view that contains all the target subtypes
type TargetView struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	// public_id is used to access the Target via an API
	// @inject_tag: gorm:"primary_key"
	PublicId string `protobuf:"bytes,10,opt,name=public_id,json=publicId,proto3" json:"public_id,omitempty" gorm:"primary_key"`
	// scope id for the Target
	// @inject_tag: `gorm:"default:null"`
	ScopeId string `protobuf:"bytes,20,opt,name=scope_id,json=scopeId,proto3" json:"scope_id,omitempty" gorm:"default:null"`
	// name is the optional friendly name used to
	// access the Target via an API
	// @inject_tag: `gorm:"default:null"`
	Name string `protobuf:"bytes,30,opt,name=name,proto3" json:"name,omitempty" gorm:"default:null"`
	// description of the Target
	// @inject_tag: `gorm:"default:null"`
	Description string `protobuf:"bytes,40,opt,name=description,proto3" json:"description,omitempty" gorm:"default:null"`
	// create_time from the RDBMS
	// @inject_tag: `gorm:"default:current_timestamp"`
	CreateTime *timestamp.Timestamp `protobuf:"bytes,50,opt,name=create_time,json=createTime,proto3" json:"create_time,omitempty" gorm:"default:current_timestamp"`
	// update_time from the RDBMS
	// @inject_tag: `gorm:"default:current_timestamp"`
	UpdateTime *timestamp.Timestamp `protobuf:"bytes,60,opt,name=update_time,json=updateTime,proto3" json:"update_time,omitempty" gorm:"default:current_timestamp"`
	// version allows optimistic locking of the Target when modifying the
	// Target
	// @inject_tag: `gorm:"default:null"`
	Version uint32 `protobuf:"varint,70,opt,name=version,proto3" json:"version,omitempty" gorm:"default:null"`
	// type represents the type of the Target
	// @inject_tag: `gorm:"default:null"`
	Type string `protobuf:"bytes,80,opt,name=type,proto3" json:"type,omitempty" gorm:"default:null"`
	// default port of the Target
	// @inject_tag: `gorm:"default:null"`
	DefaultPort uint32 `protobuf:"varint,90,opt,name=default_port,json=defaultPort,proto3" json:"default_port,omitempty" gorm:"default:null"`
	// Maximum total lifetime of a created session, in seconds
	// @inject_tag: `gorm:"default:null"`
	SessionMaxSeconds uint32 `protobuf:"varint,100,opt,name=session_max_seconds,json=sessionMaxSeconds,proto3" json:"session_max_seconds,omitempty" gorm:"default:null"`
	// Maximum number of connections in a session
	// @inject_tag: `gorm:"default:null"`
	SessionConnectionLimit int32 `protobuf:"varint,110,opt,name=session_connection_limit,json=sessionConnectionLimit,proto3" json:"session_connection_limit,omitempty" gorm:"default:null"`
	// A boolean expression that allows filtering the workers that can handle a session
	// @inject_tag: `gorm:"default:null"`
	WorkerFilter string `protobuf:"bytes,120,opt,name=worker_filter,json=workerFilter,proto3" json:"worker_filter,omitempty" gorm:"default:null"`
}

func (x *TargetView) Reset() {
	*x = TargetView{}
	if protoimpl.UnsafeEnabled {
		mi := &file_controller_storage_target_store_v1_target_proto_msgTypes[0]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *TargetView) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*TargetView) ProtoMessage() {}

func (x *TargetView) ProtoReflect() protoreflect.Message {
	mi := &file_controller_storage_target_store_v1_target_proto_msgTypes[0]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use TargetView.ProtoReflect.Descriptor instead.
func (*TargetView) Descriptor() ([]byte, []int) {
	return file_controller_storage_target_store_v1_target_proto_rawDescGZIP(), []int{0}
}

func (x *TargetView) GetPublicId() string {
	if x != nil {
		return x.PublicId
	}
	return ""
}

func (x *TargetView) GetScopeId() string {
	if x != nil {
		return x.ScopeId
	}
	return ""
}

func (x *TargetView) GetName() string {
	if x != nil {
		return x.Name
	}
	return ""
}

func (x *TargetView) GetDescription() string {
	if x != nil {
		return x.Description
	}
	return ""
}

func (x *TargetView) GetCreateTime() *timestamp.Timestamp {
	if x != nil {
		return x.CreateTime
	}
	return nil
}

func (x *TargetView) GetUpdateTime() *timestamp.Timestamp {
	if x != nil {
		return x.UpdateTime
	}
	return nil
}

func (x *TargetView) GetVersion() uint32 {
	if x != nil {
		return x.Version
	}
	return 0
}

func (x *TargetView) GetType() string {
	if x != nil {
		return x.Type
	}
	return ""
}

func (x *TargetView) GetDefaultPort() uint32 {
	if x != nil {
		return x.DefaultPort
	}
	return 0
}

func (x *TargetView) GetSessionMaxSeconds() uint32 {
	if x != nil {
		return x.SessionMaxSeconds
	}
	return 0
}

func (x *TargetView) GetSessionConnectionLimit() int32 {
	if x != nil {
		return x.SessionConnectionLimit
	}
	return 0
}

func (x *TargetView) GetWorkerFilter() string {
	if x != nil {
		return x.WorkerFilter
	}
	return ""
}

type TargetHostSet struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	// target_id of the TargetHostSet
	// @inject_tag: gorm:"primary_key"
	TargetId string `protobuf:"bytes,10,opt,name=target_id,json=targetId,proto3" json:"target_id,omitempty" gorm:"primary_key"`
	// host_set_id of the TargetHostSet
	// @inject_tag: gorm:"primary_key"
	HostSetId string `protobuf:"bytes,20,opt,name=host_set_id,json=hostSetId,proto3" json:"host_set_id,omitempty" gorm:"primary_key"`
	// create_time from the RDBMS
	// @inject_tag: `gorm:"default:current_timestamp"`
	CreateTime *timestamp.Timestamp `protobuf:"bytes,30,opt,name=create_time,json=createTime,proto3" json:"create_time,omitempty" gorm:"default:current_timestamp"`
}

func (x *TargetHostSet) Reset() {
	*x = TargetHostSet{}
	if protoimpl.UnsafeEnabled {
		mi := &file_controller_storage_target_store_v1_target_proto_msgTypes[1]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *TargetHostSet) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*TargetHostSet) ProtoMessage() {}

func (x *TargetHostSet) ProtoReflect() protoreflect.Message {
	mi := &file_controller_storage_target_store_v1_target_proto_msgTypes[1]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use TargetHostSet.ProtoReflect.Descriptor instead.
func (*TargetHostSet) Descriptor() ([]byte, []int) {
	return file_controller_storage_target_store_v1_target_proto_rawDescGZIP(), []int{1}
}

func (x *TargetHostSet) GetTargetId() string {
	if x != nil {
		return x.TargetId
	}
	return ""
}

func (x *TargetHostSet) GetHostSetId() string {
	if x != nil {
		return x.HostSetId
	}
	return ""
}

func (x *TargetHostSet) GetCreateTime() *timestamp.Timestamp {
	if x != nil {
		return x.CreateTime
	}
	return nil
}

type TcpTarget struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	// public_id is used to access the TargetTcp via an API
	// @inject_tag: gorm:"primary_key"
	PublicId string `protobuf:"bytes,10,opt,name=public_id,json=publicId,proto3" json:"public_id,omitempty" gorm:"primary_key"`
	// scope id for the TargetTcp
	// @inject_tag: `gorm:"default:null"`
	ScopeId string `protobuf:"bytes,20,opt,name=scope_id,json=scopeId,proto3" json:"scope_id,omitempty" gorm:"default:null"`
	// name is the optional friendly name used to
	// access the TargetTcp via an API
	// @inject_tag: `gorm:"default:null"`
	Name string `protobuf:"bytes,30,opt,name=name,proto3" json:"name,omitempty" gorm:"default:null"`
	// description of the TargetTcp
	// @inject_tag: `gorm:"default:null"`
	Description string `protobuf:"bytes,40,opt,name=description,proto3" json:"description,omitempty" gorm:"default:null"`
	// create_time from the RDBMS
	// @inject_tag: `gorm:"default:current_timestamp"`
	CreateTime *timestamp.Timestamp `protobuf:"bytes,50,opt,name=create_time,json=createTime,proto3" json:"create_time,omitempty" gorm:"default:current_timestamp"`
	// update_time from the RDBMS
	// @inject_tag: `gorm:"default:current_timestamp"`
	UpdateTime *timestamp.Timestamp `protobuf:"bytes,60,opt,name=update_time,json=updateTime,proto3" json:"update_time,omitempty" gorm:"default:current_timestamp"`
	// version allows optimistic locking of the TargetTcp when modifying the
	// TargetTcp
	// @inject_tag: `gorm:"default:null"`
	Version uint32 `protobuf:"varint,70,opt,name=version,proto3" json:"version,omitempty" gorm:"default:null"`
	// default port of the TargetTcp
	// @inject_tag: `gorm:"default:null"`
	DefaultPort uint32 `protobuf:"varint,80,opt,name=default_port,json=defaultPort,proto3" json:"default_port,omitempty" gorm:"default:null"`
	// Maximum total lifetime of a created session, in seconds
	// @inject_tag: `gorm:"default:null"`
	SessionMaxSeconds uint32 `protobuf:"varint,100,opt,name=session_max_seconds,json=sessionMaxSeconds,proto3" json:"session_max_seconds,omitempty" gorm:"default:null"`
	// Maximum number of connections in a session
	// @inject_tag: `gorm:"default:null"`
	SessionConnectionLimit int32 `protobuf:"varint,110,opt,name=session_connection_limit,json=sessionConnectionLimit,proto3" json:"session_connection_limit,omitempty" gorm:"default:null"`
	// A boolean expression that allows filtering the workers that can handle a session
	// @inject_tag: `gorm:"default:null"`
	WorkerFilter string `protobuf:"bytes,120,opt,name=worker_filter,json=workerFilter,proto3" json:"worker_filter,omitempty" gorm:"default:null"`
}

func (x *TcpTarget) Reset() {
	*x = TcpTarget{}
	if protoimpl.UnsafeEnabled {
		mi := &file_controller_storage_target_store_v1_target_proto_msgTypes[2]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *TcpTarget) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*TcpTarget) ProtoMessage() {}

func (x *TcpTarget) ProtoReflect() protoreflect.Message {
	mi := &file_controller_storage_target_store_v1_target_proto_msgTypes[2]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use TcpTarget.ProtoReflect.Descriptor instead.
func (*TcpTarget) Descriptor() ([]byte, []int) {
	return file_controller_storage_target_store_v1_target_proto_rawDescGZIP(), []int{2}
}

func (x *TcpTarget) GetPublicId() string {
	if x != nil {
		return x.PublicId
	}
	return ""
}

func (x *TcpTarget) GetScopeId() string {
	if x != nil {
		return x.ScopeId
	}
	return ""
}

func (x *TcpTarget) GetName() string {
	if x != nil {
		return x.Name
	}
	return ""
}

func (x *TcpTarget) GetDescription() string {
	if x != nil {
		return x.Description
	}
	return ""
}

func (x *TcpTarget) GetCreateTime() *timestamp.Timestamp {
	if x != nil {
		return x.CreateTime
	}
	return nil
}

func (x *TcpTarget) GetUpdateTime() *timestamp.Timestamp {
	if x != nil {
		return x.UpdateTime
	}
	return nil
}

func (x *TcpTarget) GetVersion() uint32 {
	if x != nil {
		return x.Version
	}
	return 0
}

func (x *TcpTarget) GetDefaultPort() uint32 {
	if x != nil {
		return x.DefaultPort
	}
	return 0
}

func (x *TcpTarget) GetSessionMaxSeconds() uint32 {
	if x != nil {
		return x.SessionMaxSeconds
	}
	return 0
}

func (x *TcpTarget) GetSessionConnectionLimit() int32 {
	if x != nil {
		return x.SessionConnectionLimit
	}
	return 0
}

func (x *TcpTarget) GetWorkerFilter() string {
	if x != nil {
		return x.WorkerFilter
	}
	return ""
}

type CredentialLibrary struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	// target_id of the Target
	// @inject_tag: gorm:"primary_key"
	TargetId string `protobuf:"bytes,10,opt,name=target_id,json=targetId,proto3" json:"target_id,omitempty" gorm:"primary_key"`
	// credential_library_id of the CredentialLibrary
	// @inject_tag: gorm:"primary_key"
	CredentialLibraryId string `protobuf:"bytes,20,opt,name=credential_library_id,json=credentialLibraryId,proto3" json:"credential_library_id,omitempty" gorm:"primary_key"`
	// credential_purpose is the purpose of the credential for the target
	// @inject_tag: gorm:"primary_key"
	CredentialPurpose string `protobuf:"bytes,30,opt,name=credential_purpose,json=credentialPurpose,proto3" json:"credential_purpose,omitempty" gorm:"primary_key"`
	// create_time from the RDBMS
	// @inject_tag: `gorm:"default:current_timestamp"`
	CreateTime *timestamp.Timestamp `protobuf:"bytes,40,opt,name=create_time,json=createTime,proto3" json:"create_time,omitempty" gorm:"default:current_timestamp"`
}

func (x *CredentialLibrary) Reset() {
	*x = CredentialLibrary{}
	if protoimpl.UnsafeEnabled {
		mi := &file_controller_storage_target_store_v1_target_proto_msgTypes[3]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *CredentialLibrary) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*CredentialLibrary) ProtoMessage() {}

func (x *CredentialLibrary) ProtoReflect() protoreflect.Message {
	mi := &file_controller_storage_target_store_v1_target_proto_msgTypes[3]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use CredentialLibrary.ProtoReflect.Descriptor instead.
func (*CredentialLibrary) Descriptor() ([]byte, []int) {
	return file_controller_storage_target_store_v1_target_proto_rawDescGZIP(), []int{3}
}

func (x *CredentialLibrary) GetTargetId() string {
	if x != nil {
		return x.TargetId
	}
	return ""
}

func (x *CredentialLibrary) GetCredentialLibraryId() string {
	if x != nil {
		return x.CredentialLibraryId
	}
	return ""
}

func (x *CredentialLibrary) GetCredentialPurpose() string {
	if x != nil {
		return x.CredentialPurpose
	}
	return ""
}

func (x *CredentialLibrary) GetCreateTime() *timestamp.Timestamp {
	if x != nil {
		return x.CreateTime
	}
	return nil
}

var File_controller_storage_target_store_v1_target_proto protoreflect.FileDescriptor

var file_controller_storage_target_store_v1_target_proto_rawDesc = []byte{
	0x0a, 0x2f, 0x63, 0x6f, 0x6e, 0x74, 0x72, 0x6f, 0x6c, 0x6c, 0x65, 0x72, 0x2f, 0x73, 0x74, 0x6f,
	0x72, 0x61, 0x67, 0x65, 0x2f, 0x74, 0x61, 0x72, 0x67, 0x65, 0x74, 0x2f, 0x73, 0x74, 0x6f, 0x72,
	0x65, 0x2f, 0x76, 0x31, 0x2f, 0x74, 0x61, 0x72, 0x67, 0x65, 0x74, 0x2e, 0x70, 0x72, 0x6f, 0x74,
	0x6f, 0x12, 0x22, 0x63, 0x6f, 0x6e, 0x74, 0x72, 0x6f, 0x6c, 0x6c, 0x65, 0x72, 0x2e, 0x73, 0x74,
	0x6f, 0x72, 0x61, 0x67, 0x65, 0x2e, 0x74, 0x61, 0x72, 0x67, 0x65, 0x74, 0x2e, 0x73, 0x74, 0x6f,
	0x72, 0x65, 0x2e, 0x76, 0x31, 0x1a, 0x2f, 0x63, 0x6f, 0x6e, 0x74, 0x72, 0x6f, 0x6c, 0x6c, 0x65,
	0x72, 0x2f, 0x73, 0x74, 0x6f, 0x72, 0x61, 0x67, 0x65, 0x2f, 0x74, 0x69, 0x6d, 0x65, 0x73, 0x74,
	0x61, 0x6d, 0x70, 0x2f, 0x76, 0x31, 0x2f, 0x74, 0x69, 0x6d, 0x65, 0x73, 0x74, 0x61, 0x6d, 0x70,
	0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x1a, 0x2a, 0x63, 0x6f, 0x6e, 0x74, 0x72, 0x6f, 0x6c, 0x6c,
	0x65, 0x72, 0x2f, 0x63, 0x75, 0x73, 0x74, 0x6f, 0x6d, 0x5f, 0x6f, 0x70, 0x74, 0x69, 0x6f, 0x6e,
	0x73, 0x2f, 0x76, 0x31, 0x2f, 0x6f, 0x70, 0x74, 0x69, 0x6f, 0x6e, 0x73, 0x2e, 0x70, 0x72, 0x6f,
	0x74, 0x6f, 0x22, 0xf4, 0x03, 0x0a, 0x0a, 0x54, 0x61, 0x72, 0x67, 0x65, 0x74, 0x56, 0x69, 0x65,
	0x77, 0x12, 0x1b, 0x0a, 0x09, 0x70, 0x75, 0x62, 0x6c, 0x69, 0x63, 0x5f, 0x69, 0x64, 0x18, 0x0a,
	0x20, 0x01, 0x28, 0x09, 0x52, 0x08, 0x70, 0x75, 0x62, 0x6c, 0x69, 0x63, 0x49, 0x64, 0x12, 0x19,
	0x0a, 0x08, 0x73, 0x63, 0x6f, 0x70, 0x65, 0x5f, 0x69, 0x64, 0x18, 0x14, 0x20, 0x01, 0x28, 0x09,
	0x52, 0x07, 0x73, 0x63, 0x6f, 0x70, 0x65, 0x49, 0x64, 0x12, 0x12, 0x0a, 0x04, 0x6e, 0x61, 0x6d,
	0x65, 0x18, 0x1e, 0x20, 0x01, 0x28, 0x09, 0x52, 0x04, 0x6e, 0x61, 0x6d, 0x65, 0x12, 0x20, 0x0a,
	0x0b, 0x64, 0x65, 0x73, 0x63, 0x72, 0x69, 0x70, 0x74, 0x69, 0x6f, 0x6e, 0x18, 0x28, 0x20, 0x01,
	0x28, 0x09, 0x52, 0x0b, 0x64, 0x65, 0x73, 0x63, 0x72, 0x69, 0x70, 0x74, 0x69, 0x6f, 0x6e, 0x12,
	0x4b, 0x0a, 0x0b, 0x63, 0x72, 0x65, 0x61, 0x74, 0x65, 0x5f, 0x74, 0x69, 0x6d, 0x65, 0x18, 0x32,
	0x20, 0x01, 0x28, 0x0b, 0x32, 0x2a, 0x2e, 0x63, 0x6f, 0x6e, 0x74, 0x72, 0x6f, 0x6c, 0x6c, 0x65,
	0x72, 0x2e, 0x73, 0x74, 0x6f, 0x72, 0x61, 0x67, 0x65, 0x2e, 0x74, 0x69, 0x6d, 0x65, 0x73, 0x74,
	0x61, 0x6d, 0x70, 0x2e, 0x76, 0x31, 0x2e, 0x54, 0x69, 0x6d, 0x65, 0x73, 0x74, 0x61, 0x6d, 0x70,
	0x52, 0x0a, 0x63, 0x72, 0x65, 0x61, 0x74, 0x65, 0x54, 0x69, 0x6d, 0x65, 0x12, 0x4b, 0x0a, 0x0b,
	0x75, 0x70, 0x64, 0x61, 0x74, 0x65, 0x5f, 0x74, 0x69, 0x6d, 0x65, 0x18, 0x3c, 0x20, 0x01, 0x28,
	0x0b, 0x32, 0x2a, 0x2e, 0x63, 0x6f, 0x6e, 0x74, 0x72, 0x6f, 0x6c, 0x6c, 0x65, 0x72, 0x2e, 0x73,
	0x74, 0x6f, 0x72, 0x61, 0x67, 0x65, 0x2e, 0x74, 0x69, 0x6d, 0x65, 0x73, 0x74, 0x61, 0x6d, 0x70,
	0x2e, 0x76, 0x31, 0x2e, 0x54, 0x69, 0x6d, 0x65, 0x73, 0x74, 0x61, 0x6d, 0x70, 0x52, 0x0a, 0x75,
	0x70, 0x64, 0x61, 0x74, 0x65, 0x54, 0x69, 0x6d, 0x65, 0x12, 0x18, 0x0a, 0x07, 0x76, 0x65, 0x72,
	0x73, 0x69, 0x6f, 0x6e, 0x18, 0x46, 0x20, 0x01, 0x28, 0x0d, 0x52, 0x07, 0x76, 0x65, 0x72, 0x73,
	0x69, 0x6f, 0x6e, 0x12, 0x12, 0x0a, 0x04, 0x74, 0x79, 0x70, 0x65, 0x18, 0x50, 0x20, 0x01, 0x28,
	0x09, 0x52, 0x04, 0x74, 0x79, 0x70, 0x65, 0x12, 0x21, 0x0a, 0x0c, 0x64, 0x65, 0x66, 0x61, 0x75,
	0x6c, 0x74, 0x5f, 0x70, 0x6f, 0x72, 0x74, 0x18, 0x5a, 0x20, 0x01, 0x28, 0x0d, 0x52, 0x0b, 0x64,
	0x65, 0x66, 0x61, 0x75, 0x6c, 0x74, 0x50, 0x6f, 0x72, 0x74, 0x12, 0x2e, 0x0a, 0x13, 0x73, 0x65,
	0x73, 0x73, 0x69, 0x6f, 0x6e, 0x5f, 0x6d, 0x61, 0x78, 0x5f, 0x73, 0x65, 0x63, 0x6f, 0x6e, 0x64,
	0x73, 0x18, 0x64, 0x20, 0x01, 0x28, 0x0d, 0x52, 0x11, 0x73, 0x65, 0x73, 0x73, 0x69, 0x6f, 0x6e,
	0x4d, 0x61, 0x78, 0x53, 0x65, 0x63, 0x6f, 0x6e, 0x64, 0x73, 0x12, 0x38, 0x0a, 0x18, 0x73, 0x65,
	0x73, 0x73, 0x69, 0x6f, 0x6e, 0x5f, 0x63, 0x6f, 0x6e, 0x6e, 0x65, 0x63, 0x74, 0x69, 0x6f, 0x6e,
	0x5f, 0x6c, 0x69, 0x6d, 0x69, 0x74, 0x18, 0x6e, 0x20, 0x01, 0x28, 0x05, 0x52, 0x16, 0x73, 0x65,
	0x73, 0x73, 0x69, 0x6f, 0x6e, 0x43, 0x6f, 0x6e, 0x6e, 0x65, 0x63, 0x74, 0x69, 0x6f, 0x6e, 0x4c,
	0x69, 0x6d, 0x69, 0x74, 0x12, 0x23, 0x0a, 0x0d, 0x77, 0x6f, 0x72, 0x6b, 0x65, 0x72, 0x5f, 0x66,
	0x69, 0x6c, 0x74, 0x65, 0x72, 0x18, 0x78, 0x20, 0x01, 0x28, 0x09, 0x52, 0x0c, 0x77, 0x6f, 0x72,
	0x6b, 0x65, 0x72, 0x46, 0x69, 0x6c, 0x74, 0x65, 0x72, 0x22, 0x99, 0x01, 0x0a, 0x0d, 0x54, 0x61,
	0x72, 0x67, 0x65, 0x74, 0x48, 0x6f, 0x73, 0x74, 0x53, 0x65, 0x74, 0x12, 0x1b, 0x0a, 0x09, 0x74,
	0x61, 0x72, 0x67, 0x65, 0x74, 0x5f, 0x69, 0x64, 0x18, 0x0a, 0x20, 0x01, 0x28, 0x09, 0x52, 0x08,
	0x74, 0x61, 0x72, 0x67, 0x65, 0x74, 0x49, 0x64, 0x12, 0x1e, 0x0a, 0x0b, 0x68, 0x6f, 0x73, 0x74,
	0x5f, 0x73, 0x65, 0x74, 0x5f, 0x69, 0x64, 0x18, 0x14, 0x20, 0x01, 0x28, 0x09, 0x52, 0x09, 0x68,
	0x6f, 0x73, 0x74, 0x53, 0x65, 0x74, 0x49, 0x64, 0x12, 0x4b, 0x0a, 0x0b, 0x63, 0x72, 0x65, 0x61,
	0x74, 0x65, 0x5f, 0x74, 0x69, 0x6d, 0x65, 0x18, 0x1e, 0x20, 0x01, 0x28, 0x0b, 0x32, 0x2a, 0x2e,
	0x63, 0x6f, 0x6e, 0x74, 0x72, 0x6f, 0x6c, 0x6c, 0x65, 0x72, 0x2e, 0x73, 0x74, 0x6f, 0x72, 0x61,
	0x67, 0x65, 0x2e, 0x74, 0x69, 0x6d, 0x65, 0x73, 0x74, 0x61, 0x6d, 0x70, 0x2e, 0x76, 0x31, 0x2e,
	0x54, 0x69, 0x6d, 0x65, 0x73, 0x74, 0x61, 0x6d, 0x70, 0x52, 0x0a, 0x63, 0x72, 0x65, 0x61, 0x74,
	0x65, 0x54, 0x69, 0x6d, 0x65, 0x22, 0xc6, 0x05, 0x0a, 0x09, 0x54, 0x63, 0x70, 0x54, 0x61, 0x72,
	0x67, 0x65, 0x74, 0x12, 0x1b, 0x0a, 0x09, 0x70, 0x75, 0x62, 0x6c, 0x69, 0x63, 0x5f, 0x69, 0x64,
	0x18, 0x0a, 0x20, 0x01, 0x28, 0x09, 0x52, 0x08, 0x70, 0x75, 0x62, 0x6c, 0x69, 0x63, 0x49, 0x64,
	0x12, 0x19, 0x0a, 0x08, 0x73, 0x63, 0x6f, 0x70, 0x65, 0x5f, 0x69, 0x64, 0x18, 0x14, 0x20, 0x01,
	0x28, 0x09, 0x52, 0x07, 0x73, 0x63, 0x6f, 0x70, 0x65, 0x49, 0x64, 0x12, 0x24, 0x0a, 0x04, 0x6e,
	0x61, 0x6d, 0x65, 0x18, 0x1e, 0x20, 0x01, 0x28, 0x09, 0x42, 0x10, 0xc2, 0xdd, 0x29, 0x0c, 0x0a,
	0x04, 0x6e, 0x61, 0x6d, 0x65, 0x12, 0x04, 0x6e, 0x61, 0x6d, 0x65, 0x52, 0x04, 0x6e, 0x61, 0x6d,
	0x65, 0x12, 0x40, 0x0a, 0x0b, 0x64, 0x65, 0x73, 0x63, 0x72, 0x69, 0x70, 0x74, 0x69, 0x6f, 0x6e,
	0x18, 0x28, 0x20, 0x01, 0x28, 0x09, 0x42, 0x1e, 0xc2, 0xdd, 0x29, 0x1a, 0x0a, 0x0b, 0x64, 0x65,
	0x73, 0x63, 0x72, 0x69, 0x70, 0x74, 0x69, 0x6f, 0x6e, 0x12, 0x0b, 0x64, 0x65, 0x73, 0x63, 0x72,
	0x69, 0x70, 0x74, 0x69, 0x6f, 0x6e, 0x52, 0x0b, 0x64, 0x65, 0x73, 0x63, 0x72, 0x69, 0x70, 0x74,
	0x69, 0x6f, 0x6e, 0x12, 0x4b, 0x0a, 0x0b, 0x63, 0x72, 0x65, 0x61, 0x74, 0x65, 0x5f, 0x74, 0x69,
	0x6d, 0x65, 0x18, 0x32, 0x20, 0x01, 0x28, 0x0b, 0x32, 0x2a, 0x2e, 0x63, 0x6f, 0x6e, 0x74, 0x72,
	0x6f, 0x6c, 0x6c, 0x65, 0x72, 0x2e, 0x73, 0x74, 0x6f, 0x72, 0x61, 0x67, 0x65, 0x2e, 0x74, 0x69,
	0x6d, 0x65, 0x73, 0x74, 0x61, 0x6d, 0x70, 0x2e, 0x76, 0x31, 0x2e, 0x54, 0x69, 0x6d, 0x65, 0x73,
	0x74, 0x61, 0x6d, 0x70, 0x52, 0x0a, 0x63, 0x72, 0x65, 0x61, 0x74, 0x65, 0x54, 0x69, 0x6d, 0x65,
	0x12, 0x4b, 0x0a, 0x0b, 0x75, 0x70, 0x64, 0x61, 0x74, 0x65, 0x5f, 0x74, 0x69, 0x6d, 0x65, 0x18,
	0x3c, 0x20, 0x01, 0x28, 0x0b, 0x32, 0x2a, 0x2e, 0x63, 0x6f, 0x6e, 0x74, 0x72, 0x6f, 0x6c, 0x6c,
	0x65, 0x72, 0x2e, 0x73, 0x74, 0x6f, 0x72, 0x61, 0x67, 0x65, 0x2e, 0x74, 0x69, 0x6d, 0x65, 0x73,
	0x74, 0x61, 0x6d, 0x70, 0x2e, 0x76, 0x31, 0x2e, 0x54, 0x69, 0x6d, 0x65, 0x73, 0x74, 0x61, 0x6d,
	0x70, 0x52, 0x0a, 0x75, 0x70, 0x64, 0x61, 0x74, 0x65, 0x54, 0x69, 0x6d, 0x65, 0x12, 0x18, 0x0a,
	0x07, 0x76, 0x65, 0x72, 0x73, 0x69, 0x6f, 0x6e, 0x18, 0x46, 0x20, 0x01, 0x28, 0x0d, 0x52, 0x07,
	0x76, 0x65, 0x72, 0x73, 0x69, 0x6f, 0x6e, 0x12, 0x4d, 0x0a, 0x0c, 0x64, 0x65, 0x66, 0x61, 0x75,
	0x6c, 0x74, 0x5f, 0x70, 0x6f, 0x72, 0x74, 0x18, 0x50, 0x20, 0x01, 0x28, 0x0d, 0x42, 0x2a, 0xc2,
	0xdd, 0x29, 0x26, 0x0a, 0x0b, 0x44, 0x65, 0x66, 0x61, 0x75, 0x6c, 0x74, 0x50, 0x6f, 0x72, 0x74,
	0x12, 0x17, 0x61, 0x74, 0x74, 0x72, 0x69, 0x62, 0x75, 0x74, 0x65, 0x73, 0x2e, 0x64, 0x65, 0x66,
	0x61, 0x75, 0x6c, 0x74, 0x5f, 0x70, 0x6f, 0x72, 0x74, 0x52, 0x0b, 0x64, 0x65, 0x66, 0x61, 0x75,
	0x6c, 0x74, 0x50, 0x6f, 0x72, 0x74, 0x12, 0x5c, 0x0a, 0x13, 0x73, 0x65, 0x73, 0x73, 0x69, 0x6f,
	0x6e, 0x5f, 0x6d, 0x61, 0x78, 0x5f, 0x73, 0x65, 0x63, 0x6f, 0x6e, 0x64, 0x73, 0x18, 0x64, 0x20,
	0x01, 0x28, 0x0d, 0x42, 0x2c, 0xc2, 0xdd, 0x29, 0x28, 0x0a, 0x11, 0x53, 0x65, 0x73, 0x73, 0x69,
	0x6f, 0x6e, 0x4d, 0x61, 0x78, 0x53, 0x65, 0x63, 0x6f, 0x6e, 0x64, 0x73, 0x12, 0x13, 0x73, 0x65,
	0x73, 0x73, 0x69, 0x6f, 0x6e, 0x5f, 0x6d, 0x61, 0x78, 0x5f, 0x73, 0x65, 0x63, 0x6f, 0x6e, 0x64,
	0x73, 0x52, 0x11, 0x73, 0x65, 0x73, 0x73, 0x69, 0x6f, 0x6e, 0x4d, 0x61, 0x78, 0x53, 0x65, 0x63,
	0x6f, 0x6e, 0x64, 0x73, 0x12, 0x70, 0x0a, 0x18, 0x73, 0x65, 0x73, 0x73, 0x69, 0x6f, 0x6e, 0x5f,
	0x63, 0x6f, 0x6e, 0x6e, 0x65, 0x63, 0x74, 0x69, 0x6f, 0x6e, 0x5f, 0x6c, 0x69, 0x6d, 0x69, 0x74,
	0x18, 0x6e, 0x20, 0x01, 0x28, 0x05, 0x42, 0x36, 0xc2, 0xdd, 0x29, 0x32, 0x0a, 0x16, 0x53, 0x65,
	0x73, 0x73, 0x69, 0x6f, 0x6e, 0x43, 0x6f, 0x6e, 0x6e, 0x65, 0x63, 0x74, 0x69, 0x6f, 0x6e, 0x4c,
	0x69, 0x6d, 0x69, 0x74, 0x12, 0x18, 0x73, 0x65, 0x73, 0x73, 0x69, 0x6f, 0x6e, 0x5f, 0x63, 0x6f,
	0x6e, 0x6e, 0x65, 0x63, 0x74, 0x69, 0x6f, 0x6e, 0x5f, 0x6c, 0x69, 0x6d, 0x69, 0x74, 0x52, 0x16,
	0x73, 0x65, 0x73, 0x73, 0x69, 0x6f, 0x6e, 0x43, 0x6f, 0x6e, 0x6e, 0x65, 0x63, 0x74, 0x69, 0x6f,
	0x6e, 0x4c, 0x69, 0x6d, 0x69, 0x74, 0x12, 0x46, 0x0a, 0x0d, 0x77, 0x6f, 0x72, 0x6b, 0x65, 0x72,
	0x5f, 0x66, 0x69, 0x6c, 0x74, 0x65, 0x72, 0x18, 0x78, 0x20, 0x01, 0x28, 0x09, 0x42, 0x21, 0xc2,
	0xdd, 0x29, 0x1d, 0x0a, 0x0c, 0x57, 0x6f, 0x72, 0x6b, 0x65, 0x72, 0x46, 0x69, 0x6c, 0x74, 0x65,
	0x72, 0x12, 0x0d, 0x77, 0x6f, 0x72, 0x6b, 0x65, 0x72, 0x5f, 0x66, 0x69, 0x6c, 0x74, 0x65, 0x72,
	0x52, 0x0c, 0x77, 0x6f, 0x72, 0x6b, 0x65, 0x72, 0x46, 0x69, 0x6c, 0x74, 0x65, 0x72, 0x22, 0xe0,
	0x01, 0x0a, 0x11, 0x43, 0x72, 0x65, 0x64, 0x65, 0x6e, 0x74, 0x69, 0x61, 0x6c, 0x4c, 0x69, 0x62,
	0x72, 0x61, 0x72, 0x79, 0x12, 0x1b, 0x0a, 0x09, 0x74, 0x61, 0x72, 0x67, 0x65, 0x74, 0x5f, 0x69,
	0x64, 0x18, 0x0a, 0x20, 0x01, 0x28, 0x09, 0x52, 0x08, 0x74, 0x61, 0x72, 0x67, 0x65, 0x74, 0x49,
	0x64, 0x12, 0x32, 0x0a, 0x15, 0x63, 0x72, 0x65, 0x64, 0x65, 0x6e, 0x74, 0x69, 0x61, 0x6c, 0x5f,
	0x6c, 0x69, 0x62, 0x72, 0x61, 0x72, 0x79, 0x5f, 0x69, 0x64, 0x18, 0x14, 0x20, 0x01, 0x28, 0x09,
	0x52, 0x13, 0x63, 0x72, 0x65, 0x64, 0x65, 0x6e, 0x74, 0x69, 0x61, 0x6c, 0x4c, 0x69, 0x62, 0x72,
	0x61, 0x72, 0x79, 0x49, 0x64, 0x12, 0x2d, 0x0a, 0x12, 0x63, 0x72, 0x65, 0x64, 0x65, 0x6e, 0x74,
	0x69, 0x61, 0x6c, 0x5f, 0x70, 0x75, 0x72, 0x70, 0x6f, 0x73, 0x65, 0x18, 0x1e, 0x20, 0x01, 0x28,
	0x09, 0x52, 0x11, 0x63, 0x72, 0x65, 0x64, 0x65, 0x6e, 0x74, 0x69, 0x61, 0x6c, 0x50, 0x75, 0x72,
	0x70, 0x6f, 0x73, 0x65, 0x12, 0x4b, 0x0a, 0x0b, 0x63, 0x72, 0x65, 0x61, 0x74, 0x65, 0x5f, 0x74,
	0x69, 0x6d, 0x65, 0x18, 0x28, 0x20, 0x01, 0x28, 0x0b, 0x32, 0x2a, 0x2e, 0x63, 0x6f, 0x6e, 0x74,
	0x72, 0x6f, 0x6c, 0x6c, 0x65, 0x72, 0x2e, 0x73, 0x74, 0x6f, 0x72, 0x61, 0x67, 0x65, 0x2e, 0x74,
	0x69, 0x6d, 0x65, 0x73, 0x74, 0x61, 0x6d, 0x70, 0x2e, 0x76, 0x31, 0x2e, 0x54, 0x69, 0x6d, 0x65,
	0x73, 0x74, 0x61, 0x6d, 0x70, 0x52, 0x0a, 0x63, 0x72, 0x65, 0x61, 0x74, 0x65, 0x54, 0x69, 0x6d,
	0x65, 0x42, 0x3b, 0x5a, 0x39, 0x67, 0x69, 0x74, 0x68, 0x75, 0x62, 0x2e, 0x63, 0x6f, 0x6d, 0x2f,
	0x68, 0x61, 0x73, 0x68, 0x69, 0x63, 0x6f, 0x72, 0x70, 0x2f, 0x62, 0x6f, 0x75, 0x6e, 0x64, 0x61,
	0x72, 0x79, 0x2f, 0x69, 0x6e, 0x74, 0x65, 0x72, 0x6e, 0x61, 0x6c, 0x2f, 0x74, 0x61, 0x72, 0x67,
	0x65, 0x74, 0x2f, 0x73, 0x74, 0x6f, 0x72, 0x65, 0x3b, 0x73, 0x74, 0x6f, 0x72, 0x65, 0x62, 0x06,
	0x70, 0x72, 0x6f, 0x74, 0x6f, 0x33,
}

var (
	file_controller_storage_target_store_v1_target_proto_rawDescOnce sync.Once
	file_controller_storage_target_store_v1_target_proto_rawDescData = file_controller_storage_target_store_v1_target_proto_rawDesc
)

func file_controller_storage_target_store_v1_target_proto_rawDescGZIP() []byte {
	file_controller_storage_target_store_v1_target_proto_rawDescOnce.Do(func() {
		file_controller_storage_target_store_v1_target_proto_rawDescData = protoimpl.X.CompressGZIP(file_controller_storage_target_store_v1_target_proto_rawDescData)
	})
	return file_controller_storage_target_store_v1_target_proto_rawDescData
}

var file_controller_storage_target_store_v1_target_proto_msgTypes = make([]protoimpl.MessageInfo, 4)
var file_controller_storage_target_store_v1_target_proto_goTypes = []interface{}{
	(*TargetView)(nil),          // 0: controller.storage.target.store.v1.TargetView
	(*TargetHostSet)(nil),       // 1: controller.storage.target.store.v1.TargetHostSet
	(*TcpTarget)(nil),           // 2: controller.storage.target.store.v1.TcpTarget
	(*CredentialLibrary)(nil),   // 3: controller.storage.target.store.v1.CredentialLibrary
	(*timestamp.Timestamp)(nil), // 4: controller.storage.timestamp.v1.Timestamp
}
var file_controller_storage_target_store_v1_target_proto_depIdxs = []int32{
	4, // 0: controller.storage.target.store.v1.TargetView.create_time:type_name -> controller.storage.timestamp.v1.Timestamp
	4, // 1: controller.storage.target.store.v1.TargetView.update_time:type_name -> controller.storage.timestamp.v1.Timestamp
	4, // 2: controller.storage.target.store.v1.TargetHostSet.create_time:type_name -> controller.storage.timestamp.v1.Timestamp
	4, // 3: controller.storage.target.store.v1.TcpTarget.create_time:type_name -> controller.storage.timestamp.v1.Timestamp
	4, // 4: controller.storage.target.store.v1.TcpTarget.update_time:type_name -> controller.storage.timestamp.v1.Timestamp
	4, // 5: controller.storage.target.store.v1.CredentialLibrary.create_time:type_name -> controller.storage.timestamp.v1.Timestamp
	6, // [6:6] is the sub-list for method output_type
	6, // [6:6] is the sub-list for method input_type
	6, // [6:6] is the sub-list for extension type_name
	6, // [6:6] is the sub-list for extension extendee
	0, // [0:6] is the sub-list for field type_name
}

func init() { file_controller_storage_target_store_v1_target_proto_init() }
func file_controller_storage_target_store_v1_target_proto_init() {
	if File_controller_storage_target_store_v1_target_proto != nil {
		return
	}
	if !protoimpl.UnsafeEnabled {
		file_controller_storage_target_store_v1_target_proto_msgTypes[0].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*TargetView); i {
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
		file_controller_storage_target_store_v1_target_proto_msgTypes[1].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*TargetHostSet); i {
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
		file_controller_storage_target_store_v1_target_proto_msgTypes[2].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*TcpTarget); i {
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
		file_controller_storage_target_store_v1_target_proto_msgTypes[3].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*CredentialLibrary); i {
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
			RawDescriptor: file_controller_storage_target_store_v1_target_proto_rawDesc,
			NumEnums:      0,
			NumMessages:   4,
			NumExtensions: 0,
			NumServices:   0,
		},
		GoTypes:           file_controller_storage_target_store_v1_target_proto_goTypes,
		DependencyIndexes: file_controller_storage_target_store_v1_target_proto_depIdxs,
		MessageInfos:      file_controller_storage_target_store_v1_target_proto_msgTypes,
	}.Build()
	File_controller_storage_target_store_v1_target_proto = out.File
	file_controller_storage_target_store_v1_target_proto_rawDesc = nil
	file_controller_storage_target_store_v1_target_proto_goTypes = nil
	file_controller_storage_target_store_v1_target_proto_depIdxs = nil
}
