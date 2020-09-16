// Code generated by protoc-gen-go. DO NOT EDIT.
// versions:
// 	protoc-gen-go v1.25.0
// 	protoc        v3.12.4
// source: controller/api/resources/targets/v1/target.proto

package targets

import (
	proto "github.com/golang/protobuf/proto"
	_struct "github.com/golang/protobuf/ptypes/struct"
	timestamp "github.com/golang/protobuf/ptypes/timestamp"
	wrappers "github.com/golang/protobuf/ptypes/wrappers"
	scopes "github.com/hashicorp/boundary/internal/gen/controller/api/resources/scopes"
	sessions "github.com/hashicorp/boundary/internal/gen/controller/api/resources/sessions"
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

type HostSet struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	Id            string `protobuf:"bytes,10,opt,name=id,proto3" json:"id,omitempty"`
	HostCatalogId string `protobuf:"bytes,20,opt,name=host_catalog_id,json=hostCatalogId,proto3" json:"host_catalog_id,omitempty"`
}

func (x *HostSet) Reset() {
	*x = HostSet{}
	if protoimpl.UnsafeEnabled {
		mi := &file_controller_api_resources_targets_v1_target_proto_msgTypes[0]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *HostSet) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*HostSet) ProtoMessage() {}

func (x *HostSet) ProtoReflect() protoreflect.Message {
	mi := &file_controller_api_resources_targets_v1_target_proto_msgTypes[0]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use HostSet.ProtoReflect.Descriptor instead.
func (*HostSet) Descriptor() ([]byte, []int) {
	return file_controller_api_resources_targets_v1_target_proto_rawDescGZIP(), []int{0}
}

func (x *HostSet) GetId() string {
	if x != nil {
		return x.Id
	}
	return ""
}

func (x *HostSet) GetHostCatalogId() string {
	if x != nil {
		return x.HostCatalogId
	}
	return ""
}

// Target contains all fields related to a Target resource
type Target struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	// The ID of the resource
	// Output only.
	Id string `protobuf:"bytes,10,opt,name=id,proto3" json:"id,omitempty"`
	// The id of the parent of this resource.  This must be defined for creation of this resource, but is otherwise
	// read only.
	ScopeId string `protobuf:"bytes,20,opt,name=scope_id,proto3" json:"scope_id,omitempty"`
	// Scope information for this resource
	// Output only.
	Scope *scopes.ScopeInfo `protobuf:"bytes,30,opt,name=scope,proto3" json:"scope,omitempty"`
	// Required name for identification purposes
	Name *wrappers.StringValue `protobuf:"bytes,40,opt,name=name,proto3" json:"name,omitempty"`
	// Optional user-set description for identification purposes
	Description *wrappers.StringValue `protobuf:"bytes,50,opt,name=description,proto3" json:"description,omitempty"`
	// The time this resource was created
	// Output only.
	CreatedTime *timestamp.Timestamp `protobuf:"bytes,60,opt,name=created_time,proto3" json:"created_time,omitempty"`
	// The time this resource was last updated.
	// Output only.
	UpdatedTime *timestamp.Timestamp `protobuf:"bytes,70,opt,name=updated_time,proto3" json:"updated_time,omitempty"`
	// The version can be used in subsequent write requests to ensure this
	// resource has not changed and to fail the write if it has.
	Version uint32 `protobuf:"varint,80,opt,name=version,proto3" json:"version,omitempty"`
	Type    string `protobuf:"bytes,90,opt,name=type,proto3" json:"type,omitempty"`
	// The ids of the host sets that make up this target.
	HostSetIds []string `protobuf:"bytes,100,rep,name=host_set_ids,json=hostSetIds,proto3" json:"host_set_ids,omitempty"`
	// The host sets that make up this target.
	// Output only.
	HostSets []*HostSet `protobuf:"bytes,110,rep,name=host_sets,json=hostSets,proto3" json:"host_sets,omitempty"`
	// The attributes that are applied for the specific Target type.
	Attributes *_struct.Struct `protobuf:"bytes,120,opt,name=attributes,proto3" json:"attributes,omitempty"`
}

func (x *Target) Reset() {
	*x = Target{}
	if protoimpl.UnsafeEnabled {
		mi := &file_controller_api_resources_targets_v1_target_proto_msgTypes[1]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *Target) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*Target) ProtoMessage() {}

func (x *Target) ProtoReflect() protoreflect.Message {
	mi := &file_controller_api_resources_targets_v1_target_proto_msgTypes[1]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use Target.ProtoReflect.Descriptor instead.
func (*Target) Descriptor() ([]byte, []int) {
	return file_controller_api_resources_targets_v1_target_proto_rawDescGZIP(), []int{1}
}

func (x *Target) GetId() string {
	if x != nil {
		return x.Id
	}
	return ""
}

func (x *Target) GetScopeId() string {
	if x != nil {
		return x.ScopeId
	}
	return ""
}

func (x *Target) GetScope() *scopes.ScopeInfo {
	if x != nil {
		return x.Scope
	}
	return nil
}

func (x *Target) GetName() *wrappers.StringValue {
	if x != nil {
		return x.Name
	}
	return nil
}

func (x *Target) GetDescription() *wrappers.StringValue {
	if x != nil {
		return x.Description
	}
	return nil
}

func (x *Target) GetCreatedTime() *timestamp.Timestamp {
	if x != nil {
		return x.CreatedTime
	}
	return nil
}

func (x *Target) GetUpdatedTime() *timestamp.Timestamp {
	if x != nil {
		return x.UpdatedTime
	}
	return nil
}

func (x *Target) GetVersion() uint32 {
	if x != nil {
		return x.Version
	}
	return 0
}

func (x *Target) GetType() string {
	if x != nil {
		return x.Type
	}
	return ""
}

func (x *Target) GetHostSetIds() []string {
	if x != nil {
		return x.HostSetIds
	}
	return nil
}

func (x *Target) GetHostSets() []*HostSet {
	if x != nil {
		return x.HostSets
	}
	return nil
}

func (x *Target) GetAttributes() *_struct.Struct {
	if x != nil {
		return x.Attributes
	}
	return nil
}

type TcpTargetAttributes struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	DefaultPort *wrappers.UInt32Value `protobuf:"bytes,10,opt,name=default_port,json=defaultPort,proto3" json:"default_port,omitempty"`
}

func (x *TcpTargetAttributes) Reset() {
	*x = TcpTargetAttributes{}
	if protoimpl.UnsafeEnabled {
		mi := &file_controller_api_resources_targets_v1_target_proto_msgTypes[2]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *TcpTargetAttributes) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*TcpTargetAttributes) ProtoMessage() {}

func (x *TcpTargetAttributes) ProtoReflect() protoreflect.Message {
	mi := &file_controller_api_resources_targets_v1_target_proto_msgTypes[2]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use TcpTargetAttributes.ProtoReflect.Descriptor instead.
func (*TcpTargetAttributes) Descriptor() ([]byte, []int) {
	return file_controller_api_resources_targets_v1_target_proto_rawDescGZIP(), []int{2}
}

func (x *TcpTargetAttributes) GetDefaultPort() *wrappers.UInt32Value {
	if x != nil {
		return x.DefaultPort
	}
	return nil
}

// SessionAuthorization contains all fields related to authorization for a
// session. It's in the Targets API because it's returned by a target authorize
// action.
type SessionAuthorization struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	// The ID of the resource
	// Output only.
	SessionId string `protobuf:"bytes,10,opt,name=session_id,json=sessionId,proto3" json:"session_id,omitempty"`
	// The id of the target authorizing this session. This must be defined for
	// creation of this resource, but is otherwise read only.
	TargetId string `protobuf:"bytes,20,opt,name=target_id,proto3" json:"target_id,omitempty"`
	// Scope information for this resource
	// Output only.
	Scope *scopes.ScopeInfo `protobuf:"bytes,30,opt,name=scope,proto3" json:"scope,omitempty"`
	// The time this resource was created
	// Output only.
	CreatedTime *timestamp.Timestamp `protobuf:"bytes,40,opt,name=created_time,proto3" json:"created_time,omitempty"`
	// Type of the session (e.g. tcp, ssh, etc.)
	Type string `protobuf:"bytes,80,opt,name=type,proto3" json:"type,omitempty"`
	// The certificate to use when connecting (or if using custom certs, to
	// serve as the "login"). Raw DER bytes.
	Certificate []byte `protobuf:"bytes,120,opt,name=certificate,proto3" json:"certificate,omitempty"`
	// The private key to use when connecting (or if using custom certs, to pass
	// as the "password"). We are using Ed25519 so this is purely raw bytes, no
	// marshaling.
	PrivateKey []byte `protobuf:"bytes,130,opt,name=private_key,proto3" json:"private_key,omitempty"`
	// Worker information. The first worker in the array should be prioritized.
	WorkerInfo []*sessions.WorkerInfo `protobuf:"bytes,150,rep,name=worker_info,proto3" json:"worker_info,omitempty"`
}

func (x *SessionAuthorization) Reset() {
	*x = SessionAuthorization{}
	if protoimpl.UnsafeEnabled {
		mi := &file_controller_api_resources_targets_v1_target_proto_msgTypes[3]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *SessionAuthorization) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*SessionAuthorization) ProtoMessage() {}

func (x *SessionAuthorization) ProtoReflect() protoreflect.Message {
	mi := &file_controller_api_resources_targets_v1_target_proto_msgTypes[3]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use SessionAuthorization.ProtoReflect.Descriptor instead.
func (*SessionAuthorization) Descriptor() ([]byte, []int) {
	return file_controller_api_resources_targets_v1_target_proto_rawDescGZIP(), []int{3}
}

func (x *SessionAuthorization) GetSessionId() string {
	if x != nil {
		return x.SessionId
	}
	return ""
}

func (x *SessionAuthorization) GetTargetId() string {
	if x != nil {
		return x.TargetId
	}
	return ""
}

func (x *SessionAuthorization) GetScope() *scopes.ScopeInfo {
	if x != nil {
		return x.Scope
	}
	return nil
}

func (x *SessionAuthorization) GetCreatedTime() *timestamp.Timestamp {
	if x != nil {
		return x.CreatedTime
	}
	return nil
}

func (x *SessionAuthorization) GetType() string {
	if x != nil {
		return x.Type
	}
	return ""
}

func (x *SessionAuthorization) GetCertificate() []byte {
	if x != nil {
		return x.Certificate
	}
	return nil
}

func (x *SessionAuthorization) GetPrivateKey() []byte {
	if x != nil {
		return x.PrivateKey
	}
	return nil
}

func (x *SessionAuthorization) GetWorkerInfo() []*sessions.WorkerInfo {
	if x != nil {
		return x.WorkerInfo
	}
	return nil
}

var File_controller_api_resources_targets_v1_target_proto protoreflect.FileDescriptor

var file_controller_api_resources_targets_v1_target_proto_rawDesc = []byte{
	0x0a, 0x30, 0x63, 0x6f, 0x6e, 0x74, 0x72, 0x6f, 0x6c, 0x6c, 0x65, 0x72, 0x2f, 0x61, 0x70, 0x69,
	0x2f, 0x72, 0x65, 0x73, 0x6f, 0x75, 0x72, 0x63, 0x65, 0x73, 0x2f, 0x74, 0x61, 0x72, 0x67, 0x65,
	0x74, 0x73, 0x2f, 0x76, 0x31, 0x2f, 0x74, 0x61, 0x72, 0x67, 0x65, 0x74, 0x2e, 0x70, 0x72, 0x6f,
	0x74, 0x6f, 0x12, 0x23, 0x63, 0x6f, 0x6e, 0x74, 0x72, 0x6f, 0x6c, 0x6c, 0x65, 0x72, 0x2e, 0x61,
	0x70, 0x69, 0x2e, 0x72, 0x65, 0x73, 0x6f, 0x75, 0x72, 0x63, 0x65, 0x73, 0x2e, 0x74, 0x61, 0x72,
	0x67, 0x65, 0x74, 0x73, 0x2e, 0x76, 0x31, 0x1a, 0x1f, 0x67, 0x6f, 0x6f, 0x67, 0x6c, 0x65, 0x2f,
	0x70, 0x72, 0x6f, 0x74, 0x6f, 0x62, 0x75, 0x66, 0x2f, 0x74, 0x69, 0x6d, 0x65, 0x73, 0x74, 0x61,
	0x6d, 0x70, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x1a, 0x1e, 0x67, 0x6f, 0x6f, 0x67, 0x6c, 0x65,
	0x2f, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x62, 0x75, 0x66, 0x2f, 0x77, 0x72, 0x61, 0x70, 0x70, 0x65,
	0x72, 0x73, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x1a, 0x1c, 0x67, 0x6f, 0x6f, 0x67, 0x6c, 0x65,
	0x2f, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x62, 0x75, 0x66, 0x2f, 0x73, 0x74, 0x72, 0x75, 0x63, 0x74,
	0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x1a, 0x2e, 0x63, 0x6f, 0x6e, 0x74, 0x72, 0x6f, 0x6c, 0x6c,
	0x65, 0x72, 0x2f, 0x61, 0x70, 0x69, 0x2f, 0x72, 0x65, 0x73, 0x6f, 0x75, 0x72, 0x63, 0x65, 0x73,
	0x2f, 0x73, 0x63, 0x6f, 0x70, 0x65, 0x73, 0x2f, 0x76, 0x31, 0x2f, 0x73, 0x63, 0x6f, 0x70, 0x65,
	0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x1a, 0x32, 0x63, 0x6f, 0x6e, 0x74, 0x72, 0x6f, 0x6c, 0x6c,
	0x65, 0x72, 0x2f, 0x61, 0x70, 0x69, 0x2f, 0x72, 0x65, 0x73, 0x6f, 0x75, 0x72, 0x63, 0x65, 0x73,
	0x2f, 0x73, 0x65, 0x73, 0x73, 0x69, 0x6f, 0x6e, 0x73, 0x2f, 0x76, 0x31, 0x2f, 0x73, 0x65, 0x73,
	0x73, 0x69, 0x6f, 0x6e, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x1a, 0x2a, 0x63, 0x6f, 0x6e, 0x74,
	0x72, 0x6f, 0x6c, 0x6c, 0x65, 0x72, 0x2f, 0x63, 0x75, 0x73, 0x74, 0x6f, 0x6d, 0x5f, 0x6f, 0x70,
	0x74, 0x69, 0x6f, 0x6e, 0x73, 0x2f, 0x76, 0x31, 0x2f, 0x6f, 0x70, 0x74, 0x69, 0x6f, 0x6e, 0x73,
	0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x22, 0x41, 0x0a, 0x07, 0x48, 0x6f, 0x73, 0x74, 0x53, 0x65,
	0x74, 0x12, 0x0e, 0x0a, 0x02, 0x69, 0x64, 0x18, 0x0a, 0x20, 0x01, 0x28, 0x09, 0x52, 0x02, 0x69,
	0x64, 0x12, 0x26, 0x0a, 0x0f, 0x68, 0x6f, 0x73, 0x74, 0x5f, 0x63, 0x61, 0x74, 0x61, 0x6c, 0x6f,
	0x67, 0x5f, 0x69, 0x64, 0x18, 0x14, 0x20, 0x01, 0x28, 0x09, 0x52, 0x0d, 0x68, 0x6f, 0x73, 0x74,
	0x43, 0x61, 0x74, 0x61, 0x6c, 0x6f, 0x67, 0x49, 0x64, 0x22, 0xff, 0x04, 0x0a, 0x06, 0x54, 0x61,
	0x72, 0x67, 0x65, 0x74, 0x12, 0x0e, 0x0a, 0x02, 0x69, 0x64, 0x18, 0x0a, 0x20, 0x01, 0x28, 0x09,
	0x52, 0x02, 0x69, 0x64, 0x12, 0x1a, 0x0a, 0x08, 0x73, 0x63, 0x6f, 0x70, 0x65, 0x5f, 0x69, 0x64,
	0x18, 0x14, 0x20, 0x01, 0x28, 0x09, 0x52, 0x08, 0x73, 0x63, 0x6f, 0x70, 0x65, 0x5f, 0x69, 0x64,
	0x12, 0x43, 0x0a, 0x05, 0x73, 0x63, 0x6f, 0x70, 0x65, 0x18, 0x1e, 0x20, 0x01, 0x28, 0x0b, 0x32,
	0x2d, 0x2e, 0x63, 0x6f, 0x6e, 0x74, 0x72, 0x6f, 0x6c, 0x6c, 0x65, 0x72, 0x2e, 0x61, 0x70, 0x69,
	0x2e, 0x72, 0x65, 0x73, 0x6f, 0x75, 0x72, 0x63, 0x65, 0x73, 0x2e, 0x73, 0x63, 0x6f, 0x70, 0x65,
	0x73, 0x2e, 0x76, 0x31, 0x2e, 0x53, 0x63, 0x6f, 0x70, 0x65, 0x49, 0x6e, 0x66, 0x6f, 0x52, 0x05,
	0x73, 0x63, 0x6f, 0x70, 0x65, 0x12, 0x46, 0x0a, 0x04, 0x6e, 0x61, 0x6d, 0x65, 0x18, 0x28, 0x20,
	0x01, 0x28, 0x0b, 0x32, 0x1c, 0x2e, 0x67, 0x6f, 0x6f, 0x67, 0x6c, 0x65, 0x2e, 0x70, 0x72, 0x6f,
	0x74, 0x6f, 0x62, 0x75, 0x66, 0x2e, 0x53, 0x74, 0x72, 0x69, 0x6e, 0x67, 0x56, 0x61, 0x6c, 0x75,
	0x65, 0x42, 0x14, 0xa0, 0xda, 0x29, 0x01, 0xc2, 0xdd, 0x29, 0x0c, 0x0a, 0x04, 0x6e, 0x61, 0x6d,
	0x65, 0x12, 0x04, 0x6e, 0x61, 0x6d, 0x65, 0x52, 0x04, 0x6e, 0x61, 0x6d, 0x65, 0x12, 0x62, 0x0a,
	0x0b, 0x64, 0x65, 0x73, 0x63, 0x72, 0x69, 0x70, 0x74, 0x69, 0x6f, 0x6e, 0x18, 0x32, 0x20, 0x01,
	0x28, 0x0b, 0x32, 0x1c, 0x2e, 0x67, 0x6f, 0x6f, 0x67, 0x6c, 0x65, 0x2e, 0x70, 0x72, 0x6f, 0x74,
	0x6f, 0x62, 0x75, 0x66, 0x2e, 0x53, 0x74, 0x72, 0x69, 0x6e, 0x67, 0x56, 0x61, 0x6c, 0x75, 0x65,
	0x42, 0x22, 0xa0, 0xda, 0x29, 0x01, 0xc2, 0xdd, 0x29, 0x1a, 0x0a, 0x0b, 0x64, 0x65, 0x73, 0x63,
	0x72, 0x69, 0x70, 0x74, 0x69, 0x6f, 0x6e, 0x12, 0x0b, 0x64, 0x65, 0x73, 0x63, 0x72, 0x69, 0x70,
	0x74, 0x69, 0x6f, 0x6e, 0x52, 0x0b, 0x64, 0x65, 0x73, 0x63, 0x72, 0x69, 0x70, 0x74, 0x69, 0x6f,
	0x6e, 0x12, 0x3e, 0x0a, 0x0c, 0x63, 0x72, 0x65, 0x61, 0x74, 0x65, 0x64, 0x5f, 0x74, 0x69, 0x6d,
	0x65, 0x18, 0x3c, 0x20, 0x01, 0x28, 0x0b, 0x32, 0x1a, 0x2e, 0x67, 0x6f, 0x6f, 0x67, 0x6c, 0x65,
	0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x62, 0x75, 0x66, 0x2e, 0x54, 0x69, 0x6d, 0x65, 0x73, 0x74,
	0x61, 0x6d, 0x70, 0x52, 0x0c, 0x63, 0x72, 0x65, 0x61, 0x74, 0x65, 0x64, 0x5f, 0x74, 0x69, 0x6d,
	0x65, 0x12, 0x3e, 0x0a, 0x0c, 0x75, 0x70, 0x64, 0x61, 0x74, 0x65, 0x64, 0x5f, 0x74, 0x69, 0x6d,
	0x65, 0x18, 0x46, 0x20, 0x01, 0x28, 0x0b, 0x32, 0x1a, 0x2e, 0x67, 0x6f, 0x6f, 0x67, 0x6c, 0x65,
	0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x62, 0x75, 0x66, 0x2e, 0x54, 0x69, 0x6d, 0x65, 0x73, 0x74,
	0x61, 0x6d, 0x70, 0x52, 0x0c, 0x75, 0x70, 0x64, 0x61, 0x74, 0x65, 0x64, 0x5f, 0x74, 0x69, 0x6d,
	0x65, 0x12, 0x18, 0x0a, 0x07, 0x76, 0x65, 0x72, 0x73, 0x69, 0x6f, 0x6e, 0x18, 0x50, 0x20, 0x01,
	0x28, 0x0d, 0x52, 0x07, 0x76, 0x65, 0x72, 0x73, 0x69, 0x6f, 0x6e, 0x12, 0x12, 0x0a, 0x04, 0x74,
	0x79, 0x70, 0x65, 0x18, 0x5a, 0x20, 0x01, 0x28, 0x09, 0x52, 0x04, 0x74, 0x79, 0x70, 0x65, 0x12,
	0x20, 0x0a, 0x0c, 0x68, 0x6f, 0x73, 0x74, 0x5f, 0x73, 0x65, 0x74, 0x5f, 0x69, 0x64, 0x73, 0x18,
	0x64, 0x20, 0x03, 0x28, 0x09, 0x52, 0x0a, 0x68, 0x6f, 0x73, 0x74, 0x53, 0x65, 0x74, 0x49, 0x64,
	0x73, 0x12, 0x49, 0x0a, 0x09, 0x68, 0x6f, 0x73, 0x74, 0x5f, 0x73, 0x65, 0x74, 0x73, 0x18, 0x6e,
	0x20, 0x03, 0x28, 0x0b, 0x32, 0x2c, 0x2e, 0x63, 0x6f, 0x6e, 0x74, 0x72, 0x6f, 0x6c, 0x6c, 0x65,
	0x72, 0x2e, 0x61, 0x70, 0x69, 0x2e, 0x72, 0x65, 0x73, 0x6f, 0x75, 0x72, 0x63, 0x65, 0x73, 0x2e,
	0x74, 0x61, 0x72, 0x67, 0x65, 0x74, 0x73, 0x2e, 0x76, 0x31, 0x2e, 0x48, 0x6f, 0x73, 0x74, 0x53,
	0x65, 0x74, 0x52, 0x08, 0x68, 0x6f, 0x73, 0x74, 0x53, 0x65, 0x74, 0x73, 0x12, 0x3d, 0x0a, 0x0a,
	0x61, 0x74, 0x74, 0x72, 0x69, 0x62, 0x75, 0x74, 0x65, 0x73, 0x18, 0x78, 0x20, 0x01, 0x28, 0x0b,
	0x32, 0x17, 0x2e, 0x67, 0x6f, 0x6f, 0x67, 0x6c, 0x65, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x62,
	0x75, 0x66, 0x2e, 0x53, 0x74, 0x72, 0x75, 0x63, 0x74, 0x42, 0x04, 0xa0, 0xda, 0x29, 0x01, 0x52,
	0x0a, 0x61, 0x74, 0x74, 0x72, 0x69, 0x62, 0x75, 0x74, 0x65, 0x73, 0x22, 0x86, 0x01, 0x0a, 0x13,
	0x54, 0x63, 0x70, 0x54, 0x61, 0x72, 0x67, 0x65, 0x74, 0x41, 0x74, 0x74, 0x72, 0x69, 0x62, 0x75,
	0x74, 0x65, 0x73, 0x12, 0x6f, 0x0a, 0x0c, 0x64, 0x65, 0x66, 0x61, 0x75, 0x6c, 0x74, 0x5f, 0x70,
	0x6f, 0x72, 0x74, 0x18, 0x0a, 0x20, 0x01, 0x28, 0x0b, 0x32, 0x1c, 0x2e, 0x67, 0x6f, 0x6f, 0x67,
	0x6c, 0x65, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x62, 0x75, 0x66, 0x2e, 0x55, 0x49, 0x6e, 0x74,
	0x33, 0x32, 0x56, 0x61, 0x6c, 0x75, 0x65, 0x42, 0x2e, 0xa0, 0xda, 0x29, 0x01, 0xc2, 0xdd, 0x29,
	0x26, 0x0a, 0x17, 0x61, 0x74, 0x74, 0x72, 0x69, 0x62, 0x75, 0x74, 0x65, 0x73, 0x2e, 0x64, 0x65,
	0x66, 0x61, 0x75, 0x6c, 0x74, 0x5f, 0x70, 0x6f, 0x72, 0x74, 0x12, 0x0b, 0x44, 0x65, 0x66, 0x61,
	0x75, 0x6c, 0x74, 0x50, 0x6f, 0x72, 0x74, 0x52, 0x0b, 0x64, 0x65, 0x66, 0x61, 0x75, 0x6c, 0x74,
	0x50, 0x6f, 0x72, 0x74, 0x22, 0x86, 0x03, 0x0a, 0x14, 0x53, 0x65, 0x73, 0x73, 0x69, 0x6f, 0x6e,
	0x41, 0x75, 0x74, 0x68, 0x6f, 0x72, 0x69, 0x7a, 0x61, 0x74, 0x69, 0x6f, 0x6e, 0x12, 0x1d, 0x0a,
	0x0a, 0x73, 0x65, 0x73, 0x73, 0x69, 0x6f, 0x6e, 0x5f, 0x69, 0x64, 0x18, 0x0a, 0x20, 0x01, 0x28,
	0x09, 0x52, 0x09, 0x73, 0x65, 0x73, 0x73, 0x69, 0x6f, 0x6e, 0x49, 0x64, 0x12, 0x1c, 0x0a, 0x09,
	0x74, 0x61, 0x72, 0x67, 0x65, 0x74, 0x5f, 0x69, 0x64, 0x18, 0x14, 0x20, 0x01, 0x28, 0x09, 0x52,
	0x09, 0x74, 0x61, 0x72, 0x67, 0x65, 0x74, 0x5f, 0x69, 0x64, 0x12, 0x43, 0x0a, 0x05, 0x73, 0x63,
	0x6f, 0x70, 0x65, 0x18, 0x1e, 0x20, 0x01, 0x28, 0x0b, 0x32, 0x2d, 0x2e, 0x63, 0x6f, 0x6e, 0x74,
	0x72, 0x6f, 0x6c, 0x6c, 0x65, 0x72, 0x2e, 0x61, 0x70, 0x69, 0x2e, 0x72, 0x65, 0x73, 0x6f, 0x75,
	0x72, 0x63, 0x65, 0x73, 0x2e, 0x73, 0x63, 0x6f, 0x70, 0x65, 0x73, 0x2e, 0x76, 0x31, 0x2e, 0x53,
	0x63, 0x6f, 0x70, 0x65, 0x49, 0x6e, 0x66, 0x6f, 0x52, 0x05, 0x73, 0x63, 0x6f, 0x70, 0x65, 0x12,
	0x3e, 0x0a, 0x0c, 0x63, 0x72, 0x65, 0x61, 0x74, 0x65, 0x64, 0x5f, 0x74, 0x69, 0x6d, 0x65, 0x18,
	0x28, 0x20, 0x01, 0x28, 0x0b, 0x32, 0x1a, 0x2e, 0x67, 0x6f, 0x6f, 0x67, 0x6c, 0x65, 0x2e, 0x70,
	0x72, 0x6f, 0x74, 0x6f, 0x62, 0x75, 0x66, 0x2e, 0x54, 0x69, 0x6d, 0x65, 0x73, 0x74, 0x61, 0x6d,
	0x70, 0x52, 0x0c, 0x63, 0x72, 0x65, 0x61, 0x74, 0x65, 0x64, 0x5f, 0x74, 0x69, 0x6d, 0x65, 0x12,
	0x12, 0x0a, 0x04, 0x74, 0x79, 0x70, 0x65, 0x18, 0x50, 0x20, 0x01, 0x28, 0x09, 0x52, 0x04, 0x74,
	0x79, 0x70, 0x65, 0x12, 0x20, 0x0a, 0x0b, 0x63, 0x65, 0x72, 0x74, 0x69, 0x66, 0x69, 0x63, 0x61,
	0x74, 0x65, 0x18, 0x78, 0x20, 0x01, 0x28, 0x0c, 0x52, 0x0b, 0x63, 0x65, 0x72, 0x74, 0x69, 0x66,
	0x69, 0x63, 0x61, 0x74, 0x65, 0x12, 0x21, 0x0a, 0x0b, 0x70, 0x72, 0x69, 0x76, 0x61, 0x74, 0x65,
	0x5f, 0x6b, 0x65, 0x79, 0x18, 0x82, 0x01, 0x20, 0x01, 0x28, 0x0c, 0x52, 0x0b, 0x70, 0x72, 0x69,
	0x76, 0x61, 0x74, 0x65, 0x5f, 0x6b, 0x65, 0x79, 0x12, 0x53, 0x0a, 0x0b, 0x77, 0x6f, 0x72, 0x6b,
	0x65, 0x72, 0x5f, 0x69, 0x6e, 0x66, 0x6f, 0x18, 0x96, 0x01, 0x20, 0x03, 0x28, 0x0b, 0x32, 0x30,
	0x2e, 0x63, 0x6f, 0x6e, 0x74, 0x72, 0x6f, 0x6c, 0x6c, 0x65, 0x72, 0x2e, 0x61, 0x70, 0x69, 0x2e,
	0x72, 0x65, 0x73, 0x6f, 0x75, 0x72, 0x63, 0x65, 0x73, 0x2e, 0x73, 0x65, 0x73, 0x73, 0x69, 0x6f,
	0x6e, 0x73, 0x2e, 0x76, 0x31, 0x2e, 0x57, 0x6f, 0x72, 0x6b, 0x65, 0x72, 0x49, 0x6e, 0x66, 0x6f,
	0x52, 0x0b, 0x77, 0x6f, 0x72, 0x6b, 0x65, 0x72, 0x5f, 0x69, 0x6e, 0x66, 0x6f, 0x42, 0x55, 0x5a,
	0x53, 0x67, 0x69, 0x74, 0x68, 0x75, 0x62, 0x2e, 0x63, 0x6f, 0x6d, 0x2f, 0x68, 0x61, 0x73, 0x68,
	0x69, 0x63, 0x6f, 0x72, 0x70, 0x2f, 0x62, 0x6f, 0x75, 0x6e, 0x64, 0x61, 0x72, 0x79, 0x2f, 0x69,
	0x6e, 0x74, 0x65, 0x72, 0x6e, 0x61, 0x6c, 0x2f, 0x67, 0x65, 0x6e, 0x2f, 0x63, 0x6f, 0x6e, 0x74,
	0x72, 0x6f, 0x6c, 0x6c, 0x65, 0x72, 0x2f, 0x61, 0x70, 0x69, 0x2f, 0x72, 0x65, 0x73, 0x6f, 0x75,
	0x72, 0x63, 0x65, 0x73, 0x2f, 0x74, 0x61, 0x72, 0x67, 0x65, 0x74, 0x73, 0x3b, 0x74, 0x61, 0x72,
	0x67, 0x65, 0x74, 0x73, 0x62, 0x06, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x33,
}

var (
	file_controller_api_resources_targets_v1_target_proto_rawDescOnce sync.Once
	file_controller_api_resources_targets_v1_target_proto_rawDescData = file_controller_api_resources_targets_v1_target_proto_rawDesc
)

func file_controller_api_resources_targets_v1_target_proto_rawDescGZIP() []byte {
	file_controller_api_resources_targets_v1_target_proto_rawDescOnce.Do(func() {
		file_controller_api_resources_targets_v1_target_proto_rawDescData = protoimpl.X.CompressGZIP(file_controller_api_resources_targets_v1_target_proto_rawDescData)
	})
	return file_controller_api_resources_targets_v1_target_proto_rawDescData
}

var file_controller_api_resources_targets_v1_target_proto_msgTypes = make([]protoimpl.MessageInfo, 4)
var file_controller_api_resources_targets_v1_target_proto_goTypes = []interface{}{
	(*HostSet)(nil),              // 0: controller.api.resources.targets.v1.HostSet
	(*Target)(nil),               // 1: controller.api.resources.targets.v1.Target
	(*TcpTargetAttributes)(nil),  // 2: controller.api.resources.targets.v1.TcpTargetAttributes
	(*SessionAuthorization)(nil), // 3: controller.api.resources.targets.v1.SessionAuthorization
	(*scopes.ScopeInfo)(nil),     // 4: controller.api.resources.scopes.v1.ScopeInfo
	(*wrappers.StringValue)(nil), // 5: google.protobuf.StringValue
	(*timestamp.Timestamp)(nil),  // 6: google.protobuf.Timestamp
	(*_struct.Struct)(nil),       // 7: google.protobuf.Struct
	(*wrappers.UInt32Value)(nil), // 8: google.protobuf.UInt32Value
	(*sessions.WorkerInfo)(nil),  // 9: controller.api.resources.sessions.v1.WorkerInfo
}
var file_controller_api_resources_targets_v1_target_proto_depIdxs = []int32{
	4,  // 0: controller.api.resources.targets.v1.Target.scope:type_name -> controller.api.resources.scopes.v1.ScopeInfo
	5,  // 1: controller.api.resources.targets.v1.Target.name:type_name -> google.protobuf.StringValue
	5,  // 2: controller.api.resources.targets.v1.Target.description:type_name -> google.protobuf.StringValue
	6,  // 3: controller.api.resources.targets.v1.Target.created_time:type_name -> google.protobuf.Timestamp
	6,  // 4: controller.api.resources.targets.v1.Target.updated_time:type_name -> google.protobuf.Timestamp
	0,  // 5: controller.api.resources.targets.v1.Target.host_sets:type_name -> controller.api.resources.targets.v1.HostSet
	7,  // 6: controller.api.resources.targets.v1.Target.attributes:type_name -> google.protobuf.Struct
	8,  // 7: controller.api.resources.targets.v1.TcpTargetAttributes.default_port:type_name -> google.protobuf.UInt32Value
	4,  // 8: controller.api.resources.targets.v1.SessionAuthorization.scope:type_name -> controller.api.resources.scopes.v1.ScopeInfo
	6,  // 9: controller.api.resources.targets.v1.SessionAuthorization.created_time:type_name -> google.protobuf.Timestamp
	9,  // 10: controller.api.resources.targets.v1.SessionAuthorization.worker_info:type_name -> controller.api.resources.sessions.v1.WorkerInfo
	11, // [11:11] is the sub-list for method output_type
	11, // [11:11] is the sub-list for method input_type
	11, // [11:11] is the sub-list for extension type_name
	11, // [11:11] is the sub-list for extension extendee
	0,  // [0:11] is the sub-list for field type_name
}

func init() { file_controller_api_resources_targets_v1_target_proto_init() }
func file_controller_api_resources_targets_v1_target_proto_init() {
	if File_controller_api_resources_targets_v1_target_proto != nil {
		return
	}
	if !protoimpl.UnsafeEnabled {
		file_controller_api_resources_targets_v1_target_proto_msgTypes[0].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*HostSet); i {
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
		file_controller_api_resources_targets_v1_target_proto_msgTypes[1].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*Target); i {
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
		file_controller_api_resources_targets_v1_target_proto_msgTypes[2].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*TcpTargetAttributes); i {
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
		file_controller_api_resources_targets_v1_target_proto_msgTypes[3].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*SessionAuthorization); i {
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
			RawDescriptor: file_controller_api_resources_targets_v1_target_proto_rawDesc,
			NumEnums:      0,
			NumMessages:   4,
			NumExtensions: 0,
			NumServices:   0,
		},
		GoTypes:           file_controller_api_resources_targets_v1_target_proto_goTypes,
		DependencyIndexes: file_controller_api_resources_targets_v1_target_proto_depIdxs,
		MessageInfos:      file_controller_api_resources_targets_v1_target_proto_msgTypes,
	}.Build()
	File_controller_api_resources_targets_v1_target_proto = out.File
	file_controller_api_resources_targets_v1_target_proto_rawDesc = nil
	file_controller_api_resources_targets_v1_target_proto_goTypes = nil
	file_controller_api_resources_targets_v1_target_proto_depIdxs = nil
}
