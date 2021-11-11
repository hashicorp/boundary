// Code generated by protoc-gen-go. DO NOT EDIT.
// versions:
// 	protoc-gen-go v1.27.1
// 	protoc        v3.17.3
// source: controller/storage/host/plugin/store/v1/host.proto

// Package store provides protobufs for storing types in the plugin host
// package.

package store

import (
	timestamp "github.com/hashicorp/boundary/internal/db/timestamp"
	_ "github.com/hashicorp/boundary/sdk/pbs/controller/protooptions"
	protoreflect "google.golang.org/protobuf/reflect/protoreflect"
	protoimpl "google.golang.org/protobuf/runtime/protoimpl"
	_ "google.golang.org/protobuf/types/known/structpb"
	reflect "reflect"
	sync "sync"
)

const (
	// Verify that this generated code is sufficiently up-to-date.
	_ = protoimpl.EnforceVersion(20 - protoimpl.MinVersion)
	// Verify that runtime/protoimpl is sufficiently up-to-date.
	_ = protoimpl.EnforceVersion(protoimpl.MaxVersion - 20)
)

type HostCatalog struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	// public_id is a surrogate key suitable for use in a public API.
	// @inject_tag: `gorm:"primary_key"`
	PublicId string `protobuf:"bytes,1,opt,name=public_id,json=publicId,proto3" json:"public_id,omitempty" gorm:"primary_key"`
	// The create_time is set by the database.
	// @inject_tag: `gorm:"default:current_timestamp"`
	CreateTime *timestamp.Timestamp `protobuf:"bytes,2,opt,name=create_time,json=createTime,proto3" json:"create_time,omitempty" gorm:"default:current_timestamp"`
	// The update_time is set by the database.
	// @inject_tag: `gorm:"default:current_timestamp"`
	UpdateTime *timestamp.Timestamp `protobuf:"bytes,3,opt,name=update_time,json=updateTime,proto3" json:"update_time,omitempty" gorm:"default:current_timestamp"`
	// name is optional. If set, it must be unique within scope_id.
	// @inject_tag: `gorm:"default:null"`
	Name string `protobuf:"bytes,4,opt,name=name,proto3" json:"name,omitempty" gorm:"default:null"`
	// description is optional.
	// @inject_tag: `gorm:"default:null"`
	Description string `protobuf:"bytes,5,opt,name=description,proto3" json:"description,omitempty" gorm:"default:null"`
	// The scope_id of the owning scope and must be set.
	// @inject_tag: `gorm:"not_null"`
	ScopeId string `protobuf:"bytes,6,opt,name=scope_id,json=scopeId,proto3" json:"scope_id,omitempty" gorm:"not_null"`
	// The public id of the plugin this catalog uses.
	// @inject_tag: `gorm:"not_null"`
	PluginId string `protobuf:"bytes,7,opt,name=plugin_id,json=pluginId,proto3" json:"plugin_id,omitempty" gorm:"not_null"`
	// version allows optimistic locking of the resource
	// @inject_tag: `gorm:"default:null"`
	Version uint32 `protobuf:"varint,8,opt,name=version,proto3" json:"version,omitempty" gorm:"default:null"`
	// attributes is a jsonb formatted field.
	// @inject_tag: `gorm:"not_null"`
	Attributes []byte `protobuf:"bytes,9,opt,name=attributes,proto3" json:"attributes,omitempty" gorm:"not_null"`
}

func (x *HostCatalog) Reset() {
	*x = HostCatalog{}
	if protoimpl.UnsafeEnabled {
		mi := &file_controller_storage_host_plugin_store_v1_host_proto_msgTypes[0]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *HostCatalog) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*HostCatalog) ProtoMessage() {}

func (x *HostCatalog) ProtoReflect() protoreflect.Message {
	mi := &file_controller_storage_host_plugin_store_v1_host_proto_msgTypes[0]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use HostCatalog.ProtoReflect.Descriptor instead.
func (*HostCatalog) Descriptor() ([]byte, []int) {
	return file_controller_storage_host_plugin_store_v1_host_proto_rawDescGZIP(), []int{0}
}

func (x *HostCatalog) GetPublicId() string {
	if x != nil {
		return x.PublicId
	}
	return ""
}

func (x *HostCatalog) GetCreateTime() *timestamp.Timestamp {
	if x != nil {
		return x.CreateTime
	}
	return nil
}

func (x *HostCatalog) GetUpdateTime() *timestamp.Timestamp {
	if x != nil {
		return x.UpdateTime
	}
	return nil
}

func (x *HostCatalog) GetName() string {
	if x != nil {
		return x.Name
	}
	return ""
}

func (x *HostCatalog) GetDescription() string {
	if x != nil {
		return x.Description
	}
	return ""
}

func (x *HostCatalog) GetScopeId() string {
	if x != nil {
		return x.ScopeId
	}
	return ""
}

func (x *HostCatalog) GetPluginId() string {
	if x != nil {
		return x.PluginId
	}
	return ""
}

func (x *HostCatalog) GetVersion() uint32 {
	if x != nil {
		return x.Version
	}
	return 0
}

func (x *HostCatalog) GetAttributes() []byte {
	if x != nil {
		return x.Attributes
	}
	return nil
}

type HostSet struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	// public_id is a surrogate key suitable for use in a public API.
	// @inject_tag: `gorm:"primary_key"`
	PublicId string `protobuf:"bytes,1,opt,name=public_id,json=publicId,proto3" json:"public_id,omitempty" gorm:"primary_key"`
	// The create_time is set by the database.
	// @inject_tag: `gorm:"default:current_timestamp"`
	CreateTime *timestamp.Timestamp `protobuf:"bytes,2,opt,name=create_time,json=createTime,proto3" json:"create_time,omitempty" gorm:"default:current_timestamp"`
	// The update_time is set by the database.
	// @inject_tag: `gorm:"default:current_timestamp"`
	UpdateTime *timestamp.Timestamp `protobuf:"bytes,3,opt,name=update_time,json=updateTime,proto3" json:"update_time,omitempty" gorm:"default:current_timestamp"`
	// The last_sync_time is updated every time a host set has been synced.
	// @inject_tag: `gorm:"default:null"`
	LastSyncTime *timestamp.Timestamp `protobuf:"bytes,4,opt,name=last_sync_time,json=lastSyncTime,proto3" json:"last_sync_time,omitempty" gorm:"default:null"`
	// The need_sync indicates that a sync needs to happen.
	// @inject_tag: `gorm:"not_null"`
	NeedSync bool `protobuf:"varint,5,opt,name=need_sync,json=needSync,proto3" json:"need_sync,omitempty" gorm:"not_null"`
	// name is optional. If set, it must be unique within
	// catalog_id.
	// @inject_tag: `gorm:"default:null"`
	Name string `protobuf:"bytes,6,opt,name=name,proto3" json:"name,omitempty" gorm:"default:null"`
	// description is optional.
	// @inject_tag: `gorm:"default:null"`
	Description string `protobuf:"bytes,7,opt,name=description,proto3" json:"description,omitempty" gorm:"default:null"`
	// catalog_id is the public_id of the owning
	// plugin_host_catalog and must be set.
	// @inject_tag: `gorm:"not_null"`
	CatalogId string `protobuf:"bytes,8,opt,name=catalog_id,json=catalogId,proto3" json:"catalog_id,omitempty" gorm:"not_null"`
	// version allows optimistic locking of the resource
	// @inject_tag: `gorm:"default:null"`
	Version uint32 `protobuf:"varint,9,opt,name=version,proto3" json:"version,omitempty" gorm:"default:null"`
	// attributes is a byte field containing marshaled JSON data
	// @inject_tag: `gorm:"not_null"`
	Attributes []byte `protobuf:"bytes,10,opt,name=attributes,proto3" json:"attributes,omitempty" gorm:"not_null"`
	// preferred_endpoints stores string preference values
	// @inject_tag: `gorm:"-"`
	PreferredEndpoints []string `protobuf:"bytes,11,rep,name=preferred_endpoints,json=preferredEndpoints,proto3" json:"preferred_endpoints,omitempty" gorm:"-"`
	// Sync interval is a value representing a duration in seconds
	// @inject_tag: `gorm:"default:null"`
	SyncIntervalSeconds int32 `protobuf:"varint,12,opt,name=sync_interval_seconds,json=syncIntervalSeconds,proto3" json:"sync_interval_seconds,omitempty" gorm:"default:null"`
}

func (x *HostSet) Reset() {
	*x = HostSet{}
	if protoimpl.UnsafeEnabled {
		mi := &file_controller_storage_host_plugin_store_v1_host_proto_msgTypes[1]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *HostSet) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*HostSet) ProtoMessage() {}

func (x *HostSet) ProtoReflect() protoreflect.Message {
	mi := &file_controller_storage_host_plugin_store_v1_host_proto_msgTypes[1]
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
	return file_controller_storage_host_plugin_store_v1_host_proto_rawDescGZIP(), []int{1}
}

func (x *HostSet) GetPublicId() string {
	if x != nil {
		return x.PublicId
	}
	return ""
}

func (x *HostSet) GetCreateTime() *timestamp.Timestamp {
	if x != nil {
		return x.CreateTime
	}
	return nil
}

func (x *HostSet) GetUpdateTime() *timestamp.Timestamp {
	if x != nil {
		return x.UpdateTime
	}
	return nil
}

func (x *HostSet) GetLastSyncTime() *timestamp.Timestamp {
	if x != nil {
		return x.LastSyncTime
	}
	return nil
}

func (x *HostSet) GetNeedSync() bool {
	if x != nil {
		return x.NeedSync
	}
	return false
}

func (x *HostSet) GetName() string {
	if x != nil {
		return x.Name
	}
	return ""
}

func (x *HostSet) GetDescription() string {
	if x != nil {
		return x.Description
	}
	return ""
}

func (x *HostSet) GetCatalogId() string {
	if x != nil {
		return x.CatalogId
	}
	return ""
}

func (x *HostSet) GetVersion() uint32 {
	if x != nil {
		return x.Version
	}
	return 0
}

func (x *HostSet) GetAttributes() []byte {
	if x != nil {
		return x.Attributes
	}
	return nil
}

func (x *HostSet) GetPreferredEndpoints() []string {
	if x != nil {
		return x.PreferredEndpoints
	}
	return nil
}

func (x *HostSet) GetSyncIntervalSeconds() int32 {
	if x != nil {
		return x.SyncIntervalSeconds
	}
	return 0
}

type HostCatalogSecret struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	// catalog_id is the public id of the catalog containing this secret.
	// @inject_tag: `gorm:"primary_key"`
	CatalogId string `protobuf:"bytes,1,opt,name=catalog_id,json=catalogId,proto3" json:"catalog_id,omitempty" gorm:"primary_key"`
	// The create_time is set by the database.
	// @inject_tag: `gorm:"default:current_timestamp"`
	CreateTime *timestamp.Timestamp `protobuf:"bytes,2,opt,name=create_time,json=createTime,proto3" json:"create_time,omitempty" gorm:"default:current_timestamp"`
	// The update_time is set by the database.
	// @inject_tag: `gorm:"default:current_timestamp"`
	UpdateTime *timestamp.Timestamp `protobuf:"bytes,3,opt,name=update_time,json=updateTime,proto3" json:"update_time,omitempty" gorm:"default:current_timestamp"`
	// attributes is the plain-text of the attribute data.  We are not storing
	// this plain-text value in the database.
	// @inject_tag: `gorm:"-" wrapping:"pt,secret_data"`
	Secret []byte `protobuf:"bytes,4,opt,name=secret,proto3" json:"secret,omitempty" gorm:"-" wrapping:"pt,secret_data"`
	// ct_attributes is the ciphertext of the attribute data stored in the db.
	// @inject_tag: `gorm:"column:secret;not_null" wrapping:"ct,secret_data"`
	CtSecret []byte `protobuf:"bytes,5,opt,name=ct_secret,json=ctSecret,proto3" json:"ct_secret,omitempty" gorm:"column:secret;not_null" wrapping:"ct,secret_data"`
	// The key_id of the kms database key used for encrypting this entry.
	// It must be set.
	// @inject_tag: `gorm:"not_null"`
	KeyId string `protobuf:"bytes,6,opt,name=key_id,json=keyId,proto3" json:"key_id,omitempty" gorm:"not_null"`
}

func (x *HostCatalogSecret) Reset() {
	*x = HostCatalogSecret{}
	if protoimpl.UnsafeEnabled {
		mi := &file_controller_storage_host_plugin_store_v1_host_proto_msgTypes[2]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *HostCatalogSecret) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*HostCatalogSecret) ProtoMessage() {}

func (x *HostCatalogSecret) ProtoReflect() protoreflect.Message {
	mi := &file_controller_storage_host_plugin_store_v1_host_proto_msgTypes[2]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use HostCatalogSecret.ProtoReflect.Descriptor instead.
func (*HostCatalogSecret) Descriptor() ([]byte, []int) {
	return file_controller_storage_host_plugin_store_v1_host_proto_rawDescGZIP(), []int{2}
}

func (x *HostCatalogSecret) GetCatalogId() string {
	if x != nil {
		return x.CatalogId
	}
	return ""
}

func (x *HostCatalogSecret) GetCreateTime() *timestamp.Timestamp {
	if x != nil {
		return x.CreateTime
	}
	return nil
}

func (x *HostCatalogSecret) GetUpdateTime() *timestamp.Timestamp {
	if x != nil {
		return x.UpdateTime
	}
	return nil
}

func (x *HostCatalogSecret) GetSecret() []byte {
	if x != nil {
		return x.Secret
	}
	return nil
}

func (x *HostCatalogSecret) GetCtSecret() []byte {
	if x != nil {
		return x.CtSecret
	}
	return nil
}

func (x *HostCatalogSecret) GetKeyId() string {
	if x != nil {
		return x.KeyId
	}
	return ""
}

// TODO: Add a field which tracks if the host in cache should be considered
//       invalid and fall back to the plugin provided data.
type Host struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	// public_id is a surrogate key suitable for use in a public API.
	// @inject_tag: `gorm:"primary_key"`
	PublicId string `protobuf:"bytes,1,opt,name=public_id,json=publicId,proto3" json:"public_id,omitempty" gorm:"primary_key"`
	// external_id is an id provided by the plugin.
	// @inject_tag: `gorm:"not_null"`
	ExternalId string `protobuf:"bytes,2,opt,name=external_id,json=externalId,proto3" json:"external_id,omitempty" gorm:"not_null"`
	// The create_time is set by the database.
	// @inject_tag: `gorm:"default:current_timestamp"`
	CreateTime *timestamp.Timestamp `protobuf:"bytes,3,opt,name=create_time,json=createTime,proto3" json:"create_time,omitempty" gorm:"default:current_timestamp"`
	// The update_time is set by the database.
	// @inject_tag: `gorm:"default:current_timestamp"`
	UpdateTime *timestamp.Timestamp `protobuf:"bytes,4,opt,name=update_time,json=updateTime,proto3" json:"update_time,omitempty" gorm:"default:current_timestamp"`
	// name is optional. If set, it must be unique within
	// catalog_id.
	// @inject_tag: `gorm:"default:null"`
	Name string `protobuf:"bytes,5,opt,name=name,proto3" json:"name,omitempty" gorm:"default:null"`
	// description is optional.
	// @inject_tag: `gorm:"default:null"`
	Description string `protobuf:"bytes,6,opt,name=description,proto3" json:"description,omitempty" gorm:"default:null"`
	// catalog_id is the public_id of the owning
	// plugin_host_catalog and must be set.
	// @inject_tag: `gorm:"not_null"`
	CatalogId string `protobuf:"bytes,7,opt,name=catalog_id,json=catalogId,proto3" json:"catalog_id,omitempty" gorm:"not_null"`
	// @inject_tag: `gorm:"-"`
	Version uint32 `protobuf:"varint,8,opt,name=version,proto3" json:"version,omitempty" gorm:"-"`
	// ip_addresses are the ip addresses associated with this host and will
	// be persisted in the db through the HostAddress message.
	// @inject_tag: `gorm:"-"`
	IpAddresses []string `protobuf:"bytes,9,rep,name=ip_addresses,json=ipAddresses,proto3" json:"ip_addresses,omitempty" gorm:"-"`
	// dns_names are the dns names associated with this host and will
	// be persisted in the db through the HostAddress message.
	// @inject_tag: `gorm:"-"`
	DnsNames []string `protobuf:"bytes,10,rep,name=dns_names,json=dnsNames,proto3" json:"dns_names,omitempty" gorm:"-"`
}

func (x *Host) Reset() {
	*x = Host{}
	if protoimpl.UnsafeEnabled {
		mi := &file_controller_storage_host_plugin_store_v1_host_proto_msgTypes[3]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *Host) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*Host) ProtoMessage() {}

func (x *Host) ProtoReflect() protoreflect.Message {
	mi := &file_controller_storage_host_plugin_store_v1_host_proto_msgTypes[3]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use Host.ProtoReflect.Descriptor instead.
func (*Host) Descriptor() ([]byte, []int) {
	return file_controller_storage_host_plugin_store_v1_host_proto_rawDescGZIP(), []int{3}
}

func (x *Host) GetPublicId() string {
	if x != nil {
		return x.PublicId
	}
	return ""
}

func (x *Host) GetExternalId() string {
	if x != nil {
		return x.ExternalId
	}
	return ""
}

func (x *Host) GetCreateTime() *timestamp.Timestamp {
	if x != nil {
		return x.CreateTime
	}
	return nil
}

func (x *Host) GetUpdateTime() *timestamp.Timestamp {
	if x != nil {
		return x.UpdateTime
	}
	return nil
}

func (x *Host) GetName() string {
	if x != nil {
		return x.Name
	}
	return ""
}

func (x *Host) GetDescription() string {
	if x != nil {
		return x.Description
	}
	return ""
}

func (x *Host) GetCatalogId() string {
	if x != nil {
		return x.CatalogId
	}
	return ""
}

func (x *Host) GetVersion() uint32 {
	if x != nil {
		return x.Version
	}
	return 0
}

func (x *Host) GetIpAddresses() []string {
	if x != nil {
		return x.IpAddresses
	}
	return nil
}

func (x *Host) GetDnsNames() []string {
	if x != nil {
		return x.DnsNames
	}
	return nil
}

type HostSetMember struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	// @inject_tag: `gorm:"primary_key"`
	HostId string `protobuf:"bytes,1,opt,name=host_id,json=hostId,proto3" json:"host_id,omitempty" gorm:"primary_key"`
	// @inject_tag: `gorm:"primary_key"`
	SetId string `protobuf:"bytes,2,opt,name=set_id,json=setId,proto3" json:"set_id,omitempty" gorm:"primary_key"`
	// @inject_tag: `gorm:"default:null"`
	CatalogId string `protobuf:"bytes,3,opt,name=catalog_id,json=catalogId,proto3" json:"catalog_id,omitempty" gorm:"default:null"`
}

func (x *HostSetMember) Reset() {
	*x = HostSetMember{}
	if protoimpl.UnsafeEnabled {
		mi := &file_controller_storage_host_plugin_store_v1_host_proto_msgTypes[4]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *HostSetMember) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*HostSetMember) ProtoMessage() {}

func (x *HostSetMember) ProtoReflect() protoreflect.Message {
	mi := &file_controller_storage_host_plugin_store_v1_host_proto_msgTypes[4]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use HostSetMember.ProtoReflect.Descriptor instead.
func (*HostSetMember) Descriptor() ([]byte, []int) {
	return file_controller_storage_host_plugin_store_v1_host_proto_rawDescGZIP(), []int{4}
}

func (x *HostSetMember) GetHostId() string {
	if x != nil {
		return x.HostId
	}
	return ""
}

func (x *HostSetMember) GetSetId() string {
	if x != nil {
		return x.SetId
	}
	return ""
}

func (x *HostSetMember) GetCatalogId() string {
	if x != nil {
		return x.CatalogId
	}
	return ""
}

var File_controller_storage_host_plugin_store_v1_host_proto protoreflect.FileDescriptor

var file_controller_storage_host_plugin_store_v1_host_proto_rawDesc = []byte{
	0x0a, 0x32, 0x63, 0x6f, 0x6e, 0x74, 0x72, 0x6f, 0x6c, 0x6c, 0x65, 0x72, 0x2f, 0x73, 0x74, 0x6f,
	0x72, 0x61, 0x67, 0x65, 0x2f, 0x68, 0x6f, 0x73, 0x74, 0x2f, 0x70, 0x6c, 0x75, 0x67, 0x69, 0x6e,
	0x2f, 0x73, 0x74, 0x6f, 0x72, 0x65, 0x2f, 0x76, 0x31, 0x2f, 0x68, 0x6f, 0x73, 0x74, 0x2e, 0x70,
	0x72, 0x6f, 0x74, 0x6f, 0x12, 0x27, 0x63, 0x6f, 0x6e, 0x74, 0x72, 0x6f, 0x6c, 0x6c, 0x65, 0x72,
	0x2e, 0x73, 0x74, 0x6f, 0x72, 0x61, 0x67, 0x65, 0x2e, 0x68, 0x6f, 0x73, 0x74, 0x2e, 0x70, 0x6c,
	0x75, 0x67, 0x69, 0x6e, 0x2e, 0x73, 0x74, 0x6f, 0x72, 0x65, 0x2e, 0x76, 0x31, 0x1a, 0x1c, 0x67,
	0x6f, 0x6f, 0x67, 0x6c, 0x65, 0x2f, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x62, 0x75, 0x66, 0x2f, 0x73,
	0x74, 0x72, 0x75, 0x63, 0x74, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x1a, 0x2f, 0x63, 0x6f, 0x6e,
	0x74, 0x72, 0x6f, 0x6c, 0x6c, 0x65, 0x72, 0x2f, 0x73, 0x74, 0x6f, 0x72, 0x61, 0x67, 0x65, 0x2f,
	0x74, 0x69, 0x6d, 0x65, 0x73, 0x74, 0x61, 0x6d, 0x70, 0x2f, 0x76, 0x31, 0x2f, 0x74, 0x69, 0x6d,
	0x65, 0x73, 0x74, 0x61, 0x6d, 0x70, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x1a, 0x2a, 0x63, 0x6f,
	0x6e, 0x74, 0x72, 0x6f, 0x6c, 0x6c, 0x65, 0x72, 0x2f, 0x63, 0x75, 0x73, 0x74, 0x6f, 0x6d, 0x5f,
	0x6f, 0x70, 0x74, 0x69, 0x6f, 0x6e, 0x73, 0x2f, 0x76, 0x31, 0x2f, 0x6f, 0x70, 0x74, 0x69, 0x6f,
	0x6e, 0x73, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x22, 0x9e, 0x03, 0x0a, 0x0b, 0x48, 0x6f, 0x73,
	0x74, 0x43, 0x61, 0x74, 0x61, 0x6c, 0x6f, 0x67, 0x12, 0x1b, 0x0a, 0x09, 0x70, 0x75, 0x62, 0x6c,
	0x69, 0x63, 0x5f, 0x69, 0x64, 0x18, 0x01, 0x20, 0x01, 0x28, 0x09, 0x52, 0x08, 0x70, 0x75, 0x62,
	0x6c, 0x69, 0x63, 0x49, 0x64, 0x12, 0x4b, 0x0a, 0x0b, 0x63, 0x72, 0x65, 0x61, 0x74, 0x65, 0x5f,
	0x74, 0x69, 0x6d, 0x65, 0x18, 0x02, 0x20, 0x01, 0x28, 0x0b, 0x32, 0x2a, 0x2e, 0x63, 0x6f, 0x6e,
	0x74, 0x72, 0x6f, 0x6c, 0x6c, 0x65, 0x72, 0x2e, 0x73, 0x74, 0x6f, 0x72, 0x61, 0x67, 0x65, 0x2e,
	0x74, 0x69, 0x6d, 0x65, 0x73, 0x74, 0x61, 0x6d, 0x70, 0x2e, 0x76, 0x31, 0x2e, 0x54, 0x69, 0x6d,
	0x65, 0x73, 0x74, 0x61, 0x6d, 0x70, 0x52, 0x0a, 0x63, 0x72, 0x65, 0x61, 0x74, 0x65, 0x54, 0x69,
	0x6d, 0x65, 0x12, 0x4b, 0x0a, 0x0b, 0x75, 0x70, 0x64, 0x61, 0x74, 0x65, 0x5f, 0x74, 0x69, 0x6d,
	0x65, 0x18, 0x03, 0x20, 0x01, 0x28, 0x0b, 0x32, 0x2a, 0x2e, 0x63, 0x6f, 0x6e, 0x74, 0x72, 0x6f,
	0x6c, 0x6c, 0x65, 0x72, 0x2e, 0x73, 0x74, 0x6f, 0x72, 0x61, 0x67, 0x65, 0x2e, 0x74, 0x69, 0x6d,
	0x65, 0x73, 0x74, 0x61, 0x6d, 0x70, 0x2e, 0x76, 0x31, 0x2e, 0x54, 0x69, 0x6d, 0x65, 0x73, 0x74,
	0x61, 0x6d, 0x70, 0x52, 0x0a, 0x75, 0x70, 0x64, 0x61, 0x74, 0x65, 0x54, 0x69, 0x6d, 0x65, 0x12,
	0x24, 0x0a, 0x04, 0x6e, 0x61, 0x6d, 0x65, 0x18, 0x04, 0x20, 0x01, 0x28, 0x09, 0x42, 0x10, 0xc2,
	0xdd, 0x29, 0x0c, 0x0a, 0x04, 0x6e, 0x61, 0x6d, 0x65, 0x12, 0x04, 0x6e, 0x61, 0x6d, 0x65, 0x52,
	0x04, 0x6e, 0x61, 0x6d, 0x65, 0x12, 0x40, 0x0a, 0x0b, 0x64, 0x65, 0x73, 0x63, 0x72, 0x69, 0x70,
	0x74, 0x69, 0x6f, 0x6e, 0x18, 0x05, 0x20, 0x01, 0x28, 0x09, 0x42, 0x1e, 0xc2, 0xdd, 0x29, 0x1a,
	0x0a, 0x0b, 0x64, 0x65, 0x73, 0x63, 0x72, 0x69, 0x70, 0x74, 0x69, 0x6f, 0x6e, 0x12, 0x0b, 0x64,
	0x65, 0x73, 0x63, 0x72, 0x69, 0x70, 0x74, 0x69, 0x6f, 0x6e, 0x52, 0x0b, 0x64, 0x65, 0x73, 0x63,
	0x72, 0x69, 0x70, 0x74, 0x69, 0x6f, 0x6e, 0x12, 0x19, 0x0a, 0x08, 0x73, 0x63, 0x6f, 0x70, 0x65,
	0x5f, 0x69, 0x64, 0x18, 0x06, 0x20, 0x01, 0x28, 0x09, 0x52, 0x07, 0x73, 0x63, 0x6f, 0x70, 0x65,
	0x49, 0x64, 0x12, 0x1b, 0x0a, 0x09, 0x70, 0x6c, 0x75, 0x67, 0x69, 0x6e, 0x5f, 0x69, 0x64, 0x18,
	0x07, 0x20, 0x01, 0x28, 0x09, 0x52, 0x08, 0x70, 0x6c, 0x75, 0x67, 0x69, 0x6e, 0x49, 0x64, 0x12,
	0x18, 0x0a, 0x07, 0x76, 0x65, 0x72, 0x73, 0x69, 0x6f, 0x6e, 0x18, 0x08, 0x20, 0x01, 0x28, 0x0d,
	0x52, 0x07, 0x76, 0x65, 0x72, 0x73, 0x69, 0x6f, 0x6e, 0x12, 0x1e, 0x0a, 0x0a, 0x61, 0x74, 0x74,
	0x72, 0x69, 0x62, 0x75, 0x74, 0x65, 0x73, 0x18, 0x09, 0x20, 0x01, 0x28, 0x0c, 0x52, 0x0a, 0x61,
	0x74, 0x74, 0x72, 0x69, 0x62, 0x75, 0x74, 0x65, 0x73, 0x22, 0xb6, 0x05, 0x0a, 0x07, 0x48, 0x6f,
	0x73, 0x74, 0x53, 0x65, 0x74, 0x12, 0x1b, 0x0a, 0x09, 0x70, 0x75, 0x62, 0x6c, 0x69, 0x63, 0x5f,
	0x69, 0x64, 0x18, 0x01, 0x20, 0x01, 0x28, 0x09, 0x52, 0x08, 0x70, 0x75, 0x62, 0x6c, 0x69, 0x63,
	0x49, 0x64, 0x12, 0x4b, 0x0a, 0x0b, 0x63, 0x72, 0x65, 0x61, 0x74, 0x65, 0x5f, 0x74, 0x69, 0x6d,
	0x65, 0x18, 0x02, 0x20, 0x01, 0x28, 0x0b, 0x32, 0x2a, 0x2e, 0x63, 0x6f, 0x6e, 0x74, 0x72, 0x6f,
	0x6c, 0x6c, 0x65, 0x72, 0x2e, 0x73, 0x74, 0x6f, 0x72, 0x61, 0x67, 0x65, 0x2e, 0x74, 0x69, 0x6d,
	0x65, 0x73, 0x74, 0x61, 0x6d, 0x70, 0x2e, 0x76, 0x31, 0x2e, 0x54, 0x69, 0x6d, 0x65, 0x73, 0x74,
	0x61, 0x6d, 0x70, 0x52, 0x0a, 0x63, 0x72, 0x65, 0x61, 0x74, 0x65, 0x54, 0x69, 0x6d, 0x65, 0x12,
	0x4b, 0x0a, 0x0b, 0x75, 0x70, 0x64, 0x61, 0x74, 0x65, 0x5f, 0x74, 0x69, 0x6d, 0x65, 0x18, 0x03,
	0x20, 0x01, 0x28, 0x0b, 0x32, 0x2a, 0x2e, 0x63, 0x6f, 0x6e, 0x74, 0x72, 0x6f, 0x6c, 0x6c, 0x65,
	0x72, 0x2e, 0x73, 0x74, 0x6f, 0x72, 0x61, 0x67, 0x65, 0x2e, 0x74, 0x69, 0x6d, 0x65, 0x73, 0x74,
	0x61, 0x6d, 0x70, 0x2e, 0x76, 0x31, 0x2e, 0x54, 0x69, 0x6d, 0x65, 0x73, 0x74, 0x61, 0x6d, 0x70,
	0x52, 0x0a, 0x75, 0x70, 0x64, 0x61, 0x74, 0x65, 0x54, 0x69, 0x6d, 0x65, 0x12, 0x50, 0x0a, 0x0e,
	0x6c, 0x61, 0x73, 0x74, 0x5f, 0x73, 0x79, 0x6e, 0x63, 0x5f, 0x74, 0x69, 0x6d, 0x65, 0x18, 0x04,
	0x20, 0x01, 0x28, 0x0b, 0x32, 0x2a, 0x2e, 0x63, 0x6f, 0x6e, 0x74, 0x72, 0x6f, 0x6c, 0x6c, 0x65,
	0x72, 0x2e, 0x73, 0x74, 0x6f, 0x72, 0x61, 0x67, 0x65, 0x2e, 0x74, 0x69, 0x6d, 0x65, 0x73, 0x74,
	0x61, 0x6d, 0x70, 0x2e, 0x76, 0x31, 0x2e, 0x54, 0x69, 0x6d, 0x65, 0x73, 0x74, 0x61, 0x6d, 0x70,
	0x52, 0x0c, 0x6c, 0x61, 0x73, 0x74, 0x53, 0x79, 0x6e, 0x63, 0x54, 0x69, 0x6d, 0x65, 0x12, 0x1b,
	0x0a, 0x09, 0x6e, 0x65, 0x65, 0x64, 0x5f, 0x73, 0x79, 0x6e, 0x63, 0x18, 0x05, 0x20, 0x01, 0x28,
	0x08, 0x52, 0x08, 0x6e, 0x65, 0x65, 0x64, 0x53, 0x79, 0x6e, 0x63, 0x12, 0x24, 0x0a, 0x04, 0x6e,
	0x61, 0x6d, 0x65, 0x18, 0x06, 0x20, 0x01, 0x28, 0x09, 0x42, 0x10, 0xc2, 0xdd, 0x29, 0x0c, 0x0a,
	0x04, 0x6e, 0x61, 0x6d, 0x65, 0x12, 0x04, 0x6e, 0x61, 0x6d, 0x65, 0x52, 0x04, 0x6e, 0x61, 0x6d,
	0x65, 0x12, 0x40, 0x0a, 0x0b, 0x64, 0x65, 0x73, 0x63, 0x72, 0x69, 0x70, 0x74, 0x69, 0x6f, 0x6e,
	0x18, 0x07, 0x20, 0x01, 0x28, 0x09, 0x42, 0x1e, 0xc2, 0xdd, 0x29, 0x1a, 0x0a, 0x0b, 0x64, 0x65,
	0x73, 0x63, 0x72, 0x69, 0x70, 0x74, 0x69, 0x6f, 0x6e, 0x12, 0x0b, 0x64, 0x65, 0x73, 0x63, 0x72,
	0x69, 0x70, 0x74, 0x69, 0x6f, 0x6e, 0x52, 0x0b, 0x64, 0x65, 0x73, 0x63, 0x72, 0x69, 0x70, 0x74,
	0x69, 0x6f, 0x6e, 0x12, 0x1d, 0x0a, 0x0a, 0x63, 0x61, 0x74, 0x61, 0x6c, 0x6f, 0x67, 0x5f, 0x69,
	0x64, 0x18, 0x08, 0x20, 0x01, 0x28, 0x09, 0x52, 0x09, 0x63, 0x61, 0x74, 0x61, 0x6c, 0x6f, 0x67,
	0x49, 0x64, 0x12, 0x18, 0x0a, 0x07, 0x76, 0x65, 0x72, 0x73, 0x69, 0x6f, 0x6e, 0x18, 0x09, 0x20,
	0x01, 0x28, 0x0d, 0x52, 0x07, 0x76, 0x65, 0x72, 0x73, 0x69, 0x6f, 0x6e, 0x12, 0x1e, 0x0a, 0x0a,
	0x61, 0x74, 0x74, 0x72, 0x69, 0x62, 0x75, 0x74, 0x65, 0x73, 0x18, 0x0a, 0x20, 0x01, 0x28, 0x0c,
	0x52, 0x0a, 0x61, 0x74, 0x74, 0x72, 0x69, 0x62, 0x75, 0x74, 0x65, 0x73, 0x12, 0x5e, 0x0a, 0x13,
	0x70, 0x72, 0x65, 0x66, 0x65, 0x72, 0x72, 0x65, 0x64, 0x5f, 0x65, 0x6e, 0x64, 0x70, 0x6f, 0x69,
	0x6e, 0x74, 0x73, 0x18, 0x0b, 0x20, 0x03, 0x28, 0x09, 0x42, 0x2d, 0xc2, 0xdd, 0x29, 0x29, 0x0a,
	0x12, 0x50, 0x72, 0x65, 0x66, 0x65, 0x72, 0x72, 0x65, 0x64, 0x45, 0x6e, 0x64, 0x70, 0x6f, 0x69,
	0x6e, 0x74, 0x73, 0x12, 0x13, 0x70, 0x72, 0x65, 0x66, 0x65, 0x72, 0x72, 0x65, 0x64, 0x5f, 0x65,
	0x6e, 0x64, 0x70, 0x6f, 0x69, 0x6e, 0x74, 0x73, 0x52, 0x12, 0x70, 0x72, 0x65, 0x66, 0x65, 0x72,
	0x72, 0x65, 0x64, 0x45, 0x6e, 0x64, 0x70, 0x6f, 0x69, 0x6e, 0x74, 0x73, 0x12, 0x64, 0x0a, 0x15,
	0x73, 0x79, 0x6e, 0x63, 0x5f, 0x69, 0x6e, 0x74, 0x65, 0x72, 0x76, 0x61, 0x6c, 0x5f, 0x73, 0x65,
	0x63, 0x6f, 0x6e, 0x64, 0x73, 0x18, 0x0c, 0x20, 0x01, 0x28, 0x05, 0x42, 0x30, 0xc2, 0xdd, 0x29,
	0x2c, 0x0a, 0x13, 0x53, 0x79, 0x6e, 0x63, 0x49, 0x6e, 0x74, 0x65, 0x72, 0x76, 0x61, 0x6c, 0x53,
	0x65, 0x63, 0x6f, 0x6e, 0x64, 0x73, 0x12, 0x15, 0x73, 0x79, 0x6e, 0x63, 0x5f, 0x69, 0x6e, 0x74,
	0x65, 0x72, 0x76, 0x61, 0x6c, 0x5f, 0x73, 0x65, 0x63, 0x6f, 0x6e, 0x64, 0x73, 0x52, 0x13, 0x73,
	0x79, 0x6e, 0x63, 0x49, 0x6e, 0x74, 0x65, 0x72, 0x76, 0x61, 0x6c, 0x53, 0x65, 0x63, 0x6f, 0x6e,
	0x64, 0x73, 0x22, 0x98, 0x02, 0x0a, 0x11, 0x48, 0x6f, 0x73, 0x74, 0x43, 0x61, 0x74, 0x61, 0x6c,
	0x6f, 0x67, 0x53, 0x65, 0x63, 0x72, 0x65, 0x74, 0x12, 0x1d, 0x0a, 0x0a, 0x63, 0x61, 0x74, 0x61,
	0x6c, 0x6f, 0x67, 0x5f, 0x69, 0x64, 0x18, 0x01, 0x20, 0x01, 0x28, 0x09, 0x52, 0x09, 0x63, 0x61,
	0x74, 0x61, 0x6c, 0x6f, 0x67, 0x49, 0x64, 0x12, 0x4b, 0x0a, 0x0b, 0x63, 0x72, 0x65, 0x61, 0x74,
	0x65, 0x5f, 0x74, 0x69, 0x6d, 0x65, 0x18, 0x02, 0x20, 0x01, 0x28, 0x0b, 0x32, 0x2a, 0x2e, 0x63,
	0x6f, 0x6e, 0x74, 0x72, 0x6f, 0x6c, 0x6c, 0x65, 0x72, 0x2e, 0x73, 0x74, 0x6f, 0x72, 0x61, 0x67,
	0x65, 0x2e, 0x74, 0x69, 0x6d, 0x65, 0x73, 0x74, 0x61, 0x6d, 0x70, 0x2e, 0x76, 0x31, 0x2e, 0x54,
	0x69, 0x6d, 0x65, 0x73, 0x74, 0x61, 0x6d, 0x70, 0x52, 0x0a, 0x63, 0x72, 0x65, 0x61, 0x74, 0x65,
	0x54, 0x69, 0x6d, 0x65, 0x12, 0x4b, 0x0a, 0x0b, 0x75, 0x70, 0x64, 0x61, 0x74, 0x65, 0x5f, 0x74,
	0x69, 0x6d, 0x65, 0x18, 0x03, 0x20, 0x01, 0x28, 0x0b, 0x32, 0x2a, 0x2e, 0x63, 0x6f, 0x6e, 0x74,
	0x72, 0x6f, 0x6c, 0x6c, 0x65, 0x72, 0x2e, 0x73, 0x74, 0x6f, 0x72, 0x61, 0x67, 0x65, 0x2e, 0x74,
	0x69, 0x6d, 0x65, 0x73, 0x74, 0x61, 0x6d, 0x70, 0x2e, 0x76, 0x31, 0x2e, 0x54, 0x69, 0x6d, 0x65,
	0x73, 0x74, 0x61, 0x6d, 0x70, 0x52, 0x0a, 0x75, 0x70, 0x64, 0x61, 0x74, 0x65, 0x54, 0x69, 0x6d,
	0x65, 0x12, 0x16, 0x0a, 0x06, 0x73, 0x65, 0x63, 0x72, 0x65, 0x74, 0x18, 0x04, 0x20, 0x01, 0x28,
	0x0c, 0x52, 0x06, 0x73, 0x65, 0x63, 0x72, 0x65, 0x74, 0x12, 0x1b, 0x0a, 0x09, 0x63, 0x74, 0x5f,
	0x73, 0x65, 0x63, 0x72, 0x65, 0x74, 0x18, 0x05, 0x20, 0x01, 0x28, 0x0c, 0x52, 0x08, 0x63, 0x74,
	0x53, 0x65, 0x63, 0x72, 0x65, 0x74, 0x12, 0x15, 0x0a, 0x06, 0x6b, 0x65, 0x79, 0x5f, 0x69, 0x64,
	0x18, 0x06, 0x20, 0x01, 0x28, 0x09, 0x52, 0x05, 0x6b, 0x65, 0x79, 0x49, 0x64, 0x22, 0x8d, 0x03,
	0x0a, 0x04, 0x48, 0x6f, 0x73, 0x74, 0x12, 0x1b, 0x0a, 0x09, 0x70, 0x75, 0x62, 0x6c, 0x69, 0x63,
	0x5f, 0x69, 0x64, 0x18, 0x01, 0x20, 0x01, 0x28, 0x09, 0x52, 0x08, 0x70, 0x75, 0x62, 0x6c, 0x69,
	0x63, 0x49, 0x64, 0x12, 0x1f, 0x0a, 0x0b, 0x65, 0x78, 0x74, 0x65, 0x72, 0x6e, 0x61, 0x6c, 0x5f,
	0x69, 0x64, 0x18, 0x02, 0x20, 0x01, 0x28, 0x09, 0x52, 0x0a, 0x65, 0x78, 0x74, 0x65, 0x72, 0x6e,
	0x61, 0x6c, 0x49, 0x64, 0x12, 0x4b, 0x0a, 0x0b, 0x63, 0x72, 0x65, 0x61, 0x74, 0x65, 0x5f, 0x74,
	0x69, 0x6d, 0x65, 0x18, 0x03, 0x20, 0x01, 0x28, 0x0b, 0x32, 0x2a, 0x2e, 0x63, 0x6f, 0x6e, 0x74,
	0x72, 0x6f, 0x6c, 0x6c, 0x65, 0x72, 0x2e, 0x73, 0x74, 0x6f, 0x72, 0x61, 0x67, 0x65, 0x2e, 0x74,
	0x69, 0x6d, 0x65, 0x73, 0x74, 0x61, 0x6d, 0x70, 0x2e, 0x76, 0x31, 0x2e, 0x54, 0x69, 0x6d, 0x65,
	0x73, 0x74, 0x61, 0x6d, 0x70, 0x52, 0x0a, 0x63, 0x72, 0x65, 0x61, 0x74, 0x65, 0x54, 0x69, 0x6d,
	0x65, 0x12, 0x4b, 0x0a, 0x0b, 0x75, 0x70, 0x64, 0x61, 0x74, 0x65, 0x5f, 0x74, 0x69, 0x6d, 0x65,
	0x18, 0x04, 0x20, 0x01, 0x28, 0x0b, 0x32, 0x2a, 0x2e, 0x63, 0x6f, 0x6e, 0x74, 0x72, 0x6f, 0x6c,
	0x6c, 0x65, 0x72, 0x2e, 0x73, 0x74, 0x6f, 0x72, 0x61, 0x67, 0x65, 0x2e, 0x74, 0x69, 0x6d, 0x65,
	0x73, 0x74, 0x61, 0x6d, 0x70, 0x2e, 0x76, 0x31, 0x2e, 0x54, 0x69, 0x6d, 0x65, 0x73, 0x74, 0x61,
	0x6d, 0x70, 0x52, 0x0a, 0x75, 0x70, 0x64, 0x61, 0x74, 0x65, 0x54, 0x69, 0x6d, 0x65, 0x12, 0x12,
	0x0a, 0x04, 0x6e, 0x61, 0x6d, 0x65, 0x18, 0x05, 0x20, 0x01, 0x28, 0x09, 0x52, 0x04, 0x6e, 0x61,
	0x6d, 0x65, 0x12, 0x20, 0x0a, 0x0b, 0x64, 0x65, 0x73, 0x63, 0x72, 0x69, 0x70, 0x74, 0x69, 0x6f,
	0x6e, 0x18, 0x06, 0x20, 0x01, 0x28, 0x09, 0x52, 0x0b, 0x64, 0x65, 0x73, 0x63, 0x72, 0x69, 0x70,
	0x74, 0x69, 0x6f, 0x6e, 0x12, 0x1d, 0x0a, 0x0a, 0x63, 0x61, 0x74, 0x61, 0x6c, 0x6f, 0x67, 0x5f,
	0x69, 0x64, 0x18, 0x07, 0x20, 0x01, 0x28, 0x09, 0x52, 0x09, 0x63, 0x61, 0x74, 0x61, 0x6c, 0x6f,
	0x67, 0x49, 0x64, 0x12, 0x18, 0x0a, 0x07, 0x76, 0x65, 0x72, 0x73, 0x69, 0x6f, 0x6e, 0x18, 0x08,
	0x20, 0x01, 0x28, 0x0d, 0x52, 0x07, 0x76, 0x65, 0x72, 0x73, 0x69, 0x6f, 0x6e, 0x12, 0x21, 0x0a,
	0x0c, 0x69, 0x70, 0x5f, 0x61, 0x64, 0x64, 0x72, 0x65, 0x73, 0x73, 0x65, 0x73, 0x18, 0x09, 0x20,
	0x03, 0x28, 0x09, 0x52, 0x0b, 0x69, 0x70, 0x41, 0x64, 0x64, 0x72, 0x65, 0x73, 0x73, 0x65, 0x73,
	0x12, 0x1b, 0x0a, 0x09, 0x64, 0x6e, 0x73, 0x5f, 0x6e, 0x61, 0x6d, 0x65, 0x73, 0x18, 0x0a, 0x20,
	0x03, 0x28, 0x09, 0x52, 0x08, 0x64, 0x6e, 0x73, 0x4e, 0x61, 0x6d, 0x65, 0x73, 0x22, 0x5e, 0x0a,
	0x0d, 0x48, 0x6f, 0x73, 0x74, 0x53, 0x65, 0x74, 0x4d, 0x65, 0x6d, 0x62, 0x65, 0x72, 0x12, 0x17,
	0x0a, 0x07, 0x68, 0x6f, 0x73, 0x74, 0x5f, 0x69, 0x64, 0x18, 0x01, 0x20, 0x01, 0x28, 0x09, 0x52,
	0x06, 0x68, 0x6f, 0x73, 0x74, 0x49, 0x64, 0x12, 0x15, 0x0a, 0x06, 0x73, 0x65, 0x74, 0x5f, 0x69,
	0x64, 0x18, 0x02, 0x20, 0x01, 0x28, 0x09, 0x52, 0x05, 0x73, 0x65, 0x74, 0x49, 0x64, 0x12, 0x1d,
	0x0a, 0x0a, 0x63, 0x61, 0x74, 0x61, 0x6c, 0x6f, 0x67, 0x5f, 0x69, 0x64, 0x18, 0x03, 0x20, 0x01,
	0x28, 0x09, 0x52, 0x09, 0x63, 0x61, 0x74, 0x61, 0x6c, 0x6f, 0x67, 0x49, 0x64, 0x42, 0x40, 0x5a,
	0x3e, 0x67, 0x69, 0x74, 0x68, 0x75, 0x62, 0x2e, 0x63, 0x6f, 0x6d, 0x2f, 0x68, 0x61, 0x73, 0x68,
	0x69, 0x63, 0x6f, 0x72, 0x70, 0x2f, 0x62, 0x6f, 0x75, 0x6e, 0x64, 0x61, 0x72, 0x79, 0x2f, 0x69,
	0x6e, 0x74, 0x65, 0x72, 0x6e, 0x61, 0x6c, 0x2f, 0x68, 0x6f, 0x73, 0x74, 0x2f, 0x70, 0x6c, 0x75,
	0x67, 0x69, 0x6e, 0x2f, 0x73, 0x74, 0x6f, 0x72, 0x65, 0x3b, 0x73, 0x74, 0x6f, 0x72, 0x65, 0x62,
	0x06, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x33,
}

var (
	file_controller_storage_host_plugin_store_v1_host_proto_rawDescOnce sync.Once
	file_controller_storage_host_plugin_store_v1_host_proto_rawDescData = file_controller_storage_host_plugin_store_v1_host_proto_rawDesc
)

func file_controller_storage_host_plugin_store_v1_host_proto_rawDescGZIP() []byte {
	file_controller_storage_host_plugin_store_v1_host_proto_rawDescOnce.Do(func() {
		file_controller_storage_host_plugin_store_v1_host_proto_rawDescData = protoimpl.X.CompressGZIP(file_controller_storage_host_plugin_store_v1_host_proto_rawDescData)
	})
	return file_controller_storage_host_plugin_store_v1_host_proto_rawDescData
}

var file_controller_storage_host_plugin_store_v1_host_proto_msgTypes = make([]protoimpl.MessageInfo, 5)
var file_controller_storage_host_plugin_store_v1_host_proto_goTypes = []interface{}{
	(*HostCatalog)(nil),         // 0: controller.storage.host.plugin.store.v1.HostCatalog
	(*HostSet)(nil),             // 1: controller.storage.host.plugin.store.v1.HostSet
	(*HostCatalogSecret)(nil),   // 2: controller.storage.host.plugin.store.v1.HostCatalogSecret
	(*Host)(nil),                // 3: controller.storage.host.plugin.store.v1.Host
	(*HostSetMember)(nil),       // 4: controller.storage.host.plugin.store.v1.HostSetMember
	(*timestamp.Timestamp)(nil), // 5: controller.storage.timestamp.v1.Timestamp
}
var file_controller_storage_host_plugin_store_v1_host_proto_depIdxs = []int32{
	5, // 0: controller.storage.host.plugin.store.v1.HostCatalog.create_time:type_name -> controller.storage.timestamp.v1.Timestamp
	5, // 1: controller.storage.host.plugin.store.v1.HostCatalog.update_time:type_name -> controller.storage.timestamp.v1.Timestamp
	5, // 2: controller.storage.host.plugin.store.v1.HostSet.create_time:type_name -> controller.storage.timestamp.v1.Timestamp
	5, // 3: controller.storage.host.plugin.store.v1.HostSet.update_time:type_name -> controller.storage.timestamp.v1.Timestamp
	5, // 4: controller.storage.host.plugin.store.v1.HostSet.last_sync_time:type_name -> controller.storage.timestamp.v1.Timestamp
	5, // 5: controller.storage.host.plugin.store.v1.HostCatalogSecret.create_time:type_name -> controller.storage.timestamp.v1.Timestamp
	5, // 6: controller.storage.host.plugin.store.v1.HostCatalogSecret.update_time:type_name -> controller.storage.timestamp.v1.Timestamp
	5, // 7: controller.storage.host.plugin.store.v1.Host.create_time:type_name -> controller.storage.timestamp.v1.Timestamp
	5, // 8: controller.storage.host.plugin.store.v1.Host.update_time:type_name -> controller.storage.timestamp.v1.Timestamp
	9, // [9:9] is the sub-list for method output_type
	9, // [9:9] is the sub-list for method input_type
	9, // [9:9] is the sub-list for extension type_name
	9, // [9:9] is the sub-list for extension extendee
	0, // [0:9] is the sub-list for field type_name
}

func init() { file_controller_storage_host_plugin_store_v1_host_proto_init() }
func file_controller_storage_host_plugin_store_v1_host_proto_init() {
	if File_controller_storage_host_plugin_store_v1_host_proto != nil {
		return
	}
	if !protoimpl.UnsafeEnabled {
		file_controller_storage_host_plugin_store_v1_host_proto_msgTypes[0].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*HostCatalog); i {
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
		file_controller_storage_host_plugin_store_v1_host_proto_msgTypes[1].Exporter = func(v interface{}, i int) interface{} {
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
		file_controller_storage_host_plugin_store_v1_host_proto_msgTypes[2].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*HostCatalogSecret); i {
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
		file_controller_storage_host_plugin_store_v1_host_proto_msgTypes[3].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*Host); i {
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
		file_controller_storage_host_plugin_store_v1_host_proto_msgTypes[4].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*HostSetMember); i {
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
			RawDescriptor: file_controller_storage_host_plugin_store_v1_host_proto_rawDesc,
			NumEnums:      0,
			NumMessages:   5,
			NumExtensions: 0,
			NumServices:   0,
		},
		GoTypes:           file_controller_storage_host_plugin_store_v1_host_proto_goTypes,
		DependencyIndexes: file_controller_storage_host_plugin_store_v1_host_proto_depIdxs,
		MessageInfos:      file_controller_storage_host_plugin_store_v1_host_proto_msgTypes,
	}.Build()
	File_controller_storage_host_plugin_store_v1_host_proto = out.File
	file_controller_storage_host_plugin_store_v1_host_proto_rawDesc = nil
	file_controller_storage_host_plugin_store_v1_host_proto_goTypes = nil
	file_controller_storage_host_plugin_store_v1_host_proto_depIdxs = nil
}
