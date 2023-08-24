// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

// Code generated by protoc-gen-go. DO NOT EDIT.
// versions:
// 	protoc-gen-go v1.30.0
// 	protoc        (unknown)
// source: controller/api/resources/hostcatalogs/v1/host_catalog.proto

package hostcatalogs

import (
	plugins "github.com/hashicorp/boundary/sdk/pbs/controller/api/resources/plugins"
	scopes "github.com/hashicorp/boundary/sdk/pbs/controller/api/resources/scopes"
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

// HostCatalog manages Hosts and Host Sets
type HostCatalog struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	// Output only. The ID of the host.
	Id string `protobuf:"bytes,10,opt,name=id,proto3" json:"id,omitempty" class:"public" eventstream:"observation"` // @gotags: `class:"public" eventstream:"observation"`
	// The ID of the Scope of which this Host Catalog is a part.
	ScopeId string `protobuf:"bytes,20,opt,name=scope_id,proto3" json:"scope_id,omitempty" class:"public" eventstream:"observation"` // @gotags: `class:"public" eventstream:"observation"`
	// Output only. Scope information for this resource.
	Scope *scopes.ScopeInfo `protobuf:"bytes,30,opt,name=scope,proto3" json:"scope,omitempty"`
	// The ID of the plugin of which this catalog is created.
	PluginId string `protobuf:"bytes,34,opt,name=plugin_id,proto3" json:"plugin_id,omitempty" class:"public" eventstream:"observation"` // @gotags: `class:"public" eventstream:"observation"`
	// Output only. Plugin information for this resource.
	Plugin *plugins.PluginInfo `protobuf:"bytes,35,opt,name=plugin,proto3" json:"plugin,omitempty"`
	// Optional name for identification purposes.
	Name *wrapperspb.StringValue `protobuf:"bytes,40,opt,name=name,proto3" json:"name,omitempty" class:"public"` // @gotags: `class:"public"`
	// Optional user-set description for identification purposes.
	Description *wrapperspb.StringValue `protobuf:"bytes,50,opt,name=description,proto3" json:"description,omitempty" class:"public"` // @gotags: `class:"public"`
	// Output only. The time this resource was created.
	CreatedTime *timestamppb.Timestamp `protobuf:"bytes,60,opt,name=created_time,proto3" json:"created_time,omitempty" class:"public" eventstream:"observation"` // @gotags: `class:"public" eventstream:"observation"`
	// Output only. The time this resource was last updated.
	UpdatedTime *timestamppb.Timestamp `protobuf:"bytes,70,opt,name=updated_time,proto3" json:"updated_time,omitempty" class:"public" eventstream:"observation"` // @gotags: `class:"public" eventstream:"observation"`
	// Version is used in mutation requests, after the initial creation, to ensure this resource has not changed.
	// The mutation will fail if the version does not match the latest known good version.
	Version uint32 `protobuf:"varint,80,opt,name=version,proto3" json:"version,omitempty" class:"public"` // @gotags: `class:"public"`
	// The type of Host Catalog.
	Type string `protobuf:"bytes,90,opt,name=type,proto3" json:"type,omitempty" class:"public" eventstream:"observation"` // @gotags: `class:"public" eventstream:"observation"`
	// Types that are assignable to Attrs:
	//
	//	*HostCatalog_Attributes
	Attrs isHostCatalog_Attrs `protobuf_oneof:"attrs"`
	// Secrets specific to the catalog type. These are never output.
	Secrets *structpb.Struct `protobuf:"bytes,110,opt,name=secrets,proto3" json:"secrets,omitempty"`
	// Output only. The HMAC of the last secrets supplied via the API, if any.
	SecretsHmac string `protobuf:"bytes,120,opt,name=secrets_hmac,json=secretsHmac,proto3" json:"secrets_hmac,omitempty" class:"public"` // @gotags: `class:"public"`
	// Output only. The available actions on this resource for this user.
	AuthorizedActions []string `protobuf:"bytes,300,rep,name=authorized_actions,proto3" json:"authorized_actions,omitempty" class:"public"` // @gotags: `class:"public"`
	// Output only. The authorized actions for the scope's collections.
	AuthorizedCollectionActions map[string]*structpb.ListValue `protobuf:"bytes,310,rep,name=authorized_collection_actions,proto3" json:"authorized_collection_actions,omitempty" protobuf_key:"bytes,1,opt,name=key,proto3" protobuf_val:"bytes,2,opt,name=value,proto3"` // classified as public via taggable implementation
}

func (x *HostCatalog) Reset() {
	*x = HostCatalog{}
	if protoimpl.UnsafeEnabled {
		mi := &file_controller_api_resources_hostcatalogs_v1_host_catalog_proto_msgTypes[0]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *HostCatalog) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*HostCatalog) ProtoMessage() {}

func (x *HostCatalog) ProtoReflect() protoreflect.Message {
	mi := &file_controller_api_resources_hostcatalogs_v1_host_catalog_proto_msgTypes[0]
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
	return file_controller_api_resources_hostcatalogs_v1_host_catalog_proto_rawDescGZIP(), []int{0}
}

func (x *HostCatalog) GetId() string {
	if x != nil {
		return x.Id
	}
	return ""
}

func (x *HostCatalog) GetScopeId() string {
	if x != nil {
		return x.ScopeId
	}
	return ""
}

func (x *HostCatalog) GetScope() *scopes.ScopeInfo {
	if x != nil {
		return x.Scope
	}
	return nil
}

func (x *HostCatalog) GetPluginId() string {
	if x != nil {
		return x.PluginId
	}
	return ""
}

func (x *HostCatalog) GetPlugin() *plugins.PluginInfo {
	if x != nil {
		return x.Plugin
	}
	return nil
}

func (x *HostCatalog) GetName() *wrapperspb.StringValue {
	if x != nil {
		return x.Name
	}
	return nil
}

func (x *HostCatalog) GetDescription() *wrapperspb.StringValue {
	if x != nil {
		return x.Description
	}
	return nil
}

func (x *HostCatalog) GetCreatedTime() *timestamppb.Timestamp {
	if x != nil {
		return x.CreatedTime
	}
	return nil
}

func (x *HostCatalog) GetUpdatedTime() *timestamppb.Timestamp {
	if x != nil {
		return x.UpdatedTime
	}
	return nil
}

func (x *HostCatalog) GetVersion() uint32 {
	if x != nil {
		return x.Version
	}
	return 0
}

func (x *HostCatalog) GetType() string {
	if x != nil {
		return x.Type
	}
	return ""
}

func (m *HostCatalog) GetAttrs() isHostCatalog_Attrs {
	if m != nil {
		return m.Attrs
	}
	return nil
}

func (x *HostCatalog) GetAttributes() *structpb.Struct {
	if x, ok := x.GetAttrs().(*HostCatalog_Attributes); ok {
		return x.Attributes
	}
	return nil
}

func (x *HostCatalog) GetSecrets() *structpb.Struct {
	if x != nil {
		return x.Secrets
	}
	return nil
}

func (x *HostCatalog) GetSecretsHmac() string {
	if x != nil {
		return x.SecretsHmac
	}
	return ""
}

func (x *HostCatalog) GetAuthorizedActions() []string {
	if x != nil {
		return x.AuthorizedActions
	}
	return nil
}

func (x *HostCatalog) GetAuthorizedCollectionActions() map[string]*structpb.ListValue {
	if x != nil {
		return x.AuthorizedCollectionActions
	}
	return nil
}

type isHostCatalog_Attrs interface {
	isHostCatalog_Attrs()
}

type HostCatalog_Attributes struct {
	// Attributes specific to the catalog type.
	Attributes *structpb.Struct `protobuf:"bytes,100,opt,name=attributes,proto3,oneof"`
}

func (*HostCatalog_Attributes) isHostCatalog_Attrs() {}

var File_controller_api_resources_hostcatalogs_v1_host_catalog_proto protoreflect.FileDescriptor

var file_controller_api_resources_hostcatalogs_v1_host_catalog_proto_rawDesc = []byte{
	0x0a, 0x3b, 0x63, 0x6f, 0x6e, 0x74, 0x72, 0x6f, 0x6c, 0x6c, 0x65, 0x72, 0x2f, 0x61, 0x70, 0x69,
	0x2f, 0x72, 0x65, 0x73, 0x6f, 0x75, 0x72, 0x63, 0x65, 0x73, 0x2f, 0x68, 0x6f, 0x73, 0x74, 0x63,
	0x61, 0x74, 0x61, 0x6c, 0x6f, 0x67, 0x73, 0x2f, 0x76, 0x31, 0x2f, 0x68, 0x6f, 0x73, 0x74, 0x5f,
	0x63, 0x61, 0x74, 0x61, 0x6c, 0x6f, 0x67, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x12, 0x28, 0x63,
	0x6f, 0x6e, 0x74, 0x72, 0x6f, 0x6c, 0x6c, 0x65, 0x72, 0x2e, 0x61, 0x70, 0x69, 0x2e, 0x72, 0x65,
	0x73, 0x6f, 0x75, 0x72, 0x63, 0x65, 0x73, 0x2e, 0x68, 0x6f, 0x73, 0x74, 0x63, 0x61, 0x74, 0x61,
	0x6c, 0x6f, 0x67, 0x73, 0x2e, 0x76, 0x31, 0x1a, 0x30, 0x63, 0x6f, 0x6e, 0x74, 0x72, 0x6f, 0x6c,
	0x6c, 0x65, 0x72, 0x2f, 0x61, 0x70, 0x69, 0x2f, 0x72, 0x65, 0x73, 0x6f, 0x75, 0x72, 0x63, 0x65,
	0x73, 0x2f, 0x70, 0x6c, 0x75, 0x67, 0x69, 0x6e, 0x73, 0x2f, 0x76, 0x31, 0x2f, 0x70, 0x6c, 0x75,
	0x67, 0x69, 0x6e, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x1a, 0x2e, 0x63, 0x6f, 0x6e, 0x74, 0x72,
	0x6f, 0x6c, 0x6c, 0x65, 0x72, 0x2f, 0x61, 0x70, 0x69, 0x2f, 0x72, 0x65, 0x73, 0x6f, 0x75, 0x72,
	0x63, 0x65, 0x73, 0x2f, 0x73, 0x63, 0x6f, 0x70, 0x65, 0x73, 0x2f, 0x76, 0x31, 0x2f, 0x73, 0x63,
	0x6f, 0x70, 0x65, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x1a, 0x2a, 0x63, 0x6f, 0x6e, 0x74, 0x72,
	0x6f, 0x6c, 0x6c, 0x65, 0x72, 0x2f, 0x63, 0x75, 0x73, 0x74, 0x6f, 0x6d, 0x5f, 0x6f, 0x70, 0x74,
	0x69, 0x6f, 0x6e, 0x73, 0x2f, 0x76, 0x31, 0x2f, 0x6f, 0x70, 0x74, 0x69, 0x6f, 0x6e, 0x73, 0x2e,
	0x70, 0x72, 0x6f, 0x74, 0x6f, 0x1a, 0x1c, 0x67, 0x6f, 0x6f, 0x67, 0x6c, 0x65, 0x2f, 0x70, 0x72,
	0x6f, 0x74, 0x6f, 0x62, 0x75, 0x66, 0x2f, 0x73, 0x74, 0x72, 0x75, 0x63, 0x74, 0x2e, 0x70, 0x72,
	0x6f, 0x74, 0x6f, 0x1a, 0x1f, 0x67, 0x6f, 0x6f, 0x67, 0x6c, 0x65, 0x2f, 0x70, 0x72, 0x6f, 0x74,
	0x6f, 0x62, 0x75, 0x66, 0x2f, 0x74, 0x69, 0x6d, 0x65, 0x73, 0x74, 0x61, 0x6d, 0x70, 0x2e, 0x70,
	0x72, 0x6f, 0x74, 0x6f, 0x1a, 0x1e, 0x67, 0x6f, 0x6f, 0x67, 0x6c, 0x65, 0x2f, 0x70, 0x72, 0x6f,
	0x74, 0x6f, 0x62, 0x75, 0x66, 0x2f, 0x77, 0x72, 0x61, 0x70, 0x70, 0x65, 0x72, 0x73, 0x2e, 0x70,
	0x72, 0x6f, 0x74, 0x6f, 0x22, 0xb3, 0x08, 0x0a, 0x0b, 0x48, 0x6f, 0x73, 0x74, 0x43, 0x61, 0x74,
	0x61, 0x6c, 0x6f, 0x67, 0x12, 0x0e, 0x0a, 0x02, 0x69, 0x64, 0x18, 0x0a, 0x20, 0x01, 0x28, 0x09,
	0x52, 0x02, 0x69, 0x64, 0x12, 0x1a, 0x0a, 0x08, 0x73, 0x63, 0x6f, 0x70, 0x65, 0x5f, 0x69, 0x64,
	0x18, 0x14, 0x20, 0x01, 0x28, 0x09, 0x52, 0x08, 0x73, 0x63, 0x6f, 0x70, 0x65, 0x5f, 0x69, 0x64,
	0x12, 0x43, 0x0a, 0x05, 0x73, 0x63, 0x6f, 0x70, 0x65, 0x18, 0x1e, 0x20, 0x01, 0x28, 0x0b, 0x32,
	0x2d, 0x2e, 0x63, 0x6f, 0x6e, 0x74, 0x72, 0x6f, 0x6c, 0x6c, 0x65, 0x72, 0x2e, 0x61, 0x70, 0x69,
	0x2e, 0x72, 0x65, 0x73, 0x6f, 0x75, 0x72, 0x63, 0x65, 0x73, 0x2e, 0x73, 0x63, 0x6f, 0x70, 0x65,
	0x73, 0x2e, 0x76, 0x31, 0x2e, 0x53, 0x63, 0x6f, 0x70, 0x65, 0x49, 0x6e, 0x66, 0x6f, 0x52, 0x05,
	0x73, 0x63, 0x6f, 0x70, 0x65, 0x12, 0x22, 0x0a, 0x09, 0x70, 0x6c, 0x75, 0x67, 0x69, 0x6e, 0x5f,
	0x69, 0x64, 0x18, 0x22, 0x20, 0x01, 0x28, 0x09, 0x42, 0x04, 0xa0, 0xda, 0x29, 0x01, 0x52, 0x09,
	0x70, 0x6c, 0x75, 0x67, 0x69, 0x6e, 0x5f, 0x69, 0x64, 0x12, 0x47, 0x0a, 0x06, 0x70, 0x6c, 0x75,
	0x67, 0x69, 0x6e, 0x18, 0x23, 0x20, 0x01, 0x28, 0x0b, 0x32, 0x2f, 0x2e, 0x63, 0x6f, 0x6e, 0x74,
	0x72, 0x6f, 0x6c, 0x6c, 0x65, 0x72, 0x2e, 0x61, 0x70, 0x69, 0x2e, 0x72, 0x65, 0x73, 0x6f, 0x75,
	0x72, 0x63, 0x65, 0x73, 0x2e, 0x70, 0x6c, 0x75, 0x67, 0x69, 0x6e, 0x73, 0x2e, 0x76, 0x31, 0x2e,
	0x50, 0x6c, 0x75, 0x67, 0x69, 0x6e, 0x49, 0x6e, 0x66, 0x6f, 0x52, 0x06, 0x70, 0x6c, 0x75, 0x67,
	0x69, 0x6e, 0x12, 0x46, 0x0a, 0x04, 0x6e, 0x61, 0x6d, 0x65, 0x18, 0x28, 0x20, 0x01, 0x28, 0x0b,
	0x32, 0x1c, 0x2e, 0x67, 0x6f, 0x6f, 0x67, 0x6c, 0x65, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x62,
	0x75, 0x66, 0x2e, 0x53, 0x74, 0x72, 0x69, 0x6e, 0x67, 0x56, 0x61, 0x6c, 0x75, 0x65, 0x42, 0x14,
	0xa0, 0xda, 0x29, 0x01, 0xc2, 0xdd, 0x29, 0x0c, 0x0a, 0x04, 0x6e, 0x61, 0x6d, 0x65, 0x12, 0x04,
	0x6e, 0x61, 0x6d, 0x65, 0x52, 0x04, 0x6e, 0x61, 0x6d, 0x65, 0x12, 0x62, 0x0a, 0x0b, 0x64, 0x65,
	0x73, 0x63, 0x72, 0x69, 0x70, 0x74, 0x69, 0x6f, 0x6e, 0x18, 0x32, 0x20, 0x01, 0x28, 0x0b, 0x32,
	0x1c, 0x2e, 0x67, 0x6f, 0x6f, 0x67, 0x6c, 0x65, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x62, 0x75,
	0x66, 0x2e, 0x53, 0x74, 0x72, 0x69, 0x6e, 0x67, 0x56, 0x61, 0x6c, 0x75, 0x65, 0x42, 0x22, 0xa0,
	0xda, 0x29, 0x01, 0xc2, 0xdd, 0x29, 0x1a, 0x0a, 0x0b, 0x64, 0x65, 0x73, 0x63, 0x72, 0x69, 0x70,
	0x74, 0x69, 0x6f, 0x6e, 0x12, 0x0b, 0x64, 0x65, 0x73, 0x63, 0x72, 0x69, 0x70, 0x74, 0x69, 0x6f,
	0x6e, 0x52, 0x0b, 0x64, 0x65, 0x73, 0x63, 0x72, 0x69, 0x70, 0x74, 0x69, 0x6f, 0x6e, 0x12, 0x3e,
	0x0a, 0x0c, 0x63, 0x72, 0x65, 0x61, 0x74, 0x65, 0x64, 0x5f, 0x74, 0x69, 0x6d, 0x65, 0x18, 0x3c,
	0x20, 0x01, 0x28, 0x0b, 0x32, 0x1a, 0x2e, 0x67, 0x6f, 0x6f, 0x67, 0x6c, 0x65, 0x2e, 0x70, 0x72,
	0x6f, 0x74, 0x6f, 0x62, 0x75, 0x66, 0x2e, 0x54, 0x69, 0x6d, 0x65, 0x73, 0x74, 0x61, 0x6d, 0x70,
	0x52, 0x0c, 0x63, 0x72, 0x65, 0x61, 0x74, 0x65, 0x64, 0x5f, 0x74, 0x69, 0x6d, 0x65, 0x12, 0x3e,
	0x0a, 0x0c, 0x75, 0x70, 0x64, 0x61, 0x74, 0x65, 0x64, 0x5f, 0x74, 0x69, 0x6d, 0x65, 0x18, 0x46,
	0x20, 0x01, 0x28, 0x0b, 0x32, 0x1a, 0x2e, 0x67, 0x6f, 0x6f, 0x67, 0x6c, 0x65, 0x2e, 0x70, 0x72,
	0x6f, 0x74, 0x6f, 0x62, 0x75, 0x66, 0x2e, 0x54, 0x69, 0x6d, 0x65, 0x73, 0x74, 0x61, 0x6d, 0x70,
	0x52, 0x0c, 0x75, 0x70, 0x64, 0x61, 0x74, 0x65, 0x64, 0x5f, 0x74, 0x69, 0x6d, 0x65, 0x12, 0x18,
	0x0a, 0x07, 0x76, 0x65, 0x72, 0x73, 0x69, 0x6f, 0x6e, 0x18, 0x50, 0x20, 0x01, 0x28, 0x0d, 0x52,
	0x07, 0x76, 0x65, 0x72, 0x73, 0x69, 0x6f, 0x6e, 0x12, 0x12, 0x0a, 0x04, 0x74, 0x79, 0x70, 0x65,
	0x18, 0x5a, 0x20, 0x01, 0x28, 0x09, 0x52, 0x04, 0x74, 0x79, 0x70, 0x65, 0x12, 0x4a, 0x0a, 0x0a,
	0x61, 0x74, 0x74, 0x72, 0x69, 0x62, 0x75, 0x74, 0x65, 0x73, 0x18, 0x64, 0x20, 0x01, 0x28, 0x0b,
	0x32, 0x17, 0x2e, 0x67, 0x6f, 0x6f, 0x67, 0x6c, 0x65, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x62,
	0x75, 0x66, 0x2e, 0x53, 0x74, 0x72, 0x75, 0x63, 0x74, 0x42, 0x0f, 0xa0, 0xda, 0x29, 0x01, 0x9a,
	0xe3, 0x29, 0x07, 0x64, 0x65, 0x66, 0x61, 0x75, 0x6c, 0x74, 0x48, 0x00, 0x52, 0x0a, 0x61, 0x74,
	0x74, 0x72, 0x69, 0x62, 0x75, 0x74, 0x65, 0x73, 0x12, 0x37, 0x0a, 0x07, 0x73, 0x65, 0x63, 0x72,
	0x65, 0x74, 0x73, 0x18, 0x6e, 0x20, 0x01, 0x28, 0x0b, 0x32, 0x17, 0x2e, 0x67, 0x6f, 0x6f, 0x67,
	0x6c, 0x65, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x62, 0x75, 0x66, 0x2e, 0x53, 0x74, 0x72, 0x75,
	0x63, 0x74, 0x42, 0x04, 0xa0, 0xda, 0x29, 0x01, 0x52, 0x07, 0x73, 0x65, 0x63, 0x72, 0x65, 0x74,
	0x73, 0x12, 0x21, 0x0a, 0x0c, 0x73, 0x65, 0x63, 0x72, 0x65, 0x74, 0x73, 0x5f, 0x68, 0x6d, 0x61,
	0x63, 0x18, 0x78, 0x20, 0x01, 0x28, 0x09, 0x52, 0x0b, 0x73, 0x65, 0x63, 0x72, 0x65, 0x74, 0x73,
	0x48, 0x6d, 0x61, 0x63, 0x12, 0x2f, 0x0a, 0x12, 0x61, 0x75, 0x74, 0x68, 0x6f, 0x72, 0x69, 0x7a,
	0x65, 0x64, 0x5f, 0x61, 0x63, 0x74, 0x69, 0x6f, 0x6e, 0x73, 0x18, 0xac, 0x02, 0x20, 0x03, 0x28,
	0x09, 0x52, 0x12, 0x61, 0x75, 0x74, 0x68, 0x6f, 0x72, 0x69, 0x7a, 0x65, 0x64, 0x5f, 0x61, 0x63,
	0x74, 0x69, 0x6f, 0x6e, 0x73, 0x12, 0x9d, 0x01, 0x0a, 0x1d, 0x61, 0x75, 0x74, 0x68, 0x6f, 0x72,
	0x69, 0x7a, 0x65, 0x64, 0x5f, 0x63, 0x6f, 0x6c, 0x6c, 0x65, 0x63, 0x74, 0x69, 0x6f, 0x6e, 0x5f,
	0x61, 0x63, 0x74, 0x69, 0x6f, 0x6e, 0x73, 0x18, 0xb6, 0x02, 0x20, 0x03, 0x28, 0x0b, 0x32, 0x56,
	0x2e, 0x63, 0x6f, 0x6e, 0x74, 0x72, 0x6f, 0x6c, 0x6c, 0x65, 0x72, 0x2e, 0x61, 0x70, 0x69, 0x2e,
	0x72, 0x65, 0x73, 0x6f, 0x75, 0x72, 0x63, 0x65, 0x73, 0x2e, 0x68, 0x6f, 0x73, 0x74, 0x63, 0x61,
	0x74, 0x61, 0x6c, 0x6f, 0x67, 0x73, 0x2e, 0x76, 0x31, 0x2e, 0x48, 0x6f, 0x73, 0x74, 0x43, 0x61,
	0x74, 0x61, 0x6c, 0x6f, 0x67, 0x2e, 0x41, 0x75, 0x74, 0x68, 0x6f, 0x72, 0x69, 0x7a, 0x65, 0x64,
	0x43, 0x6f, 0x6c, 0x6c, 0x65, 0x63, 0x74, 0x69, 0x6f, 0x6e, 0x41, 0x63, 0x74, 0x69, 0x6f, 0x6e,
	0x73, 0x45, 0x6e, 0x74, 0x72, 0x79, 0x52, 0x1d, 0x61, 0x75, 0x74, 0x68, 0x6f, 0x72, 0x69, 0x7a,
	0x65, 0x64, 0x5f, 0x63, 0x6f, 0x6c, 0x6c, 0x65, 0x63, 0x74, 0x69, 0x6f, 0x6e, 0x5f, 0x61, 0x63,
	0x74, 0x69, 0x6f, 0x6e, 0x73, 0x1a, 0x6a, 0x0a, 0x20, 0x41, 0x75, 0x74, 0x68, 0x6f, 0x72, 0x69,
	0x7a, 0x65, 0x64, 0x43, 0x6f, 0x6c, 0x6c, 0x65, 0x63, 0x74, 0x69, 0x6f, 0x6e, 0x41, 0x63, 0x74,
	0x69, 0x6f, 0x6e, 0x73, 0x45, 0x6e, 0x74, 0x72, 0x79, 0x12, 0x10, 0x0a, 0x03, 0x6b, 0x65, 0x79,
	0x18, 0x01, 0x20, 0x01, 0x28, 0x09, 0x52, 0x03, 0x6b, 0x65, 0x79, 0x12, 0x30, 0x0a, 0x05, 0x76,
	0x61, 0x6c, 0x75, 0x65, 0x18, 0x02, 0x20, 0x01, 0x28, 0x0b, 0x32, 0x1a, 0x2e, 0x67, 0x6f, 0x6f,
	0x67, 0x6c, 0x65, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x62, 0x75, 0x66, 0x2e, 0x4c, 0x69, 0x73,
	0x74, 0x56, 0x61, 0x6c, 0x75, 0x65, 0x52, 0x05, 0x76, 0x61, 0x6c, 0x75, 0x65, 0x3a, 0x02, 0x38,
	0x01, 0x42, 0x07, 0x0a, 0x05, 0x61, 0x74, 0x74, 0x72, 0x73, 0x42, 0x5a, 0x5a, 0x58, 0x67, 0x69,
	0x74, 0x68, 0x75, 0x62, 0x2e, 0x63, 0x6f, 0x6d, 0x2f, 0x68, 0x61, 0x73, 0x68, 0x69, 0x63, 0x6f,
	0x72, 0x70, 0x2f, 0x62, 0x6f, 0x75, 0x6e, 0x64, 0x61, 0x72, 0x79, 0x2f, 0x73, 0x64, 0x6b, 0x2f,
	0x70, 0x62, 0x73, 0x2f, 0x63, 0x6f, 0x6e, 0x74, 0x72, 0x6f, 0x6c, 0x6c, 0x65, 0x72, 0x2f, 0x61,
	0x70, 0x69, 0x2f, 0x72, 0x65, 0x73, 0x6f, 0x75, 0x72, 0x63, 0x65, 0x73, 0x2f, 0x68, 0x6f, 0x73,
	0x74, 0x63, 0x61, 0x74, 0x61, 0x6c, 0x6f, 0x67, 0x73, 0x3b, 0x68, 0x6f, 0x73, 0x74, 0x63, 0x61,
	0x74, 0x61, 0x6c, 0x6f, 0x67, 0x73, 0x62, 0x06, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x33,
}

var (
	file_controller_api_resources_hostcatalogs_v1_host_catalog_proto_rawDescOnce sync.Once
	file_controller_api_resources_hostcatalogs_v1_host_catalog_proto_rawDescData = file_controller_api_resources_hostcatalogs_v1_host_catalog_proto_rawDesc
)

func file_controller_api_resources_hostcatalogs_v1_host_catalog_proto_rawDescGZIP() []byte {
	file_controller_api_resources_hostcatalogs_v1_host_catalog_proto_rawDescOnce.Do(func() {
		file_controller_api_resources_hostcatalogs_v1_host_catalog_proto_rawDescData = protoimpl.X.CompressGZIP(file_controller_api_resources_hostcatalogs_v1_host_catalog_proto_rawDescData)
	})
	return file_controller_api_resources_hostcatalogs_v1_host_catalog_proto_rawDescData
}

var file_controller_api_resources_hostcatalogs_v1_host_catalog_proto_msgTypes = make([]protoimpl.MessageInfo, 2)
var file_controller_api_resources_hostcatalogs_v1_host_catalog_proto_goTypes = []interface{}{
	(*HostCatalog)(nil),            // 0: controller.api.resources.hostcatalogs.v1.HostCatalog
	nil,                            // 1: controller.api.resources.hostcatalogs.v1.HostCatalog.AuthorizedCollectionActionsEntry
	(*scopes.ScopeInfo)(nil),       // 2: controller.api.resources.scopes.v1.ScopeInfo
	(*plugins.PluginInfo)(nil),     // 3: controller.api.resources.plugins.v1.PluginInfo
	(*wrapperspb.StringValue)(nil), // 4: google.protobuf.StringValue
	(*timestamppb.Timestamp)(nil),  // 5: google.protobuf.Timestamp
	(*structpb.Struct)(nil),        // 6: google.protobuf.Struct
	(*structpb.ListValue)(nil),     // 7: google.protobuf.ListValue
}
var file_controller_api_resources_hostcatalogs_v1_host_catalog_proto_depIdxs = []int32{
	2,  // 0: controller.api.resources.hostcatalogs.v1.HostCatalog.scope:type_name -> controller.api.resources.scopes.v1.ScopeInfo
	3,  // 1: controller.api.resources.hostcatalogs.v1.HostCatalog.plugin:type_name -> controller.api.resources.plugins.v1.PluginInfo
	4,  // 2: controller.api.resources.hostcatalogs.v1.HostCatalog.name:type_name -> google.protobuf.StringValue
	4,  // 3: controller.api.resources.hostcatalogs.v1.HostCatalog.description:type_name -> google.protobuf.StringValue
	5,  // 4: controller.api.resources.hostcatalogs.v1.HostCatalog.created_time:type_name -> google.protobuf.Timestamp
	5,  // 5: controller.api.resources.hostcatalogs.v1.HostCatalog.updated_time:type_name -> google.protobuf.Timestamp
	6,  // 6: controller.api.resources.hostcatalogs.v1.HostCatalog.attributes:type_name -> google.protobuf.Struct
	6,  // 7: controller.api.resources.hostcatalogs.v1.HostCatalog.secrets:type_name -> google.protobuf.Struct
	1,  // 8: controller.api.resources.hostcatalogs.v1.HostCatalog.authorized_collection_actions:type_name -> controller.api.resources.hostcatalogs.v1.HostCatalog.AuthorizedCollectionActionsEntry
	7,  // 9: controller.api.resources.hostcatalogs.v1.HostCatalog.AuthorizedCollectionActionsEntry.value:type_name -> google.protobuf.ListValue
	10, // [10:10] is the sub-list for method output_type
	10, // [10:10] is the sub-list for method input_type
	10, // [10:10] is the sub-list for extension type_name
	10, // [10:10] is the sub-list for extension extendee
	0,  // [0:10] is the sub-list for field type_name
}

func init() { file_controller_api_resources_hostcatalogs_v1_host_catalog_proto_init() }
func file_controller_api_resources_hostcatalogs_v1_host_catalog_proto_init() {
	if File_controller_api_resources_hostcatalogs_v1_host_catalog_proto != nil {
		return
	}
	if !protoimpl.UnsafeEnabled {
		file_controller_api_resources_hostcatalogs_v1_host_catalog_proto_msgTypes[0].Exporter = func(v interface{}, i int) interface{} {
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
	}
	file_controller_api_resources_hostcatalogs_v1_host_catalog_proto_msgTypes[0].OneofWrappers = []interface{}{
		(*HostCatalog_Attributes)(nil),
	}
	type x struct{}
	out := protoimpl.TypeBuilder{
		File: protoimpl.DescBuilder{
			GoPackagePath: reflect.TypeOf(x{}).PkgPath(),
			RawDescriptor: file_controller_api_resources_hostcatalogs_v1_host_catalog_proto_rawDesc,
			NumEnums:      0,
			NumMessages:   2,
			NumExtensions: 0,
			NumServices:   0,
		},
		GoTypes:           file_controller_api_resources_hostcatalogs_v1_host_catalog_proto_goTypes,
		DependencyIndexes: file_controller_api_resources_hostcatalogs_v1_host_catalog_proto_depIdxs,
		MessageInfos:      file_controller_api_resources_hostcatalogs_v1_host_catalog_proto_msgTypes,
	}.Build()
	File_controller_api_resources_hostcatalogs_v1_host_catalog_proto = out.File
	file_controller_api_resources_hostcatalogs_v1_host_catalog_proto_rawDesc = nil
	file_controller_api_resources_hostcatalogs_v1_host_catalog_proto_goTypes = nil
	file_controller_api_resources_hostcatalogs_v1_host_catalog_proto_depIdxs = nil
}
