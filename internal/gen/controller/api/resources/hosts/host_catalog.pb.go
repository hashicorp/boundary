// Code generated by protoc-gen-go. DO NOT EDIT.
// versions:
// 	protoc-gen-go v1.25.0
// 	protoc        v3.12.4
// source: controller/api/resources/hosts/v1/host_catalog.proto

package hosts

import (
	proto "github.com/golang/protobuf/proto"
	_struct "github.com/golang/protobuf/ptypes/struct"
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

// HostCatalog manages Hosts and HostSets
type HostCatalog struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	// The ID of the host
	// Output only.
	Id string `protobuf:"bytes,1,opt,name=id,proto3" json:"id,omitempty"`
	// Scope information for this resource
	// Output only.
	Scope *scopes.ScopeInfo `protobuf:"bytes,2,opt,name=scope,proto3" json:"scope,omitempty"`
	// The type of the resource, to help differentiate schemas
	Type *wrappers.StringValue `protobuf:"bytes,3,opt,name=type,proto3" json:"type,omitempty"`
	// Optional name for identification purposes
	Name *wrappers.StringValue `protobuf:"bytes,4,opt,name=name,proto3" json:"name,omitempty"`
	// Optional user-set description for identification purposes
	Description *wrappers.StringValue `protobuf:"bytes,5,opt,name=description,proto3" json:"description,omitempty"`
	// The time this resource was created
	// Output only.
	CreatedTime *timestamp.Timestamp `protobuf:"bytes,6,opt,name=created_time,proto3" json:"created_time,omitempty"`
	// The time this resource was last updated
	// Output only.
	UpdatedTime *timestamp.Timestamp `protobuf:"bytes,7,opt,name=updated_time,proto3" json:"updated_time,omitempty"`
	// Whether the catalog is disabled
	Disabled *wrappers.BoolValue `protobuf:"bytes,8,opt,name=disabled,proto3" json:"disabled,omitempty"`
	// Attributes specific to the catalog type
	Attributes *_struct.Struct `protobuf:"bytes,9,opt,name=attributes,proto3" json:"attributes,omitempty"`
}

func (x *HostCatalog) Reset() {
	*x = HostCatalog{}
	if protoimpl.UnsafeEnabled {
		mi := &file_controller_api_resources_hosts_v1_host_catalog_proto_msgTypes[0]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *HostCatalog) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*HostCatalog) ProtoMessage() {}

func (x *HostCatalog) ProtoReflect() protoreflect.Message {
	mi := &file_controller_api_resources_hosts_v1_host_catalog_proto_msgTypes[0]
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
	return file_controller_api_resources_hosts_v1_host_catalog_proto_rawDescGZIP(), []int{0}
}

func (x *HostCatalog) GetId() string {
	if x != nil {
		return x.Id
	}
	return ""
}

func (x *HostCatalog) GetScope() *scopes.ScopeInfo {
	if x != nil {
		return x.Scope
	}
	return nil
}

func (x *HostCatalog) GetType() *wrappers.StringValue {
	if x != nil {
		return x.Type
	}
	return nil
}

func (x *HostCatalog) GetName() *wrappers.StringValue {
	if x != nil {
		return x.Name
	}
	return nil
}

func (x *HostCatalog) GetDescription() *wrappers.StringValue {
	if x != nil {
		return x.Description
	}
	return nil
}

func (x *HostCatalog) GetCreatedTime() *timestamp.Timestamp {
	if x != nil {
		return x.CreatedTime
	}
	return nil
}

func (x *HostCatalog) GetUpdatedTime() *timestamp.Timestamp {
	if x != nil {
		return x.UpdatedTime
	}
	return nil
}

func (x *HostCatalog) GetDisabled() *wrappers.BoolValue {
	if x != nil {
		return x.Disabled
	}
	return nil
}

func (x *HostCatalog) GetAttributes() *_struct.Struct {
	if x != nil {
		return x.Attributes
	}
	return nil
}

type StaticHostCatalogDetails struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields
}

func (x *StaticHostCatalogDetails) Reset() {
	*x = StaticHostCatalogDetails{}
	if protoimpl.UnsafeEnabled {
		mi := &file_controller_api_resources_hosts_v1_host_catalog_proto_msgTypes[1]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *StaticHostCatalogDetails) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*StaticHostCatalogDetails) ProtoMessage() {}

func (x *StaticHostCatalogDetails) ProtoReflect() protoreflect.Message {
	mi := &file_controller_api_resources_hosts_v1_host_catalog_proto_msgTypes[1]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use StaticHostCatalogDetails.ProtoReflect.Descriptor instead.
func (*StaticHostCatalogDetails) Descriptor() ([]byte, []int) {
	return file_controller_api_resources_hosts_v1_host_catalog_proto_rawDescGZIP(), []int{1}
}

type AwsEc2HostCatalogDetails struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	// The AWS regions from which this catalog will retrieve the EC2 instances.
	Regions []string `protobuf:"bytes,1,rep,name=regions,proto3" json:"regions,omitempty"`
	// The access key used for authenticating with AWS when retrieving EC2 instance details.
	AccessKey *wrappers.StringValue `protobuf:"bytes,2,opt,name=access_key,proto3" json:"access_key,omitempty"`
	// Input only.
	SecretKey *wrappers.StringValue `protobuf:"bytes,3,opt,name=secret_key,proto3" json:"secret_key,omitempty"`
	// This value will never be returned in a response.
	Rotate *wrappers.BoolValue `protobuf:"bytes,4,opt,name=rotate,proto3" json:"rotate,omitempty"`
}

func (x *AwsEc2HostCatalogDetails) Reset() {
	*x = AwsEc2HostCatalogDetails{}
	if protoimpl.UnsafeEnabled {
		mi := &file_controller_api_resources_hosts_v1_host_catalog_proto_msgTypes[2]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *AwsEc2HostCatalogDetails) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*AwsEc2HostCatalogDetails) ProtoMessage() {}

func (x *AwsEc2HostCatalogDetails) ProtoReflect() protoreflect.Message {
	mi := &file_controller_api_resources_hosts_v1_host_catalog_proto_msgTypes[2]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use AwsEc2HostCatalogDetails.ProtoReflect.Descriptor instead.
func (*AwsEc2HostCatalogDetails) Descriptor() ([]byte, []int) {
	return file_controller_api_resources_hosts_v1_host_catalog_proto_rawDescGZIP(), []int{2}
}

func (x *AwsEc2HostCatalogDetails) GetRegions() []string {
	if x != nil {
		return x.Regions
	}
	return nil
}

func (x *AwsEc2HostCatalogDetails) GetAccessKey() *wrappers.StringValue {
	if x != nil {
		return x.AccessKey
	}
	return nil
}

func (x *AwsEc2HostCatalogDetails) GetSecretKey() *wrappers.StringValue {
	if x != nil {
		return x.SecretKey
	}
	return nil
}

func (x *AwsEc2HostCatalogDetails) GetRotate() *wrappers.BoolValue {
	if x != nil {
		return x.Rotate
	}
	return nil
}

var File_controller_api_resources_hosts_v1_host_catalog_proto protoreflect.FileDescriptor

var file_controller_api_resources_hosts_v1_host_catalog_proto_rawDesc = []byte{
	0x0a, 0x34, 0x63, 0x6f, 0x6e, 0x74, 0x72, 0x6f, 0x6c, 0x6c, 0x65, 0x72, 0x2f, 0x61, 0x70, 0x69,
	0x2f, 0x72, 0x65, 0x73, 0x6f, 0x75, 0x72, 0x63, 0x65, 0x73, 0x2f, 0x68, 0x6f, 0x73, 0x74, 0x73,
	0x2f, 0x76, 0x31, 0x2f, 0x68, 0x6f, 0x73, 0x74, 0x5f, 0x63, 0x61, 0x74, 0x61, 0x6c, 0x6f, 0x67,
	0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x12, 0x21, 0x63, 0x6f, 0x6e, 0x74, 0x72, 0x6f, 0x6c, 0x6c,
	0x65, 0x72, 0x2e, 0x61, 0x70, 0x69, 0x2e, 0x72, 0x65, 0x73, 0x6f, 0x75, 0x72, 0x63, 0x65, 0x73,
	0x2e, 0x68, 0x6f, 0x73, 0x74, 0x73, 0x2e, 0x76, 0x31, 0x1a, 0x1f, 0x67, 0x6f, 0x6f, 0x67, 0x6c,
	0x65, 0x2f, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x62, 0x75, 0x66, 0x2f, 0x74, 0x69, 0x6d, 0x65, 0x73,
	0x74, 0x61, 0x6d, 0x70, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x1a, 0x1e, 0x67, 0x6f, 0x6f, 0x67,
	0x6c, 0x65, 0x2f, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x62, 0x75, 0x66, 0x2f, 0x77, 0x72, 0x61, 0x70,
	0x70, 0x65, 0x72, 0x73, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x1a, 0x1c, 0x67, 0x6f, 0x6f, 0x67,
	0x6c, 0x65, 0x2f, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x62, 0x75, 0x66, 0x2f, 0x73, 0x74, 0x72, 0x75,
	0x63, 0x74, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x1a, 0x2e, 0x63, 0x6f, 0x6e, 0x74, 0x72, 0x6f,
	0x6c, 0x6c, 0x65, 0x72, 0x2f, 0x61, 0x70, 0x69, 0x2f, 0x72, 0x65, 0x73, 0x6f, 0x75, 0x72, 0x63,
	0x65, 0x73, 0x2f, 0x73, 0x63, 0x6f, 0x70, 0x65, 0x73, 0x2f, 0x76, 0x31, 0x2f, 0x73, 0x63, 0x6f,
	0x70, 0x65, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x1a, 0x2a, 0x63, 0x6f, 0x6e, 0x74, 0x72, 0x6f,
	0x6c, 0x6c, 0x65, 0x72, 0x2f, 0x63, 0x75, 0x73, 0x74, 0x6f, 0x6d, 0x5f, 0x6f, 0x70, 0x74, 0x69,
	0x6f, 0x6e, 0x73, 0x2f, 0x76, 0x31, 0x2f, 0x6f, 0x70, 0x74, 0x69, 0x6f, 0x6e, 0x73, 0x2e, 0x70,
	0x72, 0x6f, 0x74, 0x6f, 0x22, 0xc3, 0x04, 0x0a, 0x0b, 0x48, 0x6f, 0x73, 0x74, 0x43, 0x61, 0x74,
	0x61, 0x6c, 0x6f, 0x67, 0x12, 0x0e, 0x0a, 0x02, 0x69, 0x64, 0x18, 0x01, 0x20, 0x01, 0x28, 0x09,
	0x52, 0x02, 0x69, 0x64, 0x12, 0x43, 0x0a, 0x05, 0x73, 0x63, 0x6f, 0x70, 0x65, 0x18, 0x02, 0x20,
	0x01, 0x28, 0x0b, 0x32, 0x2d, 0x2e, 0x63, 0x6f, 0x6e, 0x74, 0x72, 0x6f, 0x6c, 0x6c, 0x65, 0x72,
	0x2e, 0x61, 0x70, 0x69, 0x2e, 0x72, 0x65, 0x73, 0x6f, 0x75, 0x72, 0x63, 0x65, 0x73, 0x2e, 0x73,
	0x63, 0x6f, 0x70, 0x65, 0x73, 0x2e, 0x76, 0x31, 0x2e, 0x53, 0x63, 0x6f, 0x70, 0x65, 0x49, 0x6e,
	0x66, 0x6f, 0x52, 0x05, 0x73, 0x63, 0x6f, 0x70, 0x65, 0x12, 0x36, 0x0a, 0x04, 0x74, 0x79, 0x70,
	0x65, 0x18, 0x03, 0x20, 0x01, 0x28, 0x0b, 0x32, 0x1c, 0x2e, 0x67, 0x6f, 0x6f, 0x67, 0x6c, 0x65,
	0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x62, 0x75, 0x66, 0x2e, 0x53, 0x74, 0x72, 0x69, 0x6e, 0x67,
	0x56, 0x61, 0x6c, 0x75, 0x65, 0x42, 0x04, 0xa0, 0xda, 0x29, 0x01, 0x52, 0x04, 0x74, 0x79, 0x70,
	0x65, 0x12, 0x46, 0x0a, 0x04, 0x6e, 0x61, 0x6d, 0x65, 0x18, 0x04, 0x20, 0x01, 0x28, 0x0b, 0x32,
	0x1c, 0x2e, 0x67, 0x6f, 0x6f, 0x67, 0x6c, 0x65, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x62, 0x75,
	0x66, 0x2e, 0x53, 0x74, 0x72, 0x69, 0x6e, 0x67, 0x56, 0x61, 0x6c, 0x75, 0x65, 0x42, 0x14, 0xa0,
	0xda, 0x29, 0x01, 0xc2, 0xdd, 0x29, 0x0c, 0x0a, 0x04, 0x6e, 0x61, 0x6d, 0x65, 0x12, 0x04, 0x6e,
	0x61, 0x6d, 0x65, 0x52, 0x04, 0x6e, 0x61, 0x6d, 0x65, 0x12, 0x62, 0x0a, 0x0b, 0x64, 0x65, 0x73,
	0x63, 0x72, 0x69, 0x70, 0x74, 0x69, 0x6f, 0x6e, 0x18, 0x05, 0x20, 0x01, 0x28, 0x0b, 0x32, 0x1c,
	0x2e, 0x67, 0x6f, 0x6f, 0x67, 0x6c, 0x65, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x62, 0x75, 0x66,
	0x2e, 0x53, 0x74, 0x72, 0x69, 0x6e, 0x67, 0x56, 0x61, 0x6c, 0x75, 0x65, 0x42, 0x22, 0xa0, 0xda,
	0x29, 0x01, 0xc2, 0xdd, 0x29, 0x1a, 0x0a, 0x0b, 0x64, 0x65, 0x73, 0x63, 0x72, 0x69, 0x70, 0x74,
	0x69, 0x6f, 0x6e, 0x12, 0x0b, 0x64, 0x65, 0x73, 0x63, 0x72, 0x69, 0x70, 0x74, 0x69, 0x6f, 0x6e,
	0x52, 0x0b, 0x64, 0x65, 0x73, 0x63, 0x72, 0x69, 0x70, 0x74, 0x69, 0x6f, 0x6e, 0x12, 0x3e, 0x0a,
	0x0c, 0x63, 0x72, 0x65, 0x61, 0x74, 0x65, 0x64, 0x5f, 0x74, 0x69, 0x6d, 0x65, 0x18, 0x06, 0x20,
	0x01, 0x28, 0x0b, 0x32, 0x1a, 0x2e, 0x67, 0x6f, 0x6f, 0x67, 0x6c, 0x65, 0x2e, 0x70, 0x72, 0x6f,
	0x74, 0x6f, 0x62, 0x75, 0x66, 0x2e, 0x54, 0x69, 0x6d, 0x65, 0x73, 0x74, 0x61, 0x6d, 0x70, 0x52,
	0x0c, 0x63, 0x72, 0x65, 0x61, 0x74, 0x65, 0x64, 0x5f, 0x74, 0x69, 0x6d, 0x65, 0x12, 0x3e, 0x0a,
	0x0c, 0x75, 0x70, 0x64, 0x61, 0x74, 0x65, 0x64, 0x5f, 0x74, 0x69, 0x6d, 0x65, 0x18, 0x07, 0x20,
	0x01, 0x28, 0x0b, 0x32, 0x1a, 0x2e, 0x67, 0x6f, 0x6f, 0x67, 0x6c, 0x65, 0x2e, 0x70, 0x72, 0x6f,
	0x74, 0x6f, 0x62, 0x75, 0x66, 0x2e, 0x54, 0x69, 0x6d, 0x65, 0x73, 0x74, 0x61, 0x6d, 0x70, 0x52,
	0x0c, 0x75, 0x70, 0x64, 0x61, 0x74, 0x65, 0x64, 0x5f, 0x74, 0x69, 0x6d, 0x65, 0x12, 0x3c, 0x0a,
	0x08, 0x64, 0x69, 0x73, 0x61, 0x62, 0x6c, 0x65, 0x64, 0x18, 0x08, 0x20, 0x01, 0x28, 0x0b, 0x32,
	0x1a, 0x2e, 0x67, 0x6f, 0x6f, 0x67, 0x6c, 0x65, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x62, 0x75,
	0x66, 0x2e, 0x42, 0x6f, 0x6f, 0x6c, 0x56, 0x61, 0x6c, 0x75, 0x65, 0x42, 0x04, 0xa0, 0xda, 0x29,
	0x01, 0x52, 0x08, 0x64, 0x69, 0x73, 0x61, 0x62, 0x6c, 0x65, 0x64, 0x12, 0x3d, 0x0a, 0x0a, 0x61,
	0x74, 0x74, 0x72, 0x69, 0x62, 0x75, 0x74, 0x65, 0x73, 0x18, 0x09, 0x20, 0x01, 0x28, 0x0b, 0x32,
	0x17, 0x2e, 0x67, 0x6f, 0x6f, 0x67, 0x6c, 0x65, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x62, 0x75,
	0x66, 0x2e, 0x53, 0x74, 0x72, 0x75, 0x63, 0x74, 0x42, 0x04, 0xa0, 0xda, 0x29, 0x01, 0x52, 0x0a,
	0x61, 0x74, 0x74, 0x72, 0x69, 0x62, 0x75, 0x74, 0x65, 0x73, 0x22, 0x1a, 0x0a, 0x18, 0x53, 0x74,
	0x61, 0x74, 0x69, 0x63, 0x48, 0x6f, 0x73, 0x74, 0x43, 0x61, 0x74, 0x61, 0x6c, 0x6f, 0x67, 0x44,
	0x65, 0x74, 0x61, 0x69, 0x6c, 0x73, 0x22, 0xe4, 0x01, 0x0a, 0x18, 0x41, 0x77, 0x73, 0x45, 0x63,
	0x32, 0x48, 0x6f, 0x73, 0x74, 0x43, 0x61, 0x74, 0x61, 0x6c, 0x6f, 0x67, 0x44, 0x65, 0x74, 0x61,
	0x69, 0x6c, 0x73, 0x12, 0x18, 0x0a, 0x07, 0x72, 0x65, 0x67, 0x69, 0x6f, 0x6e, 0x73, 0x18, 0x01,
	0x20, 0x03, 0x28, 0x09, 0x52, 0x07, 0x72, 0x65, 0x67, 0x69, 0x6f, 0x6e, 0x73, 0x12, 0x3c, 0x0a,
	0x0a, 0x61, 0x63, 0x63, 0x65, 0x73, 0x73, 0x5f, 0x6b, 0x65, 0x79, 0x18, 0x02, 0x20, 0x01, 0x28,
	0x0b, 0x32, 0x1c, 0x2e, 0x67, 0x6f, 0x6f, 0x67, 0x6c, 0x65, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f,
	0x62, 0x75, 0x66, 0x2e, 0x53, 0x74, 0x72, 0x69, 0x6e, 0x67, 0x56, 0x61, 0x6c, 0x75, 0x65, 0x52,
	0x0a, 0x61, 0x63, 0x63, 0x65, 0x73, 0x73, 0x5f, 0x6b, 0x65, 0x79, 0x12, 0x3c, 0x0a, 0x0a, 0x73,
	0x65, 0x63, 0x72, 0x65, 0x74, 0x5f, 0x6b, 0x65, 0x79, 0x18, 0x03, 0x20, 0x01, 0x28, 0x0b, 0x32,
	0x1c, 0x2e, 0x67, 0x6f, 0x6f, 0x67, 0x6c, 0x65, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x62, 0x75,
	0x66, 0x2e, 0x53, 0x74, 0x72, 0x69, 0x6e, 0x67, 0x56, 0x61, 0x6c, 0x75, 0x65, 0x52, 0x0a, 0x73,
	0x65, 0x63, 0x72, 0x65, 0x74, 0x5f, 0x6b, 0x65, 0x79, 0x12, 0x32, 0x0a, 0x06, 0x72, 0x6f, 0x74,
	0x61, 0x74, 0x65, 0x18, 0x04, 0x20, 0x01, 0x28, 0x0b, 0x32, 0x1a, 0x2e, 0x67, 0x6f, 0x6f, 0x67,
	0x6c, 0x65, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x62, 0x75, 0x66, 0x2e, 0x42, 0x6f, 0x6f, 0x6c,
	0x56, 0x61, 0x6c, 0x75, 0x65, 0x52, 0x06, 0x72, 0x6f, 0x74, 0x61, 0x74, 0x65, 0x42, 0x51, 0x5a,
	0x4f, 0x67, 0x69, 0x74, 0x68, 0x75, 0x62, 0x2e, 0x63, 0x6f, 0x6d, 0x2f, 0x68, 0x61, 0x73, 0x68,
	0x69, 0x63, 0x6f, 0x72, 0x70, 0x2f, 0x62, 0x6f, 0x75, 0x6e, 0x64, 0x61, 0x72, 0x79, 0x2f, 0x69,
	0x6e, 0x74, 0x65, 0x72, 0x6e, 0x61, 0x6c, 0x2f, 0x67, 0x65, 0x6e, 0x2f, 0x63, 0x6f, 0x6e, 0x74,
	0x72, 0x6f, 0x6c, 0x6c, 0x65, 0x72, 0x2f, 0x61, 0x70, 0x69, 0x2f, 0x72, 0x65, 0x73, 0x6f, 0x75,
	0x72, 0x63, 0x65, 0x73, 0x2f, 0x68, 0x6f, 0x73, 0x74, 0x73, 0x3b, 0x68, 0x6f, 0x73, 0x74, 0x73,
	0x62, 0x06, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x33,
}

var (
	file_controller_api_resources_hosts_v1_host_catalog_proto_rawDescOnce sync.Once
	file_controller_api_resources_hosts_v1_host_catalog_proto_rawDescData = file_controller_api_resources_hosts_v1_host_catalog_proto_rawDesc
)

func file_controller_api_resources_hosts_v1_host_catalog_proto_rawDescGZIP() []byte {
	file_controller_api_resources_hosts_v1_host_catalog_proto_rawDescOnce.Do(func() {
		file_controller_api_resources_hosts_v1_host_catalog_proto_rawDescData = protoimpl.X.CompressGZIP(file_controller_api_resources_hosts_v1_host_catalog_proto_rawDescData)
	})
	return file_controller_api_resources_hosts_v1_host_catalog_proto_rawDescData
}

var file_controller_api_resources_hosts_v1_host_catalog_proto_msgTypes = make([]protoimpl.MessageInfo, 3)
var file_controller_api_resources_hosts_v1_host_catalog_proto_goTypes = []interface{}{
	(*HostCatalog)(nil),              // 0: controller.api.resources.hosts.v1.HostCatalog
	(*StaticHostCatalogDetails)(nil), // 1: controller.api.resources.hosts.v1.StaticHostCatalogDetails
	(*AwsEc2HostCatalogDetails)(nil), // 2: controller.api.resources.hosts.v1.AwsEc2HostCatalogDetails
	(*scopes.ScopeInfo)(nil),         // 3: controller.api.resources.scopes.v1.ScopeInfo
	(*wrappers.StringValue)(nil),     // 4: google.protobuf.StringValue
	(*timestamp.Timestamp)(nil),      // 5: google.protobuf.Timestamp
	(*wrappers.BoolValue)(nil),       // 6: google.protobuf.BoolValue
	(*_struct.Struct)(nil),           // 7: google.protobuf.Struct
}
var file_controller_api_resources_hosts_v1_host_catalog_proto_depIdxs = []int32{
	3,  // 0: controller.api.resources.hosts.v1.HostCatalog.scope:type_name -> controller.api.resources.scopes.v1.ScopeInfo
	4,  // 1: controller.api.resources.hosts.v1.HostCatalog.type:type_name -> google.protobuf.StringValue
	4,  // 2: controller.api.resources.hosts.v1.HostCatalog.name:type_name -> google.protobuf.StringValue
	4,  // 3: controller.api.resources.hosts.v1.HostCatalog.description:type_name -> google.protobuf.StringValue
	5,  // 4: controller.api.resources.hosts.v1.HostCatalog.created_time:type_name -> google.protobuf.Timestamp
	5,  // 5: controller.api.resources.hosts.v1.HostCatalog.updated_time:type_name -> google.protobuf.Timestamp
	6,  // 6: controller.api.resources.hosts.v1.HostCatalog.disabled:type_name -> google.protobuf.BoolValue
	7,  // 7: controller.api.resources.hosts.v1.HostCatalog.attributes:type_name -> google.protobuf.Struct
	4,  // 8: controller.api.resources.hosts.v1.AwsEc2HostCatalogDetails.access_key:type_name -> google.protobuf.StringValue
	4,  // 9: controller.api.resources.hosts.v1.AwsEc2HostCatalogDetails.secret_key:type_name -> google.protobuf.StringValue
	6,  // 10: controller.api.resources.hosts.v1.AwsEc2HostCatalogDetails.rotate:type_name -> google.protobuf.BoolValue
	11, // [11:11] is the sub-list for method output_type
	11, // [11:11] is the sub-list for method input_type
	11, // [11:11] is the sub-list for extension type_name
	11, // [11:11] is the sub-list for extension extendee
	0,  // [0:11] is the sub-list for field type_name
}

func init() { file_controller_api_resources_hosts_v1_host_catalog_proto_init() }
func file_controller_api_resources_hosts_v1_host_catalog_proto_init() {
	if File_controller_api_resources_hosts_v1_host_catalog_proto != nil {
		return
	}
	if !protoimpl.UnsafeEnabled {
		file_controller_api_resources_hosts_v1_host_catalog_proto_msgTypes[0].Exporter = func(v interface{}, i int) interface{} {
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
		file_controller_api_resources_hosts_v1_host_catalog_proto_msgTypes[1].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*StaticHostCatalogDetails); i {
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
		file_controller_api_resources_hosts_v1_host_catalog_proto_msgTypes[2].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*AwsEc2HostCatalogDetails); i {
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
			RawDescriptor: file_controller_api_resources_hosts_v1_host_catalog_proto_rawDesc,
			NumEnums:      0,
			NumMessages:   3,
			NumExtensions: 0,
			NumServices:   0,
		},
		GoTypes:           file_controller_api_resources_hosts_v1_host_catalog_proto_goTypes,
		DependencyIndexes: file_controller_api_resources_hosts_v1_host_catalog_proto_depIdxs,
		MessageInfos:      file_controller_api_resources_hosts_v1_host_catalog_proto_msgTypes,
	}.Build()
	File_controller_api_resources_hosts_v1_host_catalog_proto = out.File
	file_controller_api_resources_hosts_v1_host_catalog_proto_rawDesc = nil
	file_controller_api_resources_hosts_v1_host_catalog_proto_goTypes = nil
	file_controller_api_resources_hosts_v1_host_catalog_proto_depIdxs = nil
}
