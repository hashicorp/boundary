// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: BUSL-1.1

// Code generated by protoc-gen-go. DO NOT EDIT.
// versions:
// 	protoc-gen-go v1.36.1
// 	protoc        (unknown)
// source: controller/servers/v1/servers.proto

package servers

import (
	plugin "github.com/hashicorp/boundary/sdk/pbs/plugin"
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

// TagPair matches a key to a value.
type TagPair struct {
	state         protoimpl.MessageState `protogen:"open.v1"`
	Key           string                 `protobuf:"bytes,1,opt,name=key,proto3" json:"key,omitempty" class:"public"`     // @gotags: `class:"public"`
	Value         string                 `protobuf:"bytes,2,opt,name=value,proto3" json:"value,omitempty" class:"public"` // @gotags: `class:"public"`
	unknownFields protoimpl.UnknownFields
	sizeCache     protoimpl.SizeCache
}

func (x *TagPair) Reset() {
	*x = TagPair{}
	mi := &file_controller_servers_v1_servers_proto_msgTypes[0]
	ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
	ms.StoreMessageInfo(mi)
}

func (x *TagPair) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*TagPair) ProtoMessage() {}

func (x *TagPair) ProtoReflect() protoreflect.Message {
	mi := &file_controller_servers_v1_servers_proto_msgTypes[0]
	if x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use TagPair.ProtoReflect.Descriptor instead.
func (*TagPair) Descriptor() ([]byte, []int) {
	return file_controller_servers_v1_servers_proto_rawDescGZIP(), []int{0}
}

func (x *TagPair) GetKey() string {
	if x != nil {
		return x.Key
	}
	return ""
}

func (x *TagPair) GetValue() string {
	if x != nil {
		return x.Value
	}
	return ""
}

// ServerWorkerStatus is the new message used in place of Server to relay status request info.
type ServerWorkerStatus struct {
	state protoimpl.MessageState `protogen:"open.v1"`
	// Id of the worker, used after the first request.
	PublicId string `protobuf:"bytes,10,opt,name=public_id,json=publicId,proto3" json:"public_id,omitempty" class:"public" eventstream:"observation"` // @gotags: `class:"public" eventstream:"observation"`
	// Name of the worker, used to identify workers in the KMS registration flow.
	Name string `protobuf:"bytes,20,opt,name=name,proto3" json:"name,omitempty" class:"public"` // @gotags: `class:"public"`
	// Description of the worker (optional). Only used by KMS workers.
	Description string `protobuf:"bytes,25,opt,name=description,proto3" json:"description,omitempty" class:"public"` // @gotags: `class:"public"`
	// Address for the worker.
	Address string `protobuf:"bytes,30,opt,name=address,proto3" json:"address,omitempty" class:"public"` // @gotags: `class:"public"`
	// Tags for workers
	Tags []*TagPair `protobuf:"bytes,40,rep,name=tags,proto3" json:"tags,omitempty"`
	// The key id of the worker, used to identify workers in the PKI registration flow.
	KeyId string `protobuf:"bytes,50,opt,name=key_id,json=keyId,proto3" json:"key_id,omitempty" class:"public"` // @gotags: `class:"public"`
	// The version of Boundary the worker binary is running
	ReleaseVersion string `protobuf:"bytes,60,opt,name=release_version,proto3" json:"release_version,omitempty" class:"public" eventstream:"observation"` // @gotags: `class:"public" eventstream:"observation"`
	// The state of the worker, to indicate if the worker is active or in shutdown.
	OperationalState string `protobuf:"bytes,70,opt,name=operational_state,proto3" json:"operational_state,omitempty" class:"public" eventstream:"observation"` // @gotags: `class:"public" eventstream:"observation"`
	// The local_storage_state indicates the state of the local disk space of the worker.
	// Possible values are:
	// - available: The worker local storage state is at an acceptable state
	// - low storage: The worker is below the minimum threshold for local storage
	// - critically low storage: The worker local storage state is below the critical minimum threshold for local storage
	// - out of storage: The worker is out of local disk space
	// - not configured: The worker does not have a local storage path configured
	// - unknown: The default local storage state of a worker. Used when the local storage state of a worker is not yet known
	LocalStorageState string `protobuf:"bytes,80,opt,name=local_storage_state,proto3" json:"local_storage_state,omitempty" class:"public" eventstream:"observation"` // @gotags: `class:"public" eventstream:"observation"
	// StorageBucketCredentialStates is a map where the key is a storage bucket id
	// and the value contains the current state of the storage bucket.
	StorageBucketCredentialStates map[string]*plugin.StorageBucketCredentialState `protobuf:"bytes,90,rep,name=storage_bucket_credential_states,json=storageBucketCredentialStates,proto3" json:"storage_bucket_credential_states,omitempty" protobuf_key:"bytes,1,opt,name=key" protobuf_val:"bytes,2,opt,name=value" class:"public" eventstream:"observation"` // @gotags: `class:"public" eventstream:"observation"`
	unknownFields                 protoimpl.UnknownFields
	sizeCache                     protoimpl.SizeCache
}

func (x *ServerWorkerStatus) Reset() {
	*x = ServerWorkerStatus{}
	mi := &file_controller_servers_v1_servers_proto_msgTypes[1]
	ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
	ms.StoreMessageInfo(mi)
}

func (x *ServerWorkerStatus) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*ServerWorkerStatus) ProtoMessage() {}

func (x *ServerWorkerStatus) ProtoReflect() protoreflect.Message {
	mi := &file_controller_servers_v1_servers_proto_msgTypes[1]
	if x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use ServerWorkerStatus.ProtoReflect.Descriptor instead.
func (*ServerWorkerStatus) Descriptor() ([]byte, []int) {
	return file_controller_servers_v1_servers_proto_rawDescGZIP(), []int{1}
}

func (x *ServerWorkerStatus) GetPublicId() string {
	if x != nil {
		return x.PublicId
	}
	return ""
}

func (x *ServerWorkerStatus) GetName() string {
	if x != nil {
		return x.Name
	}
	return ""
}

func (x *ServerWorkerStatus) GetDescription() string {
	if x != nil {
		return x.Description
	}
	return ""
}

func (x *ServerWorkerStatus) GetAddress() string {
	if x != nil {
		return x.Address
	}
	return ""
}

func (x *ServerWorkerStatus) GetTags() []*TagPair {
	if x != nil {
		return x.Tags
	}
	return nil
}

func (x *ServerWorkerStatus) GetKeyId() string {
	if x != nil {
		return x.KeyId
	}
	return ""
}

func (x *ServerWorkerStatus) GetReleaseVersion() string {
	if x != nil {
		return x.ReleaseVersion
	}
	return ""
}

func (x *ServerWorkerStatus) GetOperationalState() string {
	if x != nil {
		return x.OperationalState
	}
	return ""
}

func (x *ServerWorkerStatus) GetLocalStorageState() string {
	if x != nil {
		return x.LocalStorageState
	}
	return ""
}

func (x *ServerWorkerStatus) GetStorageBucketCredentialStates() map[string]*plugin.StorageBucketCredentialState {
	if x != nil {
		return x.StorageBucketCredentialStates
	}
	return nil
}

var File_controller_servers_v1_servers_proto protoreflect.FileDescriptor

var file_controller_servers_v1_servers_proto_rawDesc = []byte{
	0x0a, 0x23, 0x63, 0x6f, 0x6e, 0x74, 0x72, 0x6f, 0x6c, 0x6c, 0x65, 0x72, 0x2f, 0x73, 0x65, 0x72,
	0x76, 0x65, 0x72, 0x73, 0x2f, 0x76, 0x31, 0x2f, 0x73, 0x65, 0x72, 0x76, 0x65, 0x72, 0x73, 0x2e,
	0x70, 0x72, 0x6f, 0x74, 0x6f, 0x12, 0x15, 0x63, 0x6f, 0x6e, 0x74, 0x72, 0x6f, 0x6c, 0x6c, 0x65,
	0x72, 0x2e, 0x73, 0x65, 0x72, 0x76, 0x65, 0x72, 0x73, 0x2e, 0x76, 0x31, 0x1a, 0x26, 0x70, 0x6c,
	0x75, 0x67, 0x69, 0x6e, 0x2f, 0x76, 0x31, 0x2f, 0x73, 0x74, 0x6f, 0x72, 0x61, 0x67, 0x65, 0x5f,
	0x70, 0x6c, 0x75, 0x67, 0x69, 0x6e, 0x5f, 0x73, 0x65, 0x72, 0x76, 0x69, 0x63, 0x65, 0x2e, 0x70,
	0x72, 0x6f, 0x74, 0x6f, 0x22, 0x31, 0x0a, 0x07, 0x54, 0x61, 0x67, 0x50, 0x61, 0x69, 0x72, 0x12,
	0x10, 0x0a, 0x03, 0x6b, 0x65, 0x79, 0x18, 0x01, 0x20, 0x01, 0x28, 0x09, 0x52, 0x03, 0x6b, 0x65,
	0x79, 0x12, 0x14, 0x0a, 0x05, 0x76, 0x61, 0x6c, 0x75, 0x65, 0x18, 0x02, 0x20, 0x01, 0x28, 0x09,
	0x52, 0x05, 0x76, 0x61, 0x6c, 0x75, 0x65, 0x22, 0xe9, 0x04, 0x0a, 0x12, 0x53, 0x65, 0x72, 0x76,
	0x65, 0x72, 0x57, 0x6f, 0x72, 0x6b, 0x65, 0x72, 0x53, 0x74, 0x61, 0x74, 0x75, 0x73, 0x12, 0x1b,
	0x0a, 0x09, 0x70, 0x75, 0x62, 0x6c, 0x69, 0x63, 0x5f, 0x69, 0x64, 0x18, 0x0a, 0x20, 0x01, 0x28,
	0x09, 0x52, 0x08, 0x70, 0x75, 0x62, 0x6c, 0x69, 0x63, 0x49, 0x64, 0x12, 0x12, 0x0a, 0x04, 0x6e,
	0x61, 0x6d, 0x65, 0x18, 0x14, 0x20, 0x01, 0x28, 0x09, 0x52, 0x04, 0x6e, 0x61, 0x6d, 0x65, 0x12,
	0x20, 0x0a, 0x0b, 0x64, 0x65, 0x73, 0x63, 0x72, 0x69, 0x70, 0x74, 0x69, 0x6f, 0x6e, 0x18, 0x19,
	0x20, 0x01, 0x28, 0x09, 0x52, 0x0b, 0x64, 0x65, 0x73, 0x63, 0x72, 0x69, 0x70, 0x74, 0x69, 0x6f,
	0x6e, 0x12, 0x18, 0x0a, 0x07, 0x61, 0x64, 0x64, 0x72, 0x65, 0x73, 0x73, 0x18, 0x1e, 0x20, 0x01,
	0x28, 0x09, 0x52, 0x07, 0x61, 0x64, 0x64, 0x72, 0x65, 0x73, 0x73, 0x12, 0x32, 0x0a, 0x04, 0x74,
	0x61, 0x67, 0x73, 0x18, 0x28, 0x20, 0x03, 0x28, 0x0b, 0x32, 0x1e, 0x2e, 0x63, 0x6f, 0x6e, 0x74,
	0x72, 0x6f, 0x6c, 0x6c, 0x65, 0x72, 0x2e, 0x73, 0x65, 0x72, 0x76, 0x65, 0x72, 0x73, 0x2e, 0x76,
	0x31, 0x2e, 0x54, 0x61, 0x67, 0x50, 0x61, 0x69, 0x72, 0x52, 0x04, 0x74, 0x61, 0x67, 0x73, 0x12,
	0x15, 0x0a, 0x06, 0x6b, 0x65, 0x79, 0x5f, 0x69, 0x64, 0x18, 0x32, 0x20, 0x01, 0x28, 0x09, 0x52,
	0x05, 0x6b, 0x65, 0x79, 0x49, 0x64, 0x12, 0x28, 0x0a, 0x0f, 0x72, 0x65, 0x6c, 0x65, 0x61, 0x73,
	0x65, 0x5f, 0x76, 0x65, 0x72, 0x73, 0x69, 0x6f, 0x6e, 0x18, 0x3c, 0x20, 0x01, 0x28, 0x09, 0x52,
	0x0f, 0x72, 0x65, 0x6c, 0x65, 0x61, 0x73, 0x65, 0x5f, 0x76, 0x65, 0x72, 0x73, 0x69, 0x6f, 0x6e,
	0x12, 0x2c, 0x0a, 0x11, 0x6f, 0x70, 0x65, 0x72, 0x61, 0x74, 0x69, 0x6f, 0x6e, 0x61, 0x6c, 0x5f,
	0x73, 0x74, 0x61, 0x74, 0x65, 0x18, 0x46, 0x20, 0x01, 0x28, 0x09, 0x52, 0x11, 0x6f, 0x70, 0x65,
	0x72, 0x61, 0x74, 0x69, 0x6f, 0x6e, 0x61, 0x6c, 0x5f, 0x73, 0x74, 0x61, 0x74, 0x65, 0x12, 0x30,
	0x0a, 0x13, 0x6c, 0x6f, 0x63, 0x61, 0x6c, 0x5f, 0x73, 0x74, 0x6f, 0x72, 0x61, 0x67, 0x65, 0x5f,
	0x73, 0x74, 0x61, 0x74, 0x65, 0x18, 0x50, 0x20, 0x01, 0x28, 0x09, 0x52, 0x13, 0x6c, 0x6f, 0x63,
	0x61, 0x6c, 0x5f, 0x73, 0x74, 0x6f, 0x72, 0x61, 0x67, 0x65, 0x5f, 0x73, 0x74, 0x61, 0x74, 0x65,
	0x12, 0x95, 0x01, 0x0a, 0x20, 0x73, 0x74, 0x6f, 0x72, 0x61, 0x67, 0x65, 0x5f, 0x62, 0x75, 0x63,
	0x6b, 0x65, 0x74, 0x5f, 0x63, 0x72, 0x65, 0x64, 0x65, 0x6e, 0x74, 0x69, 0x61, 0x6c, 0x5f, 0x73,
	0x74, 0x61, 0x74, 0x65, 0x73, 0x18, 0x5a, 0x20, 0x03, 0x28, 0x0b, 0x32, 0x4c, 0x2e, 0x63, 0x6f,
	0x6e, 0x74, 0x72, 0x6f, 0x6c, 0x6c, 0x65, 0x72, 0x2e, 0x73, 0x65, 0x72, 0x76, 0x65, 0x72, 0x73,
	0x2e, 0x76, 0x31, 0x2e, 0x53, 0x65, 0x72, 0x76, 0x65, 0x72, 0x57, 0x6f, 0x72, 0x6b, 0x65, 0x72,
	0x53, 0x74, 0x61, 0x74, 0x75, 0x73, 0x2e, 0x53, 0x74, 0x6f, 0x72, 0x61, 0x67, 0x65, 0x42, 0x75,
	0x63, 0x6b, 0x65, 0x74, 0x43, 0x72, 0x65, 0x64, 0x65, 0x6e, 0x74, 0x69, 0x61, 0x6c, 0x53, 0x74,
	0x61, 0x74, 0x65, 0x73, 0x45, 0x6e, 0x74, 0x72, 0x79, 0x52, 0x1d, 0x73, 0x74, 0x6f, 0x72, 0x61,
	0x67, 0x65, 0x42, 0x75, 0x63, 0x6b, 0x65, 0x74, 0x43, 0x72, 0x65, 0x64, 0x65, 0x6e, 0x74, 0x69,
	0x61, 0x6c, 0x53, 0x74, 0x61, 0x74, 0x65, 0x73, 0x1a, 0x79, 0x0a, 0x22, 0x53, 0x74, 0x6f, 0x72,
	0x61, 0x67, 0x65, 0x42, 0x75, 0x63, 0x6b, 0x65, 0x74, 0x43, 0x72, 0x65, 0x64, 0x65, 0x6e, 0x74,
	0x69, 0x61, 0x6c, 0x53, 0x74, 0x61, 0x74, 0x65, 0x73, 0x45, 0x6e, 0x74, 0x72, 0x79, 0x12, 0x10,
	0x0a, 0x03, 0x6b, 0x65, 0x79, 0x18, 0x01, 0x20, 0x01, 0x28, 0x09, 0x52, 0x03, 0x6b, 0x65, 0x79,
	0x12, 0x3d, 0x0a, 0x05, 0x76, 0x61, 0x6c, 0x75, 0x65, 0x18, 0x02, 0x20, 0x01, 0x28, 0x0b, 0x32,
	0x27, 0x2e, 0x70, 0x6c, 0x75, 0x67, 0x69, 0x6e, 0x2e, 0x76, 0x31, 0x2e, 0x53, 0x74, 0x6f, 0x72,
	0x61, 0x67, 0x65, 0x42, 0x75, 0x63, 0x6b, 0x65, 0x74, 0x43, 0x72, 0x65, 0x64, 0x65, 0x6e, 0x74,
	0x69, 0x61, 0x6c, 0x53, 0x74, 0x61, 0x74, 0x65, 0x52, 0x05, 0x76, 0x61, 0x6c, 0x75, 0x65, 0x3a,
	0x02, 0x38, 0x01, 0x42, 0x47, 0x5a, 0x45, 0x67, 0x69, 0x74, 0x68, 0x75, 0x62, 0x2e, 0x63, 0x6f,
	0x6d, 0x2f, 0x68, 0x61, 0x73, 0x68, 0x69, 0x63, 0x6f, 0x72, 0x70, 0x2f, 0x62, 0x6f, 0x75, 0x6e,
	0x64, 0x61, 0x72, 0x79, 0x2f, 0x69, 0x6e, 0x74, 0x65, 0x72, 0x6e, 0x61, 0x6c, 0x2f, 0x67, 0x65,
	0x6e, 0x2f, 0x63, 0x6f, 0x6e, 0x74, 0x72, 0x6f, 0x6c, 0x6c, 0x65, 0x72, 0x2f, 0x73, 0x65, 0x72,
	0x76, 0x65, 0x72, 0x73, 0x3b, 0x73, 0x65, 0x72, 0x76, 0x65, 0x72, 0x73, 0x62, 0x06, 0x70, 0x72,
	0x6f, 0x74, 0x6f, 0x33,
}

var (
	file_controller_servers_v1_servers_proto_rawDescOnce sync.Once
	file_controller_servers_v1_servers_proto_rawDescData = file_controller_servers_v1_servers_proto_rawDesc
)

func file_controller_servers_v1_servers_proto_rawDescGZIP() []byte {
	file_controller_servers_v1_servers_proto_rawDescOnce.Do(func() {
		file_controller_servers_v1_servers_proto_rawDescData = protoimpl.X.CompressGZIP(file_controller_servers_v1_servers_proto_rawDescData)
	})
	return file_controller_servers_v1_servers_proto_rawDescData
}

var file_controller_servers_v1_servers_proto_msgTypes = make([]protoimpl.MessageInfo, 3)
var file_controller_servers_v1_servers_proto_goTypes = []any{
	(*TagPair)(nil),            // 0: controller.servers.v1.TagPair
	(*ServerWorkerStatus)(nil), // 1: controller.servers.v1.ServerWorkerStatus
	nil,                        // 2: controller.servers.v1.ServerWorkerStatus.StorageBucketCredentialStatesEntry
	(*plugin.StorageBucketCredentialState)(nil), // 3: plugin.v1.StorageBucketCredentialState
}
var file_controller_servers_v1_servers_proto_depIdxs = []int32{
	0, // 0: controller.servers.v1.ServerWorkerStatus.tags:type_name -> controller.servers.v1.TagPair
	2, // 1: controller.servers.v1.ServerWorkerStatus.storage_bucket_credential_states:type_name -> controller.servers.v1.ServerWorkerStatus.StorageBucketCredentialStatesEntry
	3, // 2: controller.servers.v1.ServerWorkerStatus.StorageBucketCredentialStatesEntry.value:type_name -> plugin.v1.StorageBucketCredentialState
	3, // [3:3] is the sub-list for method output_type
	3, // [3:3] is the sub-list for method input_type
	3, // [3:3] is the sub-list for extension type_name
	3, // [3:3] is the sub-list for extension extendee
	0, // [0:3] is the sub-list for field type_name
}

func init() { file_controller_servers_v1_servers_proto_init() }
func file_controller_servers_v1_servers_proto_init() {
	if File_controller_servers_v1_servers_proto != nil {
		return
	}
	type x struct{}
	out := protoimpl.TypeBuilder{
		File: protoimpl.DescBuilder{
			GoPackagePath: reflect.TypeOf(x{}).PkgPath(),
			RawDescriptor: file_controller_servers_v1_servers_proto_rawDesc,
			NumEnums:      0,
			NumMessages:   3,
			NumExtensions: 0,
			NumServices:   0,
		},
		GoTypes:           file_controller_servers_v1_servers_proto_goTypes,
		DependencyIndexes: file_controller_servers_v1_servers_proto_depIdxs,
		MessageInfos:      file_controller_servers_v1_servers_proto_msgTypes,
	}.Build()
	File_controller_servers_v1_servers_proto = out.File
	file_controller_servers_v1_servers_proto_rawDesc = nil
	file_controller_servers_v1_servers_proto_goTypes = nil
	file_controller_servers_v1_servers_proto_depIdxs = nil
}
