// Code generated by protoc-gen-go. DO NOT EDIT.
// versions:
// 	protoc-gen-go v1.25.0-devel
// 	protoc        v3.12.4
// source: controller/api/services/v1/authtokens_service.proto

package services

import (
	_ "github.com/grpc-ecosystem/grpc-gateway/v2/protoc-gen-openapiv2/options"
	authtokens "github.com/hashicorp/boundary/internal/gen/controller/api/resources/authtokens"
	_ "google.golang.org/genproto/googleapis/api/annotations"
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

type GetAuthTokenRequest struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	Id string `protobuf:"bytes,1,opt,name=id,proto3" json:"id,omitempty"`
}

func (x *GetAuthTokenRequest) Reset() {
	*x = GetAuthTokenRequest{}
	if protoimpl.UnsafeEnabled {
		mi := &file_controller_api_services_v1_authtokens_service_proto_msgTypes[0]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *GetAuthTokenRequest) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*GetAuthTokenRequest) ProtoMessage() {}

func (x *GetAuthTokenRequest) ProtoReflect() protoreflect.Message {
	mi := &file_controller_api_services_v1_authtokens_service_proto_msgTypes[0]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use GetAuthTokenRequest.ProtoReflect.Descriptor instead.
func (*GetAuthTokenRequest) Descriptor() ([]byte, []int) {
	return file_controller_api_services_v1_authtokens_service_proto_rawDescGZIP(), []int{0}
}

func (x *GetAuthTokenRequest) GetId() string {
	if x != nil {
		return x.Id
	}
	return ""
}

type GetAuthTokenResponse struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	Item *authtokens.AuthToken `protobuf:"bytes,1,opt,name=item,proto3" json:"item,omitempty"`
}

func (x *GetAuthTokenResponse) Reset() {
	*x = GetAuthTokenResponse{}
	if protoimpl.UnsafeEnabled {
		mi := &file_controller_api_services_v1_authtokens_service_proto_msgTypes[1]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *GetAuthTokenResponse) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*GetAuthTokenResponse) ProtoMessage() {}

func (x *GetAuthTokenResponse) ProtoReflect() protoreflect.Message {
	mi := &file_controller_api_services_v1_authtokens_service_proto_msgTypes[1]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use GetAuthTokenResponse.ProtoReflect.Descriptor instead.
func (*GetAuthTokenResponse) Descriptor() ([]byte, []int) {
	return file_controller_api_services_v1_authtokens_service_proto_rawDescGZIP(), []int{1}
}

func (x *GetAuthTokenResponse) GetItem() *authtokens.AuthToken {
	if x != nil {
		return x.Item
	}
	return nil
}

type ListAuthTokensRequest struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	ScopeId   string `protobuf:"bytes,1,opt,name=scope_id,proto3" json:"scope_id,omitempty"`
	Recursive bool   `protobuf:"varint,20,opt,name=recursive,proto3" json:"recursive,omitempty"`
}

func (x *ListAuthTokensRequest) Reset() {
	*x = ListAuthTokensRequest{}
	if protoimpl.UnsafeEnabled {
		mi := &file_controller_api_services_v1_authtokens_service_proto_msgTypes[2]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *ListAuthTokensRequest) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*ListAuthTokensRequest) ProtoMessage() {}

func (x *ListAuthTokensRequest) ProtoReflect() protoreflect.Message {
	mi := &file_controller_api_services_v1_authtokens_service_proto_msgTypes[2]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use ListAuthTokensRequest.ProtoReflect.Descriptor instead.
func (*ListAuthTokensRequest) Descriptor() ([]byte, []int) {
	return file_controller_api_services_v1_authtokens_service_proto_rawDescGZIP(), []int{2}
}

func (x *ListAuthTokensRequest) GetScopeId() string {
	if x != nil {
		return x.ScopeId
	}
	return ""
}

func (x *ListAuthTokensRequest) GetRecursive() bool {
	if x != nil {
		return x.Recursive
	}
	return false
}

type ListAuthTokensResponse struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	Items []*authtokens.AuthToken `protobuf:"bytes,1,rep,name=items,proto3" json:"items,omitempty"`
}

func (x *ListAuthTokensResponse) Reset() {
	*x = ListAuthTokensResponse{}
	if protoimpl.UnsafeEnabled {
		mi := &file_controller_api_services_v1_authtokens_service_proto_msgTypes[3]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *ListAuthTokensResponse) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*ListAuthTokensResponse) ProtoMessage() {}

func (x *ListAuthTokensResponse) ProtoReflect() protoreflect.Message {
	mi := &file_controller_api_services_v1_authtokens_service_proto_msgTypes[3]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use ListAuthTokensResponse.ProtoReflect.Descriptor instead.
func (*ListAuthTokensResponse) Descriptor() ([]byte, []int) {
	return file_controller_api_services_v1_authtokens_service_proto_rawDescGZIP(), []int{3}
}

func (x *ListAuthTokensResponse) GetItems() []*authtokens.AuthToken {
	if x != nil {
		return x.Items
	}
	return nil
}

type DeleteAuthTokenRequest struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	Id string `protobuf:"bytes,1,opt,name=id,proto3" json:"id,omitempty"`
}

func (x *DeleteAuthTokenRequest) Reset() {
	*x = DeleteAuthTokenRequest{}
	if protoimpl.UnsafeEnabled {
		mi := &file_controller_api_services_v1_authtokens_service_proto_msgTypes[4]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *DeleteAuthTokenRequest) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*DeleteAuthTokenRequest) ProtoMessage() {}

func (x *DeleteAuthTokenRequest) ProtoReflect() protoreflect.Message {
	mi := &file_controller_api_services_v1_authtokens_service_proto_msgTypes[4]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use DeleteAuthTokenRequest.ProtoReflect.Descriptor instead.
func (*DeleteAuthTokenRequest) Descriptor() ([]byte, []int) {
	return file_controller_api_services_v1_authtokens_service_proto_rawDescGZIP(), []int{4}
}

func (x *DeleteAuthTokenRequest) GetId() string {
	if x != nil {
		return x.Id
	}
	return ""
}

type DeleteAuthTokenResponse struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields
}

func (x *DeleteAuthTokenResponse) Reset() {
	*x = DeleteAuthTokenResponse{}
	if protoimpl.UnsafeEnabled {
		mi := &file_controller_api_services_v1_authtokens_service_proto_msgTypes[5]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *DeleteAuthTokenResponse) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*DeleteAuthTokenResponse) ProtoMessage() {}

func (x *DeleteAuthTokenResponse) ProtoReflect() protoreflect.Message {
	mi := &file_controller_api_services_v1_authtokens_service_proto_msgTypes[5]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use DeleteAuthTokenResponse.ProtoReflect.Descriptor instead.
func (*DeleteAuthTokenResponse) Descriptor() ([]byte, []int) {
	return file_controller_api_services_v1_authtokens_service_proto_rawDescGZIP(), []int{5}
}

var File_controller_api_services_v1_authtokens_service_proto protoreflect.FileDescriptor

var file_controller_api_services_v1_authtokens_service_proto_rawDesc = []byte{
	0x0a, 0x33, 0x63, 0x6f, 0x6e, 0x74, 0x72, 0x6f, 0x6c, 0x6c, 0x65, 0x72, 0x2f, 0x61, 0x70, 0x69,
	0x2f, 0x73, 0x65, 0x72, 0x76, 0x69, 0x63, 0x65, 0x73, 0x2f, 0x76, 0x31, 0x2f, 0x61, 0x75, 0x74,
	0x68, 0x74, 0x6f, 0x6b, 0x65, 0x6e, 0x73, 0x5f, 0x73, 0x65, 0x72, 0x76, 0x69, 0x63, 0x65, 0x2e,
	0x70, 0x72, 0x6f, 0x74, 0x6f, 0x12, 0x1a, 0x63, 0x6f, 0x6e, 0x74, 0x72, 0x6f, 0x6c, 0x6c, 0x65,
	0x72, 0x2e, 0x61, 0x70, 0x69, 0x2e, 0x73, 0x65, 0x72, 0x76, 0x69, 0x63, 0x65, 0x73, 0x2e, 0x76,
	0x31, 0x1a, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x63, 0x2d, 0x67, 0x65, 0x6e, 0x2d, 0x6f, 0x70,
	0x65, 0x6e, 0x61, 0x70, 0x69, 0x76, 0x32, 0x2f, 0x6f, 0x70, 0x74, 0x69, 0x6f, 0x6e, 0x73, 0x2f,
	0x61, 0x6e, 0x6e, 0x6f, 0x74, 0x61, 0x74, 0x69, 0x6f, 0x6e, 0x73, 0x2e, 0x70, 0x72, 0x6f, 0x74,
	0x6f, 0x1a, 0x1c, 0x67, 0x6f, 0x6f, 0x67, 0x6c, 0x65, 0x2f, 0x61, 0x70, 0x69, 0x2f, 0x61, 0x6e,
	0x6e, 0x6f, 0x74, 0x61, 0x74, 0x69, 0x6f, 0x6e, 0x73, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x1a,
	0x36, 0x63, 0x6f, 0x6e, 0x74, 0x72, 0x6f, 0x6c, 0x6c, 0x65, 0x72, 0x2f, 0x61, 0x70, 0x69, 0x2f,
	0x72, 0x65, 0x73, 0x6f, 0x75, 0x72, 0x63, 0x65, 0x73, 0x2f, 0x61, 0x75, 0x74, 0x68, 0x74, 0x6f,
	0x6b, 0x65, 0x6e, 0x73, 0x2f, 0x76, 0x31, 0x2f, 0x61, 0x75, 0x74, 0x68, 0x74, 0x6f, 0x6b, 0x65,
	0x6e, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x22, 0x25, 0x0a, 0x13, 0x47, 0x65, 0x74, 0x41, 0x75,
	0x74, 0x68, 0x54, 0x6f, 0x6b, 0x65, 0x6e, 0x52, 0x65, 0x71, 0x75, 0x65, 0x73, 0x74, 0x12, 0x0e,
	0x0a, 0x02, 0x69, 0x64, 0x18, 0x01, 0x20, 0x01, 0x28, 0x09, 0x52, 0x02, 0x69, 0x64, 0x22, 0x5d,
	0x0a, 0x14, 0x47, 0x65, 0x74, 0x41, 0x75, 0x74, 0x68, 0x54, 0x6f, 0x6b, 0x65, 0x6e, 0x52, 0x65,
	0x73, 0x70, 0x6f, 0x6e, 0x73, 0x65, 0x12, 0x45, 0x0a, 0x04, 0x69, 0x74, 0x65, 0x6d, 0x18, 0x01,
	0x20, 0x01, 0x28, 0x0b, 0x32, 0x31, 0x2e, 0x63, 0x6f, 0x6e, 0x74, 0x72, 0x6f, 0x6c, 0x6c, 0x65,
	0x72, 0x2e, 0x61, 0x70, 0x69, 0x2e, 0x72, 0x65, 0x73, 0x6f, 0x75, 0x72, 0x63, 0x65, 0x73, 0x2e,
	0x61, 0x75, 0x74, 0x68, 0x74, 0x6f, 0x6b, 0x65, 0x6e, 0x73, 0x2e, 0x76, 0x31, 0x2e, 0x41, 0x75,
	0x74, 0x68, 0x54, 0x6f, 0x6b, 0x65, 0x6e, 0x52, 0x04, 0x69, 0x74, 0x65, 0x6d, 0x22, 0x51, 0x0a,
	0x15, 0x4c, 0x69, 0x73, 0x74, 0x41, 0x75, 0x74, 0x68, 0x54, 0x6f, 0x6b, 0x65, 0x6e, 0x73, 0x52,
	0x65, 0x71, 0x75, 0x65, 0x73, 0x74, 0x12, 0x1a, 0x0a, 0x08, 0x73, 0x63, 0x6f, 0x70, 0x65, 0x5f,
	0x69, 0x64, 0x18, 0x01, 0x20, 0x01, 0x28, 0x09, 0x52, 0x08, 0x73, 0x63, 0x6f, 0x70, 0x65, 0x5f,
	0x69, 0x64, 0x12, 0x1c, 0x0a, 0x09, 0x72, 0x65, 0x63, 0x75, 0x72, 0x73, 0x69, 0x76, 0x65, 0x18,
	0x14, 0x20, 0x01, 0x28, 0x08, 0x52, 0x09, 0x72, 0x65, 0x63, 0x75, 0x72, 0x73, 0x69, 0x76, 0x65,
	0x22, 0x61, 0x0a, 0x16, 0x4c, 0x69, 0x73, 0x74, 0x41, 0x75, 0x74, 0x68, 0x54, 0x6f, 0x6b, 0x65,
	0x6e, 0x73, 0x52, 0x65, 0x73, 0x70, 0x6f, 0x6e, 0x73, 0x65, 0x12, 0x47, 0x0a, 0x05, 0x69, 0x74,
	0x65, 0x6d, 0x73, 0x18, 0x01, 0x20, 0x03, 0x28, 0x0b, 0x32, 0x31, 0x2e, 0x63, 0x6f, 0x6e, 0x74,
	0x72, 0x6f, 0x6c, 0x6c, 0x65, 0x72, 0x2e, 0x61, 0x70, 0x69, 0x2e, 0x72, 0x65, 0x73, 0x6f, 0x75,
	0x72, 0x63, 0x65, 0x73, 0x2e, 0x61, 0x75, 0x74, 0x68, 0x74, 0x6f, 0x6b, 0x65, 0x6e, 0x73, 0x2e,
	0x76, 0x31, 0x2e, 0x41, 0x75, 0x74, 0x68, 0x54, 0x6f, 0x6b, 0x65, 0x6e, 0x52, 0x05, 0x69, 0x74,
	0x65, 0x6d, 0x73, 0x22, 0x28, 0x0a, 0x16, 0x44, 0x65, 0x6c, 0x65, 0x74, 0x65, 0x41, 0x75, 0x74,
	0x68, 0x54, 0x6f, 0x6b, 0x65, 0x6e, 0x52, 0x65, 0x71, 0x75, 0x65, 0x73, 0x74, 0x12, 0x0e, 0x0a,
	0x02, 0x69, 0x64, 0x18, 0x01, 0x20, 0x01, 0x28, 0x09, 0x52, 0x02, 0x69, 0x64, 0x22, 0x19, 0x0a,
	0x17, 0x44, 0x65, 0x6c, 0x65, 0x74, 0x65, 0x41, 0x75, 0x74, 0x68, 0x54, 0x6f, 0x6b, 0x65, 0x6e,
	0x52, 0x65, 0x73, 0x70, 0x6f, 0x6e, 0x73, 0x65, 0x32, 0xac, 0x04, 0x0a, 0x10, 0x41, 0x75, 0x74,
	0x68, 0x54, 0x6f, 0x6b, 0x65, 0x6e, 0x53, 0x65, 0x72, 0x76, 0x69, 0x63, 0x65, 0x12, 0xb3, 0x01,
	0x0a, 0x0c, 0x47, 0x65, 0x74, 0x41, 0x75, 0x74, 0x68, 0x54, 0x6f, 0x6b, 0x65, 0x6e, 0x12, 0x2f,
	0x2e, 0x63, 0x6f, 0x6e, 0x74, 0x72, 0x6f, 0x6c, 0x6c, 0x65, 0x72, 0x2e, 0x61, 0x70, 0x69, 0x2e,
	0x73, 0x65, 0x72, 0x76, 0x69, 0x63, 0x65, 0x73, 0x2e, 0x76, 0x31, 0x2e, 0x47, 0x65, 0x74, 0x41,
	0x75, 0x74, 0x68, 0x54, 0x6f, 0x6b, 0x65, 0x6e, 0x52, 0x65, 0x71, 0x75, 0x65, 0x73, 0x74, 0x1a,
	0x30, 0x2e, 0x63, 0x6f, 0x6e, 0x74, 0x72, 0x6f, 0x6c, 0x6c, 0x65, 0x72, 0x2e, 0x61, 0x70, 0x69,
	0x2e, 0x73, 0x65, 0x72, 0x76, 0x69, 0x63, 0x65, 0x73, 0x2e, 0x76, 0x31, 0x2e, 0x47, 0x65, 0x74,
	0x41, 0x75, 0x74, 0x68, 0x54, 0x6f, 0x6b, 0x65, 0x6e, 0x52, 0x65, 0x73, 0x70, 0x6f, 0x6e, 0x73,
	0x65, 0x22, 0x40, 0x82, 0xd3, 0xe4, 0x93, 0x02, 0x1c, 0x12, 0x14, 0x2f, 0x76, 0x31, 0x2f, 0x61,
	0x75, 0x74, 0x68, 0x2d, 0x74, 0x6f, 0x6b, 0x65, 0x6e, 0x73, 0x2f, 0x7b, 0x69, 0x64, 0x7d, 0x62,
	0x04, 0x69, 0x74, 0x65, 0x6d, 0x92, 0x41, 0x1b, 0x12, 0x19, 0x47, 0x65, 0x74, 0x73, 0x20, 0x61,
	0x20, 0x73, 0x69, 0x6e, 0x67, 0x6c, 0x65, 0x20, 0x41, 0x75, 0x74, 0x68, 0x20, 0x54, 0x6f, 0x6b,
	0x65, 0x6e, 0x2e, 0x12, 0xab, 0x01, 0x0a, 0x0e, 0x4c, 0x69, 0x73, 0x74, 0x41, 0x75, 0x74, 0x68,
	0x54, 0x6f, 0x6b, 0x65, 0x6e, 0x73, 0x12, 0x31, 0x2e, 0x63, 0x6f, 0x6e, 0x74, 0x72, 0x6f, 0x6c,
	0x6c, 0x65, 0x72, 0x2e, 0x61, 0x70, 0x69, 0x2e, 0x73, 0x65, 0x72, 0x76, 0x69, 0x63, 0x65, 0x73,
	0x2e, 0x76, 0x31, 0x2e, 0x4c, 0x69, 0x73, 0x74, 0x41, 0x75, 0x74, 0x68, 0x54, 0x6f, 0x6b, 0x65,
	0x6e, 0x73, 0x52, 0x65, 0x71, 0x75, 0x65, 0x73, 0x74, 0x1a, 0x32, 0x2e, 0x63, 0x6f, 0x6e, 0x74,
	0x72, 0x6f, 0x6c, 0x6c, 0x65, 0x72, 0x2e, 0x61, 0x70, 0x69, 0x2e, 0x73, 0x65, 0x72, 0x76, 0x69,
	0x63, 0x65, 0x73, 0x2e, 0x76, 0x31, 0x2e, 0x4c, 0x69, 0x73, 0x74, 0x41, 0x75, 0x74, 0x68, 0x54,
	0x6f, 0x6b, 0x65, 0x6e, 0x73, 0x52, 0x65, 0x73, 0x70, 0x6f, 0x6e, 0x73, 0x65, 0x22, 0x32, 0x82,
	0xd3, 0xe4, 0x93, 0x02, 0x11, 0x12, 0x0f, 0x2f, 0x76, 0x31, 0x2f, 0x61, 0x75, 0x74, 0x68, 0x2d,
	0x74, 0x6f, 0x6b, 0x65, 0x6e, 0x73, 0x92, 0x41, 0x18, 0x12, 0x16, 0x4c, 0x69, 0x73, 0x74, 0x73,
	0x20, 0x61, 0x6c, 0x6c, 0x20, 0x41, 0x75, 0x74, 0x68, 0x20, 0x54, 0x6f, 0x6b, 0x65, 0x6e, 0x73,
	0x2e, 0x12, 0xb3, 0x01, 0x0a, 0x0f, 0x44, 0x65, 0x6c, 0x65, 0x74, 0x65, 0x41, 0x75, 0x74, 0x68,
	0x54, 0x6f, 0x6b, 0x65, 0x6e, 0x12, 0x32, 0x2e, 0x63, 0x6f, 0x6e, 0x74, 0x72, 0x6f, 0x6c, 0x6c,
	0x65, 0x72, 0x2e, 0x61, 0x70, 0x69, 0x2e, 0x73, 0x65, 0x72, 0x76, 0x69, 0x63, 0x65, 0x73, 0x2e,
	0x76, 0x31, 0x2e, 0x44, 0x65, 0x6c, 0x65, 0x74, 0x65, 0x41, 0x75, 0x74, 0x68, 0x54, 0x6f, 0x6b,
	0x65, 0x6e, 0x52, 0x65, 0x71, 0x75, 0x65, 0x73, 0x74, 0x1a, 0x33, 0x2e, 0x63, 0x6f, 0x6e, 0x74,
	0x72, 0x6f, 0x6c, 0x6c, 0x65, 0x72, 0x2e, 0x61, 0x70, 0x69, 0x2e, 0x73, 0x65, 0x72, 0x76, 0x69,
	0x63, 0x65, 0x73, 0x2e, 0x76, 0x31, 0x2e, 0x44, 0x65, 0x6c, 0x65, 0x74, 0x65, 0x41, 0x75, 0x74,
	0x68, 0x54, 0x6f, 0x6b, 0x65, 0x6e, 0x52, 0x65, 0x73, 0x70, 0x6f, 0x6e, 0x73, 0x65, 0x22, 0x37,
	0x82, 0xd3, 0xe4, 0x93, 0x02, 0x16, 0x2a, 0x14, 0x2f, 0x76, 0x31, 0x2f, 0x61, 0x75, 0x74, 0x68,
	0x2d, 0x74, 0x6f, 0x6b, 0x65, 0x6e, 0x73, 0x2f, 0x7b, 0x69, 0x64, 0x7d, 0x92, 0x41, 0x18, 0x12,
	0x16, 0x44, 0x65, 0x6c, 0x65, 0x74, 0x65, 0x73, 0x20, 0x61, 0x6e, 0x20, 0x41, 0x75, 0x74, 0x68,
	0x20, 0x54, 0x6f, 0x6b, 0x65, 0x6e, 0x2e, 0x42, 0x4d, 0x5a, 0x4b, 0x67, 0x69, 0x74, 0x68, 0x75,
	0x62, 0x2e, 0x63, 0x6f, 0x6d, 0x2f, 0x68, 0x61, 0x73, 0x68, 0x69, 0x63, 0x6f, 0x72, 0x70, 0x2f,
	0x62, 0x6f, 0x75, 0x6e, 0x64, 0x61, 0x72, 0x79, 0x2f, 0x69, 0x6e, 0x74, 0x65, 0x72, 0x6e, 0x61,
	0x6c, 0x2f, 0x67, 0x65, 0x6e, 0x2f, 0x63, 0x6f, 0x6e, 0x74, 0x72, 0x6f, 0x6c, 0x6c, 0x65, 0x72,
	0x2f, 0x61, 0x70, 0x69, 0x2f, 0x73, 0x65, 0x72, 0x76, 0x69, 0x63, 0x65, 0x73, 0x3b, 0x73, 0x65,
	0x72, 0x76, 0x69, 0x63, 0x65, 0x73, 0x62, 0x06, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x33,
}

var (
	file_controller_api_services_v1_authtokens_service_proto_rawDescOnce sync.Once
	file_controller_api_services_v1_authtokens_service_proto_rawDescData = file_controller_api_services_v1_authtokens_service_proto_rawDesc
)

func file_controller_api_services_v1_authtokens_service_proto_rawDescGZIP() []byte {
	file_controller_api_services_v1_authtokens_service_proto_rawDescOnce.Do(func() {
		file_controller_api_services_v1_authtokens_service_proto_rawDescData = protoimpl.X.CompressGZIP(file_controller_api_services_v1_authtokens_service_proto_rawDescData)
	})
	return file_controller_api_services_v1_authtokens_service_proto_rawDescData
}

var file_controller_api_services_v1_authtokens_service_proto_msgTypes = make([]protoimpl.MessageInfo, 6)
var file_controller_api_services_v1_authtokens_service_proto_goTypes = []interface{}{
	(*GetAuthTokenRequest)(nil),     // 0: controller.api.services.v1.GetAuthTokenRequest
	(*GetAuthTokenResponse)(nil),    // 1: controller.api.services.v1.GetAuthTokenResponse
	(*ListAuthTokensRequest)(nil),   // 2: controller.api.services.v1.ListAuthTokensRequest
	(*ListAuthTokensResponse)(nil),  // 3: controller.api.services.v1.ListAuthTokensResponse
	(*DeleteAuthTokenRequest)(nil),  // 4: controller.api.services.v1.DeleteAuthTokenRequest
	(*DeleteAuthTokenResponse)(nil), // 5: controller.api.services.v1.DeleteAuthTokenResponse
	(*authtokens.AuthToken)(nil),    // 6: controller.api.resources.authtokens.v1.AuthToken
}
var file_controller_api_services_v1_authtokens_service_proto_depIdxs = []int32{
	6, // 0: controller.api.services.v1.GetAuthTokenResponse.item:type_name -> controller.api.resources.authtokens.v1.AuthToken
	6, // 1: controller.api.services.v1.ListAuthTokensResponse.items:type_name -> controller.api.resources.authtokens.v1.AuthToken
	0, // 2: controller.api.services.v1.AuthTokenService.GetAuthToken:input_type -> controller.api.services.v1.GetAuthTokenRequest
	2, // 3: controller.api.services.v1.AuthTokenService.ListAuthTokens:input_type -> controller.api.services.v1.ListAuthTokensRequest
	4, // 4: controller.api.services.v1.AuthTokenService.DeleteAuthToken:input_type -> controller.api.services.v1.DeleteAuthTokenRequest
	1, // 5: controller.api.services.v1.AuthTokenService.GetAuthToken:output_type -> controller.api.services.v1.GetAuthTokenResponse
	3, // 6: controller.api.services.v1.AuthTokenService.ListAuthTokens:output_type -> controller.api.services.v1.ListAuthTokensResponse
	5, // 7: controller.api.services.v1.AuthTokenService.DeleteAuthToken:output_type -> controller.api.services.v1.DeleteAuthTokenResponse
	5, // [5:8] is the sub-list for method output_type
	2, // [2:5] is the sub-list for method input_type
	2, // [2:2] is the sub-list for extension type_name
	2, // [2:2] is the sub-list for extension extendee
	0, // [0:2] is the sub-list for field type_name
}

func init() { file_controller_api_services_v1_authtokens_service_proto_init() }
func file_controller_api_services_v1_authtokens_service_proto_init() {
	if File_controller_api_services_v1_authtokens_service_proto != nil {
		return
	}
	if !protoimpl.UnsafeEnabled {
		file_controller_api_services_v1_authtokens_service_proto_msgTypes[0].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*GetAuthTokenRequest); i {
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
		file_controller_api_services_v1_authtokens_service_proto_msgTypes[1].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*GetAuthTokenResponse); i {
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
		file_controller_api_services_v1_authtokens_service_proto_msgTypes[2].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*ListAuthTokensRequest); i {
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
		file_controller_api_services_v1_authtokens_service_proto_msgTypes[3].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*ListAuthTokensResponse); i {
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
		file_controller_api_services_v1_authtokens_service_proto_msgTypes[4].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*DeleteAuthTokenRequest); i {
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
		file_controller_api_services_v1_authtokens_service_proto_msgTypes[5].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*DeleteAuthTokenResponse); i {
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
			RawDescriptor: file_controller_api_services_v1_authtokens_service_proto_rawDesc,
			NumEnums:      0,
			NumMessages:   6,
			NumExtensions: 0,
			NumServices:   1,
		},
		GoTypes:           file_controller_api_services_v1_authtokens_service_proto_goTypes,
		DependencyIndexes: file_controller_api_services_v1_authtokens_service_proto_depIdxs,
		MessageInfos:      file_controller_api_services_v1_authtokens_service_proto_msgTypes,
	}.Build()
	File_controller_api_services_v1_authtokens_service_proto = out.File
	file_controller_api_services_v1_authtokens_service_proto_rawDesc = nil
	file_controller_api_services_v1_authtokens_service_proto_goTypes = nil
	file_controller_api_services_v1_authtokens_service_proto_depIdxs = nil
}
