// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: BUSL-1.1

// Code generated by protoc-gen-go. DO NOT EDIT.
// versions:
// 	protoc-gen-go v1.30.0
// 	protoc        (unknown)
// source: controller/api/services/v1/session_recording_service.proto

package services

import (
	_ "github.com/grpc-ecosystem/grpc-gateway/v2/protoc-gen-openapiv2/options"
	session_recordings "github.com/hashicorp/boundary/sdk/pbs/controller/api/resources/session_recordings"
	_ "google.golang.org/genproto/googleapis/api/annotations"
	httpbody "google.golang.org/genproto/googleapis/api/httpbody"
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

type GetSessionRecordingRequest struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	// The ID of the Session recording, or the ID of the Session that was recorded.
	Id string `protobuf:"bytes,1,opt,name=id,proto3" json:"id,omitempty" class:"public"` // @gotags: class:"public"
}

func (x *GetSessionRecordingRequest) Reset() {
	*x = GetSessionRecordingRequest{}
	if protoimpl.UnsafeEnabled {
		mi := &file_controller_api_services_v1_session_recording_service_proto_msgTypes[0]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *GetSessionRecordingRequest) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*GetSessionRecordingRequest) ProtoMessage() {}

func (x *GetSessionRecordingRequest) ProtoReflect() protoreflect.Message {
	mi := &file_controller_api_services_v1_session_recording_service_proto_msgTypes[0]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use GetSessionRecordingRequest.ProtoReflect.Descriptor instead.
func (*GetSessionRecordingRequest) Descriptor() ([]byte, []int) {
	return file_controller_api_services_v1_session_recording_service_proto_rawDescGZIP(), []int{0}
}

func (x *GetSessionRecordingRequest) GetId() string {
	if x != nil {
		return x.Id
	}
	return ""
}

type GetSessionRecordingResponse struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	// The requested recording.
	Item *session_recordings.SessionRecording `protobuf:"bytes,1,opt,name=item,proto3" json:"item,omitempty"`
}

func (x *GetSessionRecordingResponse) Reset() {
	*x = GetSessionRecordingResponse{}
	if protoimpl.UnsafeEnabled {
		mi := &file_controller_api_services_v1_session_recording_service_proto_msgTypes[1]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *GetSessionRecordingResponse) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*GetSessionRecordingResponse) ProtoMessage() {}

func (x *GetSessionRecordingResponse) ProtoReflect() protoreflect.Message {
	mi := &file_controller_api_services_v1_session_recording_service_proto_msgTypes[1]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use GetSessionRecordingResponse.ProtoReflect.Descriptor instead.
func (*GetSessionRecordingResponse) Descriptor() ([]byte, []int) {
	return file_controller_api_services_v1_session_recording_service_proto_rawDescGZIP(), []int{1}
}

func (x *GetSessionRecordingResponse) GetItem() *session_recordings.SessionRecording {
	if x != nil {
		return x.Item
	}
	return nil
}

type ListSessionRecordingsRequest struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	// The scope in which to list session recordings.
	// Must be set unless recursive is set.
	ScopeId string `protobuf:"bytes,1,opt,name=scope_id,json=scopeId,proto3" json:"scope_id,omitempty" class:"public"` // @gotags: class:"public"
	// Whether to recurse into child scopes when listing.
	// If set and scope_id is empty, shows session recordings in
	// all scopes the caller has access to.
	Recursive bool `protobuf:"varint,2,opt,name=recursive,proto3" json:"recursive,omitempty" class:"public"` // @gotags: class:"public"
}

func (x *ListSessionRecordingsRequest) Reset() {
	*x = ListSessionRecordingsRequest{}
	if protoimpl.UnsafeEnabled {
		mi := &file_controller_api_services_v1_session_recording_service_proto_msgTypes[2]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *ListSessionRecordingsRequest) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*ListSessionRecordingsRequest) ProtoMessage() {}

func (x *ListSessionRecordingsRequest) ProtoReflect() protoreflect.Message {
	mi := &file_controller_api_services_v1_session_recording_service_proto_msgTypes[2]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use ListSessionRecordingsRequest.ProtoReflect.Descriptor instead.
func (*ListSessionRecordingsRequest) Descriptor() ([]byte, []int) {
	return file_controller_api_services_v1_session_recording_service_proto_rawDescGZIP(), []int{2}
}

func (x *ListSessionRecordingsRequest) GetScopeId() string {
	if x != nil {
		return x.ScopeId
	}
	return ""
}

func (x *ListSessionRecordingsRequest) GetRecursive() bool {
	if x != nil {
		return x.Recursive
	}
	return false
}

type ListSessionRecordingsResponse struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	// All Session recordings, ordered by start_time descending (most recently started first).
	Items []*session_recordings.SessionRecording `protobuf:"bytes,1,rep,name=items,proto3" json:"items,omitempty"`
}

func (x *ListSessionRecordingsResponse) Reset() {
	*x = ListSessionRecordingsResponse{}
	if protoimpl.UnsafeEnabled {
		mi := &file_controller_api_services_v1_session_recording_service_proto_msgTypes[3]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *ListSessionRecordingsResponse) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*ListSessionRecordingsResponse) ProtoMessage() {}

func (x *ListSessionRecordingsResponse) ProtoReflect() protoreflect.Message {
	mi := &file_controller_api_services_v1_session_recording_service_proto_msgTypes[3]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use ListSessionRecordingsResponse.ProtoReflect.Descriptor instead.
func (*ListSessionRecordingsResponse) Descriptor() ([]byte, []int) {
	return file_controller_api_services_v1_session_recording_service_proto_rawDescGZIP(), []int{3}
}

func (x *ListSessionRecordingsResponse) GetItems() []*session_recordings.SessionRecording {
	if x != nil {
		return x.Items
	}
	return nil
}

type DownloadRequest struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	// The ID of the resource that should be downloaded. Supported types:
	//   - Session ID and Session recording ID for Session recordings
	//   - Connection ID and Connection recording ID for Connection recordings
	//   - Channel recording ID for Channel recordings
	Id string `protobuf:"bytes,1,opt,name=id,proto3" json:"id,omitempty" class:"public"` // @gotags: class:"public"
	// The format of the response. The only supported mime type is "application/x-asciicast".
	// Defaults to "application/x-asciicast" if not set.
	MimeType string `protobuf:"bytes,2,opt,name=mime_type,proto3" json:"mime_type,omitempty" class:"public"` // @gotags: class:"public"
}

func (x *DownloadRequest) Reset() {
	*x = DownloadRequest{}
	if protoimpl.UnsafeEnabled {
		mi := &file_controller_api_services_v1_session_recording_service_proto_msgTypes[4]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *DownloadRequest) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*DownloadRequest) ProtoMessage() {}

func (x *DownloadRequest) ProtoReflect() protoreflect.Message {
	mi := &file_controller_api_services_v1_session_recording_service_proto_msgTypes[4]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use DownloadRequest.ProtoReflect.Descriptor instead.
func (*DownloadRequest) Descriptor() ([]byte, []int) {
	return file_controller_api_services_v1_session_recording_service_proto_rawDescGZIP(), []int{4}
}

func (x *DownloadRequest) GetId() string {
	if x != nil {
		return x.Id
	}
	return ""
}

func (x *DownloadRequest) GetMimeType() string {
	if x != nil {
		return x.MimeType
	}
	return ""
}

var File_controller_api_services_v1_session_recording_service_proto protoreflect.FileDescriptor

var file_controller_api_services_v1_session_recording_service_proto_rawDesc = []byte{
	0x0a, 0x3a, 0x63, 0x6f, 0x6e, 0x74, 0x72, 0x6f, 0x6c, 0x6c, 0x65, 0x72, 0x2f, 0x61, 0x70, 0x69,
	0x2f, 0x73, 0x65, 0x72, 0x76, 0x69, 0x63, 0x65, 0x73, 0x2f, 0x76, 0x31, 0x2f, 0x73, 0x65, 0x73,
	0x73, 0x69, 0x6f, 0x6e, 0x5f, 0x72, 0x65, 0x63, 0x6f, 0x72, 0x64, 0x69, 0x6e, 0x67, 0x5f, 0x73,
	0x65, 0x72, 0x76, 0x69, 0x63, 0x65, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x12, 0x1a, 0x63, 0x6f,
	0x6e, 0x74, 0x72, 0x6f, 0x6c, 0x6c, 0x65, 0x72, 0x2e, 0x61, 0x70, 0x69, 0x2e, 0x73, 0x65, 0x72,
	0x76, 0x69, 0x63, 0x65, 0x73, 0x2e, 0x76, 0x31, 0x1a, 0x45, 0x63, 0x6f, 0x6e, 0x74, 0x72, 0x6f,
	0x6c, 0x6c, 0x65, 0x72, 0x2f, 0x61, 0x70, 0x69, 0x2f, 0x72, 0x65, 0x73, 0x6f, 0x75, 0x72, 0x63,
	0x65, 0x73, 0x2f, 0x73, 0x65, 0x73, 0x73, 0x69, 0x6f, 0x6e, 0x72, 0x65, 0x63, 0x6f, 0x72, 0x64,
	0x69, 0x6e, 0x67, 0x73, 0x2f, 0x76, 0x31, 0x2f, 0x73, 0x65, 0x73, 0x73, 0x69, 0x6f, 0x6e, 0x5f,
	0x72, 0x65, 0x63, 0x6f, 0x72, 0x64, 0x69, 0x6e, 0x67, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x1a,
	0x1c, 0x67, 0x6f, 0x6f, 0x67, 0x6c, 0x65, 0x2f, 0x61, 0x70, 0x69, 0x2f, 0x61, 0x6e, 0x6e, 0x6f,
	0x74, 0x61, 0x74, 0x69, 0x6f, 0x6e, 0x73, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x1a, 0x19, 0x67,
	0x6f, 0x6f, 0x67, 0x6c, 0x65, 0x2f, 0x61, 0x70, 0x69, 0x2f, 0x68, 0x74, 0x74, 0x70, 0x62, 0x6f,
	0x64, 0x79, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x1a, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x63,
	0x2d, 0x67, 0x65, 0x6e, 0x2d, 0x6f, 0x70, 0x65, 0x6e, 0x61, 0x70, 0x69, 0x76, 0x32, 0x2f, 0x6f,
	0x70, 0x74, 0x69, 0x6f, 0x6e, 0x73, 0x2f, 0x61, 0x6e, 0x6e, 0x6f, 0x74, 0x61, 0x74, 0x69, 0x6f,
	0x6e, 0x73, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x22, 0x2c, 0x0a, 0x1a, 0x47, 0x65, 0x74, 0x53,
	0x65, 0x73, 0x73, 0x69, 0x6f, 0x6e, 0x52, 0x65, 0x63, 0x6f, 0x72, 0x64, 0x69, 0x6e, 0x67, 0x52,
	0x65, 0x71, 0x75, 0x65, 0x73, 0x74, 0x12, 0x0e, 0x0a, 0x02, 0x69, 0x64, 0x18, 0x01, 0x20, 0x01,
	0x28, 0x09, 0x52, 0x02, 0x69, 0x64, 0x22, 0x72, 0x0a, 0x1b, 0x47, 0x65, 0x74, 0x53, 0x65, 0x73,
	0x73, 0x69, 0x6f, 0x6e, 0x52, 0x65, 0x63, 0x6f, 0x72, 0x64, 0x69, 0x6e, 0x67, 0x52, 0x65, 0x73,
	0x70, 0x6f, 0x6e, 0x73, 0x65, 0x12, 0x53, 0x0a, 0x04, 0x69, 0x74, 0x65, 0x6d, 0x18, 0x01, 0x20,
	0x01, 0x28, 0x0b, 0x32, 0x3f, 0x2e, 0x63, 0x6f, 0x6e, 0x74, 0x72, 0x6f, 0x6c, 0x6c, 0x65, 0x72,
	0x2e, 0x61, 0x70, 0x69, 0x2e, 0x72, 0x65, 0x73, 0x6f, 0x75, 0x72, 0x63, 0x65, 0x73, 0x2e, 0x73,
	0x65, 0x73, 0x73, 0x69, 0x6f, 0x6e, 0x72, 0x65, 0x63, 0x6f, 0x72, 0x64, 0x69, 0x6e, 0x67, 0x73,
	0x2e, 0x76, 0x31, 0x2e, 0x53, 0x65, 0x73, 0x73, 0x69, 0x6f, 0x6e, 0x52, 0x65, 0x63, 0x6f, 0x72,
	0x64, 0x69, 0x6e, 0x67, 0x52, 0x04, 0x69, 0x74, 0x65, 0x6d, 0x22, 0x57, 0x0a, 0x1c, 0x4c, 0x69,
	0x73, 0x74, 0x53, 0x65, 0x73, 0x73, 0x69, 0x6f, 0x6e, 0x52, 0x65, 0x63, 0x6f, 0x72, 0x64, 0x69,
	0x6e, 0x67, 0x73, 0x52, 0x65, 0x71, 0x75, 0x65, 0x73, 0x74, 0x12, 0x19, 0x0a, 0x08, 0x73, 0x63,
	0x6f, 0x70, 0x65, 0x5f, 0x69, 0x64, 0x18, 0x01, 0x20, 0x01, 0x28, 0x09, 0x52, 0x07, 0x73, 0x63,
	0x6f, 0x70, 0x65, 0x49, 0x64, 0x12, 0x1c, 0x0a, 0x09, 0x72, 0x65, 0x63, 0x75, 0x72, 0x73, 0x69,
	0x76, 0x65, 0x18, 0x02, 0x20, 0x01, 0x28, 0x08, 0x52, 0x09, 0x72, 0x65, 0x63, 0x75, 0x72, 0x73,
	0x69, 0x76, 0x65, 0x22, 0x76, 0x0a, 0x1d, 0x4c, 0x69, 0x73, 0x74, 0x53, 0x65, 0x73, 0x73, 0x69,
	0x6f, 0x6e, 0x52, 0x65, 0x63, 0x6f, 0x72, 0x64, 0x69, 0x6e, 0x67, 0x73, 0x52, 0x65, 0x73, 0x70,
	0x6f, 0x6e, 0x73, 0x65, 0x12, 0x55, 0x0a, 0x05, 0x69, 0x74, 0x65, 0x6d, 0x73, 0x18, 0x01, 0x20,
	0x03, 0x28, 0x0b, 0x32, 0x3f, 0x2e, 0x63, 0x6f, 0x6e, 0x74, 0x72, 0x6f, 0x6c, 0x6c, 0x65, 0x72,
	0x2e, 0x61, 0x70, 0x69, 0x2e, 0x72, 0x65, 0x73, 0x6f, 0x75, 0x72, 0x63, 0x65, 0x73, 0x2e, 0x73,
	0x65, 0x73, 0x73, 0x69, 0x6f, 0x6e, 0x72, 0x65, 0x63, 0x6f, 0x72, 0x64, 0x69, 0x6e, 0x67, 0x73,
	0x2e, 0x76, 0x31, 0x2e, 0x53, 0x65, 0x73, 0x73, 0x69, 0x6f, 0x6e, 0x52, 0x65, 0x63, 0x6f, 0x72,
	0x64, 0x69, 0x6e, 0x67, 0x52, 0x05, 0x69, 0x74, 0x65, 0x6d, 0x73, 0x22, 0x3f, 0x0a, 0x0f, 0x44,
	0x6f, 0x77, 0x6e, 0x6c, 0x6f, 0x61, 0x64, 0x52, 0x65, 0x71, 0x75, 0x65, 0x73, 0x74, 0x12, 0x0e,
	0x0a, 0x02, 0x69, 0x64, 0x18, 0x01, 0x20, 0x01, 0x28, 0x09, 0x52, 0x02, 0x69, 0x64, 0x12, 0x1c,
	0x0a, 0x09, 0x6d, 0x69, 0x6d, 0x65, 0x5f, 0x74, 0x79, 0x70, 0x65, 0x18, 0x02, 0x20, 0x01, 0x28,
	0x09, 0x52, 0x09, 0x6d, 0x69, 0x6d, 0x65, 0x5f, 0x74, 0x79, 0x70, 0x65, 0x32, 0xd1, 0x0a, 0x0a,
	0x17, 0x53, 0x65, 0x73, 0x73, 0x69, 0x6f, 0x6e, 0x52, 0x65, 0x63, 0x6f, 0x72, 0x64, 0x69, 0x6e,
	0x67, 0x53, 0x65, 0x72, 0x76, 0x69, 0x63, 0x65, 0x12, 0xea, 0x03, 0x0a, 0x13, 0x47, 0x65, 0x74,
	0x53, 0x65, 0x73, 0x73, 0x69, 0x6f, 0x6e, 0x52, 0x65, 0x63, 0x6f, 0x72, 0x64, 0x69, 0x6e, 0x67,
	0x12, 0x36, 0x2e, 0x63, 0x6f, 0x6e, 0x74, 0x72, 0x6f, 0x6c, 0x6c, 0x65, 0x72, 0x2e, 0x61, 0x70,
	0x69, 0x2e, 0x73, 0x65, 0x72, 0x76, 0x69, 0x63, 0x65, 0x73, 0x2e, 0x76, 0x31, 0x2e, 0x47, 0x65,
	0x74, 0x53, 0x65, 0x73, 0x73, 0x69, 0x6f, 0x6e, 0x52, 0x65, 0x63, 0x6f, 0x72, 0x64, 0x69, 0x6e,
	0x67, 0x52, 0x65, 0x71, 0x75, 0x65, 0x73, 0x74, 0x1a, 0x37, 0x2e, 0x63, 0x6f, 0x6e, 0x74, 0x72,
	0x6f, 0x6c, 0x6c, 0x65, 0x72, 0x2e, 0x61, 0x70, 0x69, 0x2e, 0x73, 0x65, 0x72, 0x76, 0x69, 0x63,
	0x65, 0x73, 0x2e, 0x76, 0x31, 0x2e, 0x47, 0x65, 0x74, 0x53, 0x65, 0x73, 0x73, 0x69, 0x6f, 0x6e,
	0x52, 0x65, 0x63, 0x6f, 0x72, 0x64, 0x69, 0x6e, 0x67, 0x52, 0x65, 0x73, 0x70, 0x6f, 0x6e, 0x73,
	0x65, 0x22, 0xe1, 0x02, 0x92, 0x41, 0xb4, 0x02, 0x12, 0xb1, 0x02, 0x47, 0x65, 0x74, 0x53, 0x65,
	0x73, 0x73, 0x69, 0x6f, 0x6e, 0x52, 0x65, 0x63, 0x6f, 0x72, 0x64, 0x69, 0x6e, 0x67, 0x20, 0x72,
	0x65, 0x74, 0x75, 0x72, 0x6e, 0x73, 0x20, 0x61, 0x20, 0x73, 0x74, 0x6f, 0x72, 0x65, 0x64, 0x20,
	0x53, 0x65, 0x73, 0x73, 0x69, 0x6f, 0x6e, 0x20, 0x72, 0x65, 0x63, 0x6f, 0x72, 0x64, 0x69, 0x6e,
	0x67, 0x20, 0x69, 0x66, 0x20, 0x70, 0x72, 0x65, 0x73, 0x65, 0x6e, 0x74, 0x2e, 0x20, 0x54, 0x68,
	0x65, 0x20, 0x70, 0x72, 0x6f, 0x76, 0x69, 0x64, 0x65, 0x64, 0x20, 0x72, 0x65, 0x71, 0x75, 0x65,
	0x73, 0x74, 0x20, 0x6d, 0x75, 0x73, 0x74, 0x20, 0x69, 0x6e, 0x63, 0x6c, 0x75, 0x64, 0x65, 0x20,
	0x74, 0x68, 0x65, 0x20, 0x53, 0x65, 0x73, 0x73, 0x69, 0x6f, 0x6e, 0x20, 0x72, 0x65, 0x63, 0x6f,
	0x72, 0x64, 0x69, 0x6e, 0x67, 0x20, 0x49, 0x44, 0x20, 0x66, 0x6f, 0x72, 0x20, 0x74, 0x68, 0x65,
	0x20, 0x53, 0x65, 0x73, 0x73, 0x69, 0x6f, 0x6e, 0x20, 0x72, 0x65, 0x63, 0x6f, 0x72, 0x64, 0x69,
	0x6e, 0x67, 0x20, 0x62, 0x65, 0x69, 0x6e, 0x67, 0x20, 0x72, 0x65, 0x74, 0x72, 0x69, 0x65, 0x76,
	0x65, 0x64, 0x2c, 0x20, 0x6f, 0x72, 0x20, 0x74, 0x68, 0x65, 0x20, 0x49, 0x44, 0x20, 0x6f, 0x66,
	0x20, 0x74, 0x68, 0x65, 0x20, 0x53, 0x65, 0x73, 0x73, 0x69, 0x6f, 0x6e, 0x20, 0x74, 0x68, 0x61,
	0x74, 0x20, 0x77, 0x61, 0x73, 0x20, 0x72, 0x65, 0x63, 0x6f, 0x72, 0x64, 0x65, 0x64, 0x2e, 0x20,
	0x49, 0x66, 0x20, 0x74, 0x68, 0x61, 0x74, 0x20, 0x49, 0x44, 0x20, 0x69, 0x73, 0x20, 0x6d, 0x69,
	0x73, 0x73, 0x69, 0x6e, 0x67, 0x2c, 0x20, 0x6d, 0x61, 0x6c, 0x66, 0x6f, 0x72, 0x6d, 0x65, 0x64,
	0x20, 0x6f, 0x72, 0x20, 0x72, 0x65, 0x66, 0x65, 0x72, 0x65, 0x6e, 0x63, 0x65, 0x20, 0x61, 0x20,
	0x6e, 0x6f, 0x6e, 0x20, 0x65, 0x78, 0x69, 0x73, 0x74, 0x69, 0x6e, 0x67, 0x20, 0x72, 0x65, 0x73,
	0x6f, 0x75, 0x72, 0x63, 0x65, 0x2c, 0x20, 0x61, 0x6e, 0x20, 0x65, 0x72, 0x72, 0x6f, 0x72, 0x20,
	0x69, 0x73, 0x20, 0x72, 0x65, 0x74, 0x75, 0x72, 0x6e, 0x65, 0x64, 0x2e, 0x82, 0xd3, 0xe4, 0x93,
	0x02, 0x23, 0x62, 0x04, 0x69, 0x74, 0x65, 0x6d, 0x12, 0x1b, 0x2f, 0x76, 0x31, 0x2f, 0x73, 0x65,
	0x73, 0x73, 0x69, 0x6f, 0x6e, 0x2d, 0x72, 0x65, 0x63, 0x6f, 0x72, 0x64, 0x69, 0x6e, 0x67, 0x73,
	0x2f, 0x7b, 0x69, 0x64, 0x7d, 0x12, 0xbe, 0x02, 0x0a, 0x15, 0x4c, 0x69, 0x73, 0x74, 0x53, 0x65,
	0x73, 0x73, 0x69, 0x6f, 0x6e, 0x52, 0x65, 0x63, 0x6f, 0x72, 0x64, 0x69, 0x6e, 0x67, 0x73, 0x12,
	0x38, 0x2e, 0x63, 0x6f, 0x6e, 0x74, 0x72, 0x6f, 0x6c, 0x6c, 0x65, 0x72, 0x2e, 0x61, 0x70, 0x69,
	0x2e, 0x73, 0x65, 0x72, 0x76, 0x69, 0x63, 0x65, 0x73, 0x2e, 0x76, 0x31, 0x2e, 0x4c, 0x69, 0x73,
	0x74, 0x53, 0x65, 0x73, 0x73, 0x69, 0x6f, 0x6e, 0x52, 0x65, 0x63, 0x6f, 0x72, 0x64, 0x69, 0x6e,
	0x67, 0x73, 0x52, 0x65, 0x71, 0x75, 0x65, 0x73, 0x74, 0x1a, 0x39, 0x2e, 0x63, 0x6f, 0x6e, 0x74,
	0x72, 0x6f, 0x6c, 0x6c, 0x65, 0x72, 0x2e, 0x61, 0x70, 0x69, 0x2e, 0x73, 0x65, 0x72, 0x76, 0x69,
	0x63, 0x65, 0x73, 0x2e, 0x76, 0x31, 0x2e, 0x4c, 0x69, 0x73, 0x74, 0x53, 0x65, 0x73, 0x73, 0x69,
	0x6f, 0x6e, 0x52, 0x65, 0x63, 0x6f, 0x72, 0x64, 0x69, 0x6e, 0x67, 0x73, 0x52, 0x65, 0x73, 0x70,
	0x6f, 0x6e, 0x73, 0x65, 0x22, 0xaf, 0x01, 0x92, 0x41, 0x8d, 0x01, 0x12, 0x8a, 0x01, 0x4c, 0x69,
	0x73, 0x74, 0x53, 0x65, 0x73, 0x73, 0x69, 0x6f, 0x6e, 0x52, 0x65, 0x63, 0x6f, 0x72, 0x64, 0x69,
	0x6e, 0x67, 0x73, 0x20, 0x6c, 0x69, 0x73, 0x74, 0x73, 0x20, 0x61, 0x6c, 0x6c, 0x20, 0x53, 0x65,
	0x73, 0x73, 0x69, 0x6f, 0x6e, 0x20, 0x72, 0x65, 0x63, 0x6f, 0x72, 0x64, 0x69, 0x6e, 0x67, 0x73,
	0x2e, 0x20, 0x53, 0x65, 0x73, 0x73, 0x69, 0x6f, 0x6e, 0x20, 0x72, 0x65, 0x63, 0x6f, 0x72, 0x64,
	0x69, 0x6e, 0x67, 0x73, 0x20, 0x61, 0x72, 0x65, 0x20, 0x6f, 0x72, 0x64, 0x65, 0x72, 0x65, 0x64,
	0x20, 0x62, 0x79, 0x20, 0x73, 0x74, 0x61, 0x72, 0x74, 0x5f, 0x74, 0x69, 0x6d, 0x65, 0x20, 0x64,
	0x65, 0x73, 0x63, 0x65, 0x6e, 0x64, 0x69, 0x6e, 0x67, 0x20, 0x28, 0x6d, 0x6f, 0x73, 0x74, 0x20,
	0x72, 0x65, 0x63, 0x65, 0x6e, 0x74, 0x6c, 0x79, 0x20, 0x73, 0x74, 0x61, 0x72, 0x74, 0x65, 0x64,
	0x20, 0x66, 0x69, 0x72, 0x73, 0x74, 0x29, 0x2e, 0x82, 0xd3, 0xe4, 0x93, 0x02, 0x18, 0x12, 0x16,
	0x2f, 0x76, 0x31, 0x2f, 0x73, 0x65, 0x73, 0x73, 0x69, 0x6f, 0x6e, 0x2d, 0x72, 0x65, 0x63, 0x6f,
	0x72, 0x64, 0x69, 0x6e, 0x67, 0x73, 0x12, 0x87, 0x04, 0x0a, 0x08, 0x44, 0x6f, 0x77, 0x6e, 0x6c,
	0x6f, 0x61, 0x64, 0x12, 0x2b, 0x2e, 0x63, 0x6f, 0x6e, 0x74, 0x72, 0x6f, 0x6c, 0x6c, 0x65, 0x72,
	0x2e, 0x61, 0x70, 0x69, 0x2e, 0x73, 0x65, 0x72, 0x76, 0x69, 0x63, 0x65, 0x73, 0x2e, 0x76, 0x31,
	0x2e, 0x44, 0x6f, 0x77, 0x6e, 0x6c, 0x6f, 0x61, 0x64, 0x52, 0x65, 0x71, 0x75, 0x65, 0x73, 0x74,
	0x1a, 0x14, 0x2e, 0x67, 0x6f, 0x6f, 0x67, 0x6c, 0x65, 0x2e, 0x61, 0x70, 0x69, 0x2e, 0x48, 0x74,
	0x74, 0x70, 0x42, 0x6f, 0x64, 0x79, 0x22, 0xb5, 0x03, 0x92, 0x41, 0x85, 0x03, 0x12, 0x82, 0x03,
	0x44, 0x6f, 0x77, 0x6e, 0x6c, 0x6f, 0x61, 0x64, 0x20, 0x72, 0x65, 0x74, 0x75, 0x72, 0x6e, 0x73,
	0x20, 0x74, 0x68, 0x65, 0x20, 0x63, 0x6f, 0x6e, 0x74, 0x65, 0x6e, 0x74, 0x73, 0x20, 0x6f, 0x66,
	0x20, 0x74, 0x68, 0x65, 0x20, 0x73, 0x70, 0x65, 0x63, 0x69, 0x66, 0x69, 0x65, 0x64, 0x20, 0x72,
	0x65, 0x73, 0x6f, 0x75, 0x72, 0x63, 0x65, 0x20, 0x69, 0x6e, 0x20, 0x74, 0x68, 0x65, 0x20, 0x73,
	0x70, 0x65, 0x63, 0x69, 0x66, 0x69, 0x65, 0x64, 0x20, 0x6d, 0x69, 0x6d, 0x65, 0x20, 0x74, 0x79,
	0x70, 0x65, 0x2e, 0x20, 0x53, 0x75, 0x70, 0x70, 0x6f, 0x72, 0x74, 0x73, 0x20, 0x62, 0x6f, 0x74,
	0x68, 0x20, 0x53, 0x65, 0x73, 0x73, 0x69, 0x6f, 0x6e, 0x20, 0x49, 0x44, 0x20, 0x61, 0x6e, 0x64,
	0x20, 0x53, 0x65, 0x73, 0x73, 0x69, 0x6f, 0x6e, 0x20, 0x72, 0x65, 0x63, 0x6f, 0x72, 0x64, 0x69,
	0x6e, 0x67, 0x20, 0x49, 0x44, 0x20, 0x66, 0x6f, 0x72, 0x20, 0x6c, 0x6f, 0x6f, 0x6b, 0x69, 0x6e,
	0x67, 0x20, 0x75, 0x70, 0x20, 0x61, 0x20, 0x53, 0x65, 0x73, 0x73, 0x69, 0x6f, 0x6e, 0x20, 0x72,
	0x65, 0x63, 0x6f, 0x72, 0x64, 0x69, 0x6e, 0x67, 0x2e, 0x20, 0x53, 0x75, 0x70, 0x70, 0x6f, 0x72,
	0x74, 0x73, 0x20, 0x62, 0x6f, 0x74, 0x68, 0x20, 0x43, 0x6f, 0x6e, 0x6e, 0x65, 0x63, 0x74, 0x69,
	0x6f, 0x6e, 0x20, 0x49, 0x44, 0x20, 0x61, 0x6e, 0x64, 0x20, 0x43, 0x6f, 0x6e, 0x6e, 0x65, 0x63,
	0x74, 0x69, 0x6f, 0x6e, 0x20, 0x72, 0x65, 0x63, 0x6f, 0x72, 0x64, 0x69, 0x6e, 0x67, 0x20, 0x49,
	0x44, 0x20, 0x74, 0x6f, 0x20, 0x6c, 0x6f, 0x6f, 0x6b, 0x20, 0x75, 0x70, 0x20, 0x61, 0x20, 0x43,
	0x6f, 0x6e, 0x6e, 0x65, 0x63, 0x74, 0x69, 0x6f, 0x6e, 0x20, 0x72, 0x65, 0x63, 0x6f, 0x72, 0x64,
	0x69, 0x6e, 0x67, 0x2e, 0x20, 0x41, 0x20, 0x43, 0x68, 0x61, 0x6e, 0x6e, 0x65, 0x6c, 0x20, 0x72,
	0x65, 0x63, 0x6f, 0x72, 0x64, 0x69, 0x6e, 0x67, 0x20, 0x49, 0x44, 0x20, 0x69, 0x73, 0x20, 0x72,
	0x65, 0x71, 0x75, 0x69, 0x72, 0x65, 0x64, 0x20, 0x74, 0x6f, 0x20, 0x6c, 0x6f, 0x6f, 0x6b, 0x20,
	0x75, 0x70, 0x20, 0x61, 0x20, 0x43, 0x68, 0x61, 0x6e, 0x6e, 0x65, 0x6c, 0x20, 0x72, 0x65, 0x63,
	0x6f, 0x72, 0x64, 0x69, 0x6e, 0x67, 0x2e, 0x20, 0x54, 0x68, 0x65, 0x20, 0x6f, 0x6e, 0x6c, 0x79,
	0x20, 0x73, 0x75, 0x70, 0x70, 0x6f, 0x72, 0x74, 0x65, 0x64, 0x20, 0x6d, 0x69, 0x6d, 0x65, 0x20,
	0x74, 0x79, 0x70, 0x65, 0x20, 0x69, 0x73, 0x20, 0x22, 0x61, 0x70, 0x70, 0x6c, 0x69, 0x63, 0x61,
	0x74, 0x69, 0x6f, 0x6e, 0x2f, 0x78, 0x2d, 0x61, 0x73, 0x63, 0x69, 0x69, 0x63, 0x61, 0x73, 0x74,
	0x22, 0x2e, 0x82, 0xd3, 0xe4, 0x93, 0x02, 0x26, 0x12, 0x24, 0x2f, 0x76, 0x31, 0x2f, 0x73, 0x65,
	0x73, 0x73, 0x69, 0x6f, 0x6e, 0x2d, 0x72, 0x65, 0x63, 0x6f, 0x72, 0x64, 0x69, 0x6e, 0x67, 0x73,
	0x2f, 0x7b, 0x69, 0x64, 0x7d, 0x3a, 0x64, 0x6f, 0x77, 0x6e, 0x6c, 0x6f, 0x61, 0x64, 0x30, 0x01,
	0x42, 0x4d, 0x5a, 0x4b, 0x67, 0x69, 0x74, 0x68, 0x75, 0x62, 0x2e, 0x63, 0x6f, 0x6d, 0x2f, 0x68,
	0x61, 0x73, 0x68, 0x69, 0x63, 0x6f, 0x72, 0x70, 0x2f, 0x62, 0x6f, 0x75, 0x6e, 0x64, 0x61, 0x72,
	0x79, 0x2f, 0x69, 0x6e, 0x74, 0x65, 0x72, 0x6e, 0x61, 0x6c, 0x2f, 0x67, 0x65, 0x6e, 0x2f, 0x63,
	0x6f, 0x6e, 0x74, 0x72, 0x6f, 0x6c, 0x6c, 0x65, 0x72, 0x2f, 0x61, 0x70, 0x69, 0x2f, 0x73, 0x65,
	0x72, 0x76, 0x69, 0x63, 0x65, 0x73, 0x3b, 0x73, 0x65, 0x72, 0x76, 0x69, 0x63, 0x65, 0x73, 0x62,
	0x06, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x33,
}

var (
	file_controller_api_services_v1_session_recording_service_proto_rawDescOnce sync.Once
	file_controller_api_services_v1_session_recording_service_proto_rawDescData = file_controller_api_services_v1_session_recording_service_proto_rawDesc
)

func file_controller_api_services_v1_session_recording_service_proto_rawDescGZIP() []byte {
	file_controller_api_services_v1_session_recording_service_proto_rawDescOnce.Do(func() {
		file_controller_api_services_v1_session_recording_service_proto_rawDescData = protoimpl.X.CompressGZIP(file_controller_api_services_v1_session_recording_service_proto_rawDescData)
	})
	return file_controller_api_services_v1_session_recording_service_proto_rawDescData
}

var file_controller_api_services_v1_session_recording_service_proto_msgTypes = make([]protoimpl.MessageInfo, 5)
var file_controller_api_services_v1_session_recording_service_proto_goTypes = []interface{}{
	(*GetSessionRecordingRequest)(nil),          // 0: controller.api.services.v1.GetSessionRecordingRequest
	(*GetSessionRecordingResponse)(nil),         // 1: controller.api.services.v1.GetSessionRecordingResponse
	(*ListSessionRecordingsRequest)(nil),        // 2: controller.api.services.v1.ListSessionRecordingsRequest
	(*ListSessionRecordingsResponse)(nil),       // 3: controller.api.services.v1.ListSessionRecordingsResponse
	(*DownloadRequest)(nil),                     // 4: controller.api.services.v1.DownloadRequest
	(*session_recordings.SessionRecording)(nil), // 5: controller.api.resources.sessionrecordings.v1.SessionRecording
	(*httpbody.HttpBody)(nil),                   // 6: google.api.HttpBody
}
var file_controller_api_services_v1_session_recording_service_proto_depIdxs = []int32{
	5, // 0: controller.api.services.v1.GetSessionRecordingResponse.item:type_name -> controller.api.resources.sessionrecordings.v1.SessionRecording
	5, // 1: controller.api.services.v1.ListSessionRecordingsResponse.items:type_name -> controller.api.resources.sessionrecordings.v1.SessionRecording
	0, // 2: controller.api.services.v1.SessionRecordingService.GetSessionRecording:input_type -> controller.api.services.v1.GetSessionRecordingRequest
	2, // 3: controller.api.services.v1.SessionRecordingService.ListSessionRecordings:input_type -> controller.api.services.v1.ListSessionRecordingsRequest
	4, // 4: controller.api.services.v1.SessionRecordingService.Download:input_type -> controller.api.services.v1.DownloadRequest
	1, // 5: controller.api.services.v1.SessionRecordingService.GetSessionRecording:output_type -> controller.api.services.v1.GetSessionRecordingResponse
	3, // 6: controller.api.services.v1.SessionRecordingService.ListSessionRecordings:output_type -> controller.api.services.v1.ListSessionRecordingsResponse
	6, // 7: controller.api.services.v1.SessionRecordingService.Download:output_type -> google.api.HttpBody
	5, // [5:8] is the sub-list for method output_type
	2, // [2:5] is the sub-list for method input_type
	2, // [2:2] is the sub-list for extension type_name
	2, // [2:2] is the sub-list for extension extendee
	0, // [0:2] is the sub-list for field type_name
}

func init() { file_controller_api_services_v1_session_recording_service_proto_init() }
func file_controller_api_services_v1_session_recording_service_proto_init() {
	if File_controller_api_services_v1_session_recording_service_proto != nil {
		return
	}
	if !protoimpl.UnsafeEnabled {
		file_controller_api_services_v1_session_recording_service_proto_msgTypes[0].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*GetSessionRecordingRequest); i {
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
		file_controller_api_services_v1_session_recording_service_proto_msgTypes[1].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*GetSessionRecordingResponse); i {
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
		file_controller_api_services_v1_session_recording_service_proto_msgTypes[2].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*ListSessionRecordingsRequest); i {
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
		file_controller_api_services_v1_session_recording_service_proto_msgTypes[3].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*ListSessionRecordingsResponse); i {
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
		file_controller_api_services_v1_session_recording_service_proto_msgTypes[4].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*DownloadRequest); i {
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
			RawDescriptor: file_controller_api_services_v1_session_recording_service_proto_rawDesc,
			NumEnums:      0,
			NumMessages:   5,
			NumExtensions: 0,
			NumServices:   1,
		},
		GoTypes:           file_controller_api_services_v1_session_recording_service_proto_goTypes,
		DependencyIndexes: file_controller_api_services_v1_session_recording_service_proto_depIdxs,
		MessageInfos:      file_controller_api_services_v1_session_recording_service_proto_msgTypes,
	}.Build()
	File_controller_api_services_v1_session_recording_service_proto = out.File
	file_controller_api_services_v1_session_recording_service_proto_rawDesc = nil
	file_controller_api_services_v1_session_recording_service_proto_goTypes = nil
	file_controller_api_services_v1_session_recording_service_proto_depIdxs = nil
}
