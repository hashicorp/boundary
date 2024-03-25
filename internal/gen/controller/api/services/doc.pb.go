// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

// Code generated by protoc-gen-go. DO NOT EDIT.
// versions:
// 	protoc-gen-go v1.33.0
// 	protoc        (unknown)
// source: controller/api/services/v1/doc.proto

package services

import (
	_ "github.com/grpc-ecosystem/grpc-gateway/v2/protoc-gen-openapiv2/options"
	protoreflect "google.golang.org/protobuf/reflect/protoreflect"
	protoimpl "google.golang.org/protobuf/runtime/protoimpl"
	reflect "reflect"
)

const (
	// Verify that this generated code is sufficiently up-to-date.
	_ = protoimpl.EnforceVersion(20 - protoimpl.MinVersion)
	// Verify that runtime/protoimpl is sufficiently up-to-date.
	_ = protoimpl.EnforceVersion(protoimpl.MaxVersion - 20)
)

var File_controller_api_services_v1_doc_proto protoreflect.FileDescriptor

var file_controller_api_services_v1_doc_proto_rawDesc = []byte{
	0x0a, 0x24, 0x63, 0x6f, 0x6e, 0x74, 0x72, 0x6f, 0x6c, 0x6c, 0x65, 0x72, 0x2f, 0x61, 0x70, 0x69,
	0x2f, 0x73, 0x65, 0x72, 0x76, 0x69, 0x63, 0x65, 0x73, 0x2f, 0x76, 0x31, 0x2f, 0x64, 0x6f, 0x63,
	0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x12, 0x1a, 0x63, 0x6f, 0x6e, 0x74, 0x72, 0x6f, 0x6c, 0x6c,
	0x65, 0x72, 0x2e, 0x61, 0x70, 0x69, 0x2e, 0x73, 0x65, 0x72, 0x76, 0x69, 0x63, 0x65, 0x73, 0x2e,
	0x76, 0x31, 0x1a, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x63, 0x2d, 0x67, 0x65, 0x6e, 0x2d, 0x6f,
	0x70, 0x65, 0x6e, 0x61, 0x70, 0x69, 0x76, 0x32, 0x2f, 0x6f, 0x70, 0x74, 0x69, 0x6f, 0x6e, 0x73,
	0x2f, 0x61, 0x6e, 0x6e, 0x6f, 0x74, 0x61, 0x74, 0x69, 0x6f, 0x6e, 0x73, 0x2e, 0x70, 0x72, 0x6f,
	0x74, 0x6f, 0x42, 0xc9, 0x1f, 0x92, 0x41, 0xf8, 0x1e, 0x12, 0xd5, 0x1c, 0x0a, 0x1c, 0x42, 0x6f,
	0x75, 0x6e, 0x64, 0x61, 0x72, 0x79, 0x20, 0x63, 0x6f, 0x6e, 0x74, 0x72, 0x6f, 0x6c, 0x6c, 0x65,
	0x72, 0x20, 0x48, 0x54, 0x54, 0x50, 0x20, 0x41, 0x50, 0x49, 0x12, 0x90, 0x1b, 0x57, 0x65, 0x6c,
	0x63, 0x6f, 0x6d, 0x65, 0x20, 0x74, 0x6f, 0x20, 0x74, 0x68, 0x65, 0x20, 0x42, 0x6f, 0x75, 0x6e,
	0x64, 0x61, 0x72, 0x79, 0x20, 0x63, 0x6f, 0x6e, 0x74, 0x72, 0x6f, 0x6c, 0x6c, 0x65, 0x72, 0x20,
	0x48, 0x54, 0x54, 0x50, 0x20, 0x41, 0x50, 0x49, 0x20, 0x64, 0x6f, 0x63, 0x75, 0x6d, 0x65, 0x6e,
	0x74, 0x61, 0x74, 0x69, 0x6f, 0x6e, 0x2e, 0x20, 0x54, 0x68, 0x69, 0x73, 0x20, 0x70, 0x61, 0x67,
	0x65, 0x20, 0x70, 0x72, 0x6f, 0x76, 0x69, 0x64, 0x65, 0x73, 0x20, 0x61, 0x20, 0x72, 0x65, 0x66,
	0x65, 0x72, 0x65, 0x6e, 0x63, 0x65, 0x20, 0x67, 0x75, 0x69, 0x64, 0x65, 0x20, 0x66, 0x6f, 0x72,
	0x20, 0x75, 0x73, 0x69, 0x6e, 0x67, 0x20, 0x74, 0x68, 0x65, 0x20, 0x42, 0x6f, 0x75, 0x6e, 0x64,
	0x61, 0x72, 0x79, 0x20, 0x63, 0x6f, 0x6e, 0x74, 0x72, 0x6f, 0x6c, 0x6c, 0x65, 0x72, 0x20, 0x41,
	0x50, 0x49, 0x2c, 0x20, 0x61, 0x20, 0x4a, 0x53, 0x4f, 0x4e, 0x2d, 0x62, 0x61, 0x73, 0x65, 0x64,
	0x20, 0x48, 0x54, 0x54, 0x50, 0x20, 0x41, 0x50, 0x49, 0x2e, 0x20, 0x54, 0x68, 0x65, 0x20, 0x41,
	0x50, 0x49, 0x20, 0x69, 0x6d, 0x70, 0x6c, 0x65, 0x6d, 0x65, 0x6e, 0x74, 0x73, 0x20, 0x63, 0x6f,
	0x6d, 0x6d, 0x6f, 0x6e, 0x6c, 0x79, 0x20, 0x73, 0x65, 0x65, 0x6e, 0x20, 0x48, 0x54, 0x54, 0x50,
	0x20, 0x41, 0x50, 0x49, 0x20, 0x70, 0x61, 0x74, 0x74, 0x65, 0x72, 0x6e, 0x73, 0x20, 0x66, 0x6f,
	0x72, 0x20, 0x73, 0x74, 0x61, 0x74, 0x75, 0x73, 0x20, 0x63, 0x6f, 0x64, 0x65, 0x73, 0x2c, 0x20,
	0x70, 0x61, 0x74, 0x68, 0x73, 0x20, 0x61, 0x6e, 0x64, 0x20, 0x65, 0x72, 0x72, 0x6f, 0x72, 0x73,
	0x2e, 0x20, 0x53, 0x65, 0x65, 0x20, 0x74, 0x68, 0x65, 0x20, 0x5b, 0x41, 0x50, 0x49, 0x20, 0x6f,
	0x76, 0x65, 0x72, 0x76, 0x69, 0x65, 0x77, 0x5d, 0x28, 0x68, 0x74, 0x74, 0x70, 0x73, 0x3a, 0x2f,
	0x2f, 0x64, 0x65, 0x76, 0x65, 0x6c, 0x6f, 0x70, 0x65, 0x72, 0x2e, 0x68, 0x61, 0x73, 0x68, 0x69,
	0x63, 0x6f, 0x72, 0x70, 0x2e, 0x63, 0x6f, 0x6d, 0x2f, 0x62, 0x6f, 0x75, 0x6e, 0x64, 0x61, 0x72,
	0x79, 0x2f, 0x64, 0x6f, 0x63, 0x73, 0x2f, 0x61, 0x70, 0x69, 0x2d, 0x63, 0x6c, 0x69, 0x65, 0x6e,
	0x74, 0x73, 0x2f, 0x61, 0x70, 0x69, 0x29, 0x20, 0x66, 0x6f, 0x72, 0x20, 0x6d, 0x6f, 0x72, 0x65,
	0x20, 0x69, 0x6e, 0x66, 0x6f, 0x72, 0x6d, 0x61, 0x74, 0x69, 0x6f, 0x6e, 0x2e, 0x0a, 0x0a, 0x42,
	0x65, 0x66, 0x6f, 0x72, 0x65, 0x20, 0x72, 0x65, 0x61, 0x64, 0x69, 0x6e, 0x67, 0x20, 0x74, 0x68,
	0x69, 0x73, 0x20, 0x70, 0x61, 0x67, 0x65, 0x2c, 0x20, 0x69, 0x74, 0x20, 0x69, 0x73, 0x20, 0x75,
	0x73, 0x65, 0x66, 0x75, 0x6c, 0x20, 0x74, 0x6f, 0x20, 0x75, 0x6e, 0x64, 0x65, 0x72, 0x73, 0x74,
	0x61, 0x6e, 0x64, 0x20, 0x42, 0x6f, 0x75, 0x6e, 0x64, 0x61, 0x72, 0x79, 0x27, 0x73, 0x20, 0x5b,
	0x64, 0x6f, 0x6d, 0x61, 0x69, 0x6e, 0x20, 0x6d, 0x6f, 0x64, 0x65, 0x6c, 0x5d, 0x28, 0x68, 0x74,
	0x74, 0x70, 0x73, 0x3a, 0x2f, 0x2f, 0x64, 0x65, 0x76, 0x65, 0x6c, 0x6f, 0x70, 0x65, 0x72, 0x2e,
	0x68, 0x61, 0x73, 0x68, 0x69, 0x63, 0x6f, 0x72, 0x70, 0x2e, 0x63, 0x6f, 0x6d, 0x2f, 0x62, 0x6f,
	0x75, 0x6e, 0x64, 0x61, 0x72, 0x79, 0x2f, 0x64, 0x6f, 0x63, 0x73, 0x2f, 0x63, 0x6f, 0x6e, 0x63,
	0x65, 0x70, 0x74, 0x73, 0x2f, 0x64, 0x6f, 0x6d, 0x61, 0x69, 0x6e, 0x2d, 0x6d, 0x6f, 0x64, 0x65,
	0x6c, 0x29, 0x20, 0x61, 0x6e, 0x64, 0x20, 0x74, 0x6f, 0x20, 0x62, 0x65, 0x20, 0x61, 0x77, 0x61,
	0x72, 0x65, 0x20, 0x6f, 0x66, 0x20, 0x74, 0x68, 0x65, 0x20, 0x74, 0x65, 0x72, 0x6d, 0x69, 0x6e,
	0x6f, 0x6c, 0x6f, 0x67, 0x79, 0x20, 0x75, 0x73, 0x65, 0x64, 0x20, 0x68, 0x65, 0x72, 0x65, 0x2e,
	0x20, 0x54, 0x6f, 0x20, 0x67, 0x65, 0x74, 0x20, 0x73, 0x74, 0x61, 0x72, 0x74, 0x65, 0x64, 0x2c,
	0x20, 0x73, 0x65, 0x61, 0x72, 0x63, 0x68, 0x20, 0x66, 0x6f, 0x72, 0x20, 0x74, 0x68, 0x65, 0x20,
	0x73, 0x65, 0x72, 0x76, 0x69, 0x63, 0x65, 0x20, 0x79, 0x6f, 0x75, 0x20, 0x77, 0x61, 0x6e, 0x74,
	0x20, 0x74, 0x6f, 0x20, 0x69, 0x6e, 0x74, 0x65, 0x72, 0x61, 0x63, 0x74, 0x20, 0x77, 0x69, 0x74,
	0x68, 0x20, 0x69, 0x6e, 0x20, 0x74, 0x68, 0x65, 0x20, 0x73, 0x69, 0x64, 0x65, 0x62, 0x61, 0x72,
	0x20, 0x74, 0x6f, 0x20, 0x74, 0x68, 0x65, 0x20, 0x6c, 0x65, 0x66, 0x74, 0x2e, 0x20, 0x45, 0x61,
	0x63, 0x68, 0x20, 0x72, 0x65, 0x73, 0x6f, 0x75, 0x72, 0x63, 0x65, 0x20, 0x69, 0x6e, 0x20, 0x42,
	0x6f, 0x75, 0x6e, 0x64, 0x61, 0x72, 0x79, 0x2c, 0x20, 0x73, 0x75, 0x63, 0x68, 0x20, 0x61, 0x73,
	0x20, 0x61, 0x63, 0x63, 0x6f, 0x75, 0x6e, 0x74, 0x73, 0x20, 0x61, 0x6e, 0x64, 0x20, 0x63, 0x72,
	0x65, 0x64, 0x65, 0x6e, 0x74, 0x69, 0x61, 0x6c, 0x20, 0x73, 0x74, 0x6f, 0x72, 0x65, 0x73, 0x2c,
	0x20, 0x68, 0x61, 0x76, 0x65, 0x20, 0x74, 0x68, 0x65, 0x69, 0x72, 0x20, 0x6f, 0x77, 0x6e, 0x20,
	0x73, 0x65, 0x72, 0x76, 0x69, 0x63, 0x65, 0x2e, 0x20, 0x45, 0x61, 0x63, 0x68, 0x20, 0x73, 0x65,
	0x72, 0x76, 0x69, 0x63, 0x65, 0x20, 0x63, 0x6f, 0x6e, 0x74, 0x61, 0x69, 0x6e, 0x73, 0x20, 0x61,
	0x6c, 0x6c, 0x20, 0x74, 0x68, 0x65, 0x20, 0x41, 0x50, 0x49, 0x20, 0x65, 0x6e, 0x64, 0x70, 0x6f,
	0x69, 0x6e, 0x74, 0x73, 0x20, 0x66, 0x6f, 0x72, 0x20, 0x74, 0x68, 0x65, 0x20, 0x72, 0x65, 0x73,
	0x6f, 0x75, 0x72, 0x63, 0x65, 0x2e, 0x0a, 0x23, 0x23, 0x20, 0x53, 0x74, 0x61, 0x74, 0x75, 0x73,
	0x20, 0x63, 0x6f, 0x64, 0x65, 0x73, 0x0a, 0x2d, 0x20, 0x60, 0x32, 0x58, 0x58, 0x60, 0x3a, 0x20,
	0x42, 0x6f, 0x75, 0x6e, 0x64, 0x61, 0x72, 0x79, 0x20, 0x72, 0x65, 0x74, 0x75, 0x72, 0x6e, 0x73,
	0x20, 0x61, 0x20, 0x63, 0x6f, 0x64, 0x65, 0x20, 0x62, 0x65, 0x74, 0x77, 0x65, 0x65, 0x6e, 0x20,
	0x60, 0x32, 0x30, 0x30, 0x60, 0x20, 0x61, 0x6e, 0x64, 0x20, 0x60, 0x32, 0x39, 0x39, 0x60, 0x20,
	0x6f, 0x6e, 0x20, 0x73, 0x75, 0x63, 0x63, 0x65, 0x73, 0x73, 0x2e, 0x20, 0x47, 0x65, 0x6e, 0x65,
	0x72, 0x61, 0x6c, 0x6c, 0x79, 0x20, 0x74, 0x68, 0x69, 0x73, 0x20, 0x69, 0x73, 0x20, 0x60, 0x32,
	0x30, 0x30, 0x60, 0x2c, 0x20, 0x62, 0x75, 0x74, 0x20, 0x69, 0x6d, 0x70, 0x6c, 0x65, 0x6d, 0x65,
	0x6e, 0x74, 0x61, 0x74, 0x69, 0x6f, 0x6e, 0x73, 0x20, 0x73, 0x68, 0x6f, 0x75, 0x6c, 0x64, 0x20,
	0x62, 0x65, 0x20, 0x70, 0x72, 0x65, 0x70, 0x61, 0x72, 0x65, 0x64, 0x20, 0x74, 0x6f, 0x20, 0x61,
	0x63, 0x63, 0x65, 0x70, 0x74, 0x20, 0x61, 0x6e, 0x79, 0x20, 0x60, 0x32, 0x58, 0x58, 0x60, 0x20,
	0x73, 0x74, 0x61, 0x74, 0x75, 0x73, 0x20, 0x63, 0x6f, 0x64, 0x65, 0x20, 0x61, 0x73, 0x20, 0x69,
	0x6e, 0x64, 0x69, 0x63, 0x61, 0x74, 0x69, 0x6e, 0x67, 0x20, 0x73, 0x75, 0x63, 0x63, 0x65, 0x73,
	0x73, 0x2e, 0x20, 0x49, 0x66, 0x20, 0x61, 0x20, 0x63, 0x61, 0x6c, 0x6c, 0x20, 0x72, 0x65, 0x74,
	0x75, 0x72, 0x6e, 0x73, 0x20, 0x61, 0x20, 0x60, 0x32, 0x58, 0x58, 0x60, 0x20, 0x63, 0x6f, 0x64,
	0x65, 0x20, 0x74, 0x68, 0x61, 0x74, 0x20, 0x69, 0x73, 0x20, 0x6e, 0x6f, 0x74, 0x20, 0x60, 0x32,
	0x30, 0x30, 0x60, 0x2c, 0x20, 0x69, 0x74, 0x20, 0x77, 0x69, 0x6c, 0x6c, 0x20, 0x66, 0x6f, 0x6c,
	0x6c, 0x6f, 0x77, 0x20, 0x77, 0x65, 0x6c, 0x6c, 0x2d, 0x75, 0x6e, 0x64, 0x65, 0x72, 0x73, 0x74,
	0x6f, 0x6f, 0x64, 0x20, 0x73, 0x65, 0x6d, 0x61, 0x6e, 0x74, 0x69, 0x63, 0x73, 0x20, 0x66, 0x6f,
	0x72, 0x20, 0x74, 0x68, 0x6f, 0x73, 0x65, 0x20, 0x73, 0x74, 0x61, 0x74, 0x75, 0x73, 0x20, 0x63,
	0x6f, 0x64, 0x65, 0x73, 0x2e, 0x0a, 0x2d, 0x20, 0x60, 0x34, 0x30, 0x30, 0x60, 0x3a, 0x20, 0x42,
	0x6f, 0x75, 0x6e, 0x64, 0x61, 0x72, 0x79, 0x20, 0x72, 0x65, 0x74, 0x75, 0x72, 0x6e, 0x73, 0x20,
	0x60, 0x34, 0x30, 0x30, 0x60, 0x20, 0x77, 0x68, 0x65, 0x6e, 0x20, 0x61, 0x20, 0x63, 0x6f, 0x6d,
	0x6d, 0x61, 0x6e, 0x64, 0x20, 0x63, 0x61, 0x6e, 0x6e, 0x6f, 0x74, 0x20, 0x62, 0x65, 0x20, 0x63,
	0x6f, 0x6d, 0x70, 0x6c, 0x65, 0x74, 0x65, 0x64, 0x20, 0x64, 0x75, 0x65, 0x20, 0x74, 0x6f, 0x20,
	0x69, 0x6e, 0x76, 0x61, 0x6c, 0x69, 0x64, 0x20, 0x75, 0x73, 0x65, 0x72, 0x20, 0x69, 0x6e, 0x70,
	0x75, 0x74, 0x2c, 0x20, 0x65, 0x78, 0x63, 0x65, 0x70, 0x74, 0x20, 0x66, 0x6f, 0x72, 0x20, 0x61,
	0x20, 0x70, 0x72, 0x6f, 0x70, 0x65, 0x72, 0x6c, 0x79, 0x2d, 0x66, 0x6f, 0x72, 0x6d, 0x61, 0x74,
	0x74, 0x65, 0x64, 0x20, 0x69, 0x64, 0x65, 0x6e, 0x74, 0x69, 0x66, 0x69, 0x65, 0x72, 0x20, 0x74,
	0x68, 0x61, 0x74, 0x20, 0x64, 0x6f, 0x65, 0x73, 0x20, 0x6e, 0x6f, 0x74, 0x20, 0x6d, 0x61, 0x70,
	0x20, 0x74, 0x6f, 0x20, 0x61, 0x6e, 0x20, 0x65, 0x78, 0x69, 0x73, 0x74, 0x69, 0x6e, 0x67, 0x20,
	0x72, 0x65, 0x73, 0x6f, 0x75, 0x72, 0x63, 0x65, 0x2c, 0x20, 0x77, 0x68, 0x69, 0x63, 0x68, 0x20,
	0x77, 0x69, 0x6c, 0x6c, 0x20, 0x72, 0x65, 0x74, 0x75, 0x72, 0x6e, 0x20, 0x61, 0x20, 0x60, 0x34,
	0x30, 0x34, 0x60, 0x20, 0x61, 0x73, 0x20, 0x64, 0x69, 0x73, 0x63, 0x75, 0x73, 0x73, 0x65, 0x64,
	0x20, 0x62, 0x65, 0x6c, 0x6f, 0x77, 0x2e, 0x0a, 0x2d, 0x20, 0x60, 0x34, 0x30, 0x31, 0x60, 0x3a,
	0x20, 0x42, 0x6f, 0x75, 0x6e, 0x64, 0x61, 0x72, 0x79, 0x20, 0x72, 0x65, 0x74, 0x75, 0x72, 0x6e,
	0x73, 0x20, 0x60, 0x34, 0x30, 0x31, 0x60, 0x20, 0x69, 0x66, 0x20, 0x6e, 0x6f, 0x20, 0x61, 0x75,
	0x74, 0x68, 0x65, 0x6e, 0x74, 0x69, 0x63, 0x61, 0x74, 0x69, 0x6f, 0x6e, 0x20, 0x74, 0x6f, 0x6b,
	0x65, 0x6e, 0x20, 0x69, 0x73, 0x20, 0x70, 0x72, 0x6f, 0x76, 0x69, 0x64, 0x65, 0x64, 0x20, 0x6f,
	0x72, 0x20, 0x69, 0x66, 0x20, 0x74, 0x68, 0x65, 0x20, 0x70, 0x72, 0x6f, 0x76, 0x69, 0x64, 0x65,
	0x64, 0x20, 0x74, 0x6f, 0x6b, 0x65, 0x6e, 0x20, 0x69, 0x73, 0x20, 0x69, 0x6e, 0x76, 0x61, 0x6c,
	0x69, 0x64, 0x2e, 0x20, 0x41, 0x20, 0x76, 0x61, 0x6c, 0x69, 0x64, 0x20, 0x74, 0x6f, 0x6b, 0x65,
	0x6e, 0x20, 0x74, 0x68, 0x61, 0x74, 0x20, 0x73, 0x69, 0x6d, 0x70, 0x6c, 0x79, 0x20, 0x64, 0x6f,
	0x65, 0x73, 0x20, 0x6e, 0x6f, 0x74, 0x20, 0x68, 0x61, 0x76, 0x65, 0x20, 0x70, 0x65, 0x72, 0x6d,
	0x69, 0x73, 0x73, 0x69, 0x6f, 0x6e, 0x20, 0x66, 0x6f, 0x72, 0x20, 0x61, 0x20, 0x72, 0x65, 0x73,
	0x6f, 0x75, 0x72, 0x63, 0x65, 0x20, 0x77, 0x69, 0x6c, 0x6c, 0x20, 0x72, 0x65, 0x74, 0x75, 0x72,
	0x6e, 0x20, 0x61, 0x20, 0x60, 0x34, 0x30, 0x33, 0x60, 0x20, 0x69, 0x6e, 0x73, 0x74, 0x65, 0x61,
	0x64, 0x2e, 0x20, 0x41, 0x20, 0x74, 0x6f, 0x6b, 0x65, 0x6e, 0x20, 0x74, 0x68, 0x61, 0x74, 0x20,
	0x69, 0x73, 0x20, 0x69, 0x6e, 0x76, 0x61, 0x6c, 0x69, 0x64, 0x20, 0x6f, 0x72, 0x20, 0x6d, 0x69,
	0x73, 0x73, 0x69, 0x6e, 0x67, 0x2c, 0x20, 0x62, 0x75, 0x74, 0x20, 0x77, 0x68, 0x65, 0x72, 0x65,
	0x20, 0x74, 0x68, 0x65, 0x20, 0x61, 0x6e, 0x6f, 0x6e, 0x79, 0x6d, 0x6f, 0x75, 0x73, 0x20, 0x75,
	0x73, 0x65, 0x72, 0x20, 0x28, 0x60, 0x75, 0x5f, 0x61, 0x6e, 0x6f, 0x6e, 0x60, 0x29, 0x20, 0x69,
	0x73, 0x20, 0x61, 0x62, 0x6c, 0x65, 0x20, 0x74, 0x6f, 0x20, 0x73, 0x75, 0x63, 0x63, 0x65, 0x73,
	0x73, 0x66, 0x75, 0x6c, 0x6c, 0x79, 0x20, 0x70, 0x65, 0x72, 0x66, 0x6f, 0x72, 0x6d, 0x20, 0x74,
	0x68, 0x65, 0x20, 0x61, 0x63, 0x74, 0x69, 0x6f, 0x6e, 0x2c, 0x20, 0x77, 0x69, 0x6c, 0x6c, 0x20,
	0x6e, 0x6f, 0x74, 0x20, 0x72, 0x65, 0x74, 0x75, 0x72, 0x6e, 0x20, 0x61, 0x20, 0x60, 0x34, 0x30,
	0x31, 0x60, 0x20, 0x62, 0x75, 0x74, 0x20, 0x69, 0x6e, 0x73, 0x74, 0x65, 0x61, 0x64, 0x20, 0x77,
	0x69, 0x6c, 0x6c, 0x20, 0x72, 0x65, 0x74, 0x75, 0x72, 0x6e, 0x20, 0x74, 0x68, 0x65, 0x20, 0x72,
	0x65, 0x73, 0x75, 0x6c, 0x74, 0x20, 0x6f, 0x66, 0x20, 0x74, 0x68, 0x65, 0x20, 0x61, 0x63, 0x74,
	0x69, 0x6f, 0x6e, 0x2e, 0x0a, 0x2d, 0x20, 0x60, 0x34, 0x30, 0x33, 0x60, 0x3a, 0x20, 0x42, 0x6f,
	0x75, 0x6e, 0x64, 0x61, 0x72, 0x79, 0x20, 0x72, 0x65, 0x74, 0x75, 0x72, 0x6e, 0x73, 0x20, 0x60,
	0x34, 0x30, 0x33, 0x60, 0x20, 0x69, 0x66, 0x20, 0x61, 0x20, 0x70, 0x72, 0x6f, 0x76, 0x69, 0x64,
	0x65, 0x64, 0x20, 0x74, 0x6f, 0x6b, 0x65, 0x6e, 0x20, 0x77, 0x61, 0x73, 0x20, 0x76, 0x61, 0x6c,
	0x69, 0x64, 0x20, 0x62, 0x75, 0x74, 0x20, 0x64, 0x6f, 0x65, 0x73, 0x20, 0x6e, 0x6f, 0x74, 0x20,
	0x68, 0x61, 0x76, 0x65, 0x20, 0x74, 0x68, 0x65, 0x20, 0x67, 0x72, 0x61, 0x6e, 0x74, 0x73, 0x20,
	0x72, 0x65, 0x71, 0x75, 0x69, 0x72, 0x65, 0x64, 0x20, 0x74, 0x6f, 0x20, 0x70, 0x65, 0x72, 0x66,
	0x6f, 0x72, 0x6d, 0x20, 0x74, 0x68, 0x65, 0x20, 0x72, 0x65, 0x71, 0x75, 0x65, 0x73, 0x74, 0x65,
	0x64, 0x20, 0x61, 0x63, 0x74, 0x69, 0x6f, 0x6e, 0x2e, 0x0a, 0x2d, 0x20, 0x60, 0x34, 0x30, 0x34,
	0x60, 0x3a, 0x20, 0x42, 0x6f, 0x75, 0x6e, 0x64, 0x61, 0x72, 0x79, 0x20, 0x72, 0x65, 0x74, 0x75,
	0x72, 0x6e, 0x73, 0x20, 0x60, 0x34, 0x30, 0x34, 0x60, 0x20, 0x69, 0x66, 0x20, 0x61, 0x20, 0x72,
	0x65, 0x73, 0x6f, 0x75, 0x72, 0x63, 0x65, 0x20, 0x63, 0x61, 0x6e, 0x6e, 0x6f, 0x74, 0x20, 0x62,
	0x65, 0x20, 0x66, 0x6f, 0x75, 0x6e, 0x64, 0x2e, 0x20, 0x4e, 0x6f, 0x74, 0x65, 0x20, 0x74, 0x68,
	0x61, 0x74, 0x20, 0x74, 0x68, 0x69, 0x73, 0x20, 0x68, 0x61, 0x70, 0x70, 0x65, 0x6e, 0x73, 0x20,
	0x5f, 0x70, 0x72, 0x69, 0x6f, 0x72, 0x5f, 0x20, 0x74, 0x6f, 0x20, 0x61, 0x75, 0x74, 0x68, 0x65,
	0x6e, 0x74, 0x69, 0x63, 0x61, 0x74, 0x69, 0x6f, 0x6e, 0x2f, 0x61, 0x75, 0x74, 0x68, 0x6f, 0x72,
	0x69, 0x7a, 0x61, 0x74, 0x69, 0x6f, 0x6e, 0x20, 0x63, 0x68, 0x65, 0x63, 0x6b, 0x69, 0x6e, 0x67,
	0x20, 0x69, 0x6e, 0x20, 0x6e, 0x65, 0x61, 0x72, 0x6c, 0x79, 0x20, 0x61, 0x6c, 0x6c, 0x20, 0x63,
	0x61, 0x73, 0x65, 0x73, 0x20, 0x61, 0x73, 0x20, 0x74, 0x68, 0x65, 0x20, 0x72, 0x65, 0x73, 0x6f,
	0x75, 0x72, 0x63, 0x65, 0x20, 0x69, 0x6e, 0x66, 0x6f, 0x72, 0x6d, 0x61, 0x74, 0x69, 0x6f, 0x6e,
	0x20, 0x28, 0x73, 0x75, 0x63, 0x68, 0x20, 0x61, 0x73, 0x20, 0x69, 0x74, 0x73, 0x20, 0x73, 0x63,
	0x6f, 0x70, 0x65, 0x2c, 0x20, 0x61, 0x76, 0x61, 0x69, 0x6c, 0x61, 0x62, 0x6c, 0x65, 0x20, 0x61,
	0x63, 0x74, 0x69, 0x6f, 0x6e, 0x73, 0x2c, 0x20, 0x65, 0x74, 0x63, 0x2e, 0x29, 0x20, 0x69, 0x73,
	0x20, 0x61, 0x20, 0x72, 0x65, 0x71, 0x75, 0x69, 0x72, 0x65, 0x64, 0x20, 0x70, 0x61, 0x72, 0x74,
	0x20, 0x6f, 0x66, 0x20, 0x74, 0x68, 0x61, 0x74, 0x20, 0x63, 0x68, 0x65, 0x63, 0x6b, 0x2e, 0x20,
	0x41, 0x73, 0x20, 0x61, 0x20, 0x72, 0x65, 0x73, 0x75, 0x6c, 0x74, 0x2c, 0x20, 0x61, 0x6e, 0x20,
	0x61, 0x63, 0x74, 0x69, 0x6f, 0x6e, 0x20, 0x61, 0x67, 0x61, 0x69, 0x6e, 0x73, 0x74, 0x20, 0x61,
	0x20, 0x72, 0x65, 0x73, 0x6f, 0x75, 0x72, 0x63, 0x65, 0x20, 0x74, 0x68, 0x61, 0x74, 0x20, 0x64,
	0x6f, 0x65, 0x73, 0x20, 0x6e, 0x6f, 0x74, 0x20, 0x65, 0x78, 0x69, 0x73, 0x74, 0x20, 0x77, 0x69,
	0x6c, 0x6c, 0x20, 0x72, 0x65, 0x74, 0x75, 0x72, 0x6e, 0x20, 0x61, 0x20, 0x60, 0x34, 0x30, 0x34,
	0x60, 0x20, 0x69, 0x6e, 0x73, 0x74, 0x65, 0x61, 0x64, 0x20, 0x6f, 0x66, 0x20, 0x61, 0x20, 0x60,
	0x34, 0x30, 0x31, 0x60, 0x20, 0x6f, 0x72, 0x20, 0x60, 0x34, 0x30, 0x33, 0x60, 0x2e, 0x20, 0x57,
	0x68, 0x69, 0x6c, 0x65, 0x20, 0x74, 0x68, 0x69, 0x73, 0x20, 0x63, 0x6f, 0x75, 0x6c, 0x64, 0x20,
	0x62, 0x65, 0x20, 0x63, 0x6f, 0x6e, 0x73, 0x69, 0x64, 0x65, 0x72, 0x65, 0x64, 0x20, 0x61, 0x6e,
	0x20, 0x69, 0x6e, 0x66, 0x6f, 0x72, 0x6d, 0x61, 0x74, 0x69, 0x6f, 0x6e, 0x20, 0x6c, 0x65, 0x61,
	0x6b, 0x2c, 0x20, 0x73, 0x69, 0x6e, 0x63, 0x65, 0x20, 0x49, 0x44, 0x73, 0x20, 0x61, 0x72, 0x65,
	0x20, 0x72, 0x61, 0x6e, 0x64, 0x6f, 0x6d, 0x6c, 0x79, 0x20, 0x67, 0x65, 0x6e, 0x65, 0x72, 0x61,
	0x74, 0x65, 0x64, 0x20, 0x61, 0x6e, 0x64, 0x20, 0x74, 0x68, 0x69, 0x73, 0x20, 0x6f, 0x6e, 0x6c,
	0x79, 0x20, 0x64, 0x69, 0x73, 0x63, 0x6c, 0x6f, 0x73, 0x65, 0x73, 0x20, 0x77, 0x68, 0x65, 0x74,
	0x68, 0x65, 0x72, 0x20, 0x61, 0x6e, 0x20, 0x49, 0x44, 0x20, 0x69, 0x73, 0x20, 0x76, 0x61, 0x6c,
	0x69, 0x64, 0x2c, 0x20, 0x69, 0x74, 0x27, 0x73, 0x20, 0x74, 0x6f, 0x6c, 0x65, 0x72, 0x61, 0x62,
	0x6c, 0x65, 0x20, 0x61, 0x73, 0x20, 0x69, 0x74, 0x20, 0x61, 0x6c, 0x6c, 0x6f, 0x77, 0x73, 0x20,
	0x66, 0x6f, 0x72, 0x20, 0x66, 0x61, 0x72, 0x20, 0x73, 0x69, 0x6d, 0x70, 0x6c, 0x65, 0x72, 0x20,
	0x61, 0x6e, 0x64, 0x20, 0x6d, 0x6f, 0x72, 0x65, 0x20, 0x72, 0x6f, 0x62, 0x75, 0x73, 0x74, 0x20,
	0x63, 0x6c, 0x69, 0x65, 0x6e, 0x74, 0x20, 0x69, 0x6d, 0x70, 0x6c, 0x65, 0x6d, 0x65, 0x6e, 0x74,
	0x61, 0x74, 0x69, 0x6f, 0x6e, 0x2e, 0x0a, 0x2d, 0x20, 0x60, 0x34, 0x30, 0x35, 0x60, 0x3a, 0x20,
	0x42, 0x6f, 0x75, 0x6e, 0x64, 0x61, 0x72, 0x79, 0x20, 0x72, 0x65, 0x74, 0x75, 0x72, 0x6e, 0x73,
	0x20, 0x61, 0x20, 0x60, 0x34, 0x30, 0x35, 0x60, 0x20, 0x74, 0x6f, 0x20, 0x69, 0x6e, 0x64, 0x69,
	0x63, 0x61, 0x74, 0x65, 0x20, 0x74, 0x68, 0x61, 0x74, 0x20, 0x74, 0x68, 0x65, 0x20, 0x6d, 0x65,
	0x74, 0x68, 0x6f, 0x64, 0x20, 0x28, 0x48, 0x54, 0x54, 0x50, 0x20, 0x76, 0x65, 0x72, 0x62, 0x20,
	0x6f, 0x72, 0x20, 0x63, 0x75, 0x73, 0x74, 0x6f, 0x6d, 0x20, 0x61, 0x63, 0x74, 0x69, 0x6f, 0x6e,
	0x29, 0x20, 0x69, 0x73, 0x20, 0x6e, 0x6f, 0x74, 0x20, 0x69, 0x6d, 0x70, 0x6c, 0x65, 0x6d, 0x65,
	0x6e, 0x74, 0x65, 0x64, 0x20, 0x66, 0x6f, 0x72, 0x20, 0x74, 0x68, 0x65, 0x20, 0x67, 0x69, 0x76,
	0x65, 0x6e, 0x20, 0x72, 0x65, 0x73, 0x6f, 0x75, 0x72, 0x63, 0x65, 0x2e, 0x0a, 0x2d, 0x20, 0x60,
	0x34, 0x32, 0x39, 0x60, 0x3a, 0x20, 0x42, 0x6f, 0x75, 0x6e, 0x64, 0x61, 0x72, 0x79, 0x20, 0x72,
	0x65, 0x74, 0x75, 0x72, 0x6e, 0x73, 0x20, 0x61, 0x20, 0x60, 0x34, 0x32, 0x39, 0x60, 0x20, 0x69,
	0x66, 0x20, 0x61, 0x6e, 0x79, 0x20, 0x6f, 0x66, 0x20, 0x74, 0x68, 0x65, 0x20, 0x41, 0x50, 0x49,
	0x20, 0x72, 0x61, 0x74, 0x65, 0x20, 0x6c, 0x69, 0x6d, 0x69, 0x74, 0x20, 0x71, 0x75, 0x6f, 0x74,
	0x61, 0x73, 0x20, 0x68, 0x61, 0x76, 0x65, 0x20, 0x62, 0x65, 0x65, 0x6e, 0x20, 0x65, 0x78, 0x68,
	0x61, 0x75, 0x73, 0x74, 0x65, 0x64, 0x20, 0x66, 0x6f, 0x72, 0x20, 0x74, 0x68, 0x65, 0x20, 0x72,
	0x65, 0x73, 0x6f, 0x75, 0x72, 0x63, 0x65, 0x20, 0x61, 0x6e, 0x64, 0x20, 0x61, 0x63, 0x74, 0x69,
	0x6f, 0x6e, 0x2e, 0x20, 0x49, 0x74, 0x20, 0x69, 0x6e, 0x63, 0x6c, 0x75, 0x64, 0x65, 0x73, 0x20,
	0x74, 0x68, 0x65, 0x20, 0x60, 0x52, 0x65, 0x74, 0x72, 0x79, 0x2d, 0x41, 0x66, 0x74, 0x65, 0x72,
	0x60, 0x20, 0x68, 0x65, 0x61, 0x64, 0x65, 0x72, 0x20, 0x73, 0x6f, 0x20, 0x74, 0x68, 0x61, 0x74,
	0x20, 0x74, 0x68, 0x65, 0x20, 0x63, 0x6c, 0x69, 0x65, 0x6e, 0x74, 0x20, 0x6b, 0x6e, 0x6f, 0x77,
	0x73, 0x20, 0x68, 0x6f, 0x77, 0x20, 0x6c, 0x6f, 0x6e, 0x67, 0x20, 0x74, 0x6f, 0x20, 0x77, 0x61,
	0x69, 0x74, 0x20, 0x62, 0x65, 0x66, 0x6f, 0x72, 0x65, 0x20, 0x6d, 0x61, 0x6b, 0x69, 0x6e, 0x67,
	0x20, 0x61, 0x20, 0x6e, 0x65, 0x77, 0x20, 0x72, 0x65, 0x71, 0x75, 0x65, 0x73, 0x74, 0x2e, 0x0a,
	0x2d, 0x20, 0x60, 0x35, 0x30, 0x30, 0x60, 0x3a, 0x20, 0x42, 0x6f, 0x75, 0x6e, 0x64, 0x61, 0x72,
	0x79, 0x20, 0x72, 0x65, 0x74, 0x75, 0x72, 0x6e, 0x73, 0x20, 0x60, 0x35, 0x30, 0x30, 0x60, 0x20,
	0x69, 0x66, 0x20, 0x61, 0x6e, 0x20, 0x65, 0x72, 0x72, 0x6f, 0x72, 0x20, 0x6f, 0x63, 0x63, 0x75,
	0x72, 0x72, 0x65, 0x64, 0x20, 0x74, 0x68, 0x61, 0x74, 0x20, 0x69, 0x73, 0x20, 0x6e, 0x6f, 0x74,
	0x20, 0x28, 0x64, 0x69, 0x72, 0x65, 0x63, 0x74, 0x6c, 0x79, 0x29, 0x20, 0x74, 0x69, 0x65, 0x64,
	0x20, 0x74, 0x6f, 0x20, 0x69, 0x6e, 0x76, 0x61, 0x6c, 0x69, 0x64, 0x20, 0x75, 0x73, 0x65, 0x72,
	0x20, 0x69, 0x6e, 0x70, 0x75, 0x74, 0x2e, 0x20, 0x49, 0x66, 0x20, 0x61, 0x20, 0x60, 0x35, 0x30,
	0x30, 0x60, 0x20, 0x69, 0x73, 0x20, 0x67, 0x65, 0x6e, 0x65, 0x72, 0x61, 0x74, 0x65, 0x64, 0x2c,
	0x20, 0x69, 0x6e, 0x66, 0x6f, 0x72, 0x6d, 0x61, 0x74, 0x69, 0x6f, 0x6e, 0x20, 0x61, 0x62, 0x6f,
	0x75, 0x74, 0x20, 0x74, 0x68, 0x65, 0x20, 0x65, 0x72, 0x72, 0x6f, 0x72, 0x20, 0x77, 0x69, 0x6c,
	0x6c, 0x20, 0x62, 0x65, 0x20, 0x6c, 0x6f, 0x67, 0x67, 0x65, 0x64, 0x20, 0x74, 0x6f, 0x20, 0x42,
	0x6f, 0x75, 0x6e, 0x64, 0x61, 0x72, 0x79, 0x27, 0x73, 0x20, 0x73, 0x65, 0x72, 0x76, 0x65, 0x72,
	0x20, 0x6c, 0x6f, 0x67, 0x20, 0x62, 0x75, 0x74, 0x20, 0x69, 0x73, 0x20, 0x6e, 0x6f, 0x74, 0x20,
	0x67, 0x65, 0x6e, 0x65, 0x72, 0x61, 0x6c, 0x6c, 0x79, 0x20, 0x70, 0x72, 0x6f, 0x76, 0x69, 0x64,
	0x65, 0x64, 0x20, 0x74, 0x6f, 0x20, 0x74, 0x68, 0x65, 0x20, 0x63, 0x6c, 0x69, 0x65, 0x6e, 0x74,
	0x2e, 0x0a, 0x2d, 0x20, 0x60, 0x35, 0x30, 0x33, 0x60, 0x3a, 0x20, 0x42, 0x6f, 0x75, 0x6e, 0x64,
	0x61, 0x72, 0x79, 0x20, 0x72, 0x65, 0x74, 0x75, 0x72, 0x6e, 0x73, 0x20, 0x61, 0x20, 0x60, 0x35,
	0x30, 0x33, 0x60, 0x20, 0x69, 0x66, 0x20, 0x69, 0x74, 0x20, 0x69, 0x73, 0x20, 0x75, 0x6e, 0x61,
	0x62, 0x6c, 0x65, 0x20, 0x74, 0x6f, 0x20, 0x73, 0x74, 0x6f, 0x72, 0x65, 0x20, 0x61, 0x20, 0x71,
	0x75, 0x6f, 0x74, 0x61, 0x20, 0x64, 0x75, 0x65, 0x20, 0x74, 0x6f, 0x20, 0x74, 0x68, 0x65, 0x20,
	0x41, 0x50, 0x49, 0x20, 0x72, 0x61, 0x74, 0x65, 0x20, 0x6c, 0x69, 0x6d, 0x69, 0x74, 0x20, 0x62,
	0x65, 0x69, 0x6e, 0x67, 0x20, 0x65, 0x78, 0x63, 0x65, 0x65, 0x64, 0x65, 0x64, 0x2e, 0x20, 0x49,
	0x74, 0x20, 0x69, 0x6e, 0x63, 0x6c, 0x75, 0x64, 0x65, 0x73, 0x20, 0x74, 0x68, 0x65, 0x20, 0x60,
	0x52, 0x65, 0x74, 0x72, 0x79, 0x2d, 0x41, 0x66, 0x74, 0x65, 0x72, 0x60, 0x20, 0x68, 0x65, 0x61,
	0x64, 0x65, 0x72, 0x20, 0x73, 0x6f, 0x20, 0x74, 0x68, 0x61, 0x74, 0x20, 0x74, 0x68, 0x65, 0x20,
	0x63, 0x6c, 0x69, 0x65, 0x6e, 0x74, 0x20, 0x6b, 0x6e, 0x6f, 0x77, 0x73, 0x20, 0x68, 0x6f, 0x77,
	0x20, 0x6c, 0x6f, 0x6e, 0x67, 0x20, 0x74, 0x6f, 0x20, 0x77, 0x61, 0x69, 0x74, 0x20, 0x62, 0x65,
	0x66, 0x6f, 0x72, 0x65, 0x20, 0x6d, 0x61, 0x6b, 0x69, 0x6e, 0x67, 0x20, 0x61, 0x20, 0x6e, 0x65,
	0x77, 0x20, 0x72, 0x65, 0x71, 0x75, 0x65, 0x73, 0x74, 0x2e, 0x0a, 0x23, 0x23, 0x20, 0x4c, 0x69,
	0x73, 0x74, 0x20, 0x70, 0x61, 0x67, 0x69, 0x6e, 0x61, 0x74, 0x69, 0x6f, 0x6e, 0x0a, 0x42, 0x6f,
	0x75, 0x6e, 0x64, 0x61, 0x72, 0x79, 0x20, 0x75, 0x73, 0x65, 0x73, 0x20, 0x5b, 0x41, 0x50, 0x49,
	0x20, 0x70, 0x61, 0x67, 0x69, 0x6e, 0x61, 0x74, 0x69, 0x6f, 0x6e, 0x5d, 0x28, 0x68, 0x74, 0x74,
	0x70, 0x73, 0x3a, 0x2f, 0x2f, 0x64, 0x65, 0x76, 0x65, 0x6c, 0x6f, 0x70, 0x65, 0x72, 0x2e, 0x68,
	0x61, 0x73, 0x68, 0x69, 0x63, 0x6f, 0x72, 0x70, 0x2e, 0x63, 0x6f, 0x6d, 0x2f, 0x62, 0x6f, 0x75,
	0x6e, 0x64, 0x61, 0x72, 0x79, 0x2f, 0x64, 0x6f, 0x63, 0x73, 0x2f, 0x61, 0x70, 0x69, 0x2d, 0x63,
	0x6c, 0x69, 0x65, 0x6e, 0x74, 0x73, 0x2f, 0x61, 0x70, 0x69, 0x2f, 0x70, 0x61, 0x67, 0x69, 0x6e,
	0x61, 0x74, 0x69, 0x6f, 0x6e, 0x29, 0x20, 0x74, 0x6f, 0x20, 0x73, 0x75, 0x70, 0x70, 0x6f, 0x72,
	0x74, 0x20, 0x73, 0x65, 0x61, 0x72, 0x63, 0x68, 0x69, 0x6e, 0x67, 0x20, 0x61, 0x6e, 0x64, 0x20,
	0x66, 0x69, 0x6c, 0x74, 0x65, 0x72, 0x69, 0x6e, 0x67, 0x20, 0x6c, 0x61, 0x72, 0x67, 0x65, 0x20,
	0x6c, 0x69, 0x73, 0x74, 0x73, 0x20, 0x6f, 0x66, 0x20, 0x72, 0x65, 0x73, 0x75, 0x6c, 0x74, 0x73,
	0x20, 0x65, 0x66, 0x66, 0x69, 0x63, 0x69, 0x65, 0x6e, 0x74, 0x6c, 0x79, 0x2e, 0x22, 0x35, 0x0a,
	0x12, 0x48, 0x61, 0x73, 0x68, 0x69, 0x43, 0x6f, 0x72, 0x70, 0x20, 0x42, 0x6f, 0x75, 0x6e, 0x64,
	0x61, 0x72, 0x79, 0x12, 0x1f, 0x68, 0x74, 0x74, 0x70, 0x73, 0x3a, 0x2f, 0x2f, 0x77, 0x77, 0x77,
	0x2e, 0x62, 0x6f, 0x75, 0x6e, 0x64, 0x61, 0x72, 0x79, 0x70, 0x72, 0x6f, 0x6a, 0x65, 0x63, 0x74,
	0x2e, 0x69, 0x6f, 0x2f, 0x2a, 0x56, 0x0a, 0x1b, 0x42, 0x75, 0x73, 0x69, 0x6e, 0x65, 0x73, 0x73,
	0x20, 0x53, 0x6f, 0x75, 0x72, 0x63, 0x65, 0x20, 0x4c, 0x69, 0x63, 0x65, 0x6e, 0x73, 0x65, 0x20,
	0x31, 0x2e, 0x31, 0x12, 0x37, 0x68, 0x74, 0x74, 0x70, 0x73, 0x3a, 0x2f, 0x2f, 0x67, 0x69, 0x74,
	0x68, 0x75, 0x62, 0x2e, 0x63, 0x6f, 0x6d, 0x2f, 0x68, 0x61, 0x73, 0x68, 0x69, 0x63, 0x6f, 0x72,
	0x70, 0x2f, 0x62, 0x6f, 0x75, 0x6e, 0x64, 0x61, 0x72, 0x79, 0x2f, 0x62, 0x6c, 0x6f, 0x62, 0x2f,
	0x6d, 0x61, 0x69, 0x6e, 0x2f, 0x4c, 0x49, 0x43, 0x45, 0x4e, 0x53, 0x45, 0x32, 0x13, 0x70, 0x6c,
	0x61, 0x63, 0x65, 0x68, 0x6f, 0x6c, 0x64, 0x65, 0x72, 0x2d, 0x76, 0x65, 0x72, 0x73, 0x69, 0x6f,
	0x6e, 0x1a, 0x1a, 0x79, 0x6f, 0x75, 0x72, 0x2d, 0x62, 0x6f, 0x75, 0x6e, 0x64, 0x61, 0x72, 0x79,
	0x2d, 0x68, 0x6f, 0x73, 0x74, 0x6e, 0x61, 0x6d, 0x65, 0x2e, 0x63, 0x6f, 0x6d, 0x2a, 0x02, 0x02,
	0x01, 0x32, 0x10, 0x61, 0x70, 0x70, 0x6c, 0x69, 0x63, 0x61, 0x74, 0x69, 0x6f, 0x6e, 0x2f, 0x6a,
	0x73, 0x6f, 0x6e, 0x3a, 0x10, 0x61, 0x70, 0x70, 0x6c, 0x69, 0x63, 0x61, 0x74, 0x69, 0x6f, 0x6e,
	0x2f, 0x6a, 0x73, 0x6f, 0x6e, 0x52, 0x63, 0x0a, 0x07, 0x64, 0x65, 0x66, 0x61, 0x75, 0x6c, 0x74,
	0x12, 0x58, 0x0a, 0x38, 0x52, 0x65, 0x74, 0x75, 0x72, 0x6e, 0x65, 0x64, 0x20, 0x77, 0x68, 0x65,
	0x6e, 0x20, 0x74, 0x68, 0x65, 0x72, 0x65, 0x20, 0x77, 0x61, 0x73, 0x20, 0x61, 0x6e, 0x20, 0x65,
	0x72, 0x72, 0x6f, 0x72, 0x20, 0x70, 0x72, 0x6f, 0x63, 0x65, 0x73, 0x73, 0x69, 0x6e, 0x67, 0x20,
	0x74, 0x68, 0x65, 0x20, 0x72, 0x65, 0x71, 0x75, 0x65, 0x73, 0x74, 0x2e, 0x12, 0x1c, 0x0a, 0x1a,
	0x1a, 0x18, 0x2e, 0x63, 0x6f, 0x6e, 0x74, 0x72, 0x6f, 0x6c, 0x6c, 0x65, 0x72, 0x2e, 0x61, 0x70,
	0x69, 0x2e, 0x76, 0x31, 0x2e, 0x45, 0x72, 0x72, 0x6f, 0x72, 0x5a, 0x23, 0x0a, 0x21, 0x0a, 0x0a,
	0x41, 0x70, 0x69, 0x4b, 0x65, 0x79, 0x41, 0x75, 0x74, 0x68, 0x12, 0x13, 0x08, 0x02, 0x1a, 0x0d,
	0x41, 0x75, 0x74, 0x68, 0x6f, 0x72, 0x69, 0x7a, 0x61, 0x74, 0x69, 0x6f, 0x6e, 0x20, 0x02, 0x62,
	0x10, 0x0a, 0x0e, 0x0a, 0x0a, 0x41, 0x70, 0x69, 0x4b, 0x65, 0x79, 0x41, 0x75, 0x74, 0x68, 0x12,
	0x00, 0x72, 0x3e, 0x0a, 0x0d, 0x42, 0x6f, 0x75, 0x6e, 0x64, 0x61, 0x72, 0x79, 0x20, 0x44, 0x6f,
	0x63, 0x73, 0x12, 0x2d, 0x68, 0x74, 0x74, 0x70, 0x73, 0x3a, 0x2f, 0x2f, 0x64, 0x65, 0x76, 0x65,
	0x6c, 0x6f, 0x70, 0x65, 0x72, 0x2e, 0x68, 0x61, 0x73, 0x68, 0x69, 0x63, 0x6f, 0x72, 0x70, 0x2e,
	0x63, 0x6f, 0x6d, 0x2f, 0x62, 0x6f, 0x75, 0x6e, 0x64, 0x61, 0x72, 0x79, 0x2f, 0x64, 0x6f, 0x63,
	0x73, 0x5a, 0x4b, 0x67, 0x69, 0x74, 0x68, 0x75, 0x62, 0x2e, 0x63, 0x6f, 0x6d, 0x2f, 0x68, 0x61,
	0x73, 0x68, 0x69, 0x63, 0x6f, 0x72, 0x70, 0x2f, 0x62, 0x6f, 0x75, 0x6e, 0x64, 0x61, 0x72, 0x79,
	0x2f, 0x69, 0x6e, 0x74, 0x65, 0x72, 0x6e, 0x61, 0x6c, 0x2f, 0x67, 0x65, 0x6e, 0x2f, 0x63, 0x6f,
	0x6e, 0x74, 0x72, 0x6f, 0x6c, 0x6c, 0x65, 0x72, 0x2f, 0x61, 0x70, 0x69, 0x2f, 0x73, 0x65, 0x72,
	0x76, 0x69, 0x63, 0x65, 0x73, 0x3b, 0x73, 0x65, 0x72, 0x76, 0x69, 0x63, 0x65, 0x73, 0x62, 0x06,
	0x70, 0x72, 0x6f, 0x74, 0x6f, 0x33,
}

var file_controller_api_services_v1_doc_proto_goTypes = []interface{}{}
var file_controller_api_services_v1_doc_proto_depIdxs = []int32{
	0, // [0:0] is the sub-list for method output_type
	0, // [0:0] is the sub-list for method input_type
	0, // [0:0] is the sub-list for extension type_name
	0, // [0:0] is the sub-list for extension extendee
	0, // [0:0] is the sub-list for field type_name
}

func init() { file_controller_api_services_v1_doc_proto_init() }
func file_controller_api_services_v1_doc_proto_init() {
	if File_controller_api_services_v1_doc_proto != nil {
		return
	}
	type x struct{}
	out := protoimpl.TypeBuilder{
		File: protoimpl.DescBuilder{
			GoPackagePath: reflect.TypeOf(x{}).PkgPath(),
			RawDescriptor: file_controller_api_services_v1_doc_proto_rawDesc,
			NumEnums:      0,
			NumMessages:   0,
			NumExtensions: 0,
			NumServices:   0,
		},
		GoTypes:           file_controller_api_services_v1_doc_proto_goTypes,
		DependencyIndexes: file_controller_api_services_v1_doc_proto_depIdxs,
	}.Build()
	File_controller_api_services_v1_doc_proto = out.File
	file_controller_api_services_v1_doc_proto_rawDesc = nil
	file_controller_api_services_v1_doc_proto_goTypes = nil
	file_controller_api_services_v1_doc_proto_depIdxs = nil
}
