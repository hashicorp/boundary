// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: BUSL-1.1

// Code generated by protoc-gen-go. DO NOT EDIT.
// versions:
// 	protoc-gen-go v1.36.1
// 	protoc        (unknown)
// source: controller/storage/db/db_test/v1/db_test.proto

// define a test proto package for the internal/db package.  These protos
// are only used for unit tests and are not part of the rest of the boundary
// domain model

package db_test

import (
	timestamp "github.com/hashicorp/boundary/internal/db/timestamp"
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

// TestUser for gorm test user model
type StoreTestUser struct {
	state protoimpl.MessageState `protogen:"open.v1"`
	// @inject_tag: gorm:"primary_key"
	Id uint32 `protobuf:"varint,1,opt,name=id,proto3" json:"id,omitempty" gorm:"primary_key"`
	// create_time from the RDBMS
	// @inject_tag: `gorm:"default:CURRENT_TIMESTAMP"`
	CreateTime *timestamp.Timestamp `protobuf:"bytes,2,opt,name=create_time,json=createTime,proto3" json:"create_time,omitempty" gorm:"default:CURRENT_TIMESTAMP"`
	// update_time from the RDBMS
	// @inject_tag: `gorm:"default:CURRENT_TIMESTAMP"`
	UpdateTime *timestamp.Timestamp `protobuf:"bytes,3,opt,name=update_time,json=updateTime,proto3" json:"update_time,omitempty" gorm:"default:CURRENT_TIMESTAMP"`
	// public_id is the used to access the user via an API
	PublicId string `protobuf:"bytes,4,opt,name=public_id,json=publicId,proto3" json:"public_id,omitempty"`
	// name is the optional friendly name used to
	// access the user via an API
	// @inject_tag: `gorm:"default:null"`
	Name string `protobuf:"bytes,5,opt,name=name,proto3" json:"name,omitempty" gorm:"default:null"`
	// @inject_tag: `gorm:"default:null"`
	PhoneNumber string `protobuf:"bytes,6,opt,name=phone_number,json=phoneNumber,proto3" json:"phone_number,omitempty" gorm:"default:null"`
	// @inject_tag: `gorm:"default:null"`
	Email string `protobuf:"bytes,7,opt,name=email,proto3" json:"email,omitempty" gorm:"default:null"`
	// @inject_tag: `gorm:"default:null"`
	Version       uint32 `protobuf:"varint,8,opt,name=version,proto3" json:"version,omitempty" gorm:"default:null"`
	unknownFields protoimpl.UnknownFields
	sizeCache     protoimpl.SizeCache
}

func (x *StoreTestUser) Reset() {
	*x = StoreTestUser{}
	mi := &file_controller_storage_db_db_test_v1_db_test_proto_msgTypes[0]
	ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
	ms.StoreMessageInfo(mi)
}

func (x *StoreTestUser) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*StoreTestUser) ProtoMessage() {}

func (x *StoreTestUser) ProtoReflect() protoreflect.Message {
	mi := &file_controller_storage_db_db_test_v1_db_test_proto_msgTypes[0]
	if x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use StoreTestUser.ProtoReflect.Descriptor instead.
func (*StoreTestUser) Descriptor() ([]byte, []int) {
	return file_controller_storage_db_db_test_v1_db_test_proto_rawDescGZIP(), []int{0}
}

func (x *StoreTestUser) GetId() uint32 {
	if x != nil {
		return x.Id
	}
	return 0
}

func (x *StoreTestUser) GetCreateTime() *timestamp.Timestamp {
	if x != nil {
		return x.CreateTime
	}
	return nil
}

func (x *StoreTestUser) GetUpdateTime() *timestamp.Timestamp {
	if x != nil {
		return x.UpdateTime
	}
	return nil
}

func (x *StoreTestUser) GetPublicId() string {
	if x != nil {
		return x.PublicId
	}
	return ""
}

func (x *StoreTestUser) GetName() string {
	if x != nil {
		return x.Name
	}
	return ""
}

func (x *StoreTestUser) GetPhoneNumber() string {
	if x != nil {
		return x.PhoneNumber
	}
	return ""
}

func (x *StoreTestUser) GetEmail() string {
	if x != nil {
		return x.Email
	}
	return ""
}

func (x *StoreTestUser) GetVersion() uint32 {
	if x != nil {
		return x.Version
	}
	return 0
}

// TestCar for gorm test car model
type StoreTestCar struct {
	state protoimpl.MessageState `protogen:"open.v1"`
	// @inject_tag: gorm:"primary_key"
	Id uint32 `protobuf:"varint,1,opt,name=id,proto3" json:"id,omitempty" gorm:"primary_key"`
	// create_time from the RDBMS
	// @inject_tag: `gorm:"default:CURRENT_TIMESTAMP"`
	CreateTime *timestamp.Timestamp `protobuf:"bytes,2,opt,name=create_time,json=createTime,proto3" json:"create_time,omitempty" gorm:"default:CURRENT_TIMESTAMP"`
	// update_time from the RDBMS
	// @inject_tag: `gorm:"default:CURRENT_TIMESTAMP"`
	UpdateTime *timestamp.Timestamp `protobuf:"bytes,3,opt,name=update_time,json=updateTime,proto3" json:"update_time,omitempty" gorm:"default:CURRENT_TIMESTAMP"`
	// public_id is the used to access the car via an API
	PublicId string `protobuf:"bytes,4,opt,name=public_id,json=publicId,proto3" json:"public_id,omitempty"`
	// name is the optional friendly name used to
	// access the Scope via an API
	// @inject_tag: `gorm:"default:null"`
	Name string `protobuf:"bytes,5,opt,name=name,proto3" json:"name,omitempty" gorm:"default:null"`
	// @inject_tag: `gorm:"default:null"`
	Model string `protobuf:"bytes,6,opt,name=model,proto3" json:"model,omitempty" gorm:"default:null"`
	// @inject_tag: `gorm:"default:null"`
	Mpg           int32 `protobuf:"varint,7,opt,name=mpg,proto3" json:"mpg,omitempty" gorm:"default:null"`
	unknownFields protoimpl.UnknownFields
	sizeCache     protoimpl.SizeCache
}

func (x *StoreTestCar) Reset() {
	*x = StoreTestCar{}
	mi := &file_controller_storage_db_db_test_v1_db_test_proto_msgTypes[1]
	ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
	ms.StoreMessageInfo(mi)
}

func (x *StoreTestCar) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*StoreTestCar) ProtoMessage() {}

func (x *StoreTestCar) ProtoReflect() protoreflect.Message {
	mi := &file_controller_storage_db_db_test_v1_db_test_proto_msgTypes[1]
	if x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use StoreTestCar.ProtoReflect.Descriptor instead.
func (*StoreTestCar) Descriptor() ([]byte, []int) {
	return file_controller_storage_db_db_test_v1_db_test_proto_rawDescGZIP(), []int{1}
}

func (x *StoreTestCar) GetId() uint32 {
	if x != nil {
		return x.Id
	}
	return 0
}

func (x *StoreTestCar) GetCreateTime() *timestamp.Timestamp {
	if x != nil {
		return x.CreateTime
	}
	return nil
}

func (x *StoreTestCar) GetUpdateTime() *timestamp.Timestamp {
	if x != nil {
		return x.UpdateTime
	}
	return nil
}

func (x *StoreTestCar) GetPublicId() string {
	if x != nil {
		return x.PublicId
	}
	return ""
}

func (x *StoreTestCar) GetName() string {
	if x != nil {
		return x.Name
	}
	return ""
}

func (x *StoreTestCar) GetModel() string {
	if x != nil {
		return x.Model
	}
	return ""
}

func (x *StoreTestCar) GetMpg() int32 {
	if x != nil {
		return x.Mpg
	}
	return 0
}

// TestRental for gorm test rental model
type StoreTestRental struct {
	state protoimpl.MessageState `protogen:"open.v1"`
	// @inject_tag: gorm:"primary_key"
	Id uint32 `protobuf:"varint,1,opt,name=id,proto3" json:"id,omitempty" gorm:"primary_key"`
	// create_time from the RDBMS
	// @inject_tag: `gorm:"default:CURRENT_TIMESTAMP"`
	CreateTime *timestamp.Timestamp `protobuf:"bytes,2,opt,name=create_time,json=createTime,proto3" json:"create_time,omitempty" gorm:"default:CURRENT_TIMESTAMP"`
	// update_time from the RDBMS
	// @inject_tag: `gorm:"default:CURRENT_TIMESTAMP"`
	UpdateTime *timestamp.Timestamp `protobuf:"bytes,3,opt,name=update_time,json=updateTime,proto3" json:"update_time,omitempty" gorm:"default:CURRENT_TIMESTAMP"`
	// public_id is the used to access the rental via an API
	PublicId string `protobuf:"bytes,4,opt,name=public_id,json=publicId,proto3" json:"public_id,omitempty"`
	// name is the optional friendly name used to
	// access the rental via an API
	// @inject_tag: `gorm:"default:null"`
	Name string `protobuf:"bytes,5,opt,name=name,proto3" json:"name,omitempty" gorm:"default:null"`
	// @inject_tag: `gorm:"default:null"`
	UserId uint32 `protobuf:"varint,6,opt,name=user_id,json=userId,proto3" json:"user_id,omitempty" gorm:"default:null"`
	// @inject_tag: `gorm:"default:null"`
	CarId         uint32 `protobuf:"varint,7,opt,name=car_id,json=carId,proto3" json:"car_id,omitempty" gorm:"default:null"`
	unknownFields protoimpl.UnknownFields
	sizeCache     protoimpl.SizeCache
}

func (x *StoreTestRental) Reset() {
	*x = StoreTestRental{}
	mi := &file_controller_storage_db_db_test_v1_db_test_proto_msgTypes[2]
	ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
	ms.StoreMessageInfo(mi)
}

func (x *StoreTestRental) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*StoreTestRental) ProtoMessage() {}

func (x *StoreTestRental) ProtoReflect() protoreflect.Message {
	mi := &file_controller_storage_db_db_test_v1_db_test_proto_msgTypes[2]
	if x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use StoreTestRental.ProtoReflect.Descriptor instead.
func (*StoreTestRental) Descriptor() ([]byte, []int) {
	return file_controller_storage_db_db_test_v1_db_test_proto_rawDescGZIP(), []int{2}
}

func (x *StoreTestRental) GetId() uint32 {
	if x != nil {
		return x.Id
	}
	return 0
}

func (x *StoreTestRental) GetCreateTime() *timestamp.Timestamp {
	if x != nil {
		return x.CreateTime
	}
	return nil
}

func (x *StoreTestRental) GetUpdateTime() *timestamp.Timestamp {
	if x != nil {
		return x.UpdateTime
	}
	return nil
}

func (x *StoreTestRental) GetPublicId() string {
	if x != nil {
		return x.PublicId
	}
	return ""
}

func (x *StoreTestRental) GetName() string {
	if x != nil {
		return x.Name
	}
	return ""
}

func (x *StoreTestRental) GetUserId() uint32 {
	if x != nil {
		return x.UserId
	}
	return 0
}

func (x *StoreTestRental) GetCarId() uint32 {
	if x != nil {
		return x.CarId
	}
	return 0
}

// StoreTestScooter used in the db tests only and provides a gorm resource with
// a private id.
type StoreTestScooter struct {
	state protoimpl.MessageState `protogen:"open.v1"`
	// @inject_tag: gorm:"primary_key"
	Id uint32 `protobuf:"varint,1,opt,name=id,proto3" json:"id,omitempty" gorm:"primary_key"`
	// create_time from the RDBMS
	// @inject_tag: `gorm:"default:CURRENT_TIMESTAMP"`
	CreateTime *timestamp.Timestamp `protobuf:"bytes,2,opt,name=create_time,json=createTime,proto3" json:"create_time,omitempty" gorm:"default:CURRENT_TIMESTAMP"`
	// update_time from the RDBMS
	// @inject_tag: `gorm:"default:CURRENT_TIMESTAMP"`
	UpdateTime *timestamp.Timestamp `protobuf:"bytes,3,opt,name=update_time,json=updateTime,proto3" json:"update_time,omitempty" gorm:"default:CURRENT_TIMESTAMP"`
	// private_id is the used to access scooter, but not intended to be available
	// via the API
	PrivateId string `protobuf:"bytes,4,opt,name=private_id,json=privateId,proto3" json:"private_id,omitempty"`
	// @inject_tag: `gorm:"default:null"`
	Model string `protobuf:"bytes,6,opt,name=model,proto3" json:"model,omitempty" gorm:"default:null"`
	// @inject_tag: `gorm:"default:null"`
	Mpg           int32 `protobuf:"varint,7,opt,name=mpg,proto3" json:"mpg,omitempty" gorm:"default:null"`
	unknownFields protoimpl.UnknownFields
	sizeCache     protoimpl.SizeCache
}

func (x *StoreTestScooter) Reset() {
	*x = StoreTestScooter{}
	mi := &file_controller_storage_db_db_test_v1_db_test_proto_msgTypes[3]
	ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
	ms.StoreMessageInfo(mi)
}

func (x *StoreTestScooter) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*StoreTestScooter) ProtoMessage() {}

func (x *StoreTestScooter) ProtoReflect() protoreflect.Message {
	mi := &file_controller_storage_db_db_test_v1_db_test_proto_msgTypes[3]
	if x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use StoreTestScooter.ProtoReflect.Descriptor instead.
func (*StoreTestScooter) Descriptor() ([]byte, []int) {
	return file_controller_storage_db_db_test_v1_db_test_proto_rawDescGZIP(), []int{3}
}

func (x *StoreTestScooter) GetId() uint32 {
	if x != nil {
		return x.Id
	}
	return 0
}

func (x *StoreTestScooter) GetCreateTime() *timestamp.Timestamp {
	if x != nil {
		return x.CreateTime
	}
	return nil
}

func (x *StoreTestScooter) GetUpdateTime() *timestamp.Timestamp {
	if x != nil {
		return x.UpdateTime
	}
	return nil
}

func (x *StoreTestScooter) GetPrivateId() string {
	if x != nil {
		return x.PrivateId
	}
	return ""
}

func (x *StoreTestScooter) GetModel() string {
	if x != nil {
		return x.Model
	}
	return ""
}

func (x *StoreTestScooter) GetMpg() int32 {
	if x != nil {
		return x.Mpg
	}
	return 0
}

// StoreTestAccessory used in the db tests only and provides a gorm resource with
// an id that's not a private or public id
type StoreTestAccessory struct {
	state protoimpl.MessageState `protogen:"open.v1"`
	// @inject_tag: gorm:"primary_key"
	AccessoryId uint32 `protobuf:"varint,1,opt,name=accessory_id,json=accessoryId,proto3" json:"accessory_id,omitempty" gorm:"primary_key"`
	// @inject_tag: `gorm:"default:not_null"`
	Description   string `protobuf:"bytes,2,opt,name=description,proto3" json:"description,omitempty" gorm:"default:not_null"`
	unknownFields protoimpl.UnknownFields
	sizeCache     protoimpl.SizeCache
}

func (x *StoreTestAccessory) Reset() {
	*x = StoreTestAccessory{}
	mi := &file_controller_storage_db_db_test_v1_db_test_proto_msgTypes[4]
	ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
	ms.StoreMessageInfo(mi)
}

func (x *StoreTestAccessory) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*StoreTestAccessory) ProtoMessage() {}

func (x *StoreTestAccessory) ProtoReflect() protoreflect.Message {
	mi := &file_controller_storage_db_db_test_v1_db_test_proto_msgTypes[4]
	if x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use StoreTestAccessory.ProtoReflect.Descriptor instead.
func (*StoreTestAccessory) Descriptor() ([]byte, []int) {
	return file_controller_storage_db_db_test_v1_db_test_proto_rawDescGZIP(), []int{4}
}

func (x *StoreTestAccessory) GetAccessoryId() uint32 {
	if x != nil {
		return x.AccessoryId
	}
	return 0
}

func (x *StoreTestAccessory) GetDescription() string {
	if x != nil {
		return x.Description
	}
	return ""
}

// StoreTestScooterAccessory used in the db tests only and provides a gorm
// resource with multiple pks
type StoreTestScooterAccessory struct {
	state protoimpl.MessageState `protogen:"open.v1"`
	// @inject_tag: gorm:"primary_key"
	AccessoryId uint32 `protobuf:"varint,1,opt,name=accessory_id,json=accessoryId,proto3" json:"accessory_id,omitempty" gorm:"primary_key"`
	// @inject_tag: gorm:"primary_key"
	ScooterId uint32 `protobuf:"varint,2,opt,name=scooter_id,json=scooterId,proto3" json:"scooter_id,omitempty" gorm:"primary_key"`
	// @inject_tag: `gorm:"default:null"`
	Review        string `protobuf:"bytes,3,opt,name=review,proto3" json:"review,omitempty" gorm:"default:null"`
	unknownFields protoimpl.UnknownFields
	sizeCache     protoimpl.SizeCache
}

func (x *StoreTestScooterAccessory) Reset() {
	*x = StoreTestScooterAccessory{}
	mi := &file_controller_storage_db_db_test_v1_db_test_proto_msgTypes[5]
	ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
	ms.StoreMessageInfo(mi)
}

func (x *StoreTestScooterAccessory) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*StoreTestScooterAccessory) ProtoMessage() {}

func (x *StoreTestScooterAccessory) ProtoReflect() protoreflect.Message {
	mi := &file_controller_storage_db_db_test_v1_db_test_proto_msgTypes[5]
	if x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use StoreTestScooterAccessory.ProtoReflect.Descriptor instead.
func (*StoreTestScooterAccessory) Descriptor() ([]byte, []int) {
	return file_controller_storage_db_db_test_v1_db_test_proto_rawDescGZIP(), []int{5}
}

func (x *StoreTestScooterAccessory) GetAccessoryId() uint32 {
	if x != nil {
		return x.AccessoryId
	}
	return 0
}

func (x *StoreTestScooterAccessory) GetScooterId() uint32 {
	if x != nil {
		return x.ScooterId
	}
	return 0
}

func (x *StoreTestScooterAccessory) GetReview() string {
	if x != nil {
		return x.Review
	}
	return ""
}

var File_controller_storage_db_db_test_v1_db_test_proto protoreflect.FileDescriptor

var file_controller_storage_db_db_test_v1_db_test_proto_rawDesc = []byte{
	0x0a, 0x2e, 0x63, 0x6f, 0x6e, 0x74, 0x72, 0x6f, 0x6c, 0x6c, 0x65, 0x72, 0x2f, 0x73, 0x74, 0x6f,
	0x72, 0x61, 0x67, 0x65, 0x2f, 0x64, 0x62, 0x2f, 0x64, 0x62, 0x5f, 0x74, 0x65, 0x73, 0x74, 0x2f,
	0x76, 0x31, 0x2f, 0x64, 0x62, 0x5f, 0x74, 0x65, 0x73, 0x74, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f,
	0x12, 0x20, 0x63, 0x6f, 0x6e, 0x74, 0x72, 0x6f, 0x6c, 0x6c, 0x65, 0x72, 0x2e, 0x73, 0x74, 0x6f,
	0x72, 0x61, 0x67, 0x65, 0x2e, 0x64, 0x62, 0x2e, 0x64, 0x62, 0x5f, 0x74, 0x65, 0x73, 0x74, 0x2e,
	0x76, 0x31, 0x1a, 0x2f, 0x63, 0x6f, 0x6e, 0x74, 0x72, 0x6f, 0x6c, 0x6c, 0x65, 0x72, 0x2f, 0x73,
	0x74, 0x6f, 0x72, 0x61, 0x67, 0x65, 0x2f, 0x74, 0x69, 0x6d, 0x65, 0x73, 0x74, 0x61, 0x6d, 0x70,
	0x2f, 0x76, 0x31, 0x2f, 0x74, 0x69, 0x6d, 0x65, 0x73, 0x74, 0x61, 0x6d, 0x70, 0x2e, 0x70, 0x72,
	0x6f, 0x74, 0x6f, 0x22, 0xbd, 0x02, 0x0a, 0x0d, 0x53, 0x74, 0x6f, 0x72, 0x65, 0x54, 0x65, 0x73,
	0x74, 0x55, 0x73, 0x65, 0x72, 0x12, 0x0e, 0x0a, 0x02, 0x69, 0x64, 0x18, 0x01, 0x20, 0x01, 0x28,
	0x0d, 0x52, 0x02, 0x69, 0x64, 0x12, 0x4b, 0x0a, 0x0b, 0x63, 0x72, 0x65, 0x61, 0x74, 0x65, 0x5f,
	0x74, 0x69, 0x6d, 0x65, 0x18, 0x02, 0x20, 0x01, 0x28, 0x0b, 0x32, 0x2a, 0x2e, 0x63, 0x6f, 0x6e,
	0x74, 0x72, 0x6f, 0x6c, 0x6c, 0x65, 0x72, 0x2e, 0x73, 0x74, 0x6f, 0x72, 0x61, 0x67, 0x65, 0x2e,
	0x74, 0x69, 0x6d, 0x65, 0x73, 0x74, 0x61, 0x6d, 0x70, 0x2e, 0x76, 0x31, 0x2e, 0x54, 0x69, 0x6d,
	0x65, 0x73, 0x74, 0x61, 0x6d, 0x70, 0x52, 0x0a, 0x63, 0x72, 0x65, 0x61, 0x74, 0x65, 0x54, 0x69,
	0x6d, 0x65, 0x12, 0x4b, 0x0a, 0x0b, 0x75, 0x70, 0x64, 0x61, 0x74, 0x65, 0x5f, 0x74, 0x69, 0x6d,
	0x65, 0x18, 0x03, 0x20, 0x01, 0x28, 0x0b, 0x32, 0x2a, 0x2e, 0x63, 0x6f, 0x6e, 0x74, 0x72, 0x6f,
	0x6c, 0x6c, 0x65, 0x72, 0x2e, 0x73, 0x74, 0x6f, 0x72, 0x61, 0x67, 0x65, 0x2e, 0x74, 0x69, 0x6d,
	0x65, 0x73, 0x74, 0x61, 0x6d, 0x70, 0x2e, 0x76, 0x31, 0x2e, 0x54, 0x69, 0x6d, 0x65, 0x73, 0x74,
	0x61, 0x6d, 0x70, 0x52, 0x0a, 0x75, 0x70, 0x64, 0x61, 0x74, 0x65, 0x54, 0x69, 0x6d, 0x65, 0x12,
	0x1b, 0x0a, 0x09, 0x70, 0x75, 0x62, 0x6c, 0x69, 0x63, 0x5f, 0x69, 0x64, 0x18, 0x04, 0x20, 0x01,
	0x28, 0x09, 0x52, 0x08, 0x70, 0x75, 0x62, 0x6c, 0x69, 0x63, 0x49, 0x64, 0x12, 0x12, 0x0a, 0x04,
	0x6e, 0x61, 0x6d, 0x65, 0x18, 0x05, 0x20, 0x01, 0x28, 0x09, 0x52, 0x04, 0x6e, 0x61, 0x6d, 0x65,
	0x12, 0x21, 0x0a, 0x0c, 0x70, 0x68, 0x6f, 0x6e, 0x65, 0x5f, 0x6e, 0x75, 0x6d, 0x62, 0x65, 0x72,
	0x18, 0x06, 0x20, 0x01, 0x28, 0x09, 0x52, 0x0b, 0x70, 0x68, 0x6f, 0x6e, 0x65, 0x4e, 0x75, 0x6d,
	0x62, 0x65, 0x72, 0x12, 0x14, 0x0a, 0x05, 0x65, 0x6d, 0x61, 0x69, 0x6c, 0x18, 0x07, 0x20, 0x01,
	0x28, 0x09, 0x52, 0x05, 0x65, 0x6d, 0x61, 0x69, 0x6c, 0x12, 0x18, 0x0a, 0x07, 0x76, 0x65, 0x72,
	0x73, 0x69, 0x6f, 0x6e, 0x18, 0x08, 0x20, 0x01, 0x28, 0x0d, 0x52, 0x07, 0x76, 0x65, 0x72, 0x73,
	0x69, 0x6f, 0x6e, 0x22, 0x91, 0x02, 0x0a, 0x0c, 0x53, 0x74, 0x6f, 0x72, 0x65, 0x54, 0x65, 0x73,
	0x74, 0x43, 0x61, 0x72, 0x12, 0x0e, 0x0a, 0x02, 0x69, 0x64, 0x18, 0x01, 0x20, 0x01, 0x28, 0x0d,
	0x52, 0x02, 0x69, 0x64, 0x12, 0x4b, 0x0a, 0x0b, 0x63, 0x72, 0x65, 0x61, 0x74, 0x65, 0x5f, 0x74,
	0x69, 0x6d, 0x65, 0x18, 0x02, 0x20, 0x01, 0x28, 0x0b, 0x32, 0x2a, 0x2e, 0x63, 0x6f, 0x6e, 0x74,
	0x72, 0x6f, 0x6c, 0x6c, 0x65, 0x72, 0x2e, 0x73, 0x74, 0x6f, 0x72, 0x61, 0x67, 0x65, 0x2e, 0x74,
	0x69, 0x6d, 0x65, 0x73, 0x74, 0x61, 0x6d, 0x70, 0x2e, 0x76, 0x31, 0x2e, 0x54, 0x69, 0x6d, 0x65,
	0x73, 0x74, 0x61, 0x6d, 0x70, 0x52, 0x0a, 0x63, 0x72, 0x65, 0x61, 0x74, 0x65, 0x54, 0x69, 0x6d,
	0x65, 0x12, 0x4b, 0x0a, 0x0b, 0x75, 0x70, 0x64, 0x61, 0x74, 0x65, 0x5f, 0x74, 0x69, 0x6d, 0x65,
	0x18, 0x03, 0x20, 0x01, 0x28, 0x0b, 0x32, 0x2a, 0x2e, 0x63, 0x6f, 0x6e, 0x74, 0x72, 0x6f, 0x6c,
	0x6c, 0x65, 0x72, 0x2e, 0x73, 0x74, 0x6f, 0x72, 0x61, 0x67, 0x65, 0x2e, 0x74, 0x69, 0x6d, 0x65,
	0x73, 0x74, 0x61, 0x6d, 0x70, 0x2e, 0x76, 0x31, 0x2e, 0x54, 0x69, 0x6d, 0x65, 0x73, 0x74, 0x61,
	0x6d, 0x70, 0x52, 0x0a, 0x75, 0x70, 0x64, 0x61, 0x74, 0x65, 0x54, 0x69, 0x6d, 0x65, 0x12, 0x1b,
	0x0a, 0x09, 0x70, 0x75, 0x62, 0x6c, 0x69, 0x63, 0x5f, 0x69, 0x64, 0x18, 0x04, 0x20, 0x01, 0x28,
	0x09, 0x52, 0x08, 0x70, 0x75, 0x62, 0x6c, 0x69, 0x63, 0x49, 0x64, 0x12, 0x12, 0x0a, 0x04, 0x6e,
	0x61, 0x6d, 0x65, 0x18, 0x05, 0x20, 0x01, 0x28, 0x09, 0x52, 0x04, 0x6e, 0x61, 0x6d, 0x65, 0x12,
	0x14, 0x0a, 0x05, 0x6d, 0x6f, 0x64, 0x65, 0x6c, 0x18, 0x06, 0x20, 0x01, 0x28, 0x09, 0x52, 0x05,
	0x6d, 0x6f, 0x64, 0x65, 0x6c, 0x12, 0x10, 0x0a, 0x03, 0x6d, 0x70, 0x67, 0x18, 0x07, 0x20, 0x01,
	0x28, 0x05, 0x52, 0x03, 0x6d, 0x70, 0x67, 0x22, 0x9c, 0x02, 0x0a, 0x0f, 0x53, 0x74, 0x6f, 0x72,
	0x65, 0x54, 0x65, 0x73, 0x74, 0x52, 0x65, 0x6e, 0x74, 0x61, 0x6c, 0x12, 0x0e, 0x0a, 0x02, 0x69,
	0x64, 0x18, 0x01, 0x20, 0x01, 0x28, 0x0d, 0x52, 0x02, 0x69, 0x64, 0x12, 0x4b, 0x0a, 0x0b, 0x63,
	0x72, 0x65, 0x61, 0x74, 0x65, 0x5f, 0x74, 0x69, 0x6d, 0x65, 0x18, 0x02, 0x20, 0x01, 0x28, 0x0b,
	0x32, 0x2a, 0x2e, 0x63, 0x6f, 0x6e, 0x74, 0x72, 0x6f, 0x6c, 0x6c, 0x65, 0x72, 0x2e, 0x73, 0x74,
	0x6f, 0x72, 0x61, 0x67, 0x65, 0x2e, 0x74, 0x69, 0x6d, 0x65, 0x73, 0x74, 0x61, 0x6d, 0x70, 0x2e,
	0x76, 0x31, 0x2e, 0x54, 0x69, 0x6d, 0x65, 0x73, 0x74, 0x61, 0x6d, 0x70, 0x52, 0x0a, 0x63, 0x72,
	0x65, 0x61, 0x74, 0x65, 0x54, 0x69, 0x6d, 0x65, 0x12, 0x4b, 0x0a, 0x0b, 0x75, 0x70, 0x64, 0x61,
	0x74, 0x65, 0x5f, 0x74, 0x69, 0x6d, 0x65, 0x18, 0x03, 0x20, 0x01, 0x28, 0x0b, 0x32, 0x2a, 0x2e,
	0x63, 0x6f, 0x6e, 0x74, 0x72, 0x6f, 0x6c, 0x6c, 0x65, 0x72, 0x2e, 0x73, 0x74, 0x6f, 0x72, 0x61,
	0x67, 0x65, 0x2e, 0x74, 0x69, 0x6d, 0x65, 0x73, 0x74, 0x61, 0x6d, 0x70, 0x2e, 0x76, 0x31, 0x2e,
	0x54, 0x69, 0x6d, 0x65, 0x73, 0x74, 0x61, 0x6d, 0x70, 0x52, 0x0a, 0x75, 0x70, 0x64, 0x61, 0x74,
	0x65, 0x54, 0x69, 0x6d, 0x65, 0x12, 0x1b, 0x0a, 0x09, 0x70, 0x75, 0x62, 0x6c, 0x69, 0x63, 0x5f,
	0x69, 0x64, 0x18, 0x04, 0x20, 0x01, 0x28, 0x09, 0x52, 0x08, 0x70, 0x75, 0x62, 0x6c, 0x69, 0x63,
	0x49, 0x64, 0x12, 0x12, 0x0a, 0x04, 0x6e, 0x61, 0x6d, 0x65, 0x18, 0x05, 0x20, 0x01, 0x28, 0x09,
	0x52, 0x04, 0x6e, 0x61, 0x6d, 0x65, 0x12, 0x17, 0x0a, 0x07, 0x75, 0x73, 0x65, 0x72, 0x5f, 0x69,
	0x64, 0x18, 0x06, 0x20, 0x01, 0x28, 0x0d, 0x52, 0x06, 0x75, 0x73, 0x65, 0x72, 0x49, 0x64, 0x12,
	0x15, 0x0a, 0x06, 0x63, 0x61, 0x72, 0x5f, 0x69, 0x64, 0x18, 0x07, 0x20, 0x01, 0x28, 0x0d, 0x52,
	0x05, 0x63, 0x61, 0x72, 0x49, 0x64, 0x22, 0x83, 0x02, 0x0a, 0x10, 0x53, 0x74, 0x6f, 0x72, 0x65,
	0x54, 0x65, 0x73, 0x74, 0x53, 0x63, 0x6f, 0x6f, 0x74, 0x65, 0x72, 0x12, 0x0e, 0x0a, 0x02, 0x69,
	0x64, 0x18, 0x01, 0x20, 0x01, 0x28, 0x0d, 0x52, 0x02, 0x69, 0x64, 0x12, 0x4b, 0x0a, 0x0b, 0x63,
	0x72, 0x65, 0x61, 0x74, 0x65, 0x5f, 0x74, 0x69, 0x6d, 0x65, 0x18, 0x02, 0x20, 0x01, 0x28, 0x0b,
	0x32, 0x2a, 0x2e, 0x63, 0x6f, 0x6e, 0x74, 0x72, 0x6f, 0x6c, 0x6c, 0x65, 0x72, 0x2e, 0x73, 0x74,
	0x6f, 0x72, 0x61, 0x67, 0x65, 0x2e, 0x74, 0x69, 0x6d, 0x65, 0x73, 0x74, 0x61, 0x6d, 0x70, 0x2e,
	0x76, 0x31, 0x2e, 0x54, 0x69, 0x6d, 0x65, 0x73, 0x74, 0x61, 0x6d, 0x70, 0x52, 0x0a, 0x63, 0x72,
	0x65, 0x61, 0x74, 0x65, 0x54, 0x69, 0x6d, 0x65, 0x12, 0x4b, 0x0a, 0x0b, 0x75, 0x70, 0x64, 0x61,
	0x74, 0x65, 0x5f, 0x74, 0x69, 0x6d, 0x65, 0x18, 0x03, 0x20, 0x01, 0x28, 0x0b, 0x32, 0x2a, 0x2e,
	0x63, 0x6f, 0x6e, 0x74, 0x72, 0x6f, 0x6c, 0x6c, 0x65, 0x72, 0x2e, 0x73, 0x74, 0x6f, 0x72, 0x61,
	0x67, 0x65, 0x2e, 0x74, 0x69, 0x6d, 0x65, 0x73, 0x74, 0x61, 0x6d, 0x70, 0x2e, 0x76, 0x31, 0x2e,
	0x54, 0x69, 0x6d, 0x65, 0x73, 0x74, 0x61, 0x6d, 0x70, 0x52, 0x0a, 0x75, 0x70, 0x64, 0x61, 0x74,
	0x65, 0x54, 0x69, 0x6d, 0x65, 0x12, 0x1d, 0x0a, 0x0a, 0x70, 0x72, 0x69, 0x76, 0x61, 0x74, 0x65,
	0x5f, 0x69, 0x64, 0x18, 0x04, 0x20, 0x01, 0x28, 0x09, 0x52, 0x09, 0x70, 0x72, 0x69, 0x76, 0x61,
	0x74, 0x65, 0x49, 0x64, 0x12, 0x14, 0x0a, 0x05, 0x6d, 0x6f, 0x64, 0x65, 0x6c, 0x18, 0x06, 0x20,
	0x01, 0x28, 0x09, 0x52, 0x05, 0x6d, 0x6f, 0x64, 0x65, 0x6c, 0x12, 0x10, 0x0a, 0x03, 0x6d, 0x70,
	0x67, 0x18, 0x07, 0x20, 0x01, 0x28, 0x05, 0x52, 0x03, 0x6d, 0x70, 0x67, 0x22, 0x59, 0x0a, 0x12,
	0x53, 0x74, 0x6f, 0x72, 0x65, 0x54, 0x65, 0x73, 0x74, 0x41, 0x63, 0x63, 0x65, 0x73, 0x73, 0x6f,
	0x72, 0x79, 0x12, 0x21, 0x0a, 0x0c, 0x61, 0x63, 0x63, 0x65, 0x73, 0x73, 0x6f, 0x72, 0x79, 0x5f,
	0x69, 0x64, 0x18, 0x01, 0x20, 0x01, 0x28, 0x0d, 0x52, 0x0b, 0x61, 0x63, 0x63, 0x65, 0x73, 0x73,
	0x6f, 0x72, 0x79, 0x49, 0x64, 0x12, 0x20, 0x0a, 0x0b, 0x64, 0x65, 0x73, 0x63, 0x72, 0x69, 0x70,
	0x74, 0x69, 0x6f, 0x6e, 0x18, 0x02, 0x20, 0x01, 0x28, 0x09, 0x52, 0x0b, 0x64, 0x65, 0x73, 0x63,
	0x72, 0x69, 0x70, 0x74, 0x69, 0x6f, 0x6e, 0x22, 0x75, 0x0a, 0x19, 0x53, 0x74, 0x6f, 0x72, 0x65,
	0x54, 0x65, 0x73, 0x74, 0x53, 0x63, 0x6f, 0x6f, 0x74, 0x65, 0x72, 0x41, 0x63, 0x63, 0x65, 0x73,
	0x73, 0x6f, 0x72, 0x79, 0x12, 0x21, 0x0a, 0x0c, 0x61, 0x63, 0x63, 0x65, 0x73, 0x73, 0x6f, 0x72,
	0x79, 0x5f, 0x69, 0x64, 0x18, 0x01, 0x20, 0x01, 0x28, 0x0d, 0x52, 0x0b, 0x61, 0x63, 0x63, 0x65,
	0x73, 0x73, 0x6f, 0x72, 0x79, 0x49, 0x64, 0x12, 0x1d, 0x0a, 0x0a, 0x73, 0x63, 0x6f, 0x6f, 0x74,
	0x65, 0x72, 0x5f, 0x69, 0x64, 0x18, 0x02, 0x20, 0x01, 0x28, 0x0d, 0x52, 0x09, 0x73, 0x63, 0x6f,
	0x6f, 0x74, 0x65, 0x72, 0x49, 0x64, 0x12, 0x16, 0x0a, 0x06, 0x72, 0x65, 0x76, 0x69, 0x65, 0x77,
	0x18, 0x03, 0x20, 0x01, 0x28, 0x09, 0x52, 0x06, 0x72, 0x65, 0x76, 0x69, 0x65, 0x77, 0x42, 0x3b,
	0x5a, 0x39, 0x67, 0x69, 0x74, 0x68, 0x75, 0x62, 0x2e, 0x63, 0x6f, 0x6d, 0x2f, 0x68, 0x61, 0x73,
	0x68, 0x69, 0x63, 0x6f, 0x72, 0x70, 0x2f, 0x62, 0x6f, 0x75, 0x6e, 0x64, 0x61, 0x72, 0x79, 0x2f,
	0x69, 0x6e, 0x74, 0x65, 0x72, 0x6e, 0x61, 0x6c, 0x2f, 0x64, 0x62, 0x2f, 0x64, 0x62, 0x5f, 0x74,
	0x65, 0x73, 0x74, 0x3b, 0x64, 0x62, 0x5f, 0x74, 0x65, 0x73, 0x74, 0x62, 0x06, 0x70, 0x72, 0x6f,
	0x74, 0x6f, 0x33,
}

var (
	file_controller_storage_db_db_test_v1_db_test_proto_rawDescOnce sync.Once
	file_controller_storage_db_db_test_v1_db_test_proto_rawDescData = file_controller_storage_db_db_test_v1_db_test_proto_rawDesc
)

func file_controller_storage_db_db_test_v1_db_test_proto_rawDescGZIP() []byte {
	file_controller_storage_db_db_test_v1_db_test_proto_rawDescOnce.Do(func() {
		file_controller_storage_db_db_test_v1_db_test_proto_rawDescData = protoimpl.X.CompressGZIP(file_controller_storage_db_db_test_v1_db_test_proto_rawDescData)
	})
	return file_controller_storage_db_db_test_v1_db_test_proto_rawDescData
}

var file_controller_storage_db_db_test_v1_db_test_proto_msgTypes = make([]protoimpl.MessageInfo, 6)
var file_controller_storage_db_db_test_v1_db_test_proto_goTypes = []any{
	(*StoreTestUser)(nil),             // 0: controller.storage.db.db_test.v1.StoreTestUser
	(*StoreTestCar)(nil),              // 1: controller.storage.db.db_test.v1.StoreTestCar
	(*StoreTestRental)(nil),           // 2: controller.storage.db.db_test.v1.StoreTestRental
	(*StoreTestScooter)(nil),          // 3: controller.storage.db.db_test.v1.StoreTestScooter
	(*StoreTestAccessory)(nil),        // 4: controller.storage.db.db_test.v1.StoreTestAccessory
	(*StoreTestScooterAccessory)(nil), // 5: controller.storage.db.db_test.v1.StoreTestScooterAccessory
	(*timestamp.Timestamp)(nil),       // 6: controller.storage.timestamp.v1.Timestamp
}
var file_controller_storage_db_db_test_v1_db_test_proto_depIdxs = []int32{
	6, // 0: controller.storage.db.db_test.v1.StoreTestUser.create_time:type_name -> controller.storage.timestamp.v1.Timestamp
	6, // 1: controller.storage.db.db_test.v1.StoreTestUser.update_time:type_name -> controller.storage.timestamp.v1.Timestamp
	6, // 2: controller.storage.db.db_test.v1.StoreTestCar.create_time:type_name -> controller.storage.timestamp.v1.Timestamp
	6, // 3: controller.storage.db.db_test.v1.StoreTestCar.update_time:type_name -> controller.storage.timestamp.v1.Timestamp
	6, // 4: controller.storage.db.db_test.v1.StoreTestRental.create_time:type_name -> controller.storage.timestamp.v1.Timestamp
	6, // 5: controller.storage.db.db_test.v1.StoreTestRental.update_time:type_name -> controller.storage.timestamp.v1.Timestamp
	6, // 6: controller.storage.db.db_test.v1.StoreTestScooter.create_time:type_name -> controller.storage.timestamp.v1.Timestamp
	6, // 7: controller.storage.db.db_test.v1.StoreTestScooter.update_time:type_name -> controller.storage.timestamp.v1.Timestamp
	8, // [8:8] is the sub-list for method output_type
	8, // [8:8] is the sub-list for method input_type
	8, // [8:8] is the sub-list for extension type_name
	8, // [8:8] is the sub-list for extension extendee
	0, // [0:8] is the sub-list for field type_name
}

func init() { file_controller_storage_db_db_test_v1_db_test_proto_init() }
func file_controller_storage_db_db_test_v1_db_test_proto_init() {
	if File_controller_storage_db_db_test_v1_db_test_proto != nil {
		return
	}
	type x struct{}
	out := protoimpl.TypeBuilder{
		File: protoimpl.DescBuilder{
			GoPackagePath: reflect.TypeOf(x{}).PkgPath(),
			RawDescriptor: file_controller_storage_db_db_test_v1_db_test_proto_rawDesc,
			NumEnums:      0,
			NumMessages:   6,
			NumExtensions: 0,
			NumServices:   0,
		},
		GoTypes:           file_controller_storage_db_db_test_v1_db_test_proto_goTypes,
		DependencyIndexes: file_controller_storage_db_db_test_v1_db_test_proto_depIdxs,
		MessageInfos:      file_controller_storage_db_db_test_v1_db_test_proto_msgTypes,
	}.Build()
	File_controller_storage_db_db_test_v1_db_test_proto = out.File
	file_controller_storage_db_db_test_v1_db_test_proto_rawDesc = nil
	file_controller_storage_db_db_test_v1_db_test_proto_goTypes = nil
	file_controller_storage_db_db_test_v1_db_test_proto_depIdxs = nil
}
