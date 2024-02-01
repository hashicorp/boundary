// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: BUSL-1.1

// Code generated by protoc-gen-go. DO NOT EDIT.
// versions:
// 	protoc-gen-go v1.32.0
// 	protoc        (unknown)
// source: controller/storage/oplog/v1/any_operation.proto

package oplog

import (
	protoreflect "google.golang.org/protobuf/reflect/protoreflect"
	protoimpl "google.golang.org/protobuf/runtime/protoimpl"
	fieldmaskpb "google.golang.org/protobuf/types/known/fieldmaskpb"
	structpb "google.golang.org/protobuf/types/known/structpb"
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

// OpType provides the type of database operation the Any message represents
// (create, update, delete)
type OpType int32

const (
	// OP_TYPE_UNSPECIFIED defines an unspecified operation.
	OpType_OP_TYPE_UNSPECIFIED OpType = 0
	// OP_TYPE_CREATE defines a create operation.
	OpType_OP_TYPE_CREATE OpType = 1
	// OP_TYPE_UPDATE defines an update operation.
	OpType_OP_TYPE_UPDATE OpType = 2
	// OP_TYPE_DELETE defines a delete operation.
	OpType_OP_TYPE_DELETE OpType = 3
	// OP_TYPE_CREATE_ITEMS defines a create operation for multiple items.
	OpType_OP_TYPE_CREATE_ITEMS OpType = 4
	// OP_TYPE_DELETE_ITEMS defines a delete operation for multiple items.
	OpType_OP_TYPE_DELETE_ITEMS OpType = 5
)

// Enum value maps for OpType.
var (
	OpType_name = map[int32]string{
		0: "OP_TYPE_UNSPECIFIED",
		1: "OP_TYPE_CREATE",
		2: "OP_TYPE_UPDATE",
		3: "OP_TYPE_DELETE",
		4: "OP_TYPE_CREATE_ITEMS",
		5: "OP_TYPE_DELETE_ITEMS",
	}
	OpType_value = map[string]int32{
		"OP_TYPE_UNSPECIFIED":  0,
		"OP_TYPE_CREATE":       1,
		"OP_TYPE_UPDATE":       2,
		"OP_TYPE_DELETE":       3,
		"OP_TYPE_CREATE_ITEMS": 4,
		"OP_TYPE_DELETE_ITEMS": 5,
	}
)

func (x OpType) Enum() *OpType {
	p := new(OpType)
	*p = x
	return p
}

func (x OpType) String() string {
	return protoimpl.X.EnumStringOf(x.Descriptor(), protoreflect.EnumNumber(x))
}

func (OpType) Descriptor() protoreflect.EnumDescriptor {
	return file_controller_storage_oplog_v1_any_operation_proto_enumTypes[0].Descriptor()
}

func (OpType) Type() protoreflect.EnumType {
	return &file_controller_storage_oplog_v1_any_operation_proto_enumTypes[0]
}

func (x OpType) Number() protoreflect.EnumNumber {
	return protoreflect.EnumNumber(x)
}

// Deprecated: Use OpType.Descriptor instead.
func (OpType) EnumDescriptor() ([]byte, []int) {
	return file_controller_storage_oplog_v1_any_operation_proto_rawDescGZIP(), []int{0}
}

// AnyOperation provides a message for anything and the type of operation it
// represents.
type AnyOperation struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	// type_name defines type of operation.
	TypeName string `protobuf:"bytes,1,opt,name=type_name,json=typeName,proto3" json:"type_name,omitempty"`
	// value are the bytes of a marshaled proto buff.
	Value []byte `protobuf:"bytes,2,opt,name=value,proto3" json:"value,omitempty"`
	// operation_type defines the type of database operation.
	OperationType OpType `protobuf:"varint,3,opt,name=operation_type,json=operationType,proto3,enum=controller.storage.oplog.v1.OpType" json:"operation_type,omitempty"`
	// field_mask is the mask of fields to update.
	FieldMask *fieldmaskpb.FieldMask `protobuf:"bytes,4,opt,name=field_mask,json=fieldMask,proto3" json:"field_mask,omitempty"`
	// null_mask is the mask of fields to set to null.
	NullMask *fieldmaskpb.FieldMask `protobuf:"bytes,5,opt,name=null_mask,json=nullMask,proto3" json:"null_mask,omitempty"`
	// Options for the operations (see dbw package for definition/documentation of
	// options)
	Options *OperationOptions `protobuf:"bytes,6,opt,name=options,proto3" json:"options,omitempty"`
}

func (x *AnyOperation) Reset() {
	*x = AnyOperation{}
	if protoimpl.UnsafeEnabled {
		mi := &file_controller_storage_oplog_v1_any_operation_proto_msgTypes[0]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *AnyOperation) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*AnyOperation) ProtoMessage() {}

func (x *AnyOperation) ProtoReflect() protoreflect.Message {
	mi := &file_controller_storage_oplog_v1_any_operation_proto_msgTypes[0]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use AnyOperation.ProtoReflect.Descriptor instead.
func (*AnyOperation) Descriptor() ([]byte, []int) {
	return file_controller_storage_oplog_v1_any_operation_proto_rawDescGZIP(), []int{0}
}

func (x *AnyOperation) GetTypeName() string {
	if x != nil {
		return x.TypeName
	}
	return ""
}

func (x *AnyOperation) GetValue() []byte {
	if x != nil {
		return x.Value
	}
	return nil
}

func (x *AnyOperation) GetOperationType() OpType {
	if x != nil {
		return x.OperationType
	}
	return OpType_OP_TYPE_UNSPECIFIED
}

func (x *AnyOperation) GetFieldMask() *fieldmaskpb.FieldMask {
	if x != nil {
		return x.FieldMask
	}
	return nil
}

func (x *AnyOperation) GetNullMask() *fieldmaskpb.FieldMask {
	if x != nil {
		return x.NullMask
	}
	return nil
}

func (x *AnyOperation) GetOptions() *OperationOptions {
	if x != nil {
		return x.Options
	}
	return nil
}

// OperationOptions represent operations options which can/will affect the oplog write
// operation.  These options are a subset of the dbw.Options. We will not try to
// keep the docs in-sync from the dbw package, so if you need more information
// on what the option does please see the dbw package docs.
type OperationOptions struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	// with_version (see dbw package for docs)
	WithVersion *wrapperspb.UInt32Value `protobuf:"bytes,1,opt,name=with_version,json=withVersion,proto3" json:"with_version,omitempty"`
	// with_skip_vet_for_write (see dbw package for docs)
	WithSkipVetForWrite bool `protobuf:"varint,2,opt,name=with_skip_vet_for_write,json=withSkipVetForWrite,proto3" json:"with_skip_vet_for_write,omitempty"`
	// with_where_clause (see dbw package for docs)
	WithWhereClause string `protobuf:"bytes,3,opt,name=with_where_clause,json=withWhereClause,proto3" json:"with_where_clause,omitempty"`
	// with_where_clause_args (see dbw package for docs)
	WithWhereClauseArgs []*structpb.Value `protobuf:"bytes,4,rep,name=with_where_clause_args,json=withWhereClauseArgs,proto3" json:"with_where_clause_args,omitempty"`
	// with_on_conflict (see dbw package for docs)
	WithOnConflict *WithOnConflict `protobuf:"bytes,5,opt,name=with_on_conflict,json=withOnConflict,proto3" json:"with_on_conflict,omitempty"`
}

func (x *OperationOptions) Reset() {
	*x = OperationOptions{}
	if protoimpl.UnsafeEnabled {
		mi := &file_controller_storage_oplog_v1_any_operation_proto_msgTypes[1]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *OperationOptions) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*OperationOptions) ProtoMessage() {}

func (x *OperationOptions) ProtoReflect() protoreflect.Message {
	mi := &file_controller_storage_oplog_v1_any_operation_proto_msgTypes[1]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use OperationOptions.ProtoReflect.Descriptor instead.
func (*OperationOptions) Descriptor() ([]byte, []int) {
	return file_controller_storage_oplog_v1_any_operation_proto_rawDescGZIP(), []int{1}
}

func (x *OperationOptions) GetWithVersion() *wrapperspb.UInt32Value {
	if x != nil {
		return x.WithVersion
	}
	return nil
}

func (x *OperationOptions) GetWithSkipVetForWrite() bool {
	if x != nil {
		return x.WithSkipVetForWrite
	}
	return false
}

func (x *OperationOptions) GetWithWhereClause() string {
	if x != nil {
		return x.WithWhereClause
	}
	return ""
}

func (x *OperationOptions) GetWithWhereClauseArgs() []*structpb.Value {
	if x != nil {
		return x.WithWhereClauseArgs
	}
	return nil
}

func (x *OperationOptions) GetWithOnConflict() *WithOnConflict {
	if x != nil {
		return x.WithOnConflict
	}
	return nil
}

// WithOnConflict defines the parameters needed for an sql "on conflict clause"
type WithOnConflict struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	// target defines the on conflict target
	//
	// Types that are assignable to Target:
	//
	//	*WithOnConflict_Constraint
	//	*WithOnConflict_Columns
	Target isWithOnConflict_Target `protobuf_oneof:"target"`
	// action defines the on conflict action
	//
	// Types that are assignable to Action:
	//
	//	*WithOnConflict_DoNothing
	//	*WithOnConflict_UpdateAll
	//	*WithOnConflict_ColumnValues
	Action isWithOnConflict_Action `protobuf_oneof:"action"`
}

func (x *WithOnConflict) Reset() {
	*x = WithOnConflict{}
	if protoimpl.UnsafeEnabled {
		mi := &file_controller_storage_oplog_v1_any_operation_proto_msgTypes[2]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *WithOnConflict) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*WithOnConflict) ProtoMessage() {}

func (x *WithOnConflict) ProtoReflect() protoreflect.Message {
	mi := &file_controller_storage_oplog_v1_any_operation_proto_msgTypes[2]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use WithOnConflict.ProtoReflect.Descriptor instead.
func (*WithOnConflict) Descriptor() ([]byte, []int) {
	return file_controller_storage_oplog_v1_any_operation_proto_rawDescGZIP(), []int{2}
}

func (m *WithOnConflict) GetTarget() isWithOnConflict_Target {
	if m != nil {
		return m.Target
	}
	return nil
}

func (x *WithOnConflict) GetConstraint() string {
	if x, ok := x.GetTarget().(*WithOnConflict_Constraint); ok {
		return x.Constraint
	}
	return ""
}

func (x *WithOnConflict) GetColumns() *Columns {
	if x, ok := x.GetTarget().(*WithOnConflict_Columns); ok {
		return x.Columns
	}
	return nil
}

func (m *WithOnConflict) GetAction() isWithOnConflict_Action {
	if m != nil {
		return m.Action
	}
	return nil
}

func (x *WithOnConflict) GetDoNothing() bool {
	if x, ok := x.GetAction().(*WithOnConflict_DoNothing); ok {
		return x.DoNothing
	}
	return false
}

func (x *WithOnConflict) GetUpdateAll() bool {
	if x, ok := x.GetAction().(*WithOnConflict_UpdateAll); ok {
		return x.UpdateAll
	}
	return false
}

func (x *WithOnConflict) GetColumnValues() *ColumnValues {
	if x, ok := x.GetAction().(*WithOnConflict_ColumnValues); ok {
		return x.ColumnValues
	}
	return nil
}

type isWithOnConflict_Target interface {
	isWithOnConflict_Target()
}

type WithOnConflict_Constraint struct {
	// constraint is the on conflict constraint
	Constraint string `protobuf:"bytes,10,opt,name=constraint,proto3,oneof"`
}

type WithOnConflict_Columns struct {
	// columns are the on conflict columns
	Columns *Columns `protobuf:"bytes,11,opt,name=columns,proto3,oneof"`
}

func (*WithOnConflict_Constraint) isWithOnConflict_Target() {}

func (*WithOnConflict_Columns) isWithOnConflict_Target() {}

type isWithOnConflict_Action interface {
	isWithOnConflict_Action()
}

type WithOnConflict_DoNothing struct {
	// do_nothing defines an on conflict action of do nothing
	DoNothing bool `protobuf:"varint,50,opt,name=do_nothing,json=doNothing,proto3,oneof"`
}

type WithOnConflict_UpdateAll struct {
	// update_all defines an on conflict action of updating all the columns
	UpdateAll bool `protobuf:"varint,51,opt,name=update_all,json=updateAll,proto3,oneof"`
}

type WithOnConflict_ColumnValues struct {
	// column_values defines on conflict action with the columns to update
	ColumnValues *ColumnValues `protobuf:"bytes,52,opt,name=column_values,json=columnValues,proto3,oneof"`
}

func (*WithOnConflict_DoNothing) isWithOnConflict_Action() {}

func (*WithOnConflict_UpdateAll) isWithOnConflict_Action() {}

func (*WithOnConflict_ColumnValues) isWithOnConflict_Action() {}

// Columns defines a set of column properties
type Columns struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	// name of the columns
	Names []string `protobuf:"bytes,1,rep,name=names,proto3" json:"names,omitempty"`
}

func (x *Columns) Reset() {
	*x = Columns{}
	if protoimpl.UnsafeEnabled {
		mi := &file_controller_storage_oplog_v1_any_operation_proto_msgTypes[3]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *Columns) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*Columns) ProtoMessage() {}

func (x *Columns) ProtoReflect() protoreflect.Message {
	mi := &file_controller_storage_oplog_v1_any_operation_proto_msgTypes[3]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use Columns.ProtoReflect.Descriptor instead.
func (*Columns) Descriptor() ([]byte, []int) {
	return file_controller_storage_oplog_v1_any_operation_proto_rawDescGZIP(), []int{3}
}

func (x *Columns) GetNames() []string {
	if x != nil {
		return x.Names
	}
	return nil
}

// ColumnValue defines a column value
type ColumnValue struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	// name of the column
	Name string `protobuf:"bytes,1,opt,name=name,proto3" json:"name,omitempty"`
	// value of the column
	//
	// Types that are assignable to Value:
	//
	//	*ColumnValue_Raw
	//	*ColumnValue_ExprValue
	//	*ColumnValue_Column
	Value isColumnValue_Value `protobuf_oneof:"value"`
}

func (x *ColumnValue) Reset() {
	*x = ColumnValue{}
	if protoimpl.UnsafeEnabled {
		mi := &file_controller_storage_oplog_v1_any_operation_proto_msgTypes[4]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *ColumnValue) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*ColumnValue) ProtoMessage() {}

func (x *ColumnValue) ProtoReflect() protoreflect.Message {
	mi := &file_controller_storage_oplog_v1_any_operation_proto_msgTypes[4]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use ColumnValue.ProtoReflect.Descriptor instead.
func (*ColumnValue) Descriptor() ([]byte, []int) {
	return file_controller_storage_oplog_v1_any_operation_proto_rawDescGZIP(), []int{4}
}

func (x *ColumnValue) GetName() string {
	if x != nil {
		return x.Name
	}
	return ""
}

func (m *ColumnValue) GetValue() isColumnValue_Value {
	if m != nil {
		return m.Value
	}
	return nil
}

func (x *ColumnValue) GetRaw() *structpb.Value {
	if x, ok := x.GetValue().(*ColumnValue_Raw); ok {
		return x.Raw
	}
	return nil
}

func (x *ColumnValue) GetExprValue() *ExprValue {
	if x, ok := x.GetValue().(*ColumnValue_ExprValue); ok {
		return x.ExprValue
	}
	return nil
}

func (x *ColumnValue) GetColumn() *Column {
	if x, ok := x.GetValue().(*ColumnValue_Column); ok {
		return x.Column
	}
	return nil
}

type isColumnValue_Value interface {
	isColumnValue_Value()
}

type ColumnValue_Raw struct {
	Raw *structpb.Value `protobuf:"bytes,2,opt,name=raw,proto3,oneof"`
}

type ColumnValue_ExprValue struct {
	ExprValue *ExprValue `protobuf:"bytes,3,opt,name=expr_value,json=exprValue,proto3,oneof"`
}

type ColumnValue_Column struct {
	Column *Column `protobuf:"bytes,4,opt,name=column,proto3,oneof"`
}

func (*ColumnValue_Raw) isColumnValue_Value() {}

func (*ColumnValue_ExprValue) isColumnValue_Value() {}

func (*ColumnValue_Column) isColumnValue_Value() {}

// ColumnValues defines a set of column value properies
type ColumnValues struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	// values are the values of the columns
	Values []*ColumnValue `protobuf:"bytes,1,rep,name=values,proto3" json:"values,omitempty"`
}

func (x *ColumnValues) Reset() {
	*x = ColumnValues{}
	if protoimpl.UnsafeEnabled {
		mi := &file_controller_storage_oplog_v1_any_operation_proto_msgTypes[5]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *ColumnValues) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*ColumnValues) ProtoMessage() {}

func (x *ColumnValues) ProtoReflect() protoreflect.Message {
	mi := &file_controller_storage_oplog_v1_any_operation_proto_msgTypes[5]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use ColumnValues.ProtoReflect.Descriptor instead.
func (*ColumnValues) Descriptor() ([]byte, []int) {
	return file_controller_storage_oplog_v1_any_operation_proto_rawDescGZIP(), []int{5}
}

func (x *ColumnValues) GetValues() []*ColumnValue {
	if x != nil {
		return x.Values
	}
	return nil
}

// ExprValue defines an expr value that can be used as a column value
type ExprValue struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	// sql is the sql clause of the expr
	Sql string `protobuf:"bytes,1,opt,name=sql,proto3" json:"sql,omitempty"`
	// args are the sql args of the expr
	Args []*structpb.Value `protobuf:"bytes,2,rep,name=args,proto3" json:"args,omitempty"`
}

func (x *ExprValue) Reset() {
	*x = ExprValue{}
	if protoimpl.UnsafeEnabled {
		mi := &file_controller_storage_oplog_v1_any_operation_proto_msgTypes[6]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *ExprValue) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*ExprValue) ProtoMessage() {}

func (x *ExprValue) ProtoReflect() protoreflect.Message {
	mi := &file_controller_storage_oplog_v1_any_operation_proto_msgTypes[6]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use ExprValue.ProtoReflect.Descriptor instead.
func (*ExprValue) Descriptor() ([]byte, []int) {
	return file_controller_storage_oplog_v1_any_operation_proto_rawDescGZIP(), []int{6}
}

func (x *ExprValue) GetSql() string {
	if x != nil {
		return x.Sql
	}
	return ""
}

func (x *ExprValue) GetArgs() []*structpb.Value {
	if x != nil {
		return x.Args
	}
	return nil
}

// Column represents a table Column
type Column struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	// name of the column
	Name string `protobuf:"bytes,1,opt,name=name,proto3" json:"name,omitempty"`
	// table name of the column
	Table string `protobuf:"bytes,2,opt,name=table,proto3" json:"table,omitempty"`
}

func (x *Column) Reset() {
	*x = Column{}
	if protoimpl.UnsafeEnabled {
		mi := &file_controller_storage_oplog_v1_any_operation_proto_msgTypes[7]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *Column) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*Column) ProtoMessage() {}

func (x *Column) ProtoReflect() protoreflect.Message {
	mi := &file_controller_storage_oplog_v1_any_operation_proto_msgTypes[7]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use Column.ProtoReflect.Descriptor instead.
func (*Column) Descriptor() ([]byte, []int) {
	return file_controller_storage_oplog_v1_any_operation_proto_rawDescGZIP(), []int{7}
}

func (x *Column) GetName() string {
	if x != nil {
		return x.Name
	}
	return ""
}

func (x *Column) GetTable() string {
	if x != nil {
		return x.Table
	}
	return ""
}

var File_controller_storage_oplog_v1_any_operation_proto protoreflect.FileDescriptor

var file_controller_storage_oplog_v1_any_operation_proto_rawDesc = []byte{
	0x0a, 0x2f, 0x63, 0x6f, 0x6e, 0x74, 0x72, 0x6f, 0x6c, 0x6c, 0x65, 0x72, 0x2f, 0x73, 0x74, 0x6f,
	0x72, 0x61, 0x67, 0x65, 0x2f, 0x6f, 0x70, 0x6c, 0x6f, 0x67, 0x2f, 0x76, 0x31, 0x2f, 0x61, 0x6e,
	0x79, 0x5f, 0x6f, 0x70, 0x65, 0x72, 0x61, 0x74, 0x69, 0x6f, 0x6e, 0x2e, 0x70, 0x72, 0x6f, 0x74,
	0x6f, 0x12, 0x1b, 0x63, 0x6f, 0x6e, 0x74, 0x72, 0x6f, 0x6c, 0x6c, 0x65, 0x72, 0x2e, 0x73, 0x74,
	0x6f, 0x72, 0x61, 0x67, 0x65, 0x2e, 0x6f, 0x70, 0x6c, 0x6f, 0x67, 0x2e, 0x76, 0x31, 0x1a, 0x20,
	0x67, 0x6f, 0x6f, 0x67, 0x6c, 0x65, 0x2f, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x62, 0x75, 0x66, 0x2f,
	0x66, 0x69, 0x65, 0x6c, 0x64, 0x5f, 0x6d, 0x61, 0x73, 0x6b, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f,
	0x1a, 0x1c, 0x67, 0x6f, 0x6f, 0x67, 0x6c, 0x65, 0x2f, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x62, 0x75,
	0x66, 0x2f, 0x73, 0x74, 0x72, 0x75, 0x63, 0x74, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x1a, 0x1e,
	0x67, 0x6f, 0x6f, 0x67, 0x6c, 0x65, 0x2f, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x62, 0x75, 0x66, 0x2f,
	0x77, 0x72, 0x61, 0x70, 0x70, 0x65, 0x72, 0x73, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x22, 0xca,
	0x02, 0x0a, 0x0c, 0x41, 0x6e, 0x79, 0x4f, 0x70, 0x65, 0x72, 0x61, 0x74, 0x69, 0x6f, 0x6e, 0x12,
	0x1b, 0x0a, 0x09, 0x74, 0x79, 0x70, 0x65, 0x5f, 0x6e, 0x61, 0x6d, 0x65, 0x18, 0x01, 0x20, 0x01,
	0x28, 0x09, 0x52, 0x08, 0x74, 0x79, 0x70, 0x65, 0x4e, 0x61, 0x6d, 0x65, 0x12, 0x14, 0x0a, 0x05,
	0x76, 0x61, 0x6c, 0x75, 0x65, 0x18, 0x02, 0x20, 0x01, 0x28, 0x0c, 0x52, 0x05, 0x76, 0x61, 0x6c,
	0x75, 0x65, 0x12, 0x4a, 0x0a, 0x0e, 0x6f, 0x70, 0x65, 0x72, 0x61, 0x74, 0x69, 0x6f, 0x6e, 0x5f,
	0x74, 0x79, 0x70, 0x65, 0x18, 0x03, 0x20, 0x01, 0x28, 0x0e, 0x32, 0x23, 0x2e, 0x63, 0x6f, 0x6e,
	0x74, 0x72, 0x6f, 0x6c, 0x6c, 0x65, 0x72, 0x2e, 0x73, 0x74, 0x6f, 0x72, 0x61, 0x67, 0x65, 0x2e,
	0x6f, 0x70, 0x6c, 0x6f, 0x67, 0x2e, 0x76, 0x31, 0x2e, 0x4f, 0x70, 0x54, 0x79, 0x70, 0x65, 0x52,
	0x0d, 0x6f, 0x70, 0x65, 0x72, 0x61, 0x74, 0x69, 0x6f, 0x6e, 0x54, 0x79, 0x70, 0x65, 0x12, 0x39,
	0x0a, 0x0a, 0x66, 0x69, 0x65, 0x6c, 0x64, 0x5f, 0x6d, 0x61, 0x73, 0x6b, 0x18, 0x04, 0x20, 0x01,
	0x28, 0x0b, 0x32, 0x1a, 0x2e, 0x67, 0x6f, 0x6f, 0x67, 0x6c, 0x65, 0x2e, 0x70, 0x72, 0x6f, 0x74,
	0x6f, 0x62, 0x75, 0x66, 0x2e, 0x46, 0x69, 0x65, 0x6c, 0x64, 0x4d, 0x61, 0x73, 0x6b, 0x52, 0x09,
	0x66, 0x69, 0x65, 0x6c, 0x64, 0x4d, 0x61, 0x73, 0x6b, 0x12, 0x37, 0x0a, 0x09, 0x6e, 0x75, 0x6c,
	0x6c, 0x5f, 0x6d, 0x61, 0x73, 0x6b, 0x18, 0x05, 0x20, 0x01, 0x28, 0x0b, 0x32, 0x1a, 0x2e, 0x67,
	0x6f, 0x6f, 0x67, 0x6c, 0x65, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x62, 0x75, 0x66, 0x2e, 0x46,
	0x69, 0x65, 0x6c, 0x64, 0x4d, 0x61, 0x73, 0x6b, 0x52, 0x08, 0x6e, 0x75, 0x6c, 0x6c, 0x4d, 0x61,
	0x73, 0x6b, 0x12, 0x47, 0x0a, 0x07, 0x6f, 0x70, 0x74, 0x69, 0x6f, 0x6e, 0x73, 0x18, 0x06, 0x20,
	0x01, 0x28, 0x0b, 0x32, 0x2d, 0x2e, 0x63, 0x6f, 0x6e, 0x74, 0x72, 0x6f, 0x6c, 0x6c, 0x65, 0x72,
	0x2e, 0x73, 0x74, 0x6f, 0x72, 0x61, 0x67, 0x65, 0x2e, 0x6f, 0x70, 0x6c, 0x6f, 0x67, 0x2e, 0x76,
	0x31, 0x2e, 0x4f, 0x70, 0x65, 0x72, 0x61, 0x74, 0x69, 0x6f, 0x6e, 0x4f, 0x70, 0x74, 0x69, 0x6f,
	0x6e, 0x73, 0x52, 0x07, 0x6f, 0x70, 0x74, 0x69, 0x6f, 0x6e, 0x73, 0x22, 0xd9, 0x02, 0x0a, 0x10,
	0x4f, 0x70, 0x65, 0x72, 0x61, 0x74, 0x69, 0x6f, 0x6e, 0x4f, 0x70, 0x74, 0x69, 0x6f, 0x6e, 0x73,
	0x12, 0x3f, 0x0a, 0x0c, 0x77, 0x69, 0x74, 0x68, 0x5f, 0x76, 0x65, 0x72, 0x73, 0x69, 0x6f, 0x6e,
	0x18, 0x01, 0x20, 0x01, 0x28, 0x0b, 0x32, 0x1c, 0x2e, 0x67, 0x6f, 0x6f, 0x67, 0x6c, 0x65, 0x2e,
	0x70, 0x72, 0x6f, 0x74, 0x6f, 0x62, 0x75, 0x66, 0x2e, 0x55, 0x49, 0x6e, 0x74, 0x33, 0x32, 0x56,
	0x61, 0x6c, 0x75, 0x65, 0x52, 0x0b, 0x77, 0x69, 0x74, 0x68, 0x56, 0x65, 0x72, 0x73, 0x69, 0x6f,
	0x6e, 0x12, 0x34, 0x0a, 0x17, 0x77, 0x69, 0x74, 0x68, 0x5f, 0x73, 0x6b, 0x69, 0x70, 0x5f, 0x76,
	0x65, 0x74, 0x5f, 0x66, 0x6f, 0x72, 0x5f, 0x77, 0x72, 0x69, 0x74, 0x65, 0x18, 0x02, 0x20, 0x01,
	0x28, 0x08, 0x52, 0x13, 0x77, 0x69, 0x74, 0x68, 0x53, 0x6b, 0x69, 0x70, 0x56, 0x65, 0x74, 0x46,
	0x6f, 0x72, 0x57, 0x72, 0x69, 0x74, 0x65, 0x12, 0x2a, 0x0a, 0x11, 0x77, 0x69, 0x74, 0x68, 0x5f,
	0x77, 0x68, 0x65, 0x72, 0x65, 0x5f, 0x63, 0x6c, 0x61, 0x75, 0x73, 0x65, 0x18, 0x03, 0x20, 0x01,
	0x28, 0x09, 0x52, 0x0f, 0x77, 0x69, 0x74, 0x68, 0x57, 0x68, 0x65, 0x72, 0x65, 0x43, 0x6c, 0x61,
	0x75, 0x73, 0x65, 0x12, 0x4b, 0x0a, 0x16, 0x77, 0x69, 0x74, 0x68, 0x5f, 0x77, 0x68, 0x65, 0x72,
	0x65, 0x5f, 0x63, 0x6c, 0x61, 0x75, 0x73, 0x65, 0x5f, 0x61, 0x72, 0x67, 0x73, 0x18, 0x04, 0x20,
	0x03, 0x28, 0x0b, 0x32, 0x16, 0x2e, 0x67, 0x6f, 0x6f, 0x67, 0x6c, 0x65, 0x2e, 0x70, 0x72, 0x6f,
	0x74, 0x6f, 0x62, 0x75, 0x66, 0x2e, 0x56, 0x61, 0x6c, 0x75, 0x65, 0x52, 0x13, 0x77, 0x69, 0x74,
	0x68, 0x57, 0x68, 0x65, 0x72, 0x65, 0x43, 0x6c, 0x61, 0x75, 0x73, 0x65, 0x41, 0x72, 0x67, 0x73,
	0x12, 0x55, 0x0a, 0x10, 0x77, 0x69, 0x74, 0x68, 0x5f, 0x6f, 0x6e, 0x5f, 0x63, 0x6f, 0x6e, 0x66,
	0x6c, 0x69, 0x63, 0x74, 0x18, 0x05, 0x20, 0x01, 0x28, 0x0b, 0x32, 0x2b, 0x2e, 0x63, 0x6f, 0x6e,
	0x74, 0x72, 0x6f, 0x6c, 0x6c, 0x65, 0x72, 0x2e, 0x73, 0x74, 0x6f, 0x72, 0x61, 0x67, 0x65, 0x2e,
	0x6f, 0x70, 0x6c, 0x6f, 0x67, 0x2e, 0x76, 0x31, 0x2e, 0x57, 0x69, 0x74, 0x68, 0x4f, 0x6e, 0x43,
	0x6f, 0x6e, 0x66, 0x6c, 0x69, 0x63, 0x74, 0x52, 0x0e, 0x77, 0x69, 0x74, 0x68, 0x4f, 0x6e, 0x43,
	0x6f, 0x6e, 0x66, 0x6c, 0x69, 0x63, 0x74, 0x22, 0x9c, 0x02, 0x0a, 0x0e, 0x57, 0x69, 0x74, 0x68,
	0x4f, 0x6e, 0x43, 0x6f, 0x6e, 0x66, 0x6c, 0x69, 0x63, 0x74, 0x12, 0x20, 0x0a, 0x0a, 0x63, 0x6f,
	0x6e, 0x73, 0x74, 0x72, 0x61, 0x69, 0x6e, 0x74, 0x18, 0x0a, 0x20, 0x01, 0x28, 0x09, 0x48, 0x00,
	0x52, 0x0a, 0x63, 0x6f, 0x6e, 0x73, 0x74, 0x72, 0x61, 0x69, 0x6e, 0x74, 0x12, 0x40, 0x0a, 0x07,
	0x63, 0x6f, 0x6c, 0x75, 0x6d, 0x6e, 0x73, 0x18, 0x0b, 0x20, 0x01, 0x28, 0x0b, 0x32, 0x24, 0x2e,
	0x63, 0x6f, 0x6e, 0x74, 0x72, 0x6f, 0x6c, 0x6c, 0x65, 0x72, 0x2e, 0x73, 0x74, 0x6f, 0x72, 0x61,
	0x67, 0x65, 0x2e, 0x6f, 0x70, 0x6c, 0x6f, 0x67, 0x2e, 0x76, 0x31, 0x2e, 0x43, 0x6f, 0x6c, 0x75,
	0x6d, 0x6e, 0x73, 0x48, 0x00, 0x52, 0x07, 0x63, 0x6f, 0x6c, 0x75, 0x6d, 0x6e, 0x73, 0x12, 0x1f,
	0x0a, 0x0a, 0x64, 0x6f, 0x5f, 0x6e, 0x6f, 0x74, 0x68, 0x69, 0x6e, 0x67, 0x18, 0x32, 0x20, 0x01,
	0x28, 0x08, 0x48, 0x01, 0x52, 0x09, 0x64, 0x6f, 0x4e, 0x6f, 0x74, 0x68, 0x69, 0x6e, 0x67, 0x12,
	0x1f, 0x0a, 0x0a, 0x75, 0x70, 0x64, 0x61, 0x74, 0x65, 0x5f, 0x61, 0x6c, 0x6c, 0x18, 0x33, 0x20,
	0x01, 0x28, 0x08, 0x48, 0x01, 0x52, 0x09, 0x75, 0x70, 0x64, 0x61, 0x74, 0x65, 0x41, 0x6c, 0x6c,
	0x12, 0x50, 0x0a, 0x0d, 0x63, 0x6f, 0x6c, 0x75, 0x6d, 0x6e, 0x5f, 0x76, 0x61, 0x6c, 0x75, 0x65,
	0x73, 0x18, 0x34, 0x20, 0x01, 0x28, 0x0b, 0x32, 0x29, 0x2e, 0x63, 0x6f, 0x6e, 0x74, 0x72, 0x6f,
	0x6c, 0x6c, 0x65, 0x72, 0x2e, 0x73, 0x74, 0x6f, 0x72, 0x61, 0x67, 0x65, 0x2e, 0x6f, 0x70, 0x6c,
	0x6f, 0x67, 0x2e, 0x76, 0x31, 0x2e, 0x43, 0x6f, 0x6c, 0x75, 0x6d, 0x6e, 0x56, 0x61, 0x6c, 0x75,
	0x65, 0x73, 0x48, 0x01, 0x52, 0x0c, 0x63, 0x6f, 0x6c, 0x75, 0x6d, 0x6e, 0x56, 0x61, 0x6c, 0x75,
	0x65, 0x73, 0x42, 0x08, 0x0a, 0x06, 0x74, 0x61, 0x72, 0x67, 0x65, 0x74, 0x42, 0x08, 0x0a, 0x06,
	0x61, 0x63, 0x74, 0x69, 0x6f, 0x6e, 0x22, 0x1f, 0x0a, 0x07, 0x43, 0x6f, 0x6c, 0x75, 0x6d, 0x6e,
	0x73, 0x12, 0x14, 0x0a, 0x05, 0x6e, 0x61, 0x6d, 0x65, 0x73, 0x18, 0x01, 0x20, 0x03, 0x28, 0x09,
	0x52, 0x05, 0x6e, 0x61, 0x6d, 0x65, 0x73, 0x22, 0xde, 0x01, 0x0a, 0x0b, 0x43, 0x6f, 0x6c, 0x75,
	0x6d, 0x6e, 0x56, 0x61, 0x6c, 0x75, 0x65, 0x12, 0x12, 0x0a, 0x04, 0x6e, 0x61, 0x6d, 0x65, 0x18,
	0x01, 0x20, 0x01, 0x28, 0x09, 0x52, 0x04, 0x6e, 0x61, 0x6d, 0x65, 0x12, 0x2a, 0x0a, 0x03, 0x72,
	0x61, 0x77, 0x18, 0x02, 0x20, 0x01, 0x28, 0x0b, 0x32, 0x16, 0x2e, 0x67, 0x6f, 0x6f, 0x67, 0x6c,
	0x65, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x62, 0x75, 0x66, 0x2e, 0x56, 0x61, 0x6c, 0x75, 0x65,
	0x48, 0x00, 0x52, 0x03, 0x72, 0x61, 0x77, 0x12, 0x47, 0x0a, 0x0a, 0x65, 0x78, 0x70, 0x72, 0x5f,
	0x76, 0x61, 0x6c, 0x75, 0x65, 0x18, 0x03, 0x20, 0x01, 0x28, 0x0b, 0x32, 0x26, 0x2e, 0x63, 0x6f,
	0x6e, 0x74, 0x72, 0x6f, 0x6c, 0x6c, 0x65, 0x72, 0x2e, 0x73, 0x74, 0x6f, 0x72, 0x61, 0x67, 0x65,
	0x2e, 0x6f, 0x70, 0x6c, 0x6f, 0x67, 0x2e, 0x76, 0x31, 0x2e, 0x45, 0x78, 0x70, 0x72, 0x56, 0x61,
	0x6c, 0x75, 0x65, 0x48, 0x00, 0x52, 0x09, 0x65, 0x78, 0x70, 0x72, 0x56, 0x61, 0x6c, 0x75, 0x65,
	0x12, 0x3d, 0x0a, 0x06, 0x63, 0x6f, 0x6c, 0x75, 0x6d, 0x6e, 0x18, 0x04, 0x20, 0x01, 0x28, 0x0b,
	0x32, 0x23, 0x2e, 0x63, 0x6f, 0x6e, 0x74, 0x72, 0x6f, 0x6c, 0x6c, 0x65, 0x72, 0x2e, 0x73, 0x74,
	0x6f, 0x72, 0x61, 0x67, 0x65, 0x2e, 0x6f, 0x70, 0x6c, 0x6f, 0x67, 0x2e, 0x76, 0x31, 0x2e, 0x43,
	0x6f, 0x6c, 0x75, 0x6d, 0x6e, 0x48, 0x00, 0x52, 0x06, 0x63, 0x6f, 0x6c, 0x75, 0x6d, 0x6e, 0x42,
	0x07, 0x0a, 0x05, 0x76, 0x61, 0x6c, 0x75, 0x65, 0x22, 0x50, 0x0a, 0x0c, 0x43, 0x6f, 0x6c, 0x75,
	0x6d, 0x6e, 0x56, 0x61, 0x6c, 0x75, 0x65, 0x73, 0x12, 0x40, 0x0a, 0x06, 0x76, 0x61, 0x6c, 0x75,
	0x65, 0x73, 0x18, 0x01, 0x20, 0x03, 0x28, 0x0b, 0x32, 0x28, 0x2e, 0x63, 0x6f, 0x6e, 0x74, 0x72,
	0x6f, 0x6c, 0x6c, 0x65, 0x72, 0x2e, 0x73, 0x74, 0x6f, 0x72, 0x61, 0x67, 0x65, 0x2e, 0x6f, 0x70,
	0x6c, 0x6f, 0x67, 0x2e, 0x76, 0x31, 0x2e, 0x43, 0x6f, 0x6c, 0x75, 0x6d, 0x6e, 0x56, 0x61, 0x6c,
	0x75, 0x65, 0x52, 0x06, 0x76, 0x61, 0x6c, 0x75, 0x65, 0x73, 0x22, 0x49, 0x0a, 0x09, 0x45, 0x78,
	0x70, 0x72, 0x56, 0x61, 0x6c, 0x75, 0x65, 0x12, 0x10, 0x0a, 0x03, 0x73, 0x71, 0x6c, 0x18, 0x01,
	0x20, 0x01, 0x28, 0x09, 0x52, 0x03, 0x73, 0x71, 0x6c, 0x12, 0x2a, 0x0a, 0x04, 0x61, 0x72, 0x67,
	0x73, 0x18, 0x02, 0x20, 0x03, 0x28, 0x0b, 0x32, 0x16, 0x2e, 0x67, 0x6f, 0x6f, 0x67, 0x6c, 0x65,
	0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x62, 0x75, 0x66, 0x2e, 0x56, 0x61, 0x6c, 0x75, 0x65, 0x52,
	0x04, 0x61, 0x72, 0x67, 0x73, 0x22, 0x32, 0x0a, 0x06, 0x43, 0x6f, 0x6c, 0x75, 0x6d, 0x6e, 0x12,
	0x12, 0x0a, 0x04, 0x6e, 0x61, 0x6d, 0x65, 0x18, 0x01, 0x20, 0x01, 0x28, 0x09, 0x52, 0x04, 0x6e,
	0x61, 0x6d, 0x65, 0x12, 0x14, 0x0a, 0x05, 0x74, 0x61, 0x62, 0x6c, 0x65, 0x18, 0x02, 0x20, 0x01,
	0x28, 0x09, 0x52, 0x05, 0x74, 0x61, 0x62, 0x6c, 0x65, 0x2a, 0x91, 0x01, 0x0a, 0x06, 0x4f, 0x70,
	0x54, 0x79, 0x70, 0x65, 0x12, 0x17, 0x0a, 0x13, 0x4f, 0x50, 0x5f, 0x54, 0x59, 0x50, 0x45, 0x5f,
	0x55, 0x4e, 0x53, 0x50, 0x45, 0x43, 0x49, 0x46, 0x49, 0x45, 0x44, 0x10, 0x00, 0x12, 0x12, 0x0a,
	0x0e, 0x4f, 0x50, 0x5f, 0x54, 0x59, 0x50, 0x45, 0x5f, 0x43, 0x52, 0x45, 0x41, 0x54, 0x45, 0x10,
	0x01, 0x12, 0x12, 0x0a, 0x0e, 0x4f, 0x50, 0x5f, 0x54, 0x59, 0x50, 0x45, 0x5f, 0x55, 0x50, 0x44,
	0x41, 0x54, 0x45, 0x10, 0x02, 0x12, 0x12, 0x0a, 0x0e, 0x4f, 0x50, 0x5f, 0x54, 0x59, 0x50, 0x45,
	0x5f, 0x44, 0x45, 0x4c, 0x45, 0x54, 0x45, 0x10, 0x03, 0x12, 0x18, 0x0a, 0x14, 0x4f, 0x50, 0x5f,
	0x54, 0x59, 0x50, 0x45, 0x5f, 0x43, 0x52, 0x45, 0x41, 0x54, 0x45, 0x5f, 0x49, 0x54, 0x45, 0x4d,
	0x53, 0x10, 0x04, 0x12, 0x18, 0x0a, 0x14, 0x4f, 0x50, 0x5f, 0x54, 0x59, 0x50, 0x45, 0x5f, 0x44,
	0x45, 0x4c, 0x45, 0x54, 0x45, 0x5f, 0x49, 0x54, 0x45, 0x4d, 0x53, 0x10, 0x05, 0x42, 0x34, 0x5a,
	0x32, 0x67, 0x69, 0x74, 0x68, 0x75, 0x62, 0x2e, 0x63, 0x6f, 0x6d, 0x2f, 0x68, 0x61, 0x73, 0x68,
	0x69, 0x63, 0x6f, 0x72, 0x70, 0x2f, 0x62, 0x6f, 0x75, 0x6e, 0x64, 0x61, 0x72, 0x79, 0x2f, 0x69,
	0x6e, 0x74, 0x65, 0x72, 0x6e, 0x61, 0x6c, 0x2f, 0x6f, 0x70, 0x6c, 0x6f, 0x67, 0x3b, 0x6f, 0x70,
	0x6c, 0x6f, 0x67, 0x62, 0x06, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x33,
}

var (
	file_controller_storage_oplog_v1_any_operation_proto_rawDescOnce sync.Once
	file_controller_storage_oplog_v1_any_operation_proto_rawDescData = file_controller_storage_oplog_v1_any_operation_proto_rawDesc
)

func file_controller_storage_oplog_v1_any_operation_proto_rawDescGZIP() []byte {
	file_controller_storage_oplog_v1_any_operation_proto_rawDescOnce.Do(func() {
		file_controller_storage_oplog_v1_any_operation_proto_rawDescData = protoimpl.X.CompressGZIP(file_controller_storage_oplog_v1_any_operation_proto_rawDescData)
	})
	return file_controller_storage_oplog_v1_any_operation_proto_rawDescData
}

var file_controller_storage_oplog_v1_any_operation_proto_enumTypes = make([]protoimpl.EnumInfo, 1)
var file_controller_storage_oplog_v1_any_operation_proto_msgTypes = make([]protoimpl.MessageInfo, 8)
var file_controller_storage_oplog_v1_any_operation_proto_goTypes = []interface{}{
	(OpType)(0),                    // 0: controller.storage.oplog.v1.OpType
	(*AnyOperation)(nil),           // 1: controller.storage.oplog.v1.AnyOperation
	(*OperationOptions)(nil),       // 2: controller.storage.oplog.v1.OperationOptions
	(*WithOnConflict)(nil),         // 3: controller.storage.oplog.v1.WithOnConflict
	(*Columns)(nil),                // 4: controller.storage.oplog.v1.Columns
	(*ColumnValue)(nil),            // 5: controller.storage.oplog.v1.ColumnValue
	(*ColumnValues)(nil),           // 6: controller.storage.oplog.v1.ColumnValues
	(*ExprValue)(nil),              // 7: controller.storage.oplog.v1.ExprValue
	(*Column)(nil),                 // 8: controller.storage.oplog.v1.Column
	(*fieldmaskpb.FieldMask)(nil),  // 9: google.protobuf.FieldMask
	(*wrapperspb.UInt32Value)(nil), // 10: google.protobuf.UInt32Value
	(*structpb.Value)(nil),         // 11: google.protobuf.Value
}
var file_controller_storage_oplog_v1_any_operation_proto_depIdxs = []int32{
	0,  // 0: controller.storage.oplog.v1.AnyOperation.operation_type:type_name -> controller.storage.oplog.v1.OpType
	9,  // 1: controller.storage.oplog.v1.AnyOperation.field_mask:type_name -> google.protobuf.FieldMask
	9,  // 2: controller.storage.oplog.v1.AnyOperation.null_mask:type_name -> google.protobuf.FieldMask
	2,  // 3: controller.storage.oplog.v1.AnyOperation.options:type_name -> controller.storage.oplog.v1.OperationOptions
	10, // 4: controller.storage.oplog.v1.OperationOptions.with_version:type_name -> google.protobuf.UInt32Value
	11, // 5: controller.storage.oplog.v1.OperationOptions.with_where_clause_args:type_name -> google.protobuf.Value
	3,  // 6: controller.storage.oplog.v1.OperationOptions.with_on_conflict:type_name -> controller.storage.oplog.v1.WithOnConflict
	4,  // 7: controller.storage.oplog.v1.WithOnConflict.columns:type_name -> controller.storage.oplog.v1.Columns
	6,  // 8: controller.storage.oplog.v1.WithOnConflict.column_values:type_name -> controller.storage.oplog.v1.ColumnValues
	11, // 9: controller.storage.oplog.v1.ColumnValue.raw:type_name -> google.protobuf.Value
	7,  // 10: controller.storage.oplog.v1.ColumnValue.expr_value:type_name -> controller.storage.oplog.v1.ExprValue
	8,  // 11: controller.storage.oplog.v1.ColumnValue.column:type_name -> controller.storage.oplog.v1.Column
	5,  // 12: controller.storage.oplog.v1.ColumnValues.values:type_name -> controller.storage.oplog.v1.ColumnValue
	11, // 13: controller.storage.oplog.v1.ExprValue.args:type_name -> google.protobuf.Value
	14, // [14:14] is the sub-list for method output_type
	14, // [14:14] is the sub-list for method input_type
	14, // [14:14] is the sub-list for extension type_name
	14, // [14:14] is the sub-list for extension extendee
	0,  // [0:14] is the sub-list for field type_name
}

func init() { file_controller_storage_oplog_v1_any_operation_proto_init() }
func file_controller_storage_oplog_v1_any_operation_proto_init() {
	if File_controller_storage_oplog_v1_any_operation_proto != nil {
		return
	}
	if !protoimpl.UnsafeEnabled {
		file_controller_storage_oplog_v1_any_operation_proto_msgTypes[0].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*AnyOperation); i {
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
		file_controller_storage_oplog_v1_any_operation_proto_msgTypes[1].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*OperationOptions); i {
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
		file_controller_storage_oplog_v1_any_operation_proto_msgTypes[2].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*WithOnConflict); i {
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
		file_controller_storage_oplog_v1_any_operation_proto_msgTypes[3].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*Columns); i {
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
		file_controller_storage_oplog_v1_any_operation_proto_msgTypes[4].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*ColumnValue); i {
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
		file_controller_storage_oplog_v1_any_operation_proto_msgTypes[5].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*ColumnValues); i {
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
		file_controller_storage_oplog_v1_any_operation_proto_msgTypes[6].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*ExprValue); i {
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
		file_controller_storage_oplog_v1_any_operation_proto_msgTypes[7].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*Column); i {
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
	file_controller_storage_oplog_v1_any_operation_proto_msgTypes[2].OneofWrappers = []interface{}{
		(*WithOnConflict_Constraint)(nil),
		(*WithOnConflict_Columns)(nil),
		(*WithOnConflict_DoNothing)(nil),
		(*WithOnConflict_UpdateAll)(nil),
		(*WithOnConflict_ColumnValues)(nil),
	}
	file_controller_storage_oplog_v1_any_operation_proto_msgTypes[4].OneofWrappers = []interface{}{
		(*ColumnValue_Raw)(nil),
		(*ColumnValue_ExprValue)(nil),
		(*ColumnValue_Column)(nil),
	}
	type x struct{}
	out := protoimpl.TypeBuilder{
		File: protoimpl.DescBuilder{
			GoPackagePath: reflect.TypeOf(x{}).PkgPath(),
			RawDescriptor: file_controller_storage_oplog_v1_any_operation_proto_rawDesc,
			NumEnums:      1,
			NumMessages:   8,
			NumExtensions: 0,
			NumServices:   0,
		},
		GoTypes:           file_controller_storage_oplog_v1_any_operation_proto_goTypes,
		DependencyIndexes: file_controller_storage_oplog_v1_any_operation_proto_depIdxs,
		EnumInfos:         file_controller_storage_oplog_v1_any_operation_proto_enumTypes,
		MessageInfos:      file_controller_storage_oplog_v1_any_operation_proto_msgTypes,
	}.Build()
	File_controller_storage_oplog_v1_any_operation_proto = out.File
	file_controller_storage_oplog_v1_any_operation_proto_rawDesc = nil
	file_controller_storage_oplog_v1_any_operation_proto_goTypes = nil
	file_controller_storage_oplog_v1_any_operation_proto_depIdxs = nil
}
