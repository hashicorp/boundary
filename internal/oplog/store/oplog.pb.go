// Code generated by protoc-gen-gogo. DO NOT EDIT.
// source: oplog.proto

package store

import (
	fmt "fmt"
	proto "github.com/gogo/protobuf/proto"
	types "github.com/gogo/protobuf/types"
	io "io"
	math "math"
	math_bits "math/bits"
)

// Reference imports to suppress errors if they are not otherwise used.
var _ = proto.Marshal
var _ = fmt.Errorf
var _ = math.Inf

// This is a compile-time assertion to ensure that this generated file
// is compatible with the proto package it is being compiled against.
// A compilation error at this line likely means your copy of the
// proto package needs to be updated.
const _ = proto.GoGoProtoPackageIsVersion3 // please upgrade the proto package

type Timestamp struct {
	Timestamp *types.Timestamp `protobuf:"bytes,1,opt,name=timestamp,proto3" json:"timestamp,omitempty"`
}

func (m *Timestamp) Reset()         { *m = Timestamp{} }
func (m *Timestamp) String() string { return proto.CompactTextString(m) }
func (*Timestamp) ProtoMessage()    {}
func (*Timestamp) Descriptor() ([]byte, []int) {
	return fileDescriptor_5325dd45b40ec7e8, []int{0}
}
func (m *Timestamp) XXX_Unmarshal(b []byte) error {
	return m.Unmarshal(b)
}
func (m *Timestamp) XXX_Marshal(b []byte, deterministic bool) ([]byte, error) {
	if deterministic {
		return xxx_messageInfo_Timestamp.Marshal(b, m, deterministic)
	} else {
		b = b[:cap(b)]
		n, err := m.MarshalToSizedBuffer(b)
		if err != nil {
			return nil, err
		}
		return b[:n], nil
	}
}
func (m *Timestamp) XXX_Merge(src proto.Message) {
	xxx_messageInfo_Timestamp.Merge(m, src)
}
func (m *Timestamp) XXX_Size() int {
	return m.Size()
}
func (m *Timestamp) XXX_DiscardUnknown() {
	xxx_messageInfo_Timestamp.DiscardUnknown(m)
}

var xxx_messageInfo_Timestamp proto.InternalMessageInfo

func (m *Timestamp) GetTimestamp() *types.Timestamp {
	if m != nil {
		return m.Timestamp
	}
	return nil
}

type Entry struct {
	// @inject_tag: gorm:"primary_key"
	Id uint32 `protobuf:"varint,1,opt,name=id,proto3" json:"id,omitempty" gorm:"primary_key"`
	// @inject_tag: gorm:"not_null;type:TIMESTAMP"
	CreatedAt *Timestamp `protobuf:"bytes,2,opt,name=created_at,json=createdAt,proto3" json:"created_at,omitempty" gorm:"not_null;type:TIMESTAMP"`
	// @inject_tag: gorm:"not_null;type:TIMESTAMP"
	UpdatedAt *Timestamp `protobuf:"bytes,3,opt,name=updated_at,json=updatedAt,proto3" json:"updated_at,omitempty" gorm:"not_null;type:TIMESTAMP"`
	// @inject_tat: gorm:"not_null"
	Hmac []byte `protobuf:"bytes,4,opt,name=hmac,proto3" json:"hmac,omitempty"`
	// @inject_tat: gorm:"not_null"
	Kid string `protobuf:"bytes,5,opt,name=kid,proto3" json:"kid,omitempty"`
	// @inject_tat: gorm:"not_null"
	BoundedContext string `protobuf:"bytes,6,opt,name=bounded_context,json=boundedContext,proto3" json:"bounded_context,omitempty"`
	// one to many relationship
	// @inject_tag: gorm:"foreignkey:entry_id"
	Metadata []*Metadata `protobuf:"bytes,7,rep,name=metadata,proto3" json:"metadata,omitempty" gorm:"foreignkey:entry_id"`
	// @inject_tat: gorm:"not_null"
	Data []byte `protobuf:"bytes,8,opt,name=data,proto3" json:"data,omitempty"`
}

func (m *Entry) Reset()         { *m = Entry{} }
func (m *Entry) String() string { return proto.CompactTextString(m) }
func (*Entry) ProtoMessage()    {}
func (*Entry) Descriptor() ([]byte, []int) {
	return fileDescriptor_5325dd45b40ec7e8, []int{1}
}
func (m *Entry) XXX_Unmarshal(b []byte) error {
	return m.Unmarshal(b)
}
func (m *Entry) XXX_Marshal(b []byte, deterministic bool) ([]byte, error) {
	if deterministic {
		return xxx_messageInfo_Entry.Marshal(b, m, deterministic)
	} else {
		b = b[:cap(b)]
		n, err := m.MarshalToSizedBuffer(b)
		if err != nil {
			return nil, err
		}
		return b[:n], nil
	}
}
func (m *Entry) XXX_Merge(src proto.Message) {
	xxx_messageInfo_Entry.Merge(m, src)
}
func (m *Entry) XXX_Size() int {
	return m.Size()
}
func (m *Entry) XXX_DiscardUnknown() {
	xxx_messageInfo_Entry.DiscardUnknown(m)
}

var xxx_messageInfo_Entry proto.InternalMessageInfo

func (m *Entry) GetId() uint32 {
	if m != nil {
		return m.Id
	}
	return 0
}

func (m *Entry) GetCreatedAt() *Timestamp {
	if m != nil {
		return m.CreatedAt
	}
	return nil
}

func (m *Entry) GetUpdatedAt() *Timestamp {
	if m != nil {
		return m.UpdatedAt
	}
	return nil
}

func (m *Entry) GetHmac() []byte {
	if m != nil {
		return m.Hmac
	}
	return nil
}

func (m *Entry) GetKid() string {
	if m != nil {
		return m.Kid
	}
	return ""
}

func (m *Entry) GetBoundedContext() string {
	if m != nil {
		return m.BoundedContext
	}
	return ""
}

func (m *Entry) GetMetadata() []*Metadata {
	if m != nil {
		return m.Metadata
	}
	return nil
}

func (m *Entry) GetData() []byte {
	if m != nil {
		return m.Data
	}
	return nil
}

type Ticket struct {
	// @inject_tag: gorm:"primary_key"
	Id uint32 `protobuf:"varint,1,opt,name=id,proto3" json:"id,omitempty" gorm:"primary_key"`
	// @inject_tag: gorm:"not_null;type:TIMESTAMP"
	CreatedAt *Timestamp `protobuf:"bytes,2,opt,name=created_at,json=createdAt,proto3" json:"created_at,omitempty" gorm:"not_null;type:TIMESTAMP"`
	// @inject_tag: gorm:"not_null;type:TIMESTAMP"
	UpdatedAt *Timestamp `protobuf:"bytes,3,opt,name=updated_at,json=updatedAt,proto3" json:"updated_at,omitempty" gorm:"not_null;type:TIMESTAMP"`
	// @inject_tat: gorm:"not_null"
	Name string `protobuf:"bytes,6,opt,name=name,proto3" json:"name,omitempty"`
	// @inject_tat: gorm:"not_null;default:'1'"
	Version uint32 `protobuf:"varint,7,opt,name=version,proto3" json:"version,omitempty"`
}

func (m *Ticket) Reset()         { *m = Ticket{} }
func (m *Ticket) String() string { return proto.CompactTextString(m) }
func (*Ticket) ProtoMessage()    {}
func (*Ticket) Descriptor() ([]byte, []int) {
	return fileDescriptor_5325dd45b40ec7e8, []int{2}
}
func (m *Ticket) XXX_Unmarshal(b []byte) error {
	return m.Unmarshal(b)
}
func (m *Ticket) XXX_Marshal(b []byte, deterministic bool) ([]byte, error) {
	if deterministic {
		return xxx_messageInfo_Ticket.Marshal(b, m, deterministic)
	} else {
		b = b[:cap(b)]
		n, err := m.MarshalToSizedBuffer(b)
		if err != nil {
			return nil, err
		}
		return b[:n], nil
	}
}
func (m *Ticket) XXX_Merge(src proto.Message) {
	xxx_messageInfo_Ticket.Merge(m, src)
}
func (m *Ticket) XXX_Size() int {
	return m.Size()
}
func (m *Ticket) XXX_DiscardUnknown() {
	xxx_messageInfo_Ticket.DiscardUnknown(m)
}

var xxx_messageInfo_Ticket proto.InternalMessageInfo

func (m *Ticket) GetId() uint32 {
	if m != nil {
		return m.Id
	}
	return 0
}

func (m *Ticket) GetCreatedAt() *Timestamp {
	if m != nil {
		return m.CreatedAt
	}
	return nil
}

func (m *Ticket) GetUpdatedAt() *Timestamp {
	if m != nil {
		return m.UpdatedAt
	}
	return nil
}

func (m *Ticket) GetName() string {
	if m != nil {
		return m.Name
	}
	return ""
}

func (m *Ticket) GetVersion() uint32 {
	if m != nil {
		return m.Version
	}
	return 0
}

type Metadata struct {
	// @inject_tag: gorm:"primary_key"
	Id uint32 `protobuf:"varint,1,opt,name=id,proto3" json:"id,omitempty" gorm:"primary_key"`
	// @inject_tag: gorm:"not_null;type:TIMESTAMP"
	CreatedAt *Timestamp `protobuf:"bytes,2,opt,name=created_at,json=createdAt,proto3" json:"created_at,omitempty" gorm:"not_null;type:TIMESTAMP"`
	EntryId   uint32     `protobuf:"varint,3,opt,name=entry_id,json=entryId,proto3" json:"entry_id,omitempty"`
	// @inject_tag: gorm:"foreignkey:EntryId"
	Entry *Entry `protobuf:"bytes,4,opt,name=entry,proto3" json:"entry,omitempty" gorm:"foreignkey:EntryId"`
	// @inject_tag: gorm:"not_null"
	Key string `protobuf:"bytes,5,opt,name=key,proto3" json:"key,omitempty" gorm:"not_null"`
	// @inject_tag: gorm:"not_null"
	Value string `protobuf:"bytes,6,opt,name=value,proto3" json:"value,omitempty" gorm:"not_null"`
}

func (m *Metadata) Reset()         { *m = Metadata{} }
func (m *Metadata) String() string { return proto.CompactTextString(m) }
func (*Metadata) ProtoMessage()    {}
func (*Metadata) Descriptor() ([]byte, []int) {
	return fileDescriptor_5325dd45b40ec7e8, []int{3}
}
func (m *Metadata) XXX_Unmarshal(b []byte) error {
	return m.Unmarshal(b)
}
func (m *Metadata) XXX_Marshal(b []byte, deterministic bool) ([]byte, error) {
	if deterministic {
		return xxx_messageInfo_Metadata.Marshal(b, m, deterministic)
	} else {
		b = b[:cap(b)]
		n, err := m.MarshalToSizedBuffer(b)
		if err != nil {
			return nil, err
		}
		return b[:n], nil
	}
}
func (m *Metadata) XXX_Merge(src proto.Message) {
	xxx_messageInfo_Metadata.Merge(m, src)
}
func (m *Metadata) XXX_Size() int {
	return m.Size()
}
func (m *Metadata) XXX_DiscardUnknown() {
	xxx_messageInfo_Metadata.DiscardUnknown(m)
}

var xxx_messageInfo_Metadata proto.InternalMessageInfo

func (m *Metadata) GetId() uint32 {
	if m != nil {
		return m.Id
	}
	return 0
}

func (m *Metadata) GetCreatedAt() *Timestamp {
	if m != nil {
		return m.CreatedAt
	}
	return nil
}

func (m *Metadata) GetEntryId() uint32 {
	if m != nil {
		return m.EntryId
	}
	return 0
}

func (m *Metadata) GetEntry() *Entry {
	if m != nil {
		return m.Entry
	}
	return nil
}

func (m *Metadata) GetKey() string {
	if m != nil {
		return m.Key
	}
	return ""
}

func (m *Metadata) GetValue() string {
	if m != nil {
		return m.Value
	}
	return ""
}

func init() {
	proto.RegisterType((*Timestamp)(nil), "hashicorp.watchtower.controller.v1.Timestamp")
	proto.RegisterType((*Entry)(nil), "hashicorp.watchtower.controller.v1.Entry")
	proto.RegisterType((*Ticket)(nil), "hashicorp.watchtower.controller.v1.Ticket")
	proto.RegisterType((*Metadata)(nil), "hashicorp.watchtower.controller.v1.Metadata")
}

func init() { proto.RegisterFile("oplog.proto", fileDescriptor_5325dd45b40ec7e8) }

var fileDescriptor_5325dd45b40ec7e8 = []byte{
	// 454 bytes of a gzipped FileDescriptorProto
	0x1f, 0x8b, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0xff, 0xd4, 0x94, 0xbd, 0x8e, 0xd3, 0x40,
	0x10, 0xc7, 0xe3, 0xe4, 0xf2, 0xb5, 0xe1, 0x0e, 0xb4, 0xa2, 0x30, 0x57, 0x98, 0xc8, 0x0d, 0x41,
	0x82, 0xb5, 0x08, 0x0d, 0x82, 0x02, 0x1d, 0xe8, 0x24, 0x90, 0xa0, 0xb1, 0x52, 0xd1, 0x44, 0x1b,
	0xef, 0x10, 0xaf, 0xce, 0xf6, 0x5a, 0x9b, 0x71, 0x8e, 0xbc, 0x05, 0x8f, 0x45, 0x79, 0x25, 0xe5,
	0x29, 0x69, 0x79, 0x08, 0xe4, 0xf1, 0xc7, 0xd1, 0x71, 0x42, 0xa2, 0xb8, 0xc6, 0x9a, 0x99, 0xdd,
	0xf9, 0xcd, 0x87, 0xfe, 0x5e, 0x36, 0x31, 0x79, 0x62, 0xd6, 0x22, 0xb7, 0x06, 0x0d, 0xf7, 0x63,
	0xb9, 0x89, 0x75, 0x64, 0x6c, 0x2e, 0x2e, 0x25, 0x46, 0x31, 0x9a, 0x4b, 0xb0, 0x22, 0x32, 0x19,
	0x5a, 0x93, 0x24, 0x60, 0xc5, 0xf6, 0xc5, 0xe9, 0xe3, 0xb5, 0x31, 0xeb, 0x04, 0x02, 0xca, 0x58,
	0x15, 0x5f, 0x03, 0xd4, 0x29, 0x6c, 0x50, 0xa6, 0x79, 0x05, 0xf1, 0xcf, 0xd9, 0x78, 0xd1, 0x84,
	0xf8, 0x2b, 0x36, 0x6e, 0xcf, 0x5d, 0x67, 0xea, 0xcc, 0x26, 0xf3, 0x53, 0x51, 0x11, 0x44, 0x43,
	0x10, 0xed, 0xf5, 0xf0, 0xe6, 0xb2, 0x7f, 0xdd, 0x65, 0xfd, 0xf3, 0x0c, 0xed, 0x8e, 0x9f, 0xb0,
	0xae, 0x56, 0x94, 0x7c, 0x1c, 0x76, 0xb5, 0xe2, 0x9f, 0x18, 0x8b, 0x2c, 0x48, 0x04, 0xb5, 0x94,
	0xe8, 0x76, 0x09, 0xfa, 0x5c, 0xfc, 0xbd, 0xf5, 0x3f, 0xeb, 0xd4, 0x80, 0x33, 0x2c, 0x69, 0x45,
	0xae, 0x1a, 0x5a, 0xef, 0x9f, 0x68, 0x35, 0xe0, 0x0c, 0x39, 0x67, 0x47, 0x71, 0x2a, 0x23, 0xf7,
	0x68, 0xea, 0xcc, 0xee, 0x85, 0x64, 0xf3, 0x07, 0xac, 0x77, 0xa1, 0x95, 0xdb, 0x9f, 0x3a, 0xb3,
	0x71, 0x58, 0x9a, 0xfc, 0x09, 0xbb, 0xbf, 0x32, 0x45, 0xa6, 0x40, 0x2d, 0x4b, 0x26, 0x7c, 0x43,
	0x77, 0x40, 0xa7, 0x27, 0x75, 0xf8, 0x7d, 0x15, 0xe5, 0x1f, 0xd8, 0x28, 0x05, 0x94, 0x4a, 0xa2,
	0x74, 0x87, 0xd3, 0xde, 0x6c, 0x32, 0x7f, 0x76, 0x9b, 0xd6, 0x3e, 0xd7, 0x39, 0x61, 0x9b, 0x5d,
	0x36, 0x46, 0x94, 0x51, 0xd5, 0x58, 0x69, 0xfb, 0x7b, 0x87, 0x0d, 0x16, 0x3a, 0xba, 0x00, 0xbc,
	0x6b, 0x3b, 0xce, 0x64, 0x0a, 0xf5, 0xca, 0xc8, 0xe6, 0x2e, 0x1b, 0x6e, 0xc1, 0x6e, 0xb4, 0xc9,
	0xdc, 0x21, 0x0d, 0xd1, 0xb8, 0xfe, 0x2f, 0x87, 0x8d, 0x9a, 0x7d, 0xfc, 0xe7, 0x31, 0x1f, 0xb1,
	0x11, 0x94, 0x8a, 0x5d, 0x6a, 0x45, 0x43, 0x1e, 0x87, 0x43, 0xf2, 0x3f, 0x2a, 0xfe, 0x96, 0xf5,
	0xc9, 0x24, 0x61, 0x4c, 0xe6, 0x4f, 0x6f, 0x53, 0x83, 0xd4, 0x1f, 0x56, 0x79, 0x24, 0x22, 0xd8,
	0xb5, 0x22, 0x82, 0x1d, 0x7f, 0xc8, 0xfa, 0x5b, 0x99, 0x14, 0xcd, 0x1e, 0x2a, 0xe7, 0xdd, 0xe2,
	0xc7, 0xde, 0x73, 0xae, 0xf6, 0x9e, 0x73, 0xbd, 0xf7, 0x9c, 0xef, 0x07, 0xaf, 0x73, 0x75, 0xf0,
	0x3a, 0x3f, 0x0f, 0x5e, 0xe7, 0xcb, 0xeb, 0xb5, 0xc6, 0xb8, 0x58, 0x89, 0xc8, 0xa4, 0x41, 0x5b,
	0x3d, 0xb8, 0xa9, 0x1e, 0xe8, 0x0c, 0xc1, 0x66, 0x32, 0x09, 0xe8, 0x49, 0x08, 0x36, 0x68, 0x2c,
	0xbc, 0xa1, 0xef, 0x6a, 0x40, 0xff, 0xea, 0xcb, 0xdf, 0x01, 0x00, 0x00, 0xff, 0xff, 0x99, 0x5a,
	0x9b, 0xe4, 0x2e, 0x04, 0x00, 0x00,
}

func (m *Timestamp) Marshal() (dAtA []byte, err error) {
	size := m.Size()
	dAtA = make([]byte, size)
	n, err := m.MarshalToSizedBuffer(dAtA[:size])
	if err != nil {
		return nil, err
	}
	return dAtA[:n], nil
}

func (m *Timestamp) MarshalTo(dAtA []byte) (int, error) {
	size := m.Size()
	return m.MarshalToSizedBuffer(dAtA[:size])
}

func (m *Timestamp) MarshalToSizedBuffer(dAtA []byte) (int, error) {
	i := len(dAtA)
	_ = i
	var l int
	_ = l
	if m.Timestamp != nil {
		{
			size, err := m.Timestamp.MarshalToSizedBuffer(dAtA[:i])
			if err != nil {
				return 0, err
			}
			i -= size
			i = encodeVarintOplog(dAtA, i, uint64(size))
		}
		i--
		dAtA[i] = 0xa
	}
	return len(dAtA) - i, nil
}

func (m *Entry) Marshal() (dAtA []byte, err error) {
	size := m.Size()
	dAtA = make([]byte, size)
	n, err := m.MarshalToSizedBuffer(dAtA[:size])
	if err != nil {
		return nil, err
	}
	return dAtA[:n], nil
}

func (m *Entry) MarshalTo(dAtA []byte) (int, error) {
	size := m.Size()
	return m.MarshalToSizedBuffer(dAtA[:size])
}

func (m *Entry) MarshalToSizedBuffer(dAtA []byte) (int, error) {
	i := len(dAtA)
	_ = i
	var l int
	_ = l
	if len(m.Data) > 0 {
		i -= len(m.Data)
		copy(dAtA[i:], m.Data)
		i = encodeVarintOplog(dAtA, i, uint64(len(m.Data)))
		i--
		dAtA[i] = 0x42
	}
	if len(m.Metadata) > 0 {
		for iNdEx := len(m.Metadata) - 1; iNdEx >= 0; iNdEx-- {
			{
				size, err := m.Metadata[iNdEx].MarshalToSizedBuffer(dAtA[:i])
				if err != nil {
					return 0, err
				}
				i -= size
				i = encodeVarintOplog(dAtA, i, uint64(size))
			}
			i--
			dAtA[i] = 0x3a
		}
	}
	if len(m.BoundedContext) > 0 {
		i -= len(m.BoundedContext)
		copy(dAtA[i:], m.BoundedContext)
		i = encodeVarintOplog(dAtA, i, uint64(len(m.BoundedContext)))
		i--
		dAtA[i] = 0x32
	}
	if len(m.Kid) > 0 {
		i -= len(m.Kid)
		copy(dAtA[i:], m.Kid)
		i = encodeVarintOplog(dAtA, i, uint64(len(m.Kid)))
		i--
		dAtA[i] = 0x2a
	}
	if len(m.Hmac) > 0 {
		i -= len(m.Hmac)
		copy(dAtA[i:], m.Hmac)
		i = encodeVarintOplog(dAtA, i, uint64(len(m.Hmac)))
		i--
		dAtA[i] = 0x22
	}
	if m.UpdatedAt != nil {
		{
			size, err := m.UpdatedAt.MarshalToSizedBuffer(dAtA[:i])
			if err != nil {
				return 0, err
			}
			i -= size
			i = encodeVarintOplog(dAtA, i, uint64(size))
		}
		i--
		dAtA[i] = 0x1a
	}
	if m.CreatedAt != nil {
		{
			size, err := m.CreatedAt.MarshalToSizedBuffer(dAtA[:i])
			if err != nil {
				return 0, err
			}
			i -= size
			i = encodeVarintOplog(dAtA, i, uint64(size))
		}
		i--
		dAtA[i] = 0x12
	}
	if m.Id != 0 {
		i = encodeVarintOplog(dAtA, i, uint64(m.Id))
		i--
		dAtA[i] = 0x8
	}
	return len(dAtA) - i, nil
}

func (m *Ticket) Marshal() (dAtA []byte, err error) {
	size := m.Size()
	dAtA = make([]byte, size)
	n, err := m.MarshalToSizedBuffer(dAtA[:size])
	if err != nil {
		return nil, err
	}
	return dAtA[:n], nil
}

func (m *Ticket) MarshalTo(dAtA []byte) (int, error) {
	size := m.Size()
	return m.MarshalToSizedBuffer(dAtA[:size])
}

func (m *Ticket) MarshalToSizedBuffer(dAtA []byte) (int, error) {
	i := len(dAtA)
	_ = i
	var l int
	_ = l
	if m.Version != 0 {
		i = encodeVarintOplog(dAtA, i, uint64(m.Version))
		i--
		dAtA[i] = 0x38
	}
	if len(m.Name) > 0 {
		i -= len(m.Name)
		copy(dAtA[i:], m.Name)
		i = encodeVarintOplog(dAtA, i, uint64(len(m.Name)))
		i--
		dAtA[i] = 0x32
	}
	if m.UpdatedAt != nil {
		{
			size, err := m.UpdatedAt.MarshalToSizedBuffer(dAtA[:i])
			if err != nil {
				return 0, err
			}
			i -= size
			i = encodeVarintOplog(dAtA, i, uint64(size))
		}
		i--
		dAtA[i] = 0x1a
	}
	if m.CreatedAt != nil {
		{
			size, err := m.CreatedAt.MarshalToSizedBuffer(dAtA[:i])
			if err != nil {
				return 0, err
			}
			i -= size
			i = encodeVarintOplog(dAtA, i, uint64(size))
		}
		i--
		dAtA[i] = 0x12
	}
	if m.Id != 0 {
		i = encodeVarintOplog(dAtA, i, uint64(m.Id))
		i--
		dAtA[i] = 0x8
	}
	return len(dAtA) - i, nil
}

func (m *Metadata) Marshal() (dAtA []byte, err error) {
	size := m.Size()
	dAtA = make([]byte, size)
	n, err := m.MarshalToSizedBuffer(dAtA[:size])
	if err != nil {
		return nil, err
	}
	return dAtA[:n], nil
}

func (m *Metadata) MarshalTo(dAtA []byte) (int, error) {
	size := m.Size()
	return m.MarshalToSizedBuffer(dAtA[:size])
}

func (m *Metadata) MarshalToSizedBuffer(dAtA []byte) (int, error) {
	i := len(dAtA)
	_ = i
	var l int
	_ = l
	if len(m.Value) > 0 {
		i -= len(m.Value)
		copy(dAtA[i:], m.Value)
		i = encodeVarintOplog(dAtA, i, uint64(len(m.Value)))
		i--
		dAtA[i] = 0x32
	}
	if len(m.Key) > 0 {
		i -= len(m.Key)
		copy(dAtA[i:], m.Key)
		i = encodeVarintOplog(dAtA, i, uint64(len(m.Key)))
		i--
		dAtA[i] = 0x2a
	}
	if m.Entry != nil {
		{
			size, err := m.Entry.MarshalToSizedBuffer(dAtA[:i])
			if err != nil {
				return 0, err
			}
			i -= size
			i = encodeVarintOplog(dAtA, i, uint64(size))
		}
		i--
		dAtA[i] = 0x22
	}
	if m.EntryId != 0 {
		i = encodeVarintOplog(dAtA, i, uint64(m.EntryId))
		i--
		dAtA[i] = 0x18
	}
	if m.CreatedAt != nil {
		{
			size, err := m.CreatedAt.MarshalToSizedBuffer(dAtA[:i])
			if err != nil {
				return 0, err
			}
			i -= size
			i = encodeVarintOplog(dAtA, i, uint64(size))
		}
		i--
		dAtA[i] = 0x12
	}
	if m.Id != 0 {
		i = encodeVarintOplog(dAtA, i, uint64(m.Id))
		i--
		dAtA[i] = 0x8
	}
	return len(dAtA) - i, nil
}

func encodeVarintOplog(dAtA []byte, offset int, v uint64) int {
	offset -= sovOplog(v)
	base := offset
	for v >= 1<<7 {
		dAtA[offset] = uint8(v&0x7f | 0x80)
		v >>= 7
		offset++
	}
	dAtA[offset] = uint8(v)
	return base
}
func (m *Timestamp) Size() (n int) {
	if m == nil {
		return 0
	}
	var l int
	_ = l
	if m.Timestamp != nil {
		l = m.Timestamp.Size()
		n += 1 + l + sovOplog(uint64(l))
	}
	return n
}

func (m *Entry) Size() (n int) {
	if m == nil {
		return 0
	}
	var l int
	_ = l
	if m.Id != 0 {
		n += 1 + sovOplog(uint64(m.Id))
	}
	if m.CreatedAt != nil {
		l = m.CreatedAt.Size()
		n += 1 + l + sovOplog(uint64(l))
	}
	if m.UpdatedAt != nil {
		l = m.UpdatedAt.Size()
		n += 1 + l + sovOplog(uint64(l))
	}
	l = len(m.Hmac)
	if l > 0 {
		n += 1 + l + sovOplog(uint64(l))
	}
	l = len(m.Kid)
	if l > 0 {
		n += 1 + l + sovOplog(uint64(l))
	}
	l = len(m.BoundedContext)
	if l > 0 {
		n += 1 + l + sovOplog(uint64(l))
	}
	if len(m.Metadata) > 0 {
		for _, e := range m.Metadata {
			l = e.Size()
			n += 1 + l + sovOplog(uint64(l))
		}
	}
	l = len(m.Data)
	if l > 0 {
		n += 1 + l + sovOplog(uint64(l))
	}
	return n
}

func (m *Ticket) Size() (n int) {
	if m == nil {
		return 0
	}
	var l int
	_ = l
	if m.Id != 0 {
		n += 1 + sovOplog(uint64(m.Id))
	}
	if m.CreatedAt != nil {
		l = m.CreatedAt.Size()
		n += 1 + l + sovOplog(uint64(l))
	}
	if m.UpdatedAt != nil {
		l = m.UpdatedAt.Size()
		n += 1 + l + sovOplog(uint64(l))
	}
	l = len(m.Name)
	if l > 0 {
		n += 1 + l + sovOplog(uint64(l))
	}
	if m.Version != 0 {
		n += 1 + sovOplog(uint64(m.Version))
	}
	return n
}

func (m *Metadata) Size() (n int) {
	if m == nil {
		return 0
	}
	var l int
	_ = l
	if m.Id != 0 {
		n += 1 + sovOplog(uint64(m.Id))
	}
	if m.CreatedAt != nil {
		l = m.CreatedAt.Size()
		n += 1 + l + sovOplog(uint64(l))
	}
	if m.EntryId != 0 {
		n += 1 + sovOplog(uint64(m.EntryId))
	}
	if m.Entry != nil {
		l = m.Entry.Size()
		n += 1 + l + sovOplog(uint64(l))
	}
	l = len(m.Key)
	if l > 0 {
		n += 1 + l + sovOplog(uint64(l))
	}
	l = len(m.Value)
	if l > 0 {
		n += 1 + l + sovOplog(uint64(l))
	}
	return n
}

func sovOplog(x uint64) (n int) {
	return (math_bits.Len64(x|1) + 6) / 7
}
func sozOplog(x uint64) (n int) {
	return sovOplog(uint64((x << 1) ^ uint64((int64(x) >> 63))))
}
func (m *Timestamp) Unmarshal(dAtA []byte) error {
	l := len(dAtA)
	iNdEx := 0
	for iNdEx < l {
		preIndex := iNdEx
		var wire uint64
		for shift := uint(0); ; shift += 7 {
			if shift >= 64 {
				return ErrIntOverflowOplog
			}
			if iNdEx >= l {
				return io.ErrUnexpectedEOF
			}
			b := dAtA[iNdEx]
			iNdEx++
			wire |= uint64(b&0x7F) << shift
			if b < 0x80 {
				break
			}
		}
		fieldNum := int32(wire >> 3)
		wireType := int(wire & 0x7)
		if wireType == 4 {
			return fmt.Errorf("proto: Timestamp: wiretype end group for non-group")
		}
		if fieldNum <= 0 {
			return fmt.Errorf("proto: Timestamp: illegal tag %d (wire type %d)", fieldNum, wire)
		}
		switch fieldNum {
		case 1:
			if wireType != 2 {
				return fmt.Errorf("proto: wrong wireType = %d for field Timestamp", wireType)
			}
			var msglen int
			for shift := uint(0); ; shift += 7 {
				if shift >= 64 {
					return ErrIntOverflowOplog
				}
				if iNdEx >= l {
					return io.ErrUnexpectedEOF
				}
				b := dAtA[iNdEx]
				iNdEx++
				msglen |= int(b&0x7F) << shift
				if b < 0x80 {
					break
				}
			}
			if msglen < 0 {
				return ErrInvalidLengthOplog
			}
			postIndex := iNdEx + msglen
			if postIndex < 0 {
				return ErrInvalidLengthOplog
			}
			if postIndex > l {
				return io.ErrUnexpectedEOF
			}
			if m.Timestamp == nil {
				m.Timestamp = &types.Timestamp{}
			}
			if err := m.Timestamp.Unmarshal(dAtA[iNdEx:postIndex]); err != nil {
				return err
			}
			iNdEx = postIndex
		default:
			iNdEx = preIndex
			skippy, err := skipOplog(dAtA[iNdEx:])
			if err != nil {
				return err
			}
			if skippy < 0 {
				return ErrInvalidLengthOplog
			}
			if (iNdEx + skippy) < 0 {
				return ErrInvalidLengthOplog
			}
			if (iNdEx + skippy) > l {
				return io.ErrUnexpectedEOF
			}
			iNdEx += skippy
		}
	}

	if iNdEx > l {
		return io.ErrUnexpectedEOF
	}
	return nil
}
func (m *Entry) Unmarshal(dAtA []byte) error {
	l := len(dAtA)
	iNdEx := 0
	for iNdEx < l {
		preIndex := iNdEx
		var wire uint64
		for shift := uint(0); ; shift += 7 {
			if shift >= 64 {
				return ErrIntOverflowOplog
			}
			if iNdEx >= l {
				return io.ErrUnexpectedEOF
			}
			b := dAtA[iNdEx]
			iNdEx++
			wire |= uint64(b&0x7F) << shift
			if b < 0x80 {
				break
			}
		}
		fieldNum := int32(wire >> 3)
		wireType := int(wire & 0x7)
		if wireType == 4 {
			return fmt.Errorf("proto: Entry: wiretype end group for non-group")
		}
		if fieldNum <= 0 {
			return fmt.Errorf("proto: Entry: illegal tag %d (wire type %d)", fieldNum, wire)
		}
		switch fieldNum {
		case 1:
			if wireType != 0 {
				return fmt.Errorf("proto: wrong wireType = %d for field Id", wireType)
			}
			m.Id = 0
			for shift := uint(0); ; shift += 7 {
				if shift >= 64 {
					return ErrIntOverflowOplog
				}
				if iNdEx >= l {
					return io.ErrUnexpectedEOF
				}
				b := dAtA[iNdEx]
				iNdEx++
				m.Id |= uint32(b&0x7F) << shift
				if b < 0x80 {
					break
				}
			}
		case 2:
			if wireType != 2 {
				return fmt.Errorf("proto: wrong wireType = %d for field CreatedAt", wireType)
			}
			var msglen int
			for shift := uint(0); ; shift += 7 {
				if shift >= 64 {
					return ErrIntOverflowOplog
				}
				if iNdEx >= l {
					return io.ErrUnexpectedEOF
				}
				b := dAtA[iNdEx]
				iNdEx++
				msglen |= int(b&0x7F) << shift
				if b < 0x80 {
					break
				}
			}
			if msglen < 0 {
				return ErrInvalidLengthOplog
			}
			postIndex := iNdEx + msglen
			if postIndex < 0 {
				return ErrInvalidLengthOplog
			}
			if postIndex > l {
				return io.ErrUnexpectedEOF
			}
			if m.CreatedAt == nil {
				m.CreatedAt = &Timestamp{}
			}
			if err := m.CreatedAt.Unmarshal(dAtA[iNdEx:postIndex]); err != nil {
				return err
			}
			iNdEx = postIndex
		case 3:
			if wireType != 2 {
				return fmt.Errorf("proto: wrong wireType = %d for field UpdatedAt", wireType)
			}
			var msglen int
			for shift := uint(0); ; shift += 7 {
				if shift >= 64 {
					return ErrIntOverflowOplog
				}
				if iNdEx >= l {
					return io.ErrUnexpectedEOF
				}
				b := dAtA[iNdEx]
				iNdEx++
				msglen |= int(b&0x7F) << shift
				if b < 0x80 {
					break
				}
			}
			if msglen < 0 {
				return ErrInvalidLengthOplog
			}
			postIndex := iNdEx + msglen
			if postIndex < 0 {
				return ErrInvalidLengthOplog
			}
			if postIndex > l {
				return io.ErrUnexpectedEOF
			}
			if m.UpdatedAt == nil {
				m.UpdatedAt = &Timestamp{}
			}
			if err := m.UpdatedAt.Unmarshal(dAtA[iNdEx:postIndex]); err != nil {
				return err
			}
			iNdEx = postIndex
		case 4:
			if wireType != 2 {
				return fmt.Errorf("proto: wrong wireType = %d for field Hmac", wireType)
			}
			var byteLen int
			for shift := uint(0); ; shift += 7 {
				if shift >= 64 {
					return ErrIntOverflowOplog
				}
				if iNdEx >= l {
					return io.ErrUnexpectedEOF
				}
				b := dAtA[iNdEx]
				iNdEx++
				byteLen |= int(b&0x7F) << shift
				if b < 0x80 {
					break
				}
			}
			if byteLen < 0 {
				return ErrInvalidLengthOplog
			}
			postIndex := iNdEx + byteLen
			if postIndex < 0 {
				return ErrInvalidLengthOplog
			}
			if postIndex > l {
				return io.ErrUnexpectedEOF
			}
			m.Hmac = append(m.Hmac[:0], dAtA[iNdEx:postIndex]...)
			if m.Hmac == nil {
				m.Hmac = []byte{}
			}
			iNdEx = postIndex
		case 5:
			if wireType != 2 {
				return fmt.Errorf("proto: wrong wireType = %d for field Kid", wireType)
			}
			var stringLen uint64
			for shift := uint(0); ; shift += 7 {
				if shift >= 64 {
					return ErrIntOverflowOplog
				}
				if iNdEx >= l {
					return io.ErrUnexpectedEOF
				}
				b := dAtA[iNdEx]
				iNdEx++
				stringLen |= uint64(b&0x7F) << shift
				if b < 0x80 {
					break
				}
			}
			intStringLen := int(stringLen)
			if intStringLen < 0 {
				return ErrInvalidLengthOplog
			}
			postIndex := iNdEx + intStringLen
			if postIndex < 0 {
				return ErrInvalidLengthOplog
			}
			if postIndex > l {
				return io.ErrUnexpectedEOF
			}
			m.Kid = string(dAtA[iNdEx:postIndex])
			iNdEx = postIndex
		case 6:
			if wireType != 2 {
				return fmt.Errorf("proto: wrong wireType = %d for field BoundedContext", wireType)
			}
			var stringLen uint64
			for shift := uint(0); ; shift += 7 {
				if shift >= 64 {
					return ErrIntOverflowOplog
				}
				if iNdEx >= l {
					return io.ErrUnexpectedEOF
				}
				b := dAtA[iNdEx]
				iNdEx++
				stringLen |= uint64(b&0x7F) << shift
				if b < 0x80 {
					break
				}
			}
			intStringLen := int(stringLen)
			if intStringLen < 0 {
				return ErrInvalidLengthOplog
			}
			postIndex := iNdEx + intStringLen
			if postIndex < 0 {
				return ErrInvalidLengthOplog
			}
			if postIndex > l {
				return io.ErrUnexpectedEOF
			}
			m.BoundedContext = string(dAtA[iNdEx:postIndex])
			iNdEx = postIndex
		case 7:
			if wireType != 2 {
				return fmt.Errorf("proto: wrong wireType = %d for field Metadata", wireType)
			}
			var msglen int
			for shift := uint(0); ; shift += 7 {
				if shift >= 64 {
					return ErrIntOverflowOplog
				}
				if iNdEx >= l {
					return io.ErrUnexpectedEOF
				}
				b := dAtA[iNdEx]
				iNdEx++
				msglen |= int(b&0x7F) << shift
				if b < 0x80 {
					break
				}
			}
			if msglen < 0 {
				return ErrInvalidLengthOplog
			}
			postIndex := iNdEx + msglen
			if postIndex < 0 {
				return ErrInvalidLengthOplog
			}
			if postIndex > l {
				return io.ErrUnexpectedEOF
			}
			m.Metadata = append(m.Metadata, &Metadata{})
			if err := m.Metadata[len(m.Metadata)-1].Unmarshal(dAtA[iNdEx:postIndex]); err != nil {
				return err
			}
			iNdEx = postIndex
		case 8:
			if wireType != 2 {
				return fmt.Errorf("proto: wrong wireType = %d for field Data", wireType)
			}
			var byteLen int
			for shift := uint(0); ; shift += 7 {
				if shift >= 64 {
					return ErrIntOverflowOplog
				}
				if iNdEx >= l {
					return io.ErrUnexpectedEOF
				}
				b := dAtA[iNdEx]
				iNdEx++
				byteLen |= int(b&0x7F) << shift
				if b < 0x80 {
					break
				}
			}
			if byteLen < 0 {
				return ErrInvalidLengthOplog
			}
			postIndex := iNdEx + byteLen
			if postIndex < 0 {
				return ErrInvalidLengthOplog
			}
			if postIndex > l {
				return io.ErrUnexpectedEOF
			}
			m.Data = append(m.Data[:0], dAtA[iNdEx:postIndex]...)
			if m.Data == nil {
				m.Data = []byte{}
			}
			iNdEx = postIndex
		default:
			iNdEx = preIndex
			skippy, err := skipOplog(dAtA[iNdEx:])
			if err != nil {
				return err
			}
			if skippy < 0 {
				return ErrInvalidLengthOplog
			}
			if (iNdEx + skippy) < 0 {
				return ErrInvalidLengthOplog
			}
			if (iNdEx + skippy) > l {
				return io.ErrUnexpectedEOF
			}
			iNdEx += skippy
		}
	}

	if iNdEx > l {
		return io.ErrUnexpectedEOF
	}
	return nil
}
func (m *Ticket) Unmarshal(dAtA []byte) error {
	l := len(dAtA)
	iNdEx := 0
	for iNdEx < l {
		preIndex := iNdEx
		var wire uint64
		for shift := uint(0); ; shift += 7 {
			if shift >= 64 {
				return ErrIntOverflowOplog
			}
			if iNdEx >= l {
				return io.ErrUnexpectedEOF
			}
			b := dAtA[iNdEx]
			iNdEx++
			wire |= uint64(b&0x7F) << shift
			if b < 0x80 {
				break
			}
		}
		fieldNum := int32(wire >> 3)
		wireType := int(wire & 0x7)
		if wireType == 4 {
			return fmt.Errorf("proto: Ticket: wiretype end group for non-group")
		}
		if fieldNum <= 0 {
			return fmt.Errorf("proto: Ticket: illegal tag %d (wire type %d)", fieldNum, wire)
		}
		switch fieldNum {
		case 1:
			if wireType != 0 {
				return fmt.Errorf("proto: wrong wireType = %d for field Id", wireType)
			}
			m.Id = 0
			for shift := uint(0); ; shift += 7 {
				if shift >= 64 {
					return ErrIntOverflowOplog
				}
				if iNdEx >= l {
					return io.ErrUnexpectedEOF
				}
				b := dAtA[iNdEx]
				iNdEx++
				m.Id |= uint32(b&0x7F) << shift
				if b < 0x80 {
					break
				}
			}
		case 2:
			if wireType != 2 {
				return fmt.Errorf("proto: wrong wireType = %d for field CreatedAt", wireType)
			}
			var msglen int
			for shift := uint(0); ; shift += 7 {
				if shift >= 64 {
					return ErrIntOverflowOplog
				}
				if iNdEx >= l {
					return io.ErrUnexpectedEOF
				}
				b := dAtA[iNdEx]
				iNdEx++
				msglen |= int(b&0x7F) << shift
				if b < 0x80 {
					break
				}
			}
			if msglen < 0 {
				return ErrInvalidLengthOplog
			}
			postIndex := iNdEx + msglen
			if postIndex < 0 {
				return ErrInvalidLengthOplog
			}
			if postIndex > l {
				return io.ErrUnexpectedEOF
			}
			if m.CreatedAt == nil {
				m.CreatedAt = &Timestamp{}
			}
			if err := m.CreatedAt.Unmarshal(dAtA[iNdEx:postIndex]); err != nil {
				return err
			}
			iNdEx = postIndex
		case 3:
			if wireType != 2 {
				return fmt.Errorf("proto: wrong wireType = %d for field UpdatedAt", wireType)
			}
			var msglen int
			for shift := uint(0); ; shift += 7 {
				if shift >= 64 {
					return ErrIntOverflowOplog
				}
				if iNdEx >= l {
					return io.ErrUnexpectedEOF
				}
				b := dAtA[iNdEx]
				iNdEx++
				msglen |= int(b&0x7F) << shift
				if b < 0x80 {
					break
				}
			}
			if msglen < 0 {
				return ErrInvalidLengthOplog
			}
			postIndex := iNdEx + msglen
			if postIndex < 0 {
				return ErrInvalidLengthOplog
			}
			if postIndex > l {
				return io.ErrUnexpectedEOF
			}
			if m.UpdatedAt == nil {
				m.UpdatedAt = &Timestamp{}
			}
			if err := m.UpdatedAt.Unmarshal(dAtA[iNdEx:postIndex]); err != nil {
				return err
			}
			iNdEx = postIndex
		case 6:
			if wireType != 2 {
				return fmt.Errorf("proto: wrong wireType = %d for field Name", wireType)
			}
			var stringLen uint64
			for shift := uint(0); ; shift += 7 {
				if shift >= 64 {
					return ErrIntOverflowOplog
				}
				if iNdEx >= l {
					return io.ErrUnexpectedEOF
				}
				b := dAtA[iNdEx]
				iNdEx++
				stringLen |= uint64(b&0x7F) << shift
				if b < 0x80 {
					break
				}
			}
			intStringLen := int(stringLen)
			if intStringLen < 0 {
				return ErrInvalidLengthOplog
			}
			postIndex := iNdEx + intStringLen
			if postIndex < 0 {
				return ErrInvalidLengthOplog
			}
			if postIndex > l {
				return io.ErrUnexpectedEOF
			}
			m.Name = string(dAtA[iNdEx:postIndex])
			iNdEx = postIndex
		case 7:
			if wireType != 0 {
				return fmt.Errorf("proto: wrong wireType = %d for field Version", wireType)
			}
			m.Version = 0
			for shift := uint(0); ; shift += 7 {
				if shift >= 64 {
					return ErrIntOverflowOplog
				}
				if iNdEx >= l {
					return io.ErrUnexpectedEOF
				}
				b := dAtA[iNdEx]
				iNdEx++
				m.Version |= uint32(b&0x7F) << shift
				if b < 0x80 {
					break
				}
			}
		default:
			iNdEx = preIndex
			skippy, err := skipOplog(dAtA[iNdEx:])
			if err != nil {
				return err
			}
			if skippy < 0 {
				return ErrInvalidLengthOplog
			}
			if (iNdEx + skippy) < 0 {
				return ErrInvalidLengthOplog
			}
			if (iNdEx + skippy) > l {
				return io.ErrUnexpectedEOF
			}
			iNdEx += skippy
		}
	}

	if iNdEx > l {
		return io.ErrUnexpectedEOF
	}
	return nil
}
func (m *Metadata) Unmarshal(dAtA []byte) error {
	l := len(dAtA)
	iNdEx := 0
	for iNdEx < l {
		preIndex := iNdEx
		var wire uint64
		for shift := uint(0); ; shift += 7 {
			if shift >= 64 {
				return ErrIntOverflowOplog
			}
			if iNdEx >= l {
				return io.ErrUnexpectedEOF
			}
			b := dAtA[iNdEx]
			iNdEx++
			wire |= uint64(b&0x7F) << shift
			if b < 0x80 {
				break
			}
		}
		fieldNum := int32(wire >> 3)
		wireType := int(wire & 0x7)
		if wireType == 4 {
			return fmt.Errorf("proto: Metadata: wiretype end group for non-group")
		}
		if fieldNum <= 0 {
			return fmt.Errorf("proto: Metadata: illegal tag %d (wire type %d)", fieldNum, wire)
		}
		switch fieldNum {
		case 1:
			if wireType != 0 {
				return fmt.Errorf("proto: wrong wireType = %d for field Id", wireType)
			}
			m.Id = 0
			for shift := uint(0); ; shift += 7 {
				if shift >= 64 {
					return ErrIntOverflowOplog
				}
				if iNdEx >= l {
					return io.ErrUnexpectedEOF
				}
				b := dAtA[iNdEx]
				iNdEx++
				m.Id |= uint32(b&0x7F) << shift
				if b < 0x80 {
					break
				}
			}
		case 2:
			if wireType != 2 {
				return fmt.Errorf("proto: wrong wireType = %d for field CreatedAt", wireType)
			}
			var msglen int
			for shift := uint(0); ; shift += 7 {
				if shift >= 64 {
					return ErrIntOverflowOplog
				}
				if iNdEx >= l {
					return io.ErrUnexpectedEOF
				}
				b := dAtA[iNdEx]
				iNdEx++
				msglen |= int(b&0x7F) << shift
				if b < 0x80 {
					break
				}
			}
			if msglen < 0 {
				return ErrInvalidLengthOplog
			}
			postIndex := iNdEx + msglen
			if postIndex < 0 {
				return ErrInvalidLengthOplog
			}
			if postIndex > l {
				return io.ErrUnexpectedEOF
			}
			if m.CreatedAt == nil {
				m.CreatedAt = &Timestamp{}
			}
			if err := m.CreatedAt.Unmarshal(dAtA[iNdEx:postIndex]); err != nil {
				return err
			}
			iNdEx = postIndex
		case 3:
			if wireType != 0 {
				return fmt.Errorf("proto: wrong wireType = %d for field EntryId", wireType)
			}
			m.EntryId = 0
			for shift := uint(0); ; shift += 7 {
				if shift >= 64 {
					return ErrIntOverflowOplog
				}
				if iNdEx >= l {
					return io.ErrUnexpectedEOF
				}
				b := dAtA[iNdEx]
				iNdEx++
				m.EntryId |= uint32(b&0x7F) << shift
				if b < 0x80 {
					break
				}
			}
		case 4:
			if wireType != 2 {
				return fmt.Errorf("proto: wrong wireType = %d for field Entry", wireType)
			}
			var msglen int
			for shift := uint(0); ; shift += 7 {
				if shift >= 64 {
					return ErrIntOverflowOplog
				}
				if iNdEx >= l {
					return io.ErrUnexpectedEOF
				}
				b := dAtA[iNdEx]
				iNdEx++
				msglen |= int(b&0x7F) << shift
				if b < 0x80 {
					break
				}
			}
			if msglen < 0 {
				return ErrInvalidLengthOplog
			}
			postIndex := iNdEx + msglen
			if postIndex < 0 {
				return ErrInvalidLengthOplog
			}
			if postIndex > l {
				return io.ErrUnexpectedEOF
			}
			if m.Entry == nil {
				m.Entry = &Entry{}
			}
			if err := m.Entry.Unmarshal(dAtA[iNdEx:postIndex]); err != nil {
				return err
			}
			iNdEx = postIndex
		case 5:
			if wireType != 2 {
				return fmt.Errorf("proto: wrong wireType = %d for field Key", wireType)
			}
			var stringLen uint64
			for shift := uint(0); ; shift += 7 {
				if shift >= 64 {
					return ErrIntOverflowOplog
				}
				if iNdEx >= l {
					return io.ErrUnexpectedEOF
				}
				b := dAtA[iNdEx]
				iNdEx++
				stringLen |= uint64(b&0x7F) << shift
				if b < 0x80 {
					break
				}
			}
			intStringLen := int(stringLen)
			if intStringLen < 0 {
				return ErrInvalidLengthOplog
			}
			postIndex := iNdEx + intStringLen
			if postIndex < 0 {
				return ErrInvalidLengthOplog
			}
			if postIndex > l {
				return io.ErrUnexpectedEOF
			}
			m.Key = string(dAtA[iNdEx:postIndex])
			iNdEx = postIndex
		case 6:
			if wireType != 2 {
				return fmt.Errorf("proto: wrong wireType = %d for field Value", wireType)
			}
			var stringLen uint64
			for shift := uint(0); ; shift += 7 {
				if shift >= 64 {
					return ErrIntOverflowOplog
				}
				if iNdEx >= l {
					return io.ErrUnexpectedEOF
				}
				b := dAtA[iNdEx]
				iNdEx++
				stringLen |= uint64(b&0x7F) << shift
				if b < 0x80 {
					break
				}
			}
			intStringLen := int(stringLen)
			if intStringLen < 0 {
				return ErrInvalidLengthOplog
			}
			postIndex := iNdEx + intStringLen
			if postIndex < 0 {
				return ErrInvalidLengthOplog
			}
			if postIndex > l {
				return io.ErrUnexpectedEOF
			}
			m.Value = string(dAtA[iNdEx:postIndex])
			iNdEx = postIndex
		default:
			iNdEx = preIndex
			skippy, err := skipOplog(dAtA[iNdEx:])
			if err != nil {
				return err
			}
			if skippy < 0 {
				return ErrInvalidLengthOplog
			}
			if (iNdEx + skippy) < 0 {
				return ErrInvalidLengthOplog
			}
			if (iNdEx + skippy) > l {
				return io.ErrUnexpectedEOF
			}
			iNdEx += skippy
		}
	}

	if iNdEx > l {
		return io.ErrUnexpectedEOF
	}
	return nil
}
func skipOplog(dAtA []byte) (n int, err error) {
	l := len(dAtA)
	iNdEx := 0
	depth := 0
	for iNdEx < l {
		var wire uint64
		for shift := uint(0); ; shift += 7 {
			if shift >= 64 {
				return 0, ErrIntOverflowOplog
			}
			if iNdEx >= l {
				return 0, io.ErrUnexpectedEOF
			}
			b := dAtA[iNdEx]
			iNdEx++
			wire |= (uint64(b) & 0x7F) << shift
			if b < 0x80 {
				break
			}
		}
		wireType := int(wire & 0x7)
		switch wireType {
		case 0:
			for shift := uint(0); ; shift += 7 {
				if shift >= 64 {
					return 0, ErrIntOverflowOplog
				}
				if iNdEx >= l {
					return 0, io.ErrUnexpectedEOF
				}
				iNdEx++
				if dAtA[iNdEx-1] < 0x80 {
					break
				}
			}
		case 1:
			iNdEx += 8
		case 2:
			var length int
			for shift := uint(0); ; shift += 7 {
				if shift >= 64 {
					return 0, ErrIntOverflowOplog
				}
				if iNdEx >= l {
					return 0, io.ErrUnexpectedEOF
				}
				b := dAtA[iNdEx]
				iNdEx++
				length |= (int(b) & 0x7F) << shift
				if b < 0x80 {
					break
				}
			}
			if length < 0 {
				return 0, ErrInvalidLengthOplog
			}
			iNdEx += length
		case 3:
			depth++
		case 4:
			if depth == 0 {
				return 0, ErrUnexpectedEndOfGroupOplog
			}
			depth--
		case 5:
			iNdEx += 4
		default:
			return 0, fmt.Errorf("proto: illegal wireType %d", wireType)
		}
		if iNdEx < 0 {
			return 0, ErrInvalidLengthOplog
		}
		if depth == 0 {
			return iNdEx, nil
		}
	}
	return 0, io.ErrUnexpectedEOF
}

var (
	ErrInvalidLengthOplog        = fmt.Errorf("proto: negative length found during unmarshaling")
	ErrIntOverflowOplog          = fmt.Errorf("proto: integer overflow")
	ErrUnexpectedEndOfGroupOplog = fmt.Errorf("proto: unexpected end of group")
)
