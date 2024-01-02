// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: BUSL-1.1


package target

import (
	"context"
	"strings"

	"github.com/hashicorp/boundary/internal/db"
	"github.com/hashicorp/boundary/internal/errors"
	"github.com/hashicorp/boundary/internal/oplog"
	"github.com/hashicorp/boundary/internal/target/store"
	"google.golang.org/protobuf/proto"
)

const (
	DefaultTargetAddressTableName = "target_address"
)

// An Address represents the relationship between a target and a
// network address.
type Address struct {
	*store.TargetAddress
	tableName string `gorm:"-"`
}

// Ensure Address implements interfaces
var (
	_ db.VetForWriter         = (*Address)(nil)
	_ oplog.ReplayableMessage = (*Address)(nil)
)

// NewAddress creates a new in memory address. No options are
// currently supported.
func NewAddress(ctx context.Context, targetId, address string, _ ...Option) (*Address, error) {
	const op = "target.NewAddress"
	if targetId == "" {
		return nil, errors.New(ctx, errors.InvalidParameter, op, "missing target id")
	}
	if address == "" {
		return nil, errors.New(ctx, errors.InvalidParameter, op, "missing address")
	}
	address = strings.TrimSpace(address)
	t := &Address{
		TargetAddress: &store.TargetAddress{
			TargetId: targetId,
			Address:  address,
		},
	}
	return t, nil
}

// Clone creates a clone of the target address
func (t *Address) Clone() any {
	cp := proto.Clone(t.TargetAddress)
	return &Address{
		TargetAddress: cp.(*store.TargetAddress),
	}
}

// VetForWrite implements db.VetForWrite() interface and validates the target
// address before it's written.
func (t *Address) VetForWrite(ctx context.Context, _ db.Reader, opType db.OpType, _ ...db.Option) error {
	const op = "target.(Address).VetForWrite"
	if opType == db.CreateOp {
		if t.GetTargetId() == "" {
			return errors.New(ctx, errors.InvalidParameter, op, "missing target id")
		}
		if t.GetAddress() == "" {
			return errors.New(ctx, errors.InvalidParameter, op, "missing address")
		}
	}
	return nil
}

// TableName returns the tablename to override the default gorm table name
func (t *Address) TableName() string {
	if t.tableName != "" {
		return t.tableName
	}
	return DefaultTargetAddressTableName
}

// SetTableName sets the tablename and satisfies the ReplayableMessage
// interface. If the caller attempts to set the name to "" the name will be
// reset to the default name.
func (t *Address) SetTableName(n string) {
	t.tableName = n
}

func (t *Address) oplog(op oplog.OpType) oplog.Metadata {
	metadata := oplog.Metadata{
		"resource-public-id": []string{t.GetTargetId()},
		"resource-type":      []string{"target address"},
		"op-type":            []string{op.String()},
	}
	return metadata
}

func (t *Address) TargetId() string {
	return t.GetTargetId()
}

func (t *Address) Address() string {
	return t.GetAddress()
}

func (t *Address) GetPublicId() string {
	return t.GetTargetId()
}

// allocTargetAddress will allocate a address
func allocTargetAddress() *Address {
	return &Address{
		TargetAddress: &store.TargetAddress{},
	}
}
