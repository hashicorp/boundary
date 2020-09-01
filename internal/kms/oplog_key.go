package kms

import (
	"context"
	"fmt"

	"github.com/hashicorp/boundary/internal/db"
	"github.com/hashicorp/boundary/internal/kms/store"
	"google.golang.org/protobuf/proto"
)

const (
	DefaultOplogKeyTableName = "kms_oplog_key"
)

type OplogKey struct {
	*store.OplogKey
	tableName string `gorm:"-"`
}

// NewOplogKey creates a new in memory key.  No options
// are currently supported.
func NewOplogKey(rootKeyId string, opt ...Option) (*OplogKey, error) {
	if rootKeyId == "" {
		return nil, fmt.Errorf("new root key: missing root key id: %w", db.ErrInvalidParameter)
	}
	c := &OplogKey{
		OplogKey: &store.OplogKey{
			RootKeyId: rootKeyId,
		},
	}
	return c, nil
}

// AllocOplogKey will allocate a key
func AllocOplogKey() OplogKey {
	return OplogKey{
		OplogKey: &store.OplogKey{},
	}
}

// Clone creates a clone of the key
func (k *OplogKey) Clone() interface{} {
	cp := proto.Clone(k.OplogKey)
	return &OplogKey{
		OplogKey: cp.(*store.OplogKey),
	}
}

// VetForWrite implements db.VetForWrite() interface and validates the key
// before it's written.
func (k *OplogKey) VetForWrite(ctx context.Context, r db.Reader, opType db.OpType, opt ...db.Option) error {
	if k.PrivateId == "" {
		return fmt.Errorf("oplog key vet for write: missing private id: %w", db.ErrInvalidParameter)
	}
	if opType == db.CreateOp {
		if k.RootKeyId == "" {
			return fmt.Errorf("oplog key vet for write: missing root key id: %w", db.ErrInvalidParameter)
		}
	}
	return nil
}

// TableName returns the tablename to override the default gorm table name
func (k *OplogKey) TableName() string {
	if k.tableName != "" {
		return k.tableName
	}
	return DefaultOplogKeyTableName
}

// SetTableName sets the tablename and satisfies the ReplayableMessage
// interface. If the caller attempts to set the name to "" the name will be
// reset to the default name.
func (k *OplogKey) SetTableName(n string) {
	k.tableName = n
}
