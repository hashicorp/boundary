package kms

import (
	"context"

	"github.com/hashicorp/boundary/internal/db"
	"github.com/hashicorp/boundary/internal/errors"
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
func NewOplogKey(rootKeyId string, _ ...Option) (*OplogKey, error) {
	const op = "kms.NewOplogKey"
	if rootKeyId == "" {
		return nil, errors.NewDeprecated(errors.InvalidParameter, op, "missing root key id")
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
func (k *OplogKey) VetForWrite(ctx context.Context, _ db.Reader, opType db.OpType, _ ...db.Option) error {
	const op = "kms.(OplogKey).VetForWrite"
	if k.PrivateId == "" {
		return errors.New(ctx, errors.InvalidParameter, op, "missing private id")
	}
	if opType == db.CreateOp {
		if k.RootKeyId == "" {
			return errors.New(ctx, errors.InvalidParameter, op, "missing root key id")
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
