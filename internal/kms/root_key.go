package kms

import (
	"context"

	"github.com/hashicorp/boundary/internal/db"
	"github.com/hashicorp/boundary/internal/errors"
	"github.com/hashicorp/boundary/internal/kms/store"
	"google.golang.org/protobuf/proto"
)

const (
	DefaultRootKeyTableName = "kms_root_key"
)

type RootKey struct {
	*store.RootKey
	tableName string `gorm:"-"`
}

// NewRootKey creates a new in memory root key.  ScopeId must be
// for a global or org scope, but the scope type validation will be deferred
// until the in memory root key is written to the database.  No options
// are currently supported.
func NewRootKey(scopeId string, _ ...Option) (*RootKey, error) {
	const op = "kms.NewRootKey"
	if scopeId == "" {
		return nil, errors.NewDeprecated(errors.InvalidParameter, op, "missing scope id")
	}
	c := &RootKey{
		RootKey: &store.RootKey{
			ScopeId: scopeId,
		},
	}
	return c, nil
}

// AllocRootKey will allocate a root key
func AllocRootKey() RootKey {
	return RootKey{
		RootKey: &store.RootKey{},
	}
}

// Clone creates a clone of the RootKey
func (k *RootKey) Clone() interface{} {
	cp := proto.Clone(k.RootKey)
	return &RootKey{
		RootKey: cp.(*store.RootKey),
	}
}

// VetForWrite implements db.VetForWrite() interface and validates the key
// before it's written.
func (k *RootKey) VetForWrite(ctx context.Context, _ db.Reader, opType db.OpType, _ ...db.Option) error {
	const op = "kms.(RootKey).VetForWrite"
	if k.PrivateId == "" {
		return errors.New(ctx, errors.InvalidParameter, op, "missing private id")
	}
	switch opType {
	case db.CreateOp:
		if k.ScopeId == "" {
			return errors.New(ctx, errors.InvalidParameter, op, "missing scope id")
		}
	case db.UpdateOp:
		return errors.New(ctx, errors.InvalidParameter, op, "key is immutable")
	}
	return nil
}

// TableName returns the tablename to override the default gorm table name
func (k *RootKey) TableName() string {
	if k.tableName != "" {
		return k.tableName
	}
	return DefaultRootKeyTableName
}

// SetTableName sets the tablename and satisfies the ReplayableMessage
// interface. If the caller attempts to set the name to "" the name will be
// reset to the default name.
func (c *RootKey) SetTableName(n string) {
	c.tableName = n
}
