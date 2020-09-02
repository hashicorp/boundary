package kms

import (
	"context"
	"fmt"

	"github.com/hashicorp/boundary/internal/db"
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
func NewRootKey(scopeId string, opt ...Option) (*RootKey, error) {
	if scopeId == "" {
		return nil, fmt.Errorf("new root key: missing scope id: %w", db.ErrInvalidParameter)
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
func (k *RootKey) VetForWrite(ctx context.Context, r db.Reader, opType db.OpType, opt ...db.Option) error {
	if k.PrivateId == "" {
		return fmt.Errorf("root key vet for write: missing private id: %w", db.ErrInvalidParameter)
	}
	switch opType {
	case db.CreateOp:
		if k.ScopeId == "" {
			return fmt.Errorf("root key vet for write: missing scope id: %w", db.ErrInvalidParameter)
		}
	case db.UpdateOp:
		return fmt.Errorf("root key vet for write: key is immutable: %w", db.ErrInvalidParameter)
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
