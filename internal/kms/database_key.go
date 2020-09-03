package kms

import (
	"context"
	"fmt"

	"github.com/hashicorp/boundary/internal/db"
	"github.com/hashicorp/boundary/internal/kms/store"
	"google.golang.org/protobuf/proto"
)

const (
	DefaultDatabaseKeyTableName = "kms_database_key"
)

type DatabaseKey struct {
	*store.DatabaseKey
	tableName string `gorm:"-"`
}

// NewDatabaseKey creates a new in memory database key.  No options
// are currently supported.
func NewDatabaseKey(rootKeyId string, opt ...Option) (*DatabaseKey, error) {
	if rootKeyId == "" {
		return nil, fmt.Errorf("new root key: missing root key id: %w", db.ErrInvalidParameter)
	}
	c := &DatabaseKey{
		DatabaseKey: &store.DatabaseKey{
			RootKeyId: rootKeyId,
		},
	}
	return c, nil
}

// AllocDatabaseKey will allocate a DatabaseKey
func AllocDatabaseKey() DatabaseKey {
	return DatabaseKey{
		DatabaseKey: &store.DatabaseKey{},
	}
}

// Clone creates a clone of the DatabaseKey
func (k *DatabaseKey) Clone() interface{} {
	cp := proto.Clone(k.DatabaseKey)
	return &DatabaseKey{
		DatabaseKey: cp.(*store.DatabaseKey),
	}
}

// VetForWrite implements db.VetForWrite() interface and validates the key
// before it's written.
func (k *DatabaseKey) VetForWrite(ctx context.Context, r db.Reader, opType db.OpType, opt ...db.Option) error {
	if k.PrivateId == "" {
		return fmt.Errorf("database key vet for write: missing private id: %w", db.ErrInvalidParameter)
	}
	switch opType {
	case db.CreateOp:
		if k.RootKeyId == "" {
			return fmt.Errorf("database key vet for write: missing root key id: %w", db.ErrInvalidParameter)
		}
	case db.UpdateOp:
		return fmt.Errorf("database key vet for write: key is immutable: %w", db.ErrInvalidParameter)
	}
	return nil
}

// TableName returns the tablename to override the default gorm table name
func (k *DatabaseKey) TableName() string {
	if k.tableName != "" {
		return k.tableName
	}
	return DefaultDatabaseKeyTableName
}

// SetTableName sets the tablename and satisfies the ReplayableMessage
// interface. If the caller attempts to set the name to "" the name will be
// reset to the default name.
func (k *DatabaseKey) SetTableName(n string) {
	k.tableName = n
}
