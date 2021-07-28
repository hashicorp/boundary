package kms

import (
	"context"

	"github.com/hashicorp/boundary/internal/db"
	"github.com/hashicorp/boundary/internal/errors"
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
func NewDatabaseKey(rootKeyId string, _ ...Option) (*DatabaseKey, error) {
	const op = "kms.NewDatabaseKey"
	if rootKeyId == "" {
		return nil, errors.NewDeprecated(errors.InvalidParameter, op, "missing root key id")
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
	const op = "kms.(DatabaseKey).VetForWrite"
	if k.PrivateId == "" {
		return errors.New(ctx, errors.InvalidParameter, op, "missing private id")
	}
	switch opType {
	case db.CreateOp:
		if k.RootKeyId == "" {
			return errors.New(ctx, errors.InvalidParameter, op, "missing root key id")
		}
	case db.UpdateOp:
		return errors.New(ctx, errors.InvalidParameter, op, "key is immutable")
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
