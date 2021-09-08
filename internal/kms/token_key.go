package kms

import (
	"context"

	"github.com/hashicorp/boundary/internal/db"
	"github.com/hashicorp/boundary/internal/errors"
	"github.com/hashicorp/boundary/internal/kms/store"
	"google.golang.org/protobuf/proto"
)

const (
	DefaultTokenKeyTableName = "kms_token_key"
)

type TokenKey struct {
	*store.TokenKey
	tableName string `gorm:"-"`
}

// NewTokenKey creates a new in memory key.  No options
// are currently supported.
func NewTokenKey(rootKeyId string, _ ...Option) (*TokenKey, error) {
	const op = "kms.NewTokenKey"
	if rootKeyId == "" {
		return nil, errors.NewDeprecated(errors.InvalidParameter, op, "missing root key id")
	}
	c := &TokenKey{
		TokenKey: &store.TokenKey{
			RootKeyId: rootKeyId,
		},
	}
	return c, nil
}

// AllocTokenKey will allocate a key
func AllocTokenKey() TokenKey {
	return TokenKey{
		TokenKey: &store.TokenKey{},
	}
}

// Clone creates a clone of the key
func (k *TokenKey) Clone() interface{} {
	cp := proto.Clone(k.TokenKey)
	return &TokenKey{
		TokenKey: cp.(*store.TokenKey),
	}
}

// VetForWrite implements db.VetForWrite() interface and validates the key
// before it's written.
func (k *TokenKey) VetForWrite(ctx context.Context, _ db.Reader, opType db.OpType, _ ...db.Option) error {
	const op = "kms.(TokenKey).VetForWrite"
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
func (k *TokenKey) TableName() string {
	if k.tableName != "" {
		return k.tableName
	}
	return DefaultTokenKeyTableName
}

// SetTableName sets the tablename and satisfies the ReplayableMessage
// interface. If the caller attempts to set the name to "" the name will be
// reset to the default name.
func (k *TokenKey) SetTableName(n string) {
	k.tableName = n
}
