package kms

import (
	"context"
	"fmt"

	"github.com/hashicorp/boundary/internal/db"
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
func NewTokenKey(rootKeyId string, opt ...Option) (*TokenKey, error) {
	if rootKeyId == "" {
		return nil, fmt.Errorf("new root key: missing root key id: %w", db.ErrInvalidParameter)
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
func (k *TokenKey) VetForWrite(ctx context.Context, r db.Reader, opType db.OpType, opt ...db.Option) error {
	if k.PrivateId == "" {
		return fmt.Errorf("token key vet for write: missing private id: %w", db.ErrInvalidParameter)
	}
	if opType == db.CreateOp {
		if k.RootKeyId == "" {
			return fmt.Errorf("token key vet for write: missing root key id: %w", db.ErrInvalidParameter)
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
