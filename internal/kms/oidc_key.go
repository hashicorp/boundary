package kms

import (
	"context"

	"github.com/hashicorp/boundary/internal/db"
	"github.com/hashicorp/boundary/internal/errors"
	"github.com/hashicorp/boundary/internal/kms/store"
	"google.golang.org/protobuf/proto"
)

const (
	DefaultOidcKeyTableName = "kms_oidc_key"
)

type OidcKey struct {
	*store.OidcKey
	tableName string `gorm:"-"`
}

// NewOidcKey creates a new in memory oidc key.  This key is used to encrypt
// oidc state before it's included in the oidc auth url.  No options are
// currently supported.
func NewOidcKey(rootKeyId string, _ ...Option) (*OidcKey, error) {
	const op = "kms.NewOidcKey"
	if rootKeyId == "" {
		return nil, errors.NewDeprecated(errors.InvalidParameter, op, "missing root key id")
	}
	c := &OidcKey{
		OidcKey: &store.OidcKey{
			RootKeyId: rootKeyId,
		},
	}
	return c, nil
}

// AllocOidcKey will allocate a OidcKey
func AllocOidcKey() OidcKey {
	return OidcKey{
		OidcKey: &store.OidcKey{},
	}
}

// Clone creates a clone of the OidcKey
func (k *OidcKey) Clone() interface{} {
	cp := proto.Clone(k.OidcKey)
	return &OidcKey{
		OidcKey: cp.(*store.OidcKey),
	}
}

// VetForWrite implements db.VetForWrite() interface and validates the key
// before it's written.
func (k *OidcKey) VetForWrite(ctx context.Context, r db.Reader, opType db.OpType, opt ...db.Option) error {
	const op = "kms.(OidcKey).VetForWrite"
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
func (k *OidcKey) TableName() string {
	if k.tableName != "" {
		return k.tableName
	}
	return DefaultOidcKeyTableName
}

// SetTableName sets the tablename and satisfies the ReplayableMessage
// interface. If the caller attempts to set the name to "" the name will be
// reset to the default name.
func (k *OidcKey) SetTableName(n string) {
	k.tableName = n
}
