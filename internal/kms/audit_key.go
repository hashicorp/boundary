package kms

import (
	"context"

	"github.com/hashicorp/boundary/internal/db"
	"github.com/hashicorp/boundary/internal/errors"
	"github.com/hashicorp/boundary/internal/kms/store"
	"google.golang.org/protobuf/proto"
)

const (
	DefaultAuditKeyTableName = "kms_audit_key"
)

type AuditKey struct {
	*store.AuditKey
	tableName string `gorm:"-"`
}

// NewAuditKey creates a new in memory audit key.  This key is used for crypto
// operations on audit entries. No options are currently supported.
func NewAuditKey(ctx context.Context, rootKeyId string, _ ...Option) (*AuditKey, error) {
	const op = "kms.NewAuditKey"
	if rootKeyId == "" {
		return nil, errors.New(ctx, errors.InvalidParameter, op, "missing root key id")
	}
	k := &AuditKey{
		AuditKey: &store.AuditKey{
			RootKeyId: rootKeyId,
		},
	}
	return k, nil
}

// AllocAuditKey will allocate a AuditKey
func AllocAuditKey() AuditKey {
	return AuditKey{
		AuditKey: &store.AuditKey{},
	}
}

// Clone creates a clone of the AuditKey
func (k *AuditKey) Clone() interface{} {
	cp := proto.Clone(k.AuditKey)
	return &AuditKey{
		AuditKey: cp.(*store.AuditKey),
	}
}

// VetForWrite implements db.VetForWrite() interface and validates the key
// before it's written.
func (k *AuditKey) VetForWrite(ctx context.Context, r db.Reader, opType db.OpType, opt ...db.Option) error {
	const op = "kms.(AuditKey).VetForWrite"
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
func (k *AuditKey) TableName() string {
	if k.tableName != "" {
		return k.tableName
	}
	return DefaultAuditKeyTableName
}

// SetTableName sets the tablename and satisfies the ReplayableMessage
// interface. If the caller attempts to set the name to "" the name will be
// reset to the default name.
func (k *AuditKey) SetTableName(n string) {
	k.tableName = n
}
