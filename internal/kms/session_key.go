package kms

import (
	"context"

	"github.com/hashicorp/boundary/internal/db"
	"github.com/hashicorp/boundary/internal/errors"
	"github.com/hashicorp/boundary/internal/kms/store"
	"google.golang.org/protobuf/proto"
)

const (
	DefaultSessionKeyTableName = "kms_session_key"
)

type SessionKey struct {
	*store.SessionKey
	tableName string `gorm:"-"`
}

// NewSessionKey creates a new in memory key.  No options
// are currently supported.
func NewSessionKey(rootKeyId string, _ ...Option) (*SessionKey, error) {
	const op = "kms.NewSessionKey"
	if rootKeyId == "" {
		return nil, errors.NewDeprecated(errors.InvalidParameter, op, "missing root key id")
	}
	c := &SessionKey{
		SessionKey: &store.SessionKey{
			RootKeyId: rootKeyId,
		},
	}
	return c, nil
}

// AllocSessionKey will allocate a key
func AllocSessionKey() SessionKey {
	return SessionKey{
		SessionKey: &store.SessionKey{},
	}
}

// Clone creates a clone of the key
func (k *SessionKey) Clone() interface{} {
	cp := proto.Clone(k.SessionKey)
	return &SessionKey{
		SessionKey: cp.(*store.SessionKey),
	}
}

// VetForWrite implements db.VetForWrite() interface and validates the key
// before it's written.
func (k *SessionKey) VetForWrite(ctx context.Context, _ db.Reader, opType db.OpType, _ ...db.Option) error {
	const op = "kms.(SessionKey).VetForWrite"
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
func (k *SessionKey) TableName() string {
	if k.tableName != "" {
		return k.tableName
	}
	return DefaultSessionKeyTableName
}

// SetTableName sets the tablename and satisfies the ReplayableMessage
// interface. If the caller attempts to set the name to "" the name will be
// reset to the default name.
func (k *SessionKey) SetTableName(n string) {
	k.tableName = n
}
