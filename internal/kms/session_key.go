package kms

import (
	"context"
	"fmt"

	"github.com/hashicorp/boundary/internal/db"
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
func NewSessionKey(rootKeyId string, opt ...Option) (*SessionKey, error) {
	if rootKeyId == "" {
		return nil, fmt.Errorf("new root key: missing root key id: %w", db.ErrInvalidParameter)
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
func (k *SessionKey) VetForWrite(ctx context.Context, r db.Reader, opType db.OpType, opt ...db.Option) error {
	if k.PrivateId == "" {
		return fmt.Errorf("session key vet for write: missing private id: %w", db.ErrInvalidParameter)
	}
	if opType == db.CreateOp {
		if k.RootKeyId == "" {
			return fmt.Errorf("session key vet for write: missing root key id: %w", db.ErrInvalidParameter)
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
