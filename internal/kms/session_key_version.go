package kms

import (
	"context"
	"fmt"

	"github.com/hashicorp/boundary/internal/db"
	"github.com/hashicorp/boundary/internal/kms/store"
	wrapping "github.com/hashicorp/go-kms-wrapping"
	"github.com/hashicorp/go-kms-wrapping/structwrapping"
	"google.golang.org/protobuf/proto"
)

const (
	DefaultSessionKeyVersionTableName = "kms_session_key_version"
)

type SessionKeyVersion struct {
	*store.SessionKeyVersion
	tableName string `gorm:"-"`
}

// SessionKeyVersion creates a new in memory key version. No options are
// currently supported.
func NewSessionKeyVersion(sessionKeyId string, key []byte, rootKeyVersionId string, opt ...Option) (*SessionKeyVersion, error) {
	if sessionKeyId == "" {
		return nil, fmt.Errorf("new session key version: missing session key id: %w", db.ErrInvalidParameter)
	}
	if len(key) == 0 {
		return nil, fmt.Errorf("new session key version: missing key: %w", db.ErrInvalidParameter)
	}
	if rootKeyVersionId == "" {
		return nil, fmt.Errorf("new session key version: missing root key version id: %w", db.ErrInvalidParameter)
	}

	k := &SessionKeyVersion{
		SessionKeyVersion: &store.SessionKeyVersion{
			SessionKeyId:     sessionKeyId,
			RootKeyVersionId: rootKeyVersionId,
			Key:              key,
		},
	}
	return k, nil
}

// AllocSessionKeyVersion allocates a key version
func AllocSessionKeyVersion() SessionKeyVersion {
	return SessionKeyVersion{
		SessionKeyVersion: &store.SessionKeyVersion{},
	}
}

// Clone creates a clone of the key version
func (k *SessionKeyVersion) Clone() interface{} {
	cp := proto.Clone(k.SessionKeyVersion)
	return &SessionKeyVersion{
		SessionKeyVersion: cp.(*store.SessionKeyVersion),
	}
}

// VetForWrite implements db.VetForWrite() interface and validates the key
// version before it's written.
func (k *SessionKeyVersion) VetForWrite(ctx context.Context, r db.Reader, opType db.OpType, opt ...db.Option) error {
	if k.PrivateId == "" {
		return fmt.Errorf("session key version vet for write: missing private id: %w", db.ErrInvalidParameter)
	}
	if opType == db.CreateOp {
		if k.CtKey == nil {
			return fmt.Errorf("session key version vet for write: missing key: %w", db.ErrInvalidParameter)
		}
		if k.SessionKeyId == "" {
			return fmt.Errorf("session key version vet for write: missing session key id: %w", db.ErrInvalidParameter)
		}
		if k.RootKeyVersionId == "" {
			return fmt.Errorf("session key version vet for write: missing root key version id: %w", db.ErrInvalidParameter)
		}
	}
	return nil
}

// TableName returns the tablename to override the default gorm table name
func (k *SessionKeyVersion) TableName() string {
	if k.tableName != "" {
		return k.tableName
	}
	return DefaultSessionKeyVersionTableName
}

// SetTableName sets the tablename and satisfies the ReplayableMessage
// interface. If the caller attempts to set the name to "" the name will be
// reset to the default name.
func (k *SessionKeyVersion) SetTableName(n string) {
	k.tableName = n
}

// Encrypt will encrypt the key version's key
func (k *SessionKeyVersion) Encrypt(ctx context.Context, cipher wrapping.Wrapper) error {
	// structwrapping doesn't support embedding, so we'll pass in the
	// store.SessionKeyVersion directly
	if err := structwrapping.WrapStruct(ctx, cipher, k.SessionKeyVersion, nil); err != nil {
		return fmt.Errorf("error encrypting kms session key version: %w", err)
	}
	return nil
}

// Decrypt will decrypt the key version's key
func (k *SessionKeyVersion) Decrypt(ctx context.Context, cipher wrapping.Wrapper) error {
	// structwrapping doesn't support embedding, so we'll pass in the
	// store.SessionKeyVersion directly
	if err := structwrapping.UnwrapStruct(ctx, cipher, k.SessionKeyVersion, nil); err != nil {
		return fmt.Errorf("error decrypting kms session key version: %w", err)
	}
	return nil
}
