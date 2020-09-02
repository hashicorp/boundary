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
	DefaultTokenKeyVersionTableName = "kms_token_key_version"
)

type TokenKeyVersion struct {
	*store.TokenKeyVersion
	tableName string `gorm:"-"`
}

// TokenKeyVersion creates a new in memory key version. No options are
// currently supported.
func NewTokenKeyVersion(tokenKeyId string, key []byte, rootKeyVersionId string, opt ...Option) (*TokenKeyVersion, error) {
	if tokenKeyId == "" {
		return nil, fmt.Errorf("new token key version: missing token key id: %w", db.ErrInvalidParameter)
	}
	if len(key) == 0 {
		return nil, fmt.Errorf("new token key version: missing key: %w", db.ErrInvalidParameter)
	}
	if rootKeyVersionId == "" {
		return nil, fmt.Errorf("new token key version: missing root key version id: %w", db.ErrInvalidParameter)
	}

	k := &TokenKeyVersion{
		TokenKeyVersion: &store.TokenKeyVersion{
			TokenKeyId:       tokenKeyId,
			RootKeyVersionId: rootKeyVersionId,
			Key:              key,
		},
	}
	return k, nil
}

// AllocTokenKeyVersion allocates a key version
func AllocTokenKeyVersion() TokenKeyVersion {
	return TokenKeyVersion{
		TokenKeyVersion: &store.TokenKeyVersion{},
	}
}

// Clone creates a clone of the key version
func (k *TokenKeyVersion) Clone() interface{} {
	cp := proto.Clone(k.TokenKeyVersion)
	return &TokenKeyVersion{
		TokenKeyVersion: cp.(*store.TokenKeyVersion),
	}
}

// VetForWrite implements db.VetForWrite() interface and validates the key
// version before it's written.
func (k *TokenKeyVersion) VetForWrite(ctx context.Context, r db.Reader, opType db.OpType, opt ...db.Option) error {
	if k.PrivateId == "" {
		return fmt.Errorf("token key version vet for write: missing private id: %w", db.ErrInvalidParameter)
	}
	if opType == db.CreateOp {
		if k.CtKey == nil {
			return fmt.Errorf("token key version vet for write: missing key: %w", db.ErrInvalidParameter)
		}
		if k.TokenKeyId == "" {
			return fmt.Errorf("token key version vet for write: missing token key id: %w", db.ErrInvalidParameter)
		}
		if k.RootKeyVersionId == "" {
			return fmt.Errorf("token key version vet for write: missing root key version id: %w", db.ErrInvalidParameter)
		}
	}
	return nil
}

// TableName returns the tablename to override the default gorm table name
func (k *TokenKeyVersion) TableName() string {
	if k.tableName != "" {
		return k.tableName
	}
	return DefaultTokenKeyVersionTableName
}

// SetTableName sets the tablename and satisfies the ReplayableMessage
// interface. If the caller attempts to set the name to "" the name will be
// reset to the default name.
func (k *TokenKeyVersion) SetTableName(n string) {
	k.tableName = n
}

// Encrypt will encrypt the key version's key
func (k *TokenKeyVersion) Encrypt(ctx context.Context, cipher wrapping.Wrapper) error {
	// structwrapping doesn't support embedding, so we'll pass in the
	// store.TokenKeyVersion directly
	if err := structwrapping.WrapStruct(ctx, cipher, k.TokenKeyVersion, nil); err != nil {
		return fmt.Errorf("error encrypting kms token key version: %w", err)
	}
	return nil
}

// Decrypt will decrypt the key version's key
func (k *TokenKeyVersion) Decrypt(ctx context.Context, cipher wrapping.Wrapper) error {
	// structwrapping doesn't support embedding, so we'll pass in the
	// store.TokenKeyVersion directly
	if err := structwrapping.UnwrapStruct(ctx, cipher, k.TokenKeyVersion, nil); err != nil {
		return fmt.Errorf("error decrypting kms token key version: %w", err)
	}
	return nil
}
