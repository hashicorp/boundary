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
	DefaultDatabaseKeyVersionTableName = "kms_database_key_version"
)

type DatabaseKeyVersion struct {
	*store.DatabaseKeyVersion
	tableName string `gorm:"-"`
}

// NewDatabaseKeyVersion creates a new in memory database key version. No options are
// currently supported.
func NewDatabaseKeyVersion(databaseKeyId string, key []byte, rootKeyVersionId string, opt ...Option) (*DatabaseKeyVersion, error) {
	if databaseKeyId == "" {
		return nil, fmt.Errorf("new database key version: missing database key id: %w", db.ErrInvalidParameter)
	}
	if len(key) == 0 {
		return nil, fmt.Errorf("new database key version: missing key: %w", db.ErrInvalidParameter)
	}
	if rootKeyVersionId == "" {
		return nil, fmt.Errorf("new database key version: missing root key version id: %w", db.ErrInvalidParameter)
	}

	k := &DatabaseKeyVersion{
		DatabaseKeyVersion: &store.DatabaseKeyVersion{
			DatabaseKeyId:    databaseKeyId,
			RootKeyVersionId: rootKeyVersionId,
			Key:              key,
		},
	}
	return k, nil
}

// AllocDatabaseKeyVersion allocates a DatabaseKeyVersion
func AllocDatabaseKeyVersion() DatabaseKeyVersion {
	return DatabaseKeyVersion{
		DatabaseKeyVersion: &store.DatabaseKeyVersion{},
	}
}

// Clone creates a clone of the DatabaseKeyVersion
func (k *DatabaseKeyVersion) Clone() interface{} {
	cp := proto.Clone(k.DatabaseKeyVersion)
	return &DatabaseKeyVersion{
		DatabaseKeyVersion: cp.(*store.DatabaseKeyVersion),
	}
}

// VetForWrite implements db.VetForWrite() interface and validates the database key
// version before it's written.
func (k *DatabaseKeyVersion) VetForWrite(ctx context.Context, r db.Reader, opType db.OpType, opt ...db.Option) error {
	if k.PrivateId == "" {
		return fmt.Errorf("database key version vet for write: missing private id: %w", db.ErrInvalidParameter)
	}
	switch opType {
	case db.CreateOp:
		if k.CtKey == nil {
			return fmt.Errorf("database key version vet for write: missing key: %w", db.ErrInvalidParameter)
		}
		if k.DatabaseKeyId == "" {
			return fmt.Errorf("database key version vet for write: missing database key id: %w", db.ErrInvalidParameter)
		}
		if k.RootKeyVersionId == "" {
			return fmt.Errorf("database key version vet for write: missing root key version id: %w", db.ErrInvalidParameter)
		}
	case db.UpdateOp:
		return fmt.Errorf("database key version vet for write: key is immutable: %w", db.ErrInvalidParameter)
	}
	return nil
}

// TableName returns the tablename to override the default gorm table name
func (k *DatabaseKeyVersion) TableName() string {
	if k.tableName != "" {
		return k.tableName
	}
	return DefaultDatabaseKeyVersionTableName
}

// SetTableName sets the tablename and satisfies the ReplayableMessage
// interface. If the caller attempts to set the name to "" the name will be
// reset to the default name.
func (k *DatabaseKeyVersion) SetTableName(n string) {
	k.tableName = n
}

// Encrypt will encrypt the database key version's key
func (k *DatabaseKeyVersion) Encrypt(ctx context.Context, cipher wrapping.Wrapper) error {
	// structwrapping doesn't support embedding, so we'll pass in the
	// store.DatabaseKeyVersion directly
	if err := structwrapping.WrapStruct(ctx, cipher, k.DatabaseKeyVersion, nil); err != nil {
		return fmt.Errorf("error encrypting kms database key version: %w", err)
	}
	return nil
}

// Decrypt will decrypt the database key version's key
func (k *DatabaseKeyVersion) Decrypt(ctx context.Context, cipher wrapping.Wrapper) error {
	// structwrapping doesn't support embedding, so we'll pass in the
	// store.DatabaseKeyVersion directly
	if err := structwrapping.UnwrapStruct(ctx, cipher, k.DatabaseKeyVersion, nil); err != nil {
		return fmt.Errorf("error decrypting kms database key version: %w", err)
	}
	return nil
}
