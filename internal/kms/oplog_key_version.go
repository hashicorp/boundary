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
	DefaultOplogKeyVersionTableName = "kms_oplog_key_version"
)

type OplogKeyVersion struct {
	*store.OplogKeyVersion
	tableName string `gorm:"-"`
}

// OplogKeyVersion creates a new in memory key version. No options are
// currently supported.
func NewOplogKeyVersion(oplogKeyId string, key []byte, rootKeyVersionId string, opt ...Option) (*OplogKeyVersion, error) {
	if oplogKeyId == "" {
		return nil, fmt.Errorf("new oplog key version: missing oplog key id: %w", db.ErrInvalidParameter)
	}
	if len(key) == 0 {
		return nil, fmt.Errorf("new oplog key version: missing key: %w", db.ErrInvalidParameter)
	}
	if rootKeyVersionId == "" {
		return nil, fmt.Errorf("new oplog key version: missing root key version id: %w", db.ErrInvalidParameter)
	}

	k := &OplogKeyVersion{
		OplogKeyVersion: &store.OplogKeyVersion{
			OplogKeyId:       oplogKeyId,
			RootKeyVersionId: rootKeyVersionId,
			Key:              key,
		},
	}
	return k, nil
}

// AllocOplogKeyVersion allocates a key version
func AllocOplogKeyVersion() OplogKeyVersion {
	return OplogKeyVersion{
		OplogKeyVersion: &store.OplogKeyVersion{},
	}
}

// Clone creates a clone of the key version
func (k *OplogKeyVersion) Clone() interface{} {
	cp := proto.Clone(k.OplogKeyVersion)
	return &OplogKeyVersion{
		OplogKeyVersion: cp.(*store.OplogKeyVersion),
	}
}

// VetForWrite implements db.VetForWrite() interface and validates the key
// version before it's written.
func (k *OplogKeyVersion) VetForWrite(ctx context.Context, r db.Reader, opType db.OpType, opt ...db.Option) error {
	if k.PrivateId == "" {
		return fmt.Errorf("oplog key version vet for write: missing private id: %w", db.ErrInvalidParameter)
	}
	if opType == db.CreateOp {
		if k.CtKey == nil {
			return fmt.Errorf("oplog key version vet for write: missing key: %w", db.ErrInvalidParameter)
		}
		if k.OplogKeyId == "" {
			return fmt.Errorf("oplog key version vet for write: missing oplog key id: %w", db.ErrInvalidParameter)
		}
		if k.RootKeyVersionId == "" {
			return fmt.Errorf("oplog key version vet for write: missing root key version id: %w", db.ErrInvalidParameter)
		}
	}
	return nil
}

// TableName returns the tablename to override the default gorm table name
func (k *OplogKeyVersion) TableName() string {
	if k.tableName != "" {
		return k.tableName
	}
	return DefaultOplogKeyVersionTableName
}

// SetTableName sets the tablename and satisfies the ReplayableMessage
// interface. If the caller attempts to set the name to "" the name will be
// reset to the default name.
func (k *OplogKeyVersion) SetTableName(n string) {
	k.tableName = n
}

// Encrypt will encrypt the key version's key
func (k *OplogKeyVersion) Encrypt(ctx context.Context, cipher wrapping.Wrapper) error {
	// structwrapping doesn't support embedding, so we'll pass in the
	// store.OplogKeyVersion directly
	if err := structwrapping.WrapStruct(ctx, cipher, k.OplogKeyVersion, nil); err != nil {
		return fmt.Errorf("error encrypting kms oplog key version: %w", err)
	}
	return nil
}

// Decrypt will decrypt the key version's key
func (k *OplogKeyVersion) Decrypt(ctx context.Context, cipher wrapping.Wrapper) error {
	// structwrapping doesn't support embedding, so we'll pass in the
	// store.OplogKeyVersion directly
	if err := structwrapping.UnwrapStruct(ctx, cipher, k.OplogKeyVersion, nil); err != nil {
		return fmt.Errorf("error decrypting kms oplog key version: %w", err)
	}
	return nil
}
