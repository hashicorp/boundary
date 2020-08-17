package kms

import (
	"context"
	"fmt"

	"github.com/hashicorp/boundary/internal/db"
	"github.com/hashicorp/boundary/internal/kms/store"
	"github.com/hashicorp/boundary/internal/oplog"
	wrapping "github.com/hashicorp/go-kms-wrapping"
	"github.com/hashicorp/go-kms-wrapping/structwrapping"
	"google.golang.org/protobuf/proto"
)

const (
	defaultRootKeyVersionTableName = "kms_root_key_version"
)

type RootKeyVersion struct {
	*store.RootKeyVersion
	tableName string `gorm:"-"`
}

// NewRootKeyVersion creates a new in memory root key version. No options are
// currently supported.
func NewRootKeyVersion(rootKeyId string, key []byte, opt ...Option) (*RootKeyVersion, error) {
	if rootKeyId == "" {
		return nil, fmt.Errorf("new root key version: missing root key id: %w", db.ErrInvalidParameter)
	}
	if len(key) == 0 {
		return nil, fmt.Errorf("new root key version: missing key: %w", db.ErrInvalidParameter)
	}

	k := &RootKeyVersion{
		RootKeyVersion: &store.RootKeyVersion{
			RootKeyId: rootKeyId,
			Key:       key,
		},
	}
	return k, nil
}

func allocRootKeyVersion() RootKeyVersion {
	return RootKeyVersion{
		RootKeyVersion: &store.RootKeyVersion{},
	}
}

// Clone creates a clone of the RootKeyVersion
func (k *RootKeyVersion) Clone() interface{} {
	cp := proto.Clone(k.RootKeyVersion)
	return &RootKeyVersion{
		RootKeyVersion: cp.(*store.RootKeyVersion),
	}
}

// VetForWrite implements db.VetForWrite() interface and validates the root key
// version before it's written.
func (k *RootKeyVersion) VetForWrite(ctx context.Context, r db.Reader, opType db.OpType, opt ...db.Option) error {
	if k.PrivateId == "" {
		return fmt.Errorf("root key version vet for write: missing private id: %w", db.ErrInvalidParameter)
	}
	if opType == db.CreateOp {
		if k.CtKey == nil {
			return fmt.Errorf("root key version vet for write: missing key: %w", db.ErrInvalidParameter)
		}
		if k.RootKeyId == "" {
			return fmt.Errorf("root key version vet for write: missing root key id: %w", db.ErrInvalidParameter)
		}
	}
	return nil
}

// TableName returns the tablename to override the default gorm table name
func (k *RootKeyVersion) TableName() string {
	if k.tableName != "" {
		return k.tableName
	}
	return defaultRootKeyVersionTableName
}

// SetTableName sets the tablename and satisfies the ReplayableMessage
// interface. If the caller attempts to set the name to "" the name will be
// reset to the default name.
func (k *RootKeyVersion) SetTableName(n string) {
	k.tableName = n
}

func (k *RootKeyVersion) oplog(op oplog.OpType) oplog.Metadata {
	metadata := oplog.Metadata{
		"resource-public-id": []string{k.PrivateId},
		"resource-type":      []string{"kms root key version"},
		"op-type":            []string{op.String()},
		"root-key-id":        []string{k.RootKeyId},
	}
	return metadata
}

func (k *RootKeyVersion) encrypt(ctx context.Context, cipher wrapping.Wrapper) error {
	// structwrapping doesn't support embedding, so we'll pass in the
	// store.RootKey directly
	if err := structwrapping.WrapStruct(ctx, cipher, k.RootKeyVersion, nil); err != nil {
		return fmt.Errorf("error encrypting kms root key version: %w", err)
	}
	return nil
}

func (k *RootKeyVersion) decrypt(ctx context.Context, cipher wrapping.Wrapper) error {
	// structwrapping doesn't support embedding, so we'll pass in the
	// store.RootKeyVersion directly
	if err := structwrapping.UnwrapStruct(ctx, cipher, k.RootKeyVersion, nil); err != nil {
		return fmt.Errorf("error decrypting kms root key version: %w", err)
	}
	return nil
}
