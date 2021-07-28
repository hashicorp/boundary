package kms

import (
	"context"

	"github.com/hashicorp/boundary/internal/db"
	"github.com/hashicorp/boundary/internal/errors"
	"github.com/hashicorp/boundary/internal/kms/store"
	wrapping "github.com/hashicorp/go-kms-wrapping"
	"github.com/hashicorp/go-kms-wrapping/structwrapping"
	"google.golang.org/protobuf/proto"
)

const (
	DefaultRootKeyVersionTableName = "kms_root_key_version"
)

type RootKeyVersion struct {
	*store.RootKeyVersion
	tableName string `gorm:"-"`
}

// NewRootKeyVersion creates a new in memory root key version. No options are
// currently supported.
func NewRootKeyVersion(rootKeyId string, key []byte, _ ...Option) (*RootKeyVersion, error) {
	const op = "kms.NewRootKeyVersion"
	if rootKeyId == "" {
		return nil, errors.NewDeprecated(errors.InvalidParameter, op, "missing root key id")
	}
	if len(key) == 0 {
		return nil, errors.NewDeprecated(errors.InvalidParameter, op, "missing key")
	}

	k := &RootKeyVersion{
		RootKeyVersion: &store.RootKeyVersion{
			RootKeyId: rootKeyId,
			Key:       key,
		},
	}
	return k, nil
}

// AllocRootKeyVersion allocates a RootKeyVersion
func AllocRootKeyVersion() RootKeyVersion {
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
func (k *RootKeyVersion) VetForWrite(ctx context.Context, _ db.Reader, opType db.OpType, _ ...db.Option) error {
	const op = "kms.(RootKeyVersion).VetForWrite"
	if k.PrivateId == "" {
		return errors.New(ctx, errors.InvalidParameter, op, "missing private id")
	}
	switch opType {
	case db.CreateOp:
		if k.CtKey == nil {
			return errors.New(ctx, errors.InvalidParameter, op, "missing key")
		}
		if k.RootKeyId == "" {
			return errors.New(ctx, errors.InvalidParameter, op, "missing root key id")
		}
	case db.UpdateOp:
		return errors.New(ctx, errors.InvalidParameter, op, "key is immutable")
	}
	return nil
}

// TableName returns the tablename to override the default gorm table name
func (k *RootKeyVersion) TableName() string {
	if k.tableName != "" {
		return k.tableName
	}
	return DefaultRootKeyVersionTableName
}

// SetTableName sets the tablename and satisfies the ReplayableMessage
// interface. If the caller attempts to set the name to "" the name will be
// reset to the default name.
func (k *RootKeyVersion) SetTableName(n string) {
	k.tableName = n
}

// Encrypt will encrypt the root key version's key
func (k *RootKeyVersion) Encrypt(ctx context.Context, cipher wrapping.Wrapper) error {
	const op = "kms.(RootKeyVersion).Encrypt"
	// structwrapping doesn't support embedding, so we'll pass in the
	// store.RootKey directly
	if err := structwrapping.WrapStruct(ctx, cipher, k.RootKeyVersion, nil); err != nil {
		return errors.Wrap(ctx, err, op, errors.WithCode(errors.Encrypt))
	}
	return nil
}

// Decrypt will decrypt the root key version's key
func (k *RootKeyVersion) Decrypt(ctx context.Context, cipher wrapping.Wrapper) error {
	const op = "kms.(RootKeyVersion).Decrypt"
	// structwrapping doesn't support embedding, so we'll pass in the
	// store.RootKeyVersion directly
	if err := structwrapping.UnwrapStruct(ctx, cipher, k.RootKeyVersion, nil); err != nil {
		return errors.Wrap(ctx, err, op, errors.WithCode(errors.Decrypt))
	}
	return nil
}
