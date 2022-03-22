package kms

import (
	"context"

	"github.com/hashicorp/boundary/internal/db"
	"github.com/hashicorp/boundary/internal/errors"
	"github.com/hashicorp/boundary/internal/kms/store"
	wrapping "github.com/hashicorp/go-kms-wrapping/v2"
	"github.com/hashicorp/go-kms-wrapping/v2/extras/structwrapping"
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
func NewOplogKeyVersion(oplogKeyId string, key []byte, rootKeyVersionId string, _ ...Option) (*OplogKeyVersion, error) {
	const op = "kms.NewOplogKeyVersion"
	if oplogKeyId == "" {
		return nil, errors.NewDeprecated(errors.InvalidParameter, op, "missing oplog key id")
	}
	if len(key) == 0 {
		return nil, errors.NewDeprecated(errors.InvalidParameter, op, "missing key")
	}
	if rootKeyVersionId == "" {
		return nil, errors.NewDeprecated(errors.InvalidParameter, op, "missing root key version id")
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
func (k *OplogKeyVersion) VetForWrite(ctx context.Context, _ db.Reader, opType db.OpType, _ ...db.Option) error {
	const op = "kms.(OplogKeyVersion).VetForWrite"
	if k.PrivateId == "" {
		return errors.New(ctx, errors.InvalidParameter, op, "missing private id")
	}
	if opType == db.CreateOp {
		if k.CtKey == nil {
			return errors.New(ctx, errors.InvalidParameter, op, "missing key")
		}
		if k.OplogKeyId == "" {
			return errors.New(ctx, errors.InvalidParameter, op, "missing oplog key id")
		}
		if k.RootKeyVersionId == "" {
			return errors.New(ctx, errors.InvalidParameter, op, "missing root key version id")
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
	const op = "kms.(OplogKeyVersion).Encrypt"
	// structwrapping doesn't support embedding, so we'll pass in the
	// store.OplogKeyVersion directly
	if err := structwrapping.WrapStruct(ctx, cipher, k.OplogKeyVersion, nil); err != nil {
		return errors.Wrap(ctx, err, op, errors.WithCode(errors.Encrypt))
	}
	return nil
}

// Decrypt will decrypt the key version's key
func (k *OplogKeyVersion) Decrypt(ctx context.Context, cipher wrapping.Wrapper) error {
	const op = "kms.(OplogKeyVersion).Decrypt"
	// structwrapping doesn't support embedding, so we'll pass in the
	// store.OplogKeyVersion directly
	if err := structwrapping.UnwrapStruct(ctx, cipher, k.OplogKeyVersion, nil); err != nil {
		return errors.Wrap(ctx, err, op, errors.WithCode(errors.Decrypt))
	}
	return nil
}
