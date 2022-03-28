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
	DefaultDatabaseKeyVersionTableName = "kms_database_key_version"
)

type DatabaseKeyVersion struct {
	*store.DatabaseKeyVersion
	tableName string `gorm:"-"`
}

// NewDatabaseKeyVersion creates a new in memory database key version. No options are
// currently supported.
func NewDatabaseKeyVersion(databaseKeyId string, key []byte, rootKeyVersionId string, _ ...Option) (*DatabaseKeyVersion, error) {
	const op = "kms.NewDatabaseKeyVersion"
	if databaseKeyId == "" {
		return nil, errors.NewDeprecated(errors.InvalidParameter, op, "missing database key id")
	}
	if len(key) == 0 {
		return nil, errors.NewDeprecated(errors.InvalidParameter, op, "missing key")
	}
	if rootKeyVersionId == "" {
		return nil, errors.NewDeprecated(errors.InvalidParameter, op, "missing root key version id")
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
	const op = "kms.(DatabaseKeyVersion).VetForWrite"
	if k.PrivateId == "" {
		return errors.New(ctx, errors.InvalidParameter, op, "missing private id")
	}
	switch opType {
	case db.CreateOp:
		if k.CtKey == nil {
			return errors.New(ctx, errors.InvalidParameter, op, "missing key")
		}
		if k.DatabaseKeyId == "" {
			return errors.New(ctx, errors.InvalidParameter, op, "missing database key id")
		}
		if k.RootKeyVersionId == "" {
			return errors.New(ctx, errors.InvalidParameter, op, "missing root key version id")
		}
	case db.UpdateOp:
		return errors.New(ctx, errors.InvalidParameter, op, "key is immutable")
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
	const op = "kms.(DatabaseKeyVersion).Encrypt"
	// structwrapping doesn't support embedding, so we'll pass in the
	// store.DatabaseKeyVersion directly
	if err := structwrapping.WrapStruct(ctx, cipher, k.DatabaseKeyVersion, nil); err != nil {
		return errors.Wrap(ctx, err, op, errors.WithCode(errors.Encrypt))
	}
	return nil
}

// Decrypt will decrypt the database key version's key
func (k *DatabaseKeyVersion) Decrypt(ctx context.Context, cipher wrapping.Wrapper) error {
	const op = "kms.(DatabaseKeyVersion).Decrypt"
	// structwrapping doesn't support embedding, so we'll pass in the
	// store.DatabaseKeyVersion directly
	if err := structwrapping.UnwrapStruct(ctx, cipher, k.DatabaseKeyVersion, nil); err != nil {
		return errors.Wrap(ctx, err, op, errors.WithCode(errors.Decrypt))
	}
	return nil
}
