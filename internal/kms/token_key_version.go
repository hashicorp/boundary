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
	DefaultTokenKeyVersionTableName = "kms_token_key_version"
)

type TokenKeyVersion struct {
	*store.TokenKeyVersion
	tableName string `gorm:"-"`
}

// TokenKeyVersion creates a new in memory key version. No options are
// currently supported.
func NewTokenKeyVersion(tokenKeyId string, key []byte, rootKeyVersionId string, _ ...Option) (*TokenKeyVersion, error) {
	const op = "kms.NewTokenKeyVersion"
	if tokenKeyId == "" {
		return nil, errors.NewDeprecated(errors.InvalidParameter, op, "missing token key id")
	}
	if len(key) == 0 {
		return nil, errors.NewDeprecated(errors.InvalidParameter, op, "missing key")
	}
	if rootKeyVersionId == "" {
		return nil, errors.NewDeprecated(errors.InvalidParameter, op, "missing root key version id")
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
func (k *TokenKeyVersion) VetForWrite(ctx context.Context, _r db.Reader, opType db.OpType, _ ...db.Option) error {
	const op = "kms.(TokenKeyVersion).VetForWrite"
	if k.PrivateId == "" {
		return errors.New(ctx, errors.InvalidParameter, op, "missing private id")
	}
	if opType == db.CreateOp {
		if k.CtKey == nil {
			return errors.New(ctx, errors.InvalidParameter, op, "missing key")
		}
		if k.TokenKeyId == "" {
			return errors.New(ctx, errors.InvalidParameter, op, "missing token key id")
		}
		if k.RootKeyVersionId == "" {
			return errors.New(ctx, errors.InvalidParameter, op, "missing root key version id")
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
	const op = "kms.(TokenKeyVersion).Encrypt"
	// structwrapping doesn't support embedding, so we'll pass in the
	// store.TokenKeyVersion directly
	if err := structwrapping.WrapStruct(ctx, cipher, k.TokenKeyVersion, nil); err != nil {
		return errors.Wrap(ctx, err, op, errors.WithCode(errors.Encrypt))
	}
	return nil
}

// Decrypt will decrypt the key version's key
func (k *TokenKeyVersion) Decrypt(ctx context.Context, cipher wrapping.Wrapper) error {
	const op = "kms.(TokenKeyVersion).Decrypt"
	// structwrapping doesn't support embedding, so we'll pass in the
	// store.TokenKeyVersion directly
	if err := structwrapping.UnwrapStruct(ctx, cipher, k.TokenKeyVersion, nil); err != nil {
		return errors.Wrap(ctx, err, op, errors.WithCode(errors.Decrypt))
	}
	return nil
}
