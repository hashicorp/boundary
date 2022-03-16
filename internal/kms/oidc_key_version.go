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
	DefaultOidcKeyVersionTableName = "kms_oidc_key_version"
)

type OidcKeyVersion struct {
	*store.OidcKeyVersion
	tableName string `gorm:"-"`
}

// NewOidcKeyVersion creates a new in memory oidc key version.  This key is used
// to encrypt oidc state before it's included in the oidc auth url. No options
// are currently supported.
func NewOidcKeyVersion(oidcKeyId string, key []byte, rootKeyVersionId string, _ ...Option) (*OidcKeyVersion, error) {
	const op = "kms.NewOidcKeyVersion"
	if oidcKeyId == "" {
		return nil, errors.NewDeprecated(errors.InvalidParameter, op, "missing oidc key id")
	}
	if len(key) == 0 {
		return nil, errors.NewDeprecated(errors.InvalidParameter, op, "missing key")
	}
	if rootKeyVersionId == "" {
		return nil, errors.NewDeprecated(errors.InvalidParameter, op, "missing root key version id")
	}

	k := &OidcKeyVersion{
		OidcKeyVersion: &store.OidcKeyVersion{
			OidcKeyId:        oidcKeyId,
			RootKeyVersionId: rootKeyVersionId,
			Key:              key,
		},
	}
	return k, nil
}

// AllocOidcKeyVersion allocates a OidcKeyVersion
func AllocOidcKeyVersion() OidcKeyVersion {
	return OidcKeyVersion{
		OidcKeyVersion: &store.OidcKeyVersion{},
	}
}

// Clone creates a clone of the OidcKeyVersion
func (k *OidcKeyVersion) Clone() interface{} {
	cp := proto.Clone(k.OidcKeyVersion)
	return &OidcKeyVersion{
		OidcKeyVersion: cp.(*store.OidcKeyVersion),
	}
}

// VetForWrite implements db.VetForWrite() interface and validates the oidc key
// version before it's written.
func (k *OidcKeyVersion) VetForWrite(ctx context.Context, r db.Reader, opType db.OpType, opt ...db.Option) error {
	const op = "kms.(OidcKeyVersion).VetForWrite"
	if k.PrivateId == "" {
		return errors.New(ctx, errors.InvalidParameter, op, "missing private id")
	}
	switch opType {
	case db.CreateOp:
		if k.CtKey == nil {
			return errors.New(ctx, errors.InvalidParameter, op, "missing key")
		}
		if k.OidcKeyId == "" {
			return errors.New(ctx, errors.InvalidParameter, op, "missing oidc key id")
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
func (k *OidcKeyVersion) TableName() string {
	if k.tableName != "" {
		return k.tableName
	}
	return DefaultOidcKeyVersionTableName
}

// SetTableName sets the tablename and satisfies the ReplayableMessage
// interface. If the caller attempts to set the name to "" the name will be
// reset to the default name.
func (k *OidcKeyVersion) SetTableName(n string) {
	k.tableName = n
}

// Encrypt will encrypt the oidc key version's key
func (k *OidcKeyVersion) Encrypt(ctx context.Context, cipher wrapping.Wrapper) error {
	const op = "kms.(OidcKeyVersion).Encrypt"
	// structwrapping doesn't support embedding, so we'll pass in the
	// store.OidcKeyVersion directly
	if err := structwrapping.WrapStruct(ctx, cipher, k.OidcKeyVersion, nil); err != nil {
		return errors.Wrap(ctx, err, op, errors.WithCode(errors.Encrypt))
	}
	return nil
}

// Decrypt will decrypt the oidc key version's key
func (k *OidcKeyVersion) Decrypt(ctx context.Context, cipher wrapping.Wrapper) error {
	const op = "kms.(OidcKeyVersion).Decrypt"
	// structwrapping doesn't support embedding, so we'll pass in the
	// store.OidcKeyVersion directly
	if err := structwrapping.UnwrapStruct(ctx, cipher, k.OidcKeyVersion, nil); err != nil {
		return errors.Wrap(ctx, err, op, errors.WithCode(errors.Decrypt))
	}
	return nil
}
