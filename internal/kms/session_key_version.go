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
	DefaultSessionKeyVersionTableName = "kms_session_key_version"
)

type SessionKeyVersion struct {
	*store.SessionKeyVersion
	tableName string `gorm:"-"`
}

// SessionKeyVersion creates a new in memory key version. No options are
// currently supported.
func NewSessionKeyVersion(sessionKeyId string, key []byte, rootKeyVersionId string, _ ...Option) (*SessionKeyVersion, error) {
	const op = "kms.NewSessionKeyVersion"
	if sessionKeyId == "" {
		return nil, errors.NewDeprecated(errors.InvalidParameter, op, "missing session key id")
	}
	if len(key) == 0 {
		return nil, errors.NewDeprecated(errors.InvalidParameter, op, "missing key")
	}
	if rootKeyVersionId == "" {
		return nil, errors.NewDeprecated(errors.InvalidParameter, op, "missing root key version id")
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
	const op = "kms.(SessionKeyVersion).VetForWrite"
	if k.PrivateId == "" {
		return errors.New(ctx, errors.InvalidParameter, op, "missing private id")
	}
	if opType == db.CreateOp {
		if k.CtKey == nil {
			return errors.New(ctx, errors.InvalidParameter, op, "missing key")
		}
		if k.SessionKeyId == "" {
			return errors.New(ctx, errors.InvalidParameter, op, "missing session key id")
		}
		if k.RootKeyVersionId == "" {
			return errors.New(ctx, errors.InvalidParameter, op, "missing root key version id")
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
	const op = "kms.(SessionKeyVersion).Encrypt"
	// structwrapping doesn't support embedding, so we'll pass in the
	// store.SessionKeyVersion directly
	if err := structwrapping.WrapStruct(ctx, cipher, k.SessionKeyVersion, nil); err != nil {
		return errors.Wrap(ctx, err, op, errors.WithCode(errors.Encrypt))
	}
	return nil
}

// Decrypt will decrypt the key version's key
func (k *SessionKeyVersion) Decrypt(ctx context.Context, cipher wrapping.Wrapper) error {
	const op = "kms.(SessionKeyVersion).Decrypt"
	// structwrapping doesn't support embedding, so we'll pass in the
	// store.SessionKeyVersion directly
	if err := structwrapping.UnwrapStruct(ctx, cipher, k.SessionKeyVersion, nil); err != nil {
		return errors.Wrap(ctx, err, op, errors.WithCode(errors.Decrypt))
	}
	return nil
}
