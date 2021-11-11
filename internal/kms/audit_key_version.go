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
	DefaultAuditKeyVersionTableName = "kms_audit_key_version"
)

type AuditKeyVersion struct {
	*store.AuditKeyVersion
	tableName string `gorm:"-"`
}

// NewAuditKeyVersion creates a new in memory audit key version.  This key is
// used for crypto operations on audit entries. No options are currently
// supported.
func NewAuditKeyVersion(ctx context.Context, auditKeyId string, key []byte, rootKeyVersionId string, _ ...Option) (*AuditKeyVersion, error) {
	const op = "kms.NewAuditKeyVersion"
	if auditKeyId == "" {
		return nil, errors.New(ctx, errors.InvalidParameter, op, "missing audit key id")
	}
	if len(key) == 0 {
		return nil, errors.New(ctx, errors.InvalidParameter, op, "missing key")
	}
	if rootKeyVersionId == "" {
		return nil, errors.New(ctx, errors.InvalidParameter, op, "missing root key version id")
	}

	k := &AuditKeyVersion{
		AuditKeyVersion: &store.AuditKeyVersion{
			AuditKeyId:       auditKeyId,
			RootKeyVersionId: rootKeyVersionId,
			Key:              key,
		},
	}
	return k, nil
}

// AllocAuditKeyVersion allocates a AuditKeyVersion
func AllocAuditKeyVersion() AuditKeyVersion {
	return AuditKeyVersion{
		AuditKeyVersion: &store.AuditKeyVersion{},
	}
}

// Clone creates a clone of the AuditKeyVersion
func (k *AuditKeyVersion) Clone() interface{} {
	cp := proto.Clone(k.AuditKeyVersion)
	return &AuditKeyVersion{
		AuditKeyVersion: cp.(*store.AuditKeyVersion),
	}
}

// VetForWrite implements db.VetForWrite() interface and validates the audit key
// version before it's written.
func (k *AuditKeyVersion) VetForWrite(ctx context.Context, r db.Reader, opType db.OpType, opt ...db.Option) error {
	const op = "kms.(AuditKeyVersion).VetForWrite"
	if k.PrivateId == "" {
		return errors.New(ctx, errors.InvalidParameter, op, "missing private id")
	}
	switch opType {
	case db.CreateOp:
		if k.CtKey == nil {
			return errors.New(ctx, errors.InvalidParameter, op, "missing key")
		}
		if k.AuditKeyId == "" {
			return errors.New(ctx, errors.InvalidParameter, op, "missing audit key id")
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
func (k *AuditKeyVersion) TableName() string {
	if k.tableName != "" {
		return k.tableName
	}
	return DefaultAuditKeyVersionTableName
}

// SetTableName sets the tablename and satisfies the ReplayableMessage
// interface. If the caller attempts to set the name to "" the name will be
// reset to the default name.
func (k *AuditKeyVersion) SetTableName(n string) {
	k.tableName = n
}

// Encrypt will encrypt the audit key version's key
func (k *AuditKeyVersion) Encrypt(ctx context.Context, cipher wrapping.Wrapper) error {
	const op = "kms.(AuditKeyVersion).Encrypt"
	// structwrapping doesn't support embedding, so we'll pass in the
	// store.AuditKeyVersion directly
	if err := structwrapping.WrapStruct(ctx, cipher, k.AuditKeyVersion, nil); err != nil {
		return errors.Wrap(ctx, err, op, errors.WithCode(errors.Encrypt))
	}
	return nil
}

// Decrypt will decrypt the audit key version's key
func (k *AuditKeyVersion) Decrypt(ctx context.Context, cipher wrapping.Wrapper) error {
	const op = "kms.(AuditKeyVersion).Decrypt"
	// structwrapping doesn't support embedding, so we'll pass in the
	// store.AuditKeyVersion directly
	if err := structwrapping.UnwrapStruct(ctx, cipher, k.AuditKeyVersion, nil); err != nil {
		return errors.Wrap(ctx, err, op, errors.WithCode(errors.Decrypt))
	}
	return nil
}
