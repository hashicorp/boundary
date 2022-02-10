package kms

import (
	"context"
	"fmt"
	"strings"

	"github.com/hashicorp/boundary/internal/db"
	"github.com/hashicorp/boundary/internal/errors"
	wrapping "github.com/hashicorp/go-kms-wrapping/v2"
)

// CreateAuditKeyVersion inserts into the repository and returns the new key
// version with its PrivateId.  There are no valid options at this time.
func (r *Repository) CreateAuditKeyVersion(ctx context.Context, rkvWrapper wrapping.Wrapper, auditKeyId string, key []byte, _ ...Option) (*AuditKeyVersion, error) {
	const op = "kms.(Repository).CreateAuditKeyVersion"
	if rkvWrapper == nil {
		return nil, errors.New(ctx, errors.InvalidParameter, op, "missing root key version wrapper")
	}
	rootKeyVersionId := rkvWrapper.KeyID()
	switch {
	case !strings.HasPrefix(rootKeyVersionId, RootKeyVersionPrefix):
		return nil, errors.New(ctx, errors.InvalidParameter, op, fmt.Sprintf("root key version id %s doesn't start with prefix %s", rootKeyVersionId, RootKeyVersionPrefix))
	case rootKeyVersionId == "":
		return nil, errors.New(ctx, errors.InvalidParameter, op, "missing root key version id")
	}
	if auditKeyId == "" {
		return nil, errors.New(ctx, errors.InvalidParameter, op, "missing audit key id")
	}
	if len(key) == 0 {
		return nil, errors.New(ctx, errors.InvalidParameter, op, "missing key")
	}
	kv := AllocAuditKeyVersion()
	id, err := newAuditKeyVersionId(ctx)
	if err != nil {
		return nil, errors.Wrap(ctx, err, op)
	}
	kv.PrivateId = id
	kv.RootKeyVersionId = rootKeyVersionId
	kv.Key = key
	kv.AuditKeyId = auditKeyId
	if err := kv.Encrypt(ctx, rkvWrapper); err != nil {
		return nil, errors.Wrap(ctx, err, op)
	}

	var returnedKey interface{}
	_, err = r.writer.DoTx(
		ctx,
		db.StdRetryCnt,
		db.ExpBackoff{},
		func(_ db.Reader, w db.Writer) error {
			returnedKey = kv.Clone()
			// no oplog entries for root key version
			if err := w.Create(ctx, returnedKey); err != nil {
				return errors.Wrap(ctx, err, op)
			}
			return nil
		},
	)
	if err != nil {
		return nil, errors.Wrap(ctx, err, op, errors.WithMsg(fmt.Sprintf("failed for %s audit key id", kv.AuditKeyId)))
	}
	return returnedKey.(*AuditKeyVersion), nil
}

// LookupAuditKeyVersion will look up a key version in the repository.  If
// the key version is not found, it will return nil, nil.
func (r *Repository) LookupAuditKeyVersion(ctx context.Context, keyWrapper wrapping.Wrapper, privateId string, _ ...Option) (*AuditKeyVersion, error) {
	const op = "kms.(Repository).LookupAuditKeyVersion"
	if privateId == "" {
		return nil, errors.New(ctx, errors.InvalidParameter, op, "missing private id")
	}
	if keyWrapper == nil {
		return nil, errors.New(ctx, errors.InvalidParameter, op, "missing key wrapper")
	}
	k := AllocAuditKeyVersion()
	k.PrivateId = privateId
	if err := r.reader.LookupById(ctx, &k); err != nil {
		return nil, errors.Wrap(ctx, err, op, errors.WithMsg(fmt.Sprintf("failed for %s", privateId)))
	}
	if err := k.Decrypt(ctx, keyWrapper); err != nil {
		return nil, errors.Wrap(ctx, err, op)
	}
	return &k, nil
}

// DeleteAuditKeyVersion deletes the key version for the provided id from the
// repository returning a count of the number of records deleted.  All options
// are ignored.
func (r *Repository) DeleteAuditKeyVersion(ctx context.Context, privateId string, _ ...Option) (int, error) {
	const op = "kms.(Repository).DeleteAuditKeyVersion"
	if privateId == "" {
		return db.NoRowsAffected, errors.New(ctx, errors.InvalidParameter, op, "missing private id")
	}
	k := AllocAuditKeyVersion()
	k.PrivateId = privateId
	if err := r.reader.LookupById(ctx, &k); err != nil {
		return db.NoRowsAffected, errors.Wrap(ctx, err, op, errors.WithMsg(fmt.Sprintf("failed for %s", privateId)))
	}

	var rowsDeleted int
	_, err := r.writer.DoTx(
		ctx,
		db.StdRetryCnt,
		db.ExpBackoff{},
		func(_ db.Reader, w db.Writer) (err error) {
			dk := k.Clone()
			// no oplog entries for the key version
			rowsDeleted, err = w.Delete(ctx, dk)
			if err != nil {
				return errors.Wrap(ctx, err, op)
			}
			if rowsDeleted > 1 {
				return errors.New(ctx, errors.MultipleRecords, op, "more than 1 resource would have been deleted")
			}
			return nil
		},
	)
	if err != nil {
		return db.NoRowsAffected, errors.Wrap(ctx, err, op, errors.WithMsg(fmt.Sprintf("failed for %s", privateId)))
	}
	return rowsDeleted, nil
}

// LatestAuditKeyVersion searches for the key version with the highest
// version number.  When no results are found, it returns nil with an
// errors.RecordNotFound error.
func (r *Repository) LatestAuditKeyVersion(ctx context.Context, rkvWrapper wrapping.Wrapper, AuditKeyId string, _ ...Option) (*AuditKeyVersion, error) {
	const op = "kms.(Repository).LatestAuditKeyVersion"
	if AuditKeyId == "" {
		return nil, errors.New(ctx, errors.InvalidParameter, op, "missing audit key id")
	}
	if rkvWrapper == nil {
		return nil, errors.New(ctx, errors.InvalidParameter, op, "missing root key version wrapper")
	}
	var foundKeys []*AuditKeyVersion
	if err := r.reader.SearchWhere(ctx, &foundKeys, "audit_key_id = ?", []interface{}{AuditKeyId}, db.WithLimit(1), db.WithOrder("version desc")); err != nil {
		return nil, errors.Wrap(ctx, err, op, errors.WithMsg(fmt.Sprintf("failed for %s", AuditKeyId)))
	}
	if len(foundKeys) == 0 {
		return nil, errors.E(ctx, errors.WithCode(errors.RecordNotFound), errors.WithOp(op))
	}
	if err := foundKeys[0].Decrypt(ctx, rkvWrapper); err != nil {
		return nil, errors.Wrap(ctx, err, op)
	}
	return foundKeys[0], nil
}

// ListAuditKeyVersions will lists versions of a key.  Supports the WithLimit option.
func (r *Repository) ListAuditKeyVersions(ctx context.Context, rkvWrapper wrapping.Wrapper, AuditKeyId string, opt ...Option) ([]DekVersion, error) {
	const op = "kms.(Repository).ListAuditKeyVersions"
	if AuditKeyId == "" {
		return nil, errors.New(ctx, errors.InvalidParameter, op, "missing audit key id")
	}
	if rkvWrapper == nil {
		return nil, errors.New(ctx, errors.InvalidParameter, op, "missing root key version wrapper")
	}
	var versions []*AuditKeyVersion
	err := r.list(ctx, &versions, "audit_key_id = ?", []interface{}{AuditKeyId}, opt...)
	if err != nil {
		return nil, errors.Wrap(ctx, err, op)
	}
	for i, k := range versions {
		if err := k.Decrypt(ctx, rkvWrapper); err != nil {
			return nil, errors.Wrap(ctx, err, op, errors.WithMsg(fmt.Sprintf("error decrypting key num %d", i)))
		}
	}
	dekVersions := make([]DekVersion, 0, len(versions))
	for _, version := range versions {
		dekVersions = append(dekVersions, version)
	}
	return dekVersions, nil
}
