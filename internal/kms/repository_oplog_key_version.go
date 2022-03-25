package kms

import (
	"context"
	"fmt"
	"strings"

	"github.com/hashicorp/boundary/internal/db"
	"github.com/hashicorp/boundary/internal/errors"
	wrapping "github.com/hashicorp/go-kms-wrapping/v2"
)

// CreateOplogKeyVersion inserts into the repository and returns the new key
// version with its PrivateId.  There are no valid options at this time.
func (r *Repository) CreateOplogKeyVersion(ctx context.Context, rkvWrapper wrapping.Wrapper, oplogKeyId string, key []byte, _ ...Option) (*OplogKeyVersion, error) {
	const op = "kms.(Repository).CreateOplogKeyVersion"
	if rkvWrapper == nil {
		return nil, errors.New(ctx, errors.InvalidParameter, op, "missing root key version wrapper")
	}
	rootKeyVersionId, err := rkvWrapper.KeyId(ctx)
	if err != nil {
		return nil, errors.Wrap(ctx, err, op, errors.WithMsg("unable to fetch key id"))
	}
	switch {
	case !strings.HasPrefix(rootKeyVersionId, RootKeyVersionPrefix):
		return nil, errors.New(ctx, errors.InvalidParameter, op, fmt.Sprintf("root key version id %s doesn't start with prefix %s", rootKeyVersionId, RootKeyVersionPrefix))
	case rootKeyVersionId == "":
		return nil, errors.New(ctx, errors.InvalidParameter, op, "missing root key version id")
	}
	if oplogKeyId == "" {
		return nil, errors.New(ctx, errors.InvalidParameter, op, "missing oplog key id")
	}
	if len(key) == 0 {
		return nil, errors.New(ctx, errors.InvalidParameter, op, "missing key")
	}
	kv := AllocOplogKeyVersion()
	id, err := newOplogKeyVersionId()
	if err != nil {
		return nil, errors.Wrap(ctx, err, op)
	}
	kv.PrivateId = id
	kv.RootKeyVersionId = rootKeyVersionId
	kv.Key = key
	kv.OplogKeyId = oplogKeyId
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
		return nil, errors.Wrap(ctx, err, op, errors.WithMsg(fmt.Sprintf("failed for %s oplog key id", kv.OplogKeyId)))
	}
	return returnedKey.(*OplogKeyVersion), nil
}

// LookupOplogKeyVersion will look up a key version in the repository.  If
// the key version is not found, it will return nil, nil.
func (r *Repository) LookupOplogKeyVersion(ctx context.Context, keyWrapper wrapping.Wrapper, privateId string, _ ...Option) (*OplogKeyVersion, error) {
	const op = "kms.(Repository).LookupOplogKeyVersion"
	if privateId == "" {
		return nil, errors.New(ctx, errors.InvalidParameter, op, "missing private id")
	}
	if keyWrapper == nil {
		return nil, errors.New(ctx, errors.InvalidParameter, op, "missing key wrapper")
	}
	k := AllocOplogKeyVersion()
	k.PrivateId = privateId
	if err := r.reader.LookupById(ctx, &k); err != nil {
		return nil, errors.Wrap(ctx, err, op, errors.WithMsg(fmt.Sprintf("failed for %s", privateId)))
	}
	if err := k.Decrypt(ctx, keyWrapper); err != nil {
		return nil, errors.Wrap(ctx, err, op)
	}
	return &k, nil
}

// DeleteOplogKeyVersion deletes the key version for the provided id from the
// repository returning a count of the number of records deleted.  All options
// are ignored.
func (r *Repository) DeleteOplogKeyVersion(ctx context.Context, privateId string, _ ...Option) (int, error) {
	const op = "kms.(Repository).DeleteOplogKeyVersion"
	if privateId == "" {
		return db.NoRowsAffected, errors.New(ctx, errors.InvalidParameter, op, "missing private id")
	}
	k := AllocOplogKeyVersion()
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

// LatestOplogKeyVersion searches for the key version with the highest
// version number.  When no results are found, it returns nil with an
// errors.RecordNotFound error.
func (r *Repository) LatestOplogKeyVersion(ctx context.Context, rkvWrapper wrapping.Wrapper, oplogKeyId string, _ ...Option) (*OplogKeyVersion, error) {
	const op = "kms.(Repository).LatestOplogKeyVersion"
	if oplogKeyId == "" {
		return nil, errors.New(ctx, errors.InvalidParameter, op, "missing oplog key id")
	}
	if rkvWrapper == nil {
		return nil, errors.New(ctx, errors.InvalidParameter, op, "missing root key version wrapper")
	}
	var foundKeys []*OplogKeyVersion
	if err := r.reader.SearchWhere(ctx, &foundKeys, "oplog_key_id = ?", []interface{}{oplogKeyId}, db.WithLimit(1), db.WithOrder("version desc")); err != nil {
		return nil, errors.Wrap(ctx, err, op, errors.WithMsg(fmt.Sprintf("failed for %s", oplogKeyId)))
	}
	if len(foundKeys) == 0 {
		return nil, errors.E(ctx, errors.WithCode(errors.RecordNotFound), errors.WithOp(op))
	}
	if err := foundKeys[0].Decrypt(ctx, rkvWrapper); err != nil {
		return nil, errors.Wrap(ctx, err, op)
	}
	return foundKeys[0], nil
}

// ListOplogKeyVersions will lists versions of a key.  Supports the WithLimit option.
func (r *Repository) ListOplogKeyVersions(ctx context.Context, rkvWrapper wrapping.Wrapper, oplogKeyId string, opt ...Option) ([]DekVersion, error) {
	const op = "kms.(Repository).ListOplogKeyVersions"
	if oplogKeyId == "" {
		return nil, errors.New(ctx, errors.InvalidParameter, op, "missing oplog key id")
	}
	if rkvWrapper == nil {
		return nil, errors.New(ctx, errors.InvalidParameter, op, "missing root key version wrapper")
	}
	var versions []*OplogKeyVersion
	err := r.list(ctx, &versions, "oplog_key_id = ?", []interface{}{oplogKeyId}, opt...)
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
