package kms

import (
	"context"
	"fmt"

	"github.com/hashicorp/boundary/internal/db"
	"github.com/hashicorp/boundary/internal/errors"
	wrapping "github.com/hashicorp/go-kms-wrapping"
)

// CreateRootKeyVersion inserts into the repository and returns the new root key
// version with its PrivateId.  There are no valid options at this time.
func (r *Repository) CreateRootKeyVersion(ctx context.Context, keyWrapper wrapping.Wrapper, rootKeyId string, key []byte, _ ...Option) (*RootKeyVersion, error) {
	const op = "kms.(Repository).CreateRootKeyVersion"
	if rootKeyId == "" {
		return nil, errors.New(ctx, errors.InvalidParameter, op, "missing root key id")
	}
	if keyWrapper == nil {
		return nil, errors.New(ctx, errors.InvalidParameter, op, "missing key wrapper")
	}
	if len(key) == 0 {
		return nil, errors.New(ctx, errors.InvalidParameter, op, "missing key")
	}
	kv := AllocRootKeyVersion()
	id, err := newRootKeyVersionId()
	if err != nil {
		return nil, errors.Wrap(ctx, err, op)
	}
	kv.PrivateId = id
	kv.RootKeyId = rootKeyId
	kv.Key = key
	if err := kv.Encrypt(ctx, keyWrapper); err != nil {
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
		return nil, errors.Wrap(ctx, err, op, errors.WithMsg(fmt.Sprintf("failed for %s root key id", kv.RootKeyId)))
	}
	return returnedKey.(*RootKeyVersion), nil
}

// LookupRootKeyVersion will look up a root key version in the repository.  If
// the key version is not found, it will return nil, nil.
func (r *Repository) LookupRootKeyVersion(ctx context.Context, keyWrapper wrapping.Wrapper, privateId string, _ ...Option) (*RootKeyVersion, error) {
	const op = "kms.(Repository).LookupRootKeyVersion"
	if privateId == "" {
		return nil, errors.New(ctx, errors.InvalidParameter, op, "missing private id")
	}
	if keyWrapper == nil {
		return nil, errors.New(ctx, errors.InvalidParameter, op, "missing key wrapper")
	}
	k := AllocRootKeyVersion()
	k.PrivateId = privateId
	if err := r.reader.LookupById(ctx, &k); err != nil {
		return nil, errors.Wrap(ctx, err, op, errors.WithMsg(fmt.Sprintf("failed for %s", privateId)))
	}
	if err := k.Decrypt(ctx, keyWrapper); err != nil {
		return nil, errors.Wrap(ctx, err, op)
	}
	return &k, nil
}

// DeleteRootKeyVersion deletes the root key version for the provided id from the
// repository returning a count of the number of records deleted.  All options
// are ignored.
func (r *Repository) DeleteRootKeyVersion(ctx context.Context, privateId string, _ ...Option) (int, error) {
	const op = "kms.(Repository).DeleteRootKeyVersion"
	if privateId == "" {
		return db.NoRowsAffected, errors.New(ctx, errors.InvalidParameter, op, "missing private id")
	}
	k := AllocRootKeyVersion()
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
			// no oplog entries for root key version
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

// LatestRootKeyVersion searches for the root key version with the highest
// version number.  When no results are found, it returns nil with an
// errors.RecordNotFound error.
func (r *Repository) LatestRootKeyVersion(ctx context.Context, keyWrapper wrapping.Wrapper, rootKeyId string, _ ...Option) (*RootKeyVersion, error) {
	const op = "kms.(Repository).LatestRootKeyVersion"
	if rootKeyId == "" {
		return nil, errors.New(ctx, errors.InvalidParameter, op, "missing root key id")
	}
	if keyWrapper == nil {
		return nil, errors.New(ctx, errors.InvalidParameter, op, "missing key wrapper")
	}
	var foundKeys []RootKeyVersion
	if err := r.reader.SearchWhere(ctx, &foundKeys, "root_key_id = ?", []interface{}{rootKeyId}, db.WithLimit(1), db.WithOrder("version desc")); err != nil {
		return nil, errors.Wrap(ctx, err, op, errors.WithMsg(fmt.Sprintf("failed for %s", rootKeyId)))
	}
	if len(foundKeys) == 0 {
		return nil, errors.E(ctx, errors.WithCode(errors.RecordNotFound), errors.WithOp(op))
	}
	if err := foundKeys[0].Decrypt(ctx, keyWrapper); err != nil {
		return nil, errors.Wrap(ctx, err, op)
	}
	return &foundKeys[0], nil
}

// ListRootKeyVersions in versions of a root key.  Supports the WithLimit option.
func (r *Repository) ListRootKeyVersions(ctx context.Context, keyWrapper wrapping.Wrapper, rootKeyId string, opt ...Option) ([]*RootKeyVersion, error) {
	const op = "kms.(Repository).ListRootKeyVersions"
	if rootKeyId == "" {
		return nil, errors.New(ctx, errors.InvalidParameter, op, "missing root key id")
	}
	if keyWrapper == nil {
		return nil, errors.New(ctx, errors.InvalidParameter, op, "missing key wrapper")
	}
	var versions []*RootKeyVersion
	err := r.list(ctx, &versions, "root_key_id = ?", []interface{}{rootKeyId}, opt...)
	if err != nil {
		return nil, errors.Wrap(ctx, err, op)
	}
	for i, k := range versions {
		if err := k.Decrypt(ctx, keyWrapper); err != nil {
			return nil, errors.Wrap(ctx, err, op, errors.WithMsg(fmt.Sprintf("error decrypting key num %d", i)))
		}
	}
	return versions, nil
}
