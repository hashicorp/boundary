package kms

import (
	"context"
	"fmt"

	"github.com/hashicorp/boundary/internal/db"
	wrapping "github.com/hashicorp/go-kms-wrapping"
)

// CreateRootKeyVersion inserts into the repository and returns the new root key
// version with its PrivateId.  There are no valid options at this time.
func (r *Repository) CreateRootKeyVersion(ctx context.Context, keyWrapper wrapping.Wrapper, rootKeyId string, key []byte, opt ...Option) (*RootKeyVersion, error) {
	if rootKeyId == "" {
		return nil, fmt.Errorf("create root key version: missing root key id: %w", db.ErrInvalidParameter)
	}
	if keyWrapper == nil {
		return nil, fmt.Errorf("create root key version: missing key wrapper: %w", db.ErrInvalidParameter)
	}
	if len(key) == 0 {
		return nil, fmt.Errorf("create root key version: missing key: %w", db.ErrInvalidParameter)
	}
	kv := AllocRootKeyVersion()
	id, err := newRootKeyVersionId()
	if err != nil {
		return nil, fmt.Errorf("create root key version: %w", err)
	}
	kv.PrivateId = id
	kv.RootKeyId = rootKeyId
	kv.Key = key
	if err := kv.Encrypt(ctx, keyWrapper); err != nil {
		return nil, fmt.Errorf("create root key version: encrypt: %w", err)
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
				return err
			}
			return nil
		},
	)
	if err != nil {
		return nil, fmt.Errorf("create root key version: %w for %s root key id", err, kv.RootKeyId)
	}
	return returnedKey.(*RootKeyVersion), err
}

// LookupRootKeyVersion will look up a root key version in the repository.  If
// the key version is not found, it will return nil, nil.
func (r *Repository) LookupRootKeyVersion(ctx context.Context, keyWrapper wrapping.Wrapper, privateId string, opt ...Option) (*RootKeyVersion, error) {
	if privateId == "" {
		return nil, fmt.Errorf("lookup root key version: missing private id: %w", db.ErrInvalidParameter)
	}
	if keyWrapper == nil {
		return nil, fmt.Errorf("lookup root key version: missing key wrapper: %w", db.ErrInvalidParameter)
	}
	k := AllocRootKeyVersion()
	k.PrivateId = privateId
	if err := r.reader.LookupById(ctx, &k); err != nil {
		return nil, fmt.Errorf("lookup root key version: failed %w for %s", err, privateId)
	}
	if err := k.Decrypt(ctx, keyWrapper); err != nil {
		return nil, fmt.Errorf("lookup root key version: decrypt: %w", err)
	}
	return &k, nil
}

// DeleteRootKeyVersion deletes the root key version for the provided id from the
// repository returning a count of the number of records deleted.  All options
// are ignored.
func (r *Repository) DeleteRootKeyVersion(ctx context.Context, privateId string, opt ...Option) (int, error) {
	if privateId == "" {
		return db.NoRowsAffected, fmt.Errorf("delete root key version: missing private id: %w", db.ErrInvalidParameter)
	}
	k := AllocRootKeyVersion()
	k.PrivateId = privateId
	if err := r.reader.LookupById(ctx, &k); err != nil {
		return db.NoRowsAffected, fmt.Errorf("delete root key version: failed %w for %s", err, privateId)
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
			if err == nil && rowsDeleted > 1 {
				return db.ErrMultipleRecords
			}
			return err
		},
	)
	if err != nil {
		return db.NoRowsAffected, fmt.Errorf("delete root key version: %s: %w", privateId, err)
	}
	return rowsDeleted, nil
}

// LatestRootKeyVersion searches for the root key version with the highest
// version number.  When no results are found, it returns nil,
// db.ErrRecordNotFound.
func (r *Repository) LatestRootKeyVersion(ctx context.Context, keyWrapper wrapping.Wrapper, rootKeyId string, opt ...Option) (*RootKeyVersion, error) {
	if rootKeyId == "" {
		return nil, fmt.Errorf("latest root key version: missing root key id: %w", db.ErrInvalidParameter)
	}
	if keyWrapper == nil {
		return nil, fmt.Errorf("latest root key version: missing key wrapper: %w", db.ErrInvalidParameter)
	}
	var foundKeys []RootKeyVersion
	if err := r.reader.SearchWhere(ctx, &foundKeys, "root_key_id = ?", []interface{}{rootKeyId}, db.WithLimit(1), db.WithOrder("version desc")); err != nil {
		return nil, fmt.Errorf("latest root key version: failed %w for %s", err, rootKeyId)
	}
	if len(foundKeys) == 0 {
		return nil, db.ErrRecordNotFound
	}
	if err := foundKeys[0].Decrypt(ctx, keyWrapper); err != nil {
		return nil, fmt.Errorf("latest root key version: %w", err)
	}
	return &foundKeys[0], nil
}

// ListRootKeyVersions in versions of a root key.  Supports the WithLimit option.
func (r *Repository) ListRootKeyVersions(ctx context.Context, keyWrapper wrapping.Wrapper, rootKeyId string, opt ...Option) ([]*RootKeyVersion, error) {
	if rootKeyId == "" {
		return nil, fmt.Errorf("list root key versions: missing root key id %w", db.ErrInvalidParameter)
	}
	if keyWrapper == nil {
		return nil, fmt.Errorf("list root key versions: missing key wrapper: %w", db.ErrInvalidParameter)
	}
	var versions []*RootKeyVersion
	err := r.list(ctx, &versions, "root_key_id = ?", []interface{}{rootKeyId}, opt...)
	if err != nil {
		return nil, fmt.Errorf("list root key versions: %w", err)
	}
	for i, k := range versions {
		if err := k.Decrypt(ctx, keyWrapper); err != nil {
			return nil, fmt.Errorf("list root key versions: error decrypting key num %d: %w", i, err)
		}
	}
	return versions, nil
}
