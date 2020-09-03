package kms

import (
	"context"
	"fmt"
	"strings"

	"github.com/hashicorp/boundary/internal/db"
	wrapping "github.com/hashicorp/go-kms-wrapping"
)

// CreateDatabaseKeyVersion inserts into the repository and returns the new key
// version with its PrivateId.  There are no valid options at this time.
func (r *Repository) CreateDatabaseKeyVersion(ctx context.Context, rkvWrapper wrapping.Wrapper, databaseKeyId string, key []byte, opt ...Option) (*DatabaseKeyVersion, error) {
	if rkvWrapper == nil {
		return nil, fmt.Errorf("create database key version: missing root key version wrapper: %w", db.ErrInvalidParameter)
	}
	rootKeyVersionId := rkvWrapper.KeyID()
	switch {
	case !strings.HasPrefix(rootKeyVersionId, RootKeyVersionPrefix):
		return nil, fmt.Errorf("create database key version: root key version id %s doesn't start with prefix %s: %w", rootKeyVersionId, RootKeyVersionPrefix, db.ErrInvalidParameter)
	case rootKeyVersionId == "":
		return nil, fmt.Errorf("create database key version: missing root key version id: %w", db.ErrInvalidParameter)
	}
	if databaseKeyId == "" {
		return nil, fmt.Errorf("create database key version: missing database key id: %w", db.ErrInvalidParameter)
	}
	if len(key) == 0 {
		return nil, fmt.Errorf("create database key version: missing key: %w", db.ErrInvalidParameter)
	}
	kv := AllocDatabaseKeyVersion()
	id, err := newDatabaseKeyVersionId()
	if err != nil {
		return nil, fmt.Errorf("create database key version: %w", err)
	}
	kv.PrivateId = id
	kv.RootKeyVersionId = rootKeyVersionId
	kv.Key = key
	kv.DatabaseKeyId = databaseKeyId
	if err := kv.Encrypt(ctx, rkvWrapper); err != nil {
		return nil, fmt.Errorf("create database key version: encrypt: %w", err)
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
		return nil, fmt.Errorf("create database key version: %w for %s database key id", err, kv.DatabaseKeyId)
	}
	return returnedKey.(*DatabaseKeyVersion), err
}

// LookupDatabaseKeyVersion will look up a key version in the repository.  If
// the key version is not found, it will return nil, nil.
func (r *Repository) LookupDatabaseKeyVersion(ctx context.Context, keyWrapper wrapping.Wrapper, privateId string, opt ...Option) (*DatabaseKeyVersion, error) {
	if privateId == "" {
		return nil, fmt.Errorf("lookup database key version: missing private id: %w", db.ErrInvalidParameter)
	}
	if keyWrapper == nil {
		return nil, fmt.Errorf("lookup database key version: missing key wrapper: %w", db.ErrInvalidParameter)
	}
	k := AllocDatabaseKeyVersion()
	k.PrivateId = privateId
	if err := r.reader.LookupById(ctx, &k); err != nil {
		return nil, fmt.Errorf("lookup database key version: failed %w for %s", err, privateId)
	}
	if err := k.Decrypt(ctx, keyWrapper); err != nil {
		return nil, fmt.Errorf("lookup database key version: decrypt: %w", err)
	}
	return &k, nil
}

// DeleteDatabaseKeyVersion deletes the key version for the provided id from the
// repository returning a count of the number of records deleted.  All options
// are ignored.
func (r *Repository) DeleteDatabaseKeyVersion(ctx context.Context, privateId string, opt ...Option) (int, error) {
	if privateId == "" {
		return db.NoRowsAffected, fmt.Errorf("delete database key version: missing private id: %w", db.ErrInvalidParameter)
	}
	k := AllocDatabaseKeyVersion()
	k.PrivateId = privateId
	if err := r.reader.LookupById(ctx, &k); err != nil {
		return db.NoRowsAffected, fmt.Errorf("delete database key version: failed %w for %s", err, privateId)
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
			if err == nil && rowsDeleted > 1 {
				return db.ErrMultipleRecords
			}
			return err
		},
	)
	if err != nil {
		return db.NoRowsAffected, fmt.Errorf("delete database key version: %s: %w", privateId, err)
	}
	return rowsDeleted, nil
}

// LatestDatabaseKeyVersion searches for the key version with the highest
// version number.  When no results are found, it returns nil,
// db.ErrRecordNotFound.
func (r *Repository) LatestDatabaseKeyVersion(ctx context.Context, rkvWrapper wrapping.Wrapper, databaseKeyId string, opt ...Option) (*DatabaseKeyVersion, error) {
	if databaseKeyId == "" {
		return nil, fmt.Errorf("latest database key version: missing database key id: %w", db.ErrInvalidParameter)
	}
	if rkvWrapper == nil {
		return nil, fmt.Errorf("latest database key version: missing root key version wrapper: %w", db.ErrInvalidParameter)
	}
	var foundKeys []*DatabaseKeyVersion
	if err := r.reader.SearchWhere(ctx, &foundKeys, "database_key_id = ?", []interface{}{databaseKeyId}, db.WithLimit(1), db.WithOrder("version desc")); err != nil {
		return nil, fmt.Errorf("latest database key version: failed %w for %s", err, databaseKeyId)
	}
	if len(foundKeys) == 0 {
		return nil, db.ErrRecordNotFound
	}
	if err := foundKeys[0].Decrypt(ctx, rkvWrapper); err != nil {
		return nil, fmt.Errorf("latest database key version: %w", err)
	}
	return foundKeys[0], nil
}

// ListDatabaseKeyVersions will lists versions of a key.  Supports the WithLimit option.
func (r *Repository) ListDatabaseKeyVersions(ctx context.Context, rkvWrapper wrapping.Wrapper, databaseKeyId string, opt ...Option) ([]DekVersion, error) {
	if databaseKeyId == "" {
		return nil, fmt.Errorf("list database key versions: missing database key id %w", db.ErrInvalidParameter)
	}
	if rkvWrapper == nil {
		return nil, fmt.Errorf("list database key versions: missing root key version wrapper: %w", db.ErrInvalidParameter)
	}
	var versions []*DatabaseKeyVersion
	err := r.list(ctx, &versions, "database_key_id = ?", []interface{}{databaseKeyId}, opt...)
	if err != nil {
		return nil, fmt.Errorf("list database key versions: %w", err)
	}
	for i, k := range versions {
		if err := k.Decrypt(ctx, rkvWrapper); err != nil {
			return nil, fmt.Errorf("list database key versions: error decrypting key num %d: %w", i, err)
		}
	}
	dekVersions := make([]DekVersion, 0, len(versions))
	for _, version := range versions {
		dekVersions = append(dekVersions, version)
	}
	return dekVersions, nil
}
