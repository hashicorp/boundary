package kms

import (
	"context"
	"fmt"
	"strings"

	"github.com/hashicorp/boundary/internal/db"
	wrapping "github.com/hashicorp/go-kms-wrapping"
)

// CreateTokenKeyVersion inserts into the repository and returns the new key
// version with its PrivateId.  There are no valid options at this time.
func (r *Repository) CreateTokenKeyVersion(ctx context.Context, rkvWrapper wrapping.Wrapper, tokenKeyId string, key []byte, opt ...Option) (*TokenKeyVersion, error) {
	if rkvWrapper == nil {
		return nil, fmt.Errorf("create token key version: missing root key version wrapper: %w", db.ErrInvalidParameter)
	}
	rootKeyVersionId := rkvWrapper.KeyID()
	switch {
	case !strings.HasPrefix(rootKeyVersionId, RootKeyVersionPrefix):
		return nil, fmt.Errorf("create token key version: root key version id %s doesn't start with prefix %s: %w", rootKeyVersionId, RootKeyVersionPrefix, db.ErrInvalidParameter)
	case rootKeyVersionId == "":
		return nil, fmt.Errorf("create token key version: missing root key version id: %w", db.ErrInvalidParameter)
	}
	if tokenKeyId == "" {
		return nil, fmt.Errorf("create token key version: missing token key id: %w", db.ErrInvalidParameter)
	}
	if len(key) == 0 {
		return nil, fmt.Errorf("create token key version: missing key: %w", db.ErrInvalidParameter)
	}
	kv := AllocTokenKeyVersion()
	id, err := newTokenKeyVersionId()
	if err != nil {
		return nil, fmt.Errorf("create token key version: %w", err)
	}
	kv.PrivateId = id
	kv.RootKeyVersionId = rootKeyVersionId
	kv.Key = key
	kv.TokenKeyId = tokenKeyId
	if err := kv.Encrypt(ctx, rkvWrapper); err != nil {
		return nil, fmt.Errorf("create token key version: encrypt: %w", err)
	}

	var returnedKey interface{}
	_, err = r.writer.DoTx(
		ctx,
		db.StdRetryCnt,
		db.ExpBackoff{},
		func(_ db.Reader, w db.Writer) error {
			returnedKey = kv.Clone()
			// no token entries for root key version
			if err := w.Create(ctx, returnedKey); err != nil {
				return err
			}
			return nil
		},
	)
	if err != nil {
		return nil, fmt.Errorf("create token key version: %w for %s token key id", err, kv.TokenKeyId)
	}
	return returnedKey.(*TokenKeyVersion), err
}

// LookupTokenKeyVersion will look up a key version in the repository.  If
// the key version is not found, it will return nil, nil.
func (r *Repository) LookupTokenKeyVersion(ctx context.Context, keyWrapper wrapping.Wrapper, privateId string, opt ...Option) (*TokenKeyVersion, error) {
	if privateId == "" {
		return nil, fmt.Errorf("lookup token key version: missing private id: %w", db.ErrInvalidParameter)
	}
	if keyWrapper == nil {
		return nil, fmt.Errorf("lookup token key version: missing key wrapper: %w", db.ErrInvalidParameter)
	}
	k := AllocTokenKeyVersion()
	k.PrivateId = privateId
	if err := r.reader.LookupById(ctx, &k); err != nil {
		return nil, fmt.Errorf("lookup token key version: failed %w for %s", err, privateId)
	}
	if err := k.Decrypt(ctx, keyWrapper); err != nil {
		return nil, fmt.Errorf("lookup token key version: decrypt: %w", err)
	}
	return &k, nil
}

// DeleteTokenKeyVersion deletes the key version for the provided id from the
// repository returning a count of the number of records deleted.  All options
// are ignored.
func (r *Repository) DeleteTokenKeyVersion(ctx context.Context, privateId string, opt ...Option) (int, error) {
	if privateId == "" {
		return db.NoRowsAffected, fmt.Errorf("delete token key version: missing private id: %w", db.ErrInvalidParameter)
	}
	k := AllocTokenKeyVersion()
	k.PrivateId = privateId
	if err := r.reader.LookupById(ctx, &k); err != nil {
		return db.NoRowsAffected, fmt.Errorf("delete token key version: failed %w for %s", err, privateId)
	}

	var rowsDeleted int
	_, err := r.writer.DoTx(
		ctx,
		db.StdRetryCnt,
		db.ExpBackoff{},
		func(_ db.Reader, w db.Writer) (err error) {
			dk := k.Clone()
			// no token entries for the key version
			rowsDeleted, err = w.Delete(ctx, dk)
			if err == nil && rowsDeleted > 1 {
				return db.ErrMultipleRecords
			}
			return err
		},
	)
	if err != nil {
		return db.NoRowsAffected, fmt.Errorf("delete token key version: %s: %w", privateId, err)
	}
	return rowsDeleted, nil
}

// LatestTokenKeyVersion searches for the key version with the highest
// version number.  When no results are found, it returns nil,
// db.ErrRecordNotFound.
func (r *Repository) LatestTokenKeyVersion(ctx context.Context, rkvWrapper wrapping.Wrapper, tokenKeyId string, opt ...Option) (*TokenKeyVersion, error) {
	if tokenKeyId == "" {
		return nil, fmt.Errorf("latest token key version: missing token key id: %w", db.ErrInvalidParameter)
	}
	if rkvWrapper == nil {
		return nil, fmt.Errorf("latest token key version: missing root key version wrapper: %w", db.ErrInvalidParameter)
	}
	var foundKeys []*TokenKeyVersion
	if err := r.reader.SearchWhere(ctx, &foundKeys, "token_key_id = ?", []interface{}{tokenKeyId}, db.WithLimit(1), db.WithOrder("version desc")); err != nil {
		return nil, fmt.Errorf("latest token key version: failed %w for %s", err, tokenKeyId)
	}
	if len(foundKeys) == 0 {
		return nil, db.ErrRecordNotFound
	}
	if err := foundKeys[0].Decrypt(ctx, rkvWrapper); err != nil {
		return nil, fmt.Errorf("latest token key version: %w", err)
	}
	return foundKeys[0], nil
}

// ListTokenKeyVersions will lists versions of a key.  Supports the WithLimit option.
func (r *Repository) ListTokenKeyVersions(ctx context.Context, rkvWrapper wrapping.Wrapper, tokenKeyId string, opt ...Option) ([]*TokenKeyVersion, error) {
	if tokenKeyId == "" {
		return nil, fmt.Errorf("list token key versions: missing token key id %w", db.ErrInvalidParameter)
	}
	if rkvWrapper == nil {
		return nil, fmt.Errorf("list token key versions: missing root key version wrapper: %w", db.ErrInvalidParameter)
	}
	var versions []*TokenKeyVersion
	err := r.list(ctx, &versions, "token_key_id = ?", []interface{}{tokenKeyId}, opt...)
	if err != nil {
		return nil, fmt.Errorf("list token key versions: %w", err)
	}
	for i, k := range versions {
		if err := k.Decrypt(ctx, rkvWrapper); err != nil {
			return nil, fmt.Errorf("list token key versions: error decrypting key num %d: %w", i, err)
		}
	}
	return versions, nil
}
