package kms

import (
	"context"
	"fmt"
	"strings"

	"github.com/hashicorp/boundary/internal/db"
	wrapping "github.com/hashicorp/go-kms-wrapping"
)

// CreateSessionKeyVersion inserts into the repository and returns the new key
// version with its PrivateId.  There are no valid options at this time.
func (r *Repository) CreateSessionKeyVersion(ctx context.Context, rkvWrapper wrapping.Wrapper, sessionKeyId string, key []byte, opt ...Option) (*SessionKeyVersion, error) {
	if rkvWrapper == nil {
		return nil, fmt.Errorf("create session key version: missing root key version wrapper: %w", db.ErrInvalidParameter)
	}
	rootKeyVersionId := rkvWrapper.KeyID()
	switch {
	case !strings.HasPrefix(rootKeyVersionId, RootKeyVersionPrefix):
		return nil, fmt.Errorf("create session key version: root key version id %s doesn't start with prefix %s: %w", rootKeyVersionId, RootKeyVersionPrefix, db.ErrInvalidParameter)
	case rootKeyVersionId == "":
		return nil, fmt.Errorf("create session key version: missing root key version id: %w", db.ErrInvalidParameter)
	}
	if sessionKeyId == "" {
		return nil, fmt.Errorf("create session key version: missing session key id: %w", db.ErrInvalidParameter)
	}
	if len(key) == 0 {
		return nil, fmt.Errorf("create session key version: missing key: %w", db.ErrInvalidParameter)
	}
	kv := AllocSessionKeyVersion()
	id, err := newSessionKeyVersionId()
	if err != nil {
		return nil, fmt.Errorf("create session key version: %w", err)
	}
	kv.PrivateId = id
	kv.RootKeyVersionId = rootKeyVersionId
	kv.Key = key
	kv.SessionKeyId = sessionKeyId
	if err := kv.Encrypt(ctx, rkvWrapper); err != nil {
		return nil, fmt.Errorf("create session key version: encrypt: %w", err)
	}

	var returnedKey interface{}
	_, err = r.writer.DoTx(
		ctx,
		db.StdRetryCnt,
		db.ExpBackoff{},
		func(_ db.Reader, w db.Writer) error {
			returnedKey = kv.Clone()
			// no session entries for root key version
			if err := w.Create(ctx, returnedKey); err != nil {
				return err
			}
			return nil
		},
	)
	if err != nil {
		return nil, fmt.Errorf("create session key version: %w for %s session key id", err, kv.SessionKeyId)
	}
	return returnedKey.(*SessionKeyVersion), err
}

// LookupSessionKeyVersion will look up a key version in the repository.  If
// the key version is not found, it will return nil, nil.
func (r *Repository) LookupSessionKeyVersion(ctx context.Context, keyWrapper wrapping.Wrapper, privateId string, opt ...Option) (*SessionKeyVersion, error) {
	if privateId == "" {
		return nil, fmt.Errorf("lookup session key version: missing private id: %w", db.ErrInvalidParameter)
	}
	if keyWrapper == nil {
		return nil, fmt.Errorf("lookup session key version: missing key wrapper: %w", db.ErrInvalidParameter)
	}
	k := AllocSessionKeyVersion()
	k.PrivateId = privateId
	if err := r.reader.LookupById(ctx, &k); err != nil {
		return nil, fmt.Errorf("lookup session key version: failed %w for %s", err, privateId)
	}
	if err := k.Decrypt(ctx, keyWrapper); err != nil {
		return nil, fmt.Errorf("lookup session key version: decrypt: %w", err)
	}
	return &k, nil
}

// DeleteSessionKeyVersion deletes the key version for the provided id from the
// repository returning a count of the number of records deleted.  All options
// are ignored.
func (r *Repository) DeleteSessionKeyVersion(ctx context.Context, privateId string, opt ...Option) (int, error) {
	if privateId == "" {
		return db.NoRowsAffected, fmt.Errorf("delete session key version: missing private id: %w", db.ErrInvalidParameter)
	}
	k := AllocSessionKeyVersion()
	k.PrivateId = privateId
	if err := r.reader.LookupById(ctx, &k); err != nil {
		return db.NoRowsAffected, fmt.Errorf("delete session key version: failed %w for %s", err, privateId)
	}

	var rowsDeleted int
	_, err := r.writer.DoTx(
		ctx,
		db.StdRetryCnt,
		db.ExpBackoff{},
		func(_ db.Reader, w db.Writer) (err error) {
			dk := k.Clone()
			// no session entries for the key version
			rowsDeleted, err = w.Delete(ctx, dk)
			if err == nil && rowsDeleted > 1 {
				return db.ErrMultipleRecords
			}
			return err
		},
	)
	if err != nil {
		return db.NoRowsAffected, fmt.Errorf("delete session key version: %s: %w", privateId, err)
	}
	return rowsDeleted, nil
}

// LatestSessionKeyVersion searches for the key version with the highest
// version number.  When no results are found, it returns nil,
// db.ErrRecordNotFound.
func (r *Repository) LatestSessionKeyVersion(ctx context.Context, rkvWrapper wrapping.Wrapper, sessionKeyId string, opt ...Option) (*SessionKeyVersion, error) {
	if sessionKeyId == "" {
		return nil, fmt.Errorf("latest session key version: missing session key id: %w", db.ErrInvalidParameter)
	}
	if rkvWrapper == nil {
		return nil, fmt.Errorf("latest session key version: missing root key version wrapper: %w", db.ErrInvalidParameter)
	}
	var foundKeys []*SessionKeyVersion
	if err := r.reader.SearchWhere(ctx, &foundKeys, "session_key_id = ?", []interface{}{sessionKeyId}, db.WithLimit(1), db.WithOrder("version desc")); err != nil {
		return nil, fmt.Errorf("latest session key version: failed %w for %s", err, sessionKeyId)
	}
	if len(foundKeys) == 0 {
		return nil, db.ErrRecordNotFound
	}
	if err := foundKeys[0].Decrypt(ctx, rkvWrapper); err != nil {
		return nil, fmt.Errorf("latest session key version: %w", err)
	}
	return foundKeys[0], nil
}

// ListSessionKeyVersions will lists versions of a key.  Supports the WithLimit option.
func (r *Repository) ListSessionKeyVersions(ctx context.Context, rkvWrapper wrapping.Wrapper, sessionKeyId string, opt ...Option) ([]DekVersion, error) {
	if sessionKeyId == "" {
		return nil, fmt.Errorf("list session key versions: missing session key id %w", db.ErrInvalidParameter)
	}
	if rkvWrapper == nil {
		return nil, fmt.Errorf("list session key versions: missing root key version wrapper: %w", db.ErrInvalidParameter)
	}
	var versions []*SessionKeyVersion
	err := r.list(ctx, &versions, "session_key_id = ?", []interface{}{sessionKeyId}, opt...)
	if err != nil {
		return nil, fmt.Errorf("list session key versions: %w", err)
	}
	for i, k := range versions {
		if err := k.Decrypt(ctx, rkvWrapper); err != nil {
			return nil, fmt.Errorf("list session key versions: error decrypting key num %d: %w", i, err)
		}
	}
	dekVersions := make([]DekVersion, 0, len(versions))
	for _, version := range versions {
		dekVersions = append(dekVersions, version)
	}
	return dekVersions, nil
}
