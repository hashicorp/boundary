package kms

import (
	"context"
	"fmt"
	"strings"

	"github.com/hashicorp/boundary/internal/db"
	"github.com/hashicorp/boundary/internal/errors"
	wrapping "github.com/hashicorp/go-kms-wrapping"
)

// CreateOidcKeyVersion inserts into the repository and returns the new key
// version with its PrivateId.  There are no valid options at this time.
func (r *Repository) CreateOidcKeyVersion(ctx context.Context, rkvWrapper wrapping.Wrapper, oidcKeyId string, key []byte, _ ...Option) (*OidcKeyVersion, error) {
	const op = "kms.(Repository).CreateOidcKeyVersion"
	if rkvWrapper == nil {
		return nil, errors.New(errors.InvalidParameter, op, "missing root key version wrapper")
	}
	rootKeyVersionId := rkvWrapper.KeyID()
	switch {
	case !strings.HasPrefix(rootKeyVersionId, RootKeyVersionPrefix):
		return nil, errors.New(errors.InvalidParameter, op, fmt.Sprintf("root key version id %s doesn't start with prefix %s", rootKeyVersionId, RootKeyVersionPrefix))
	case rootKeyVersionId == "":
		return nil, errors.New(errors.InvalidParameter, op, "missing root key version id")
	}
	if oidcKeyId == "" {
		return nil, errors.New(errors.InvalidParameter, op, "missing oidc key id")
	}
	if len(key) == 0 {
		return nil, errors.New(errors.InvalidParameter, op, "missing key")
	}
	kv := AllocOidcKeyVersion()
	id, err := newOidcKeyVersionId()
	if err != nil {
		return nil, errors.Wrap(err, op)
	}
	kv.PrivateId = id
	kv.RootKeyVersionId = rootKeyVersionId
	kv.Key = key
	kv.OidcKeyId = oidcKeyId
	if err := kv.Encrypt(ctx, rkvWrapper); err != nil {
		return nil, errors.Wrap(err, op)
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
				return errors.Wrap(err, op)
			}
			return nil
		},
	)
	if err != nil {
		return nil, errors.Wrap(err, op, errors.WithMsg(fmt.Sprintf("failed for %s oidc key id", kv.OidcKeyId)))
	}
	return returnedKey.(*OidcKeyVersion), nil
}

// LookupOidcKeyVersion will look up a key version in the repository.  If
// the key version is not found, it will return nil, nil.
func (r *Repository) LookupOidcKeyVersion(ctx context.Context, keyWrapper wrapping.Wrapper, privateId string, _ ...Option) (*OidcKeyVersion, error) {
	const op = "kms.(Repository).LookupOidcKeyVersion"
	if privateId == "" {
		return nil, errors.New(errors.InvalidParameter, op, "missing private id")
	}
	if keyWrapper == nil {
		return nil, errors.New(errors.InvalidParameter, op, "missing key wrapper")
	}
	k := AllocOidcKeyVersion()
	k.PrivateId = privateId
	if err := r.reader.LookupById(ctx, &k); err != nil {
		return nil, errors.Wrap(err, op, errors.WithMsg(fmt.Sprintf("failed for %s", privateId)))
	}
	if err := k.Decrypt(ctx, keyWrapper); err != nil {
		return nil, errors.Wrap(err, op)
	}
	return &k, nil
}

// DeleteOidcKeyVersion deletes the key version for the provided id from the
// repository returning a count of the number of records deleted.  All options
// are ignored.
func (r *Repository) DeleteOidcKeyVersion(ctx context.Context, privateId string, _ ...Option) (int, error) {
	const op = "kms.(Repository).DeleteOidcKeyVersion"
	if privateId == "" {
		return db.NoRowsAffected, errors.New(errors.InvalidParameter, op, "missing private id")
	}
	k := AllocOidcKeyVersion()
	k.PrivateId = privateId
	if err := r.reader.LookupById(ctx, &k); err != nil {
		return db.NoRowsAffected, errors.Wrap(err, op, errors.WithMsg(fmt.Sprintf("failed for %s", privateId)))
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
				return errors.Wrap(err, op)
			}
			if rowsDeleted > 1 {
				return errors.New(errors.MultipleRecords, op, "more than 1 resource would have been deleted")
			}
			return nil
		},
	)
	if err != nil {
		return db.NoRowsAffected, errors.Wrap(err, op, errors.WithMsg(fmt.Sprintf("failed for %s", privateId)))
	}
	return rowsDeleted, nil
}

// LatestOidcKeyVersion searches for the key version with the highest
// version number.  When no results are found, it returns nil with an
// errors.RecordNotFound error.
func (r *Repository) LatestOidcKeyVersion(ctx context.Context, rkvWrapper wrapping.Wrapper, OidcKeyId string, _ ...Option) (*OidcKeyVersion, error) {
	const op = "kms.(Repository).LatestOidcKeyVersion"
	if OidcKeyId == "" {
		return nil, errors.New(errors.InvalidParameter, op, "missing oidc key id")
	}
	if rkvWrapper == nil {
		return nil, errors.New(errors.InvalidParameter, op, "missing root key version wrapper")
	}
	var foundKeys []*OidcKeyVersion
	if err := r.reader.SearchWhere(ctx, &foundKeys, "oidc_key_id = ?", []interface{}{OidcKeyId}, db.WithLimit(1), db.WithOrder("version desc")); err != nil {
		return nil, errors.Wrap(err, op, errors.WithMsg(fmt.Sprintf("failed for %s", OidcKeyId)))
	}
	if len(foundKeys) == 0 {
		return nil, errors.E(errors.WithCode(errors.RecordNotFound), errors.WithOp(op))
	}
	if err := foundKeys[0].Decrypt(ctx, rkvWrapper); err != nil {
		return nil, errors.Wrap(err, op)
	}
	return foundKeys[0], nil
}

// ListOidcKeyVersions will lists versions of a key.  Supports the WithLimit option.
func (r *Repository) ListOidcKeyVersions(ctx context.Context, rkvWrapper wrapping.Wrapper, OidcKeyId string, opt ...Option) ([]DekVersion, error) {
	const op = "kms.(Repository).ListOidcKeyVersions"
	if OidcKeyId == "" {
		return nil, errors.New(errors.InvalidParameter, op, "missing oidc key id")
	}
	if rkvWrapper == nil {
		return nil, errors.New(errors.InvalidParameter, op, "missing root key version wrapper")
	}
	var versions []*OidcKeyVersion
	err := r.list(ctx, &versions, "oidc_key_id = ?", []interface{}{OidcKeyId}, opt...)
	if err != nil {
		return nil, errors.Wrap(err, op)
	}
	for i, k := range versions {
		if err := k.Decrypt(ctx, rkvWrapper); err != nil {
			return nil, errors.Wrap(err, op, errors.WithMsg(fmt.Sprintf("error decrypting key num %d", i)))
		}
	}
	dekVersions := make([]DekVersion, 0, len(versions))
	for _, version := range versions {
		dekVersions = append(dekVersions, version)
	}
	return dekVersions, nil
}
