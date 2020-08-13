package kms

import (
	"context"
	"fmt"

	"github.com/hashicorp/boundary/internal/db"
	"github.com/hashicorp/boundary/internal/oplog"
)

// CreateRootKeyVersion inserts into the repository and returns the new root key
// version with its PrivateId.  There are no valid options at this time.
func (r *Repository) CreateRootKeyVersion(ctx context.Context, k *RootKeyVersion, opt ...Option) (*RootKeyVersion, error) {
	if k == nil {
		return nil, fmt.Errorf("create root key version: missing key %w", db.ErrNilParameter)
	}
	if k.RootKeyVersion == nil {
		return nil, fmt.Errorf("create root key version: missing key store %w", db.ErrNilParameter)
	}
	if k.PrivateId != "" {
		return nil, fmt.Errorf("create root key version: private id not empty: %w", db.ErrInvalidParameter)
	}
	if k.RootKeyId == "" {
		return nil, fmt.Errorf("create root key version: missing root key id: %w", db.ErrInvalidParameter)
	}
	if k.Key == "" {
		return nil, fmt.Errorf("create root key version: missing key: %w", db.ErrInvalidParameter)
	}
	if k.Version != 0 {
		return nil, fmt.Errorf("create root key version: version not empty: %w", db.ErrInvalidParameter)
	}
	id, err := newRootKeyVersionId()
	if err != nil {
		return nil, fmt.Errorf("create root key version: %w", err)
	}
	c := k.Clone().(*RootKeyVersion)
	c.PrivateId = id
	if err := c.encrypt(ctx, r.wrapper); err != nil {
		return nil, fmt.Errorf("create root key version: encrypt: %w", err)
	}

	var returnedKey interface{}
	_, err = r.writer.DoTx(
		ctx,
		db.StdRetryCnt,
		db.ExpBackoff{},
		func(_ db.Reader, w db.Writer) error {
			returnedKey = c.Clone()
			if err := w.Create(ctx, returnedKey, db.WithOplog(r.wrapper, c.oplog(oplog.OpType_OP_TYPE_CREATE))); err != nil {
				return err
			}
			return nil
		},
	)
	if err != nil {
		return nil, fmt.Errorf("create root key version: %w for %s", err, c.PrivateId)
	}
	return returnedKey.(*RootKeyVersion), err
}

// LookupRootKeyVersion will look up a root key version in the repository.  If
// the key version is not found, it will return nil, nil.
func (r *Repository) LookupRootKeyVersion(ctx context.Context, privateId string, opt ...Option) (*RootKeyVersion, error) {
	if privateId == "" {
		return nil, fmt.Errorf("lookup root key version: missing private id %w", db.ErrNilParameter)
	}

	k := allocRootKeyVersion()
	k.PrivateId = privateId
	if err := r.reader.LookupById(ctx, &k); err != nil {
		return nil, fmt.Errorf("lookup root key version: failed %w for %s", err, privateId)
	}
	if err := k.decrypt(ctx, r.wrapper); err != nil {
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
	k := allocRootKeyVersion()
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
			metadata := k.oplog(oplog.OpType_OP_TYPE_DELETE)
			dk := k.Clone()
			rowsDeleted, err = w.Delete(ctx, dk, db.WithOplog(r.wrapper, metadata))
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
