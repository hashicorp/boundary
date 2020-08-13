package kms

import (
	"context"
	"fmt"

	"github.com/hashicorp/boundary/internal/db"
	"github.com/hashicorp/boundary/internal/oplog"
)

// CreateRootKey inserts into the repository and returns the new root key
// with its PrivateId.  There are no valid options at this time.
func (r *Repository) CreateRootKey(ctx context.Context, k *RootKey, opt ...Option) (*RootKey, error) {
	if k == nil {
		return nil, fmt.Errorf("create root key: missing key: %w", db.ErrNilParameter)
	}
	if k.RootKey == nil {
		return nil, fmt.Errorf("create root key: missing key store: %w", db.ErrNilParameter)
	}
	if k.PrivateId != "" {
		return nil, fmt.Errorf("create root key: private id not empty: %w", db.ErrInvalidParameter)
	}
	if k.ScopeId == "" {
		return nil, fmt.Errorf("create root key: missing key scope id: %w", db.ErrInvalidParameter)
	}
	id, err := newRootKeyId()
	if err != nil {
		return nil, fmt.Errorf("create root key: %w", err)
	}
	c := k.Clone().(*RootKey)
	c.PrivateId = id

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
		return nil, fmt.Errorf("create root key: %w for %s", err, c.PrivateId)
	}
	return returnedKey.(*RootKey), err
}

// LookupRootKey will look up a root key in the repository.  If the key is not
// found, it will return nil, nil.
func (r *Repository) LookupRootKey(ctx context.Context, privateId string, opt ...Option) (*RootKey, error) {
	if privateId == "" {
		return nil, fmt.Errorf("lookup root key: missing private id: %w", db.ErrNilParameter)
	}

	k := allocRootKey()
	k.PrivateId = privateId
	if err := r.reader.LookupById(ctx, &k); err != nil {
		return nil, fmt.Errorf("lookup root key: failed %w for %s", err, privateId)
	}
	return &k, nil
}

// DeleteRootKey deletes the root key for the provided id from the
// repository returning a count of the number of records deleted.  All options
// are ignored.
func (r *Repository) DeleteRootKey(ctx context.Context, privateId string, opt ...Option) (int, error) {
	if privateId == "" {
		return db.NoRowsAffected, fmt.Errorf("delete root key: missing private id: %w", db.ErrInvalidParameter)
	}
	k := allocRootKey()
	k.PrivateId = privateId
	if err := r.reader.LookupById(ctx, &k); err != nil {
		return db.NoRowsAffected, fmt.Errorf("delete root key: failed %w for %s", err, privateId)
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
		return db.NoRowsAffected, fmt.Errorf("delete root key: %s: %w", privateId, err)
	}
	return rowsDeleted, nil
}
