package kms

import (
	"context"
	"fmt"

	"github.com/hashicorp/boundary/internal/db"
	wrapping "github.com/hashicorp/go-kms-wrapping"
)

// CreateRootKey inserts into the repository and returns the new root key and
// root key version. There are no valid options at this time.
func (r *Repository) CreateRootKey(ctx context.Context, keyWrapper wrapping.Wrapper, scopeId string, key []byte, opt ...Option) (*RootKey, *RootKeyVersion, error) {
	var returnedRk, returnedKv interface{}
	_, err := r.writer.DoTx(
		ctx,
		db.StdRetryCnt,
		db.ExpBackoff{},
		func(_ db.Reader, w db.Writer) error {
			var err error
			if returnedRk, returnedKv, err = createRootKeyTx(ctx, w, keyWrapper, scopeId, key); err != nil {
				return err
			}
			return nil
		},
	)
	if err != nil {
		return nil, nil, fmt.Errorf("create root key: %w in %s", err, scopeId)
	}
	return returnedRk.(*RootKey), returnedKv.(*RootKeyVersion), err
}

// createRootKeyTx inserts into the db (via db.Writer) and returns the new root key
// and root key version. This function encapsulates all the work required within
// a db.TxHandler and allows this capability to be shared with the iam repo.
func createRootKeyTx(ctx context.Context, w db.Writer, keyWrapper wrapping.Wrapper, scopeId string, key []byte) (*RootKey, *RootKeyVersion, error) {
	if scopeId == "" {
		return nil, nil, fmt.Errorf("create root key: missing scope id: %w", db.ErrInvalidParameter)
	}
	if keyWrapper == nil {
		return nil, nil, fmt.Errorf("create root key: missing key wrapper: %w", db.ErrInvalidParameter)
	}
	if len(key) == 0 {
		return nil, nil, fmt.Errorf("create root key: missing key: %w", db.ErrInvalidParameter)
	}
	rk := AllocRootKey()
	kv := AllocRootKeyVersion()
	id, err := newRootKeyId()
	if err != nil {
		return nil, nil, fmt.Errorf("create root key: %w", err)
	}
	rk.PrivateId = id
	rk.ScopeId = scopeId

	id, err = newRootKeyVersionId()
	if err != nil {
		return nil, nil, fmt.Errorf("create root key: %w", err)
	}
	kv.PrivateId = id
	kv.RootKeyId = rk.PrivateId
	kv.Key = key
	if err := kv.Encrypt(ctx, keyWrapper); err != nil {
		return nil, nil, fmt.Errorf("create root key: %w", err)
	}

	// no oplog entries for root keys
	if err := w.Create(ctx, &rk); err != nil {
		return nil, nil, fmt.Errorf("create root key: root create: %w", err)
	}
	// no oplog entries for root key versions
	if err := w.Create(ctx, &kv); err != nil {
		return nil, nil, fmt.Errorf("create root key: version create: %w", err)
	}

	return &rk, &kv, err
}

// LookupRootKey will look up a root key in the repository.  If the key is not
// found, it will return nil, nil.
func (r *Repository) LookupRootKey(ctx context.Context, keyWrapper wrapping.Wrapper, privateId string, opt ...Option) (*RootKey, error) {
	if privateId == "" {
		return nil, fmt.Errorf("lookup root key: missing private id: %w", db.ErrInvalidParameter)
	}
	if keyWrapper == nil {
		return nil, fmt.Errorf("lookup root key: missing key wrapper: %w", db.ErrInvalidParameter)
	}
	k := AllocRootKey()
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
	k := AllocRootKey()
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
			dk := k.Clone()
			// no oplog entries for root keys
			rowsDeleted, err = w.Delete(ctx, dk)
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

// ListRootKeys will list the root keys.  Supports the WithLimit option.
func (r *Repository) ListRootKeys(ctx context.Context, opt ...Option) ([]*RootKey, error) {
	var keys []*RootKey
	err := r.list(ctx, &keys, "1=1", nil, opt...)
	if err != nil {
		return nil, fmt.Errorf("list root keys: %w", err)
	}
	return keys, nil
}
