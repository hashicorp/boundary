package kms

import (
	"context"
	"fmt"

	"github.com/hashicorp/boundary/internal/db"
	"github.com/hashicorp/boundary/internal/errors"
	wrapping "github.com/hashicorp/go-kms-wrapping/v2"
)

// CreateRootKey inserts into the repository and returns the new root key and
// root key version. There are no valid options at this time.
func (r *Repository) CreateRootKey(ctx context.Context, keyWrapper wrapping.Wrapper, scopeId string, key []byte, _ ...Option) (*RootKey, *RootKeyVersion, error) {
	const op = "kms.(Repository).CreateRootKey"
	var returnedRk, returnedKv interface{}
	_, err := r.writer.DoTx(
		ctx,
		db.StdRetryCnt,
		db.ExpBackoff{},
		func(_ db.Reader, w db.Writer) error {
			var err error
			if returnedRk, returnedKv, err = createRootKeyTx(ctx, w, keyWrapper, scopeId, key); err != nil {
				return errors.Wrap(ctx, err, op)
			}
			return nil
		},
	)
	if err != nil {
		return nil, nil, errors.Wrap(ctx, err, op, errors.WithMsg(fmt.Sprintf("failed for %s", scopeId)))
	}
	return returnedRk.(*RootKey), returnedKv.(*RootKeyVersion), nil
}

// createRootKeyTx inserts into the db (via db.Writer) and returns the new root key
// and root key version. This function encapsulates all the work required within
// a db.TxHandler and allows this capability to be shared with the iam repo.
func createRootKeyTx(ctx context.Context, w db.Writer, keyWrapper wrapping.Wrapper, scopeId string, key []byte) (*RootKey, *RootKeyVersion, error) {
	const op = "kms.createRootKeyTx"
	if scopeId == "" {
		return nil, nil, errors.New(ctx, errors.InvalidParameter, op, "missing scope id")
	}
	if keyWrapper == nil {
		return nil, nil, errors.New(ctx, errors.InvalidParameter, op, "missing key wrapper")
	}
	if len(key) == 0 {
		return nil, nil, errors.New(ctx, errors.InvalidParameter, op, "missing key")
	}
	rk := AllocRootKey()
	kv := AllocRootKeyVersion()
	id, err := newRootKeyId()
	if err != nil {
		return nil, nil, errors.Wrap(ctx, err, op)
	}
	rk.PrivateId = id
	rk.ScopeId = scopeId

	id, err = newRootKeyVersionId()
	if err != nil {
		return nil, nil, errors.Wrap(ctx, err, op)
	}
	kv.PrivateId = id
	kv.RootKeyId = rk.PrivateId
	kv.Key = key
	if err := kv.Encrypt(ctx, keyWrapper); err != nil {
		return nil, nil, errors.Wrap(ctx, err, op)
	}

	// no oplog entries for root keys
	if err := w.Create(ctx, &rk); err != nil {
		return nil, nil, errors.Wrap(ctx, err, op, errors.WithMsg("root keys"))
	}
	// no oplog entries for root key versions
	if err := w.Create(ctx, &kv); err != nil {
		return nil, nil, errors.Wrap(ctx, err, op, errors.WithMsg("key versions"))
	}

	return &rk, &kv, nil
}

// LookupRootKey will look up a root key in the repository.  If the key is not
// found, it will return nil, nil.
func (r *Repository) LookupRootKey(ctx context.Context, keyWrapper wrapping.Wrapper, privateId string, _ ...Option) (*RootKey, error) {
	const op = "kms.(Repository).LookupRootKey"
	if privateId == "" {
		return nil, errors.New(ctx, errors.InvalidParameter, op, "missing private id")
	}
	if keyWrapper == nil {
		return nil, errors.New(ctx, errors.InvalidParameter, op, "missing key wrapper")
	}
	k := AllocRootKey()
	k.PrivateId = privateId
	if err := r.reader.LookupById(ctx, &k); err != nil {
		return nil, errors.Wrap(ctx, err, op, errors.WithMsg(fmt.Sprintf("failed for %s", privateId)))
	}
	return &k, nil
}

// DeleteRootKey deletes the root key for the provided id from the
// repository returning a count of the number of records deleted.  All options
// are ignored.
func (r *Repository) DeleteRootKey(ctx context.Context, privateId string, _ ...Option) (int, error) {
	const op = "kms.(Repository).DeleteRootKey"
	if privateId == "" {
		return db.NoRowsAffected, errors.New(ctx, errors.InvalidParameter, op, "missing private id")
	}
	k := AllocRootKey()
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
			// no oplog entries for root keys
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

// ListRootKeys will list the root keys.  Supports the WithLimit option.
func (r *Repository) ListRootKeys(ctx context.Context, opt ...Option) ([]*RootKey, error) {
	const op = "kms.(Repository).ListRootKeys"
	var keys []*RootKey
	err := r.list(ctx, &keys, "1=1", nil, opt...)
	if err != nil {
		return nil, errors.Wrap(ctx, err, op)
	}
	return keys, nil
}
