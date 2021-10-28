package kms

import (
	"context"
	"fmt"
	"strings"

	"github.com/hashicorp/boundary/internal/db"
	"github.com/hashicorp/boundary/internal/errors"
	wrapping "github.com/hashicorp/go-kms-wrapping"
)

// CreateDatabaseKey inserts into the repository and returns the new database key and
// database key version. There are no valid options at this time.
func (r *Repository) CreateDatabaseKey(ctx context.Context, rkvWrapper wrapping.Wrapper, key []byte, _ ...Option) (*DatabaseKey, *DatabaseKeyVersion, error) {
	const op = "kms.(Repository).CreateDatabaseKey"
	var returnedDk, returnedDv interface{}
	_, err := r.writer.DoTx(
		ctx,
		db.StdRetryCnt,
		db.ExpBackoff{},
		func(reader db.Reader, w db.Writer) error {
			var err error
			if returnedDk, returnedDv, err = createDatabaseKeyTx(ctx, reader, w, rkvWrapper, key); err != nil {
				return errors.Wrap(ctx, err, op)
			}
			return nil
		},
	)
	if err != nil {
		return nil, nil, errors.Wrap(ctx, err, op)
	}
	return returnedDk.(*DatabaseKey), returnedDv.(*DatabaseKeyVersion), nil
}

// createDatabaseKeyTx inserts into the db (via db.Writer) and returns the new database key
// and database key version. This function encapsulates all the work required within
// a db.TxHandler and allows this capability to be shared with the iam repo.
func createDatabaseKeyTx(ctx context.Context, r db.Reader, w db.Writer, rkvWrapper wrapping.Wrapper, key []byte) (*DatabaseKey, *DatabaseKeyVersion, error) {
	const op = "kms.createDatabaseKeyTx"
	if rkvWrapper == nil {
		return nil, nil, errors.New(ctx, errors.InvalidParameter, op, "missing key wrapper")
	}
	if len(key) == 0 {
		return nil, nil, errors.New(ctx, errors.InvalidParameter, op, "missing key")
	}
	rootKeyVersionId := rkvWrapper.KeyID()
	switch {
	case !strings.HasPrefix(rootKeyVersionId, RootKeyVersionPrefix):
		return nil, nil, errors.New(ctx, errors.InvalidParameter, op, fmt.Sprintf("root key version id %s doesn't start with prefix %s", rootKeyVersionId, RootKeyVersionPrefix))
	case rootKeyVersionId == "":
		return nil, nil, errors.New(ctx, errors.InvalidParameter, op, "missing root key version id")
	}
	rv := AllocRootKeyVersion()
	rv.PrivateId = rootKeyVersionId
	err := r.LookupById(ctx, &rv)
	if err != nil {
		return nil, nil, errors.Wrap(ctx, err, op, errors.WithMsg(fmt.Sprintf("unable to lookup root key version %s", rootKeyVersionId)))
	}

	dk := AllocDatabaseKey()
	dv := AllocDatabaseKeyVersion()
	id, err := newDatabaseKeyId()
	if err != nil {
		return nil, nil, errors.Wrap(ctx, err, op)
	}
	dk.PrivateId = id
	dk.RootKeyId = rv.RootKeyId

	id, err = newDatabaseKeyVersionId()
	if err != nil {
		return nil, nil, errors.Wrap(ctx, err, op)
	}
	dv.PrivateId = id
	dv.DatabaseKeyId = dk.PrivateId
	dv.RootKeyVersionId = rootKeyVersionId
	dv.Key = key
	if err := dv.Encrypt(ctx, rkvWrapper); err != nil {
		return nil, nil, errors.Wrap(ctx, err, op)
	}

	// no oplog entries for keys
	if err := w.Create(ctx, &dk); err != nil {
		return nil, nil, errors.Wrap(ctx, err, op, errors.WithMsg("keys create"))
	}
	// no oplog entries for key versions
	if err := w.Create(ctx, &dv); err != nil {
		return nil, nil, errors.Wrap(ctx, err, op, errors.WithMsg("key versions create"))
	}

	return &dk, &dv, nil
}

// LookupDatabaseKey will look up a key in the repository.  If the key is not
// found, it will return nil, nil.
func (r *Repository) LookupDatabaseKey(ctx context.Context, privateId string, _ ...Option) (*DatabaseKey, error) {
	const op = "kms.(Repository).LookupDatabaseKey"
	if privateId == "" {
		return nil, errors.New(ctx, errors.InvalidParameter, op, "missing private id")
	}
	k := AllocDatabaseKey()
	k.PrivateId = privateId
	if err := r.reader.LookupById(ctx, &k); err != nil {
		return nil, errors.Wrap(ctx, err, op, errors.WithMsg(fmt.Sprintf("failed for %s", privateId)))
	}
	return &k, nil
}

// DeleteDatabaseKey deletes the key for the provided id from the
// repository returning a count of the number of records deleted.  All options
// are ignored.
func (r *Repository) DeleteDatabaseKey(ctx context.Context, privateId string, _ ...Option) (int, error) {
	const op = "kms.(Repository).DeleteDatabaseKey"
	if privateId == "" {
		return db.NoRowsAffected, errors.New(ctx, errors.InvalidParameter, op, "missing private id")
	}
	k := AllocDatabaseKey()
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

// ListDatabaseKeys will list the keys.  Supports the WithLimit option.
func (r *Repository) ListDatabaseKeys(ctx context.Context, opt ...Option) ([]Dek, error) {
	const op = "kms.(Repository).ListDatabaseKeys"
	var keys []*DatabaseKey
	err := r.list(ctx, &keys, "1=1", nil, opt...)
	if err != nil {
		return nil, errors.Wrap(ctx, err, op)
	}
	deks := make([]Dek, 0, len(keys))
	for _, key := range keys {
		deks = append(deks, key)
	}
	return deks, nil
}
