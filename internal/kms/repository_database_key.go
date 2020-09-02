package kms

import (
	"context"
	"fmt"
	"strings"

	"github.com/hashicorp/boundary/internal/db"
	wrapping "github.com/hashicorp/go-kms-wrapping"
)

// CreateDatabaseKey inserts into the repository and returns the new database key and
// database key version. There are no valid options at this time.
func (r *Repository) CreateDatabaseKey(ctx context.Context, rkvWrapper wrapping.Wrapper, key []byte, opt ...Option) (*DatabaseKey, *DatabaseKeyVersion, error) {
	var returnedDk, returnedDv interface{}
	_, err := r.writer.DoTx(
		ctx,
		db.StdRetryCnt,
		db.ExpBackoff{},
		func(reader db.Reader, w db.Writer) error {
			var err error
			if returnedDk, returnedDv, err = createDatabaseKeyTx(ctx, reader, w, rkvWrapper, key); err != nil {
				return err
			}
			return nil
		},
	)
	if err != nil {
		return nil, nil, fmt.Errorf("create database key: %w", err)
	}
	return returnedDk.(*DatabaseKey), returnedDv.(*DatabaseKeyVersion), err
}

// createDatabaseKeyTx inserts into the db (via db.Writer) and returns the new database key
// and database key version. This function encapsulates all the work required within
// a db.TxHandler and allows this capability to be shared with the iam repo.
func createDatabaseKeyTx(ctx context.Context, r db.Reader, w db.Writer, rkvWrapper wrapping.Wrapper, key []byte) (*DatabaseKey, *DatabaseKeyVersion, error) {
	if rkvWrapper == nil {
		return nil, nil, fmt.Errorf("create database key: missing key wrapper: %w", db.ErrInvalidParameter)
	}
	if len(key) == 0 {
		return nil, nil, fmt.Errorf("create database key: missing key: %w", db.ErrInvalidParameter)
	}
	rootKeyVersionId := rkvWrapper.KeyID()
	switch {
	case !strings.HasPrefix(rootKeyVersionId, RootKeyVersionPrefix):
		return nil, nil, fmt.Errorf("create database key: root key version id %s doesn't start with prefix %s: %w", rootKeyVersionId, RootKeyVersionPrefix, db.ErrInvalidParameter)
	case rootKeyVersionId == "":
		return nil, nil, fmt.Errorf("create database key: missing root key version id: %w", db.ErrInvalidParameter)
	}
	rv := AllocRootKeyVersion()
	rv.PrivateId = rootKeyVersionId
	err := r.LookupById(ctx, &rv)
	if err != nil {
		return nil, nil, fmt.Errorf("create database key: unable to lookup root key version %s: %w", rootKeyVersionId, err)
	}

	dk := AllocDatabaseKey()
	dv := AllocDatabaseKeyVersion()
	id, err := newDatabaseKeyId()
	if err != nil {
		return nil, nil, fmt.Errorf("create database key: %w", err)
	}
	dk.PrivateId = id
	dk.RootKeyId = rv.RootKeyId

	id, err = newDatabaseKeyVersionId()
	if err != nil {
		return nil, nil, fmt.Errorf("create database key: %w", err)
	}
	dv.PrivateId = id
	dv.DatabaseKeyId = dk.PrivateId
	dv.RootKeyVersionId = rootKeyVersionId
	dv.Key = key
	if err := dv.Encrypt(ctx, rkvWrapper); err != nil {
		return nil, nil, fmt.Errorf("create database key: %w", err)
	}

	// no oplog entries for keys
	if err := w.Create(ctx, &dk); err != nil {
		return nil, nil, fmt.Errorf("create database key: database create: %w", err)
	}
	// no oplog entries for key versions
	if err := w.Create(ctx, &dv); err != nil {
		return nil, nil, fmt.Errorf("create database key: version create: %w", err)
	}

	return &dk, &dv, err
}

// LookupDatabaseKey will look up a key in the repository.  If the key is not
// found, it will return nil, nil.
func (r *Repository) LookupDatabaseKey(ctx context.Context, privateId string, opt ...Option) (*DatabaseKey, error) {
	if privateId == "" {
		return nil, fmt.Errorf("lookup database key: missing private id: %w", db.ErrInvalidParameter)
	}
	k := AllocDatabaseKey()
	k.PrivateId = privateId
	if err := r.reader.LookupById(ctx, &k); err != nil {
		return nil, fmt.Errorf("lookup database key: failed %w for %s", err, privateId)
	}
	return &k, nil
}

// DeleteDatabaseKey deletes the key for the provided id from the
// repository returning a count of the number of records deleted.  All options
// are ignored.
func (r *Repository) DeleteDatabaseKey(ctx context.Context, privateId string, opt ...Option) (int, error) {
	if privateId == "" {
		return db.NoRowsAffected, fmt.Errorf("delete database key: missing private id: %w", db.ErrInvalidParameter)
	}
	k := AllocDatabaseKey()
	k.PrivateId = privateId
	if err := r.reader.LookupById(ctx, &k); err != nil {
		return db.NoRowsAffected, fmt.Errorf("delete database key: failed %w for %s", err, privateId)
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
		return db.NoRowsAffected, fmt.Errorf("delete database key: %s: %w", privateId, err)
	}
	return rowsDeleted, nil
}

// ListDatabaseKeys will list the keys.  Supports the WithLimit option.
func (r *Repository) ListDatabaseKeys(ctx context.Context, opt ...Option) ([]Dek, error) {
	var keys []*DatabaseKey
	err := r.list(ctx, &keys, "1=1", nil, opt...)
	if err != nil {
		return nil, fmt.Errorf("list database keys: %w", err)
	}
	deks := make([]Dek, 0, len(keys))
	for _, key := range keys {
		deks = append(deks, key)
	}
	return deks, nil
}
