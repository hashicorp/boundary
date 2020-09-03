package kms

import (
	"context"
	"fmt"
	"strings"

	"github.com/hashicorp/boundary/internal/db"
	wrapping "github.com/hashicorp/go-kms-wrapping"
)

// CreateOplogKey inserts into the repository and returns the new key and the
// key version. There are no valid options at this time.
func (r *Repository) CreateOplogKey(ctx context.Context, rkvWrapper wrapping.Wrapper, key []byte, opt ...Option) (*OplogKey, *OplogKeyVersion, error) {
	var returnedDk, returnedDv interface{}
	_, err := r.writer.DoTx(
		ctx,
		db.StdRetryCnt,
		db.ExpBackoff{},
		func(reader db.Reader, w db.Writer) error {
			var err error
			if returnedDk, returnedDv, err = createOplogKeyTx(ctx, reader, w, rkvWrapper, key); err != nil {
				return err
			}
			return nil
		},
	)
	if err != nil {
		return nil, nil, fmt.Errorf("create oplog key: %w", err)
	}
	return returnedDk.(*OplogKey), returnedDv.(*OplogKeyVersion), err
}

// createOplogKeyTx inserts into the db (via db.Writer) and returns the new key
// and the key version. This function encapsulates all the work required within
// a db.TxHandler and allows this capability to be shared with the iam repo.
func createOplogKeyTx(ctx context.Context, r db.Reader, w db.Writer, rkvWrapper wrapping.Wrapper, key []byte) (*OplogKey, *OplogKeyVersion, error) {
	if rkvWrapper == nil {
		return nil, nil, fmt.Errorf("create oplog key: missing key wrapper: %w", db.ErrInvalidParameter)
	}
	if len(key) == 0 {
		return nil, nil, fmt.Errorf("create oplog key: missing key: %w", db.ErrInvalidParameter)
	}
	rootKeyVersionId := rkvWrapper.KeyID()
	switch {
	case !strings.HasPrefix(rootKeyVersionId, RootKeyVersionPrefix):
		return nil, nil, fmt.Errorf("create oplog key: root key version id %s doesn't start with prefix %s: %w", rootKeyVersionId, RootKeyVersionPrefix, db.ErrInvalidParameter)
	case rootKeyVersionId == "":
		return nil, nil, fmt.Errorf("create oplog key: missing root key version id: %w", db.ErrInvalidParameter)
	}
	rv := AllocRootKeyVersion()
	rv.PrivateId = rootKeyVersionId
	err := r.LookupById(ctx, &rv)
	if err != nil {
		return nil, nil, fmt.Errorf("create oplog key: unable to lookup root key version %s: %w", rootKeyVersionId, err)
	}

	opk := AllocOplogKey()
	opv := AllocOplogKeyVersion()
	id, err := newOplogKeyId()
	if err != nil {
		return nil, nil, fmt.Errorf("create oplog key: %w", err)
	}
	opk.PrivateId = id
	opk.RootKeyId = rv.RootKeyId

	id, err = newOplogKeyVersionId()
	if err != nil {
		return nil, nil, fmt.Errorf("create oplog key: %w", err)
	}
	opv.PrivateId = id
	opv.OplogKeyId = opk.PrivateId
	opv.RootKeyVersionId = rootKeyVersionId
	opv.Key = key
	if err := opv.Encrypt(ctx, rkvWrapper); err != nil {
		return nil, nil, fmt.Errorf("create oplog key: %w", err)
	}

	// no oplog entries for keys
	if err := w.Create(ctx, &opk); err != nil {
		return nil, nil, fmt.Errorf("create oplog key: key create: %w", err)
	}
	// no oplog entries for key versions
	if err := w.Create(ctx, &opv); err != nil {
		return nil, nil, fmt.Errorf("create oplog key: version create: %w", err)
	}

	return &opk, &opv, err
}

// LookupOplogKey will look up a key in the repository.  If the key is not
// found, it will return nil, nil.
func (r *Repository) LookupOplogKey(ctx context.Context, privateId string, opt ...Option) (*OplogKey, error) {
	if privateId == "" {
		return nil, fmt.Errorf("lookup oplog key: missing private id: %w", db.ErrInvalidParameter)
	}
	k := AllocOplogKey()
	k.PrivateId = privateId
	if err := r.reader.LookupById(ctx, &k); err != nil {
		return nil, fmt.Errorf("lookup oplog key: failed %w for %s", err, privateId)
	}
	return &k, nil
}

// DeleteOplogKey deletes the key for the provided id from the
// repository returning a count of the number of records deleted.  All options
// are ignored.
func (r *Repository) DeleteOplogKey(ctx context.Context, privateId string, opt ...Option) (int, error) {
	if privateId == "" {
		return db.NoRowsAffected, fmt.Errorf("delete oplog key: missing private id: %w", db.ErrInvalidParameter)
	}
	k := AllocOplogKey()
	k.PrivateId = privateId
	if err := r.reader.LookupById(ctx, &k); err != nil {
		return db.NoRowsAffected, fmt.Errorf("delete oplog key: failed %w for %s", err, privateId)
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
		return db.NoRowsAffected, fmt.Errorf("delete oplog key: %s: %w", privateId, err)
	}
	return rowsDeleted, nil
}

// ListOplogKeys will list the keys.  Supports the WithLimit option.
func (r *Repository) ListOplogKeys(ctx context.Context, opt ...Option) ([]Dek, error) {
	var keys []*OplogKey
	err := r.list(ctx, &keys, "1=1", nil, opt...)
	if err != nil {
		return nil, fmt.Errorf("list oplog keys: %w", err)
	}
	deks := make([]Dek, 0, len(keys))
	for _, key := range keys {
		deks = append(deks, key)
	}
	return deks, nil
}
