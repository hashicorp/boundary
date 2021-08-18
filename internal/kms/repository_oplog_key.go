package kms

import (
	"context"
	"fmt"
	"strings"

	"github.com/hashicorp/boundary/internal/db"
	"github.com/hashicorp/boundary/internal/errors"
	wrapping "github.com/hashicorp/go-kms-wrapping"
)

// CreateOplogKey inserts into the repository and returns the new key and the
// key version. There are no valid options at this time.
func (r *Repository) CreateOplogKey(ctx context.Context, rkvWrapper wrapping.Wrapper, key []byte, _ ...Option) (*OplogKey, *OplogKeyVersion, error) {
	const op = "kms.(Repository).CreateOplogKey"
	var returnedDk, returnedDv interface{}
	_, err := r.writer.DoTx(
		ctx,
		db.StdRetryCnt,
		db.ExpBackoff{},
		func(reader db.Reader, w db.Writer) error {
			var err error
			if returnedDk, returnedDv, err = createOplogKeyTx(ctx, reader, w, rkvWrapper, key); err != nil {
				return errors.Wrap(ctx, err, op)
			}
			return nil
		},
	)
	if err != nil {
		return nil, nil, errors.Wrap(ctx, err, op)
	}
	return returnedDk.(*OplogKey), returnedDv.(*OplogKeyVersion), nil
}

// createOplogKeyTx inserts into the db (via db.Writer) and returns the new key
// and the key version. This function encapsulates all the work required within
// a db.TxHandler and allows this capability to be shared with the iam repo.
func createOplogKeyTx(ctx context.Context, r db.Reader, w db.Writer, rkvWrapper wrapping.Wrapper, key []byte) (*OplogKey, *OplogKeyVersion, error) {
	const op = "kms.createOplogKeyTx"
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

	opk := AllocOplogKey()
	opv := AllocOplogKeyVersion()
	id, err := newOplogKeyId()
	if err != nil {
		return nil, nil, errors.Wrap(ctx, err, op)
	}
	opk.PrivateId = id
	opk.RootKeyId = rv.RootKeyId

	id, err = newOplogKeyVersionId()
	if err != nil {
		return nil, nil, errors.Wrap(ctx, err, op)
	}
	opv.PrivateId = id
	opv.OplogKeyId = opk.PrivateId
	opv.RootKeyVersionId = rootKeyVersionId
	opv.Key = key
	if err := opv.Encrypt(ctx, rkvWrapper); err != nil {
		return nil, nil, errors.Wrap(ctx, err, op)
	}

	// no oplog entries for keys
	if err := w.Create(ctx, &opk); err != nil {
		return nil, nil, errors.Wrap(ctx, err, op, errors.WithMsg("key create"))
	}
	// no oplog entries for key versions
	if err := w.Create(ctx, &opv); err != nil {
		return nil, nil, errors.Wrap(ctx, err, op, errors.WithMsg("key versions create"))
	}

	return &opk, &opv, nil
}

// LookupOplogKey will look up a key in the repository.  If the key is not
// found, it will return nil, nil.
func (r *Repository) LookupOplogKey(ctx context.Context, privateId string, _ ...Option) (*OplogKey, error) {
	const op = "kms.(Repository).LookupOplogKey"
	if privateId == "" {
		return nil, errors.New(ctx, errors.InvalidParameter, op, "missing private id")
	}
	k := AllocOplogKey()
	k.PrivateId = privateId
	if err := r.reader.LookupById(ctx, &k); err != nil {
		return nil, errors.Wrap(ctx, err, op, errors.WithMsg(fmt.Sprintf("failed for %s", privateId)))
	}
	return &k, nil
}

// DeleteOplogKey deletes the key for the provided id from the
// repository returning a count of the number of records deleted.  All options
// are ignored.
func (r *Repository) DeleteOplogKey(ctx context.Context, privateId string, _ ...Option) (int, error) {
	const op = "kms.(Repository).DeleteOplogKey"
	if privateId == "" {
		return db.NoRowsAffected, errors.New(ctx, errors.InvalidParameter, op, "missing private id")
	}
	k := AllocOplogKey()
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

// ListOplogKeys will list the keys.  Supports the WithLimit option.
func (r *Repository) ListOplogKeys(ctx context.Context, opt ...Option) ([]Dek, error) {
	const op = "kms.(Repository).ListOplogKeys"
	var keys []*OplogKey
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
