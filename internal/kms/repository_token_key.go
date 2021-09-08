package kms

import (
	"context"
	"fmt"
	"strings"

	"github.com/hashicorp/boundary/internal/db"
	"github.com/hashicorp/boundary/internal/errors"
	wrapping "github.com/hashicorp/go-kms-wrapping"
)

// CreateTokenKey inserts into the repository and returns the new key and the
// key version. There are no valid options at this time.
func (r *Repository) CreateTokenKey(ctx context.Context, rkvWrapper wrapping.Wrapper, key []byte, _ ...Option) (*TokenKey, *TokenKeyVersion, error) {
	const op = "kms.(Repository).CreateTokenKey"
	var returnedDk, returnedDv interface{}
	_, err := r.writer.DoTx(
		ctx,
		db.StdRetryCnt,
		db.ExpBackoff{},
		func(reader db.Reader, w db.Writer) error {
			var err error
			if returnedDk, returnedDv, err = createTokenKeyTx(ctx, reader, w, rkvWrapper, key); err != nil {
				return errors.Wrap(ctx, err, op)
			}
			return nil
		},
	)
	if err != nil {
		return nil, nil, errors.Wrap(ctx, err, op)
	}
	return returnedDk.(*TokenKey), returnedDv.(*TokenKeyVersion), nil
}

// createTokenKeyTx inserts into the db (via db.Writer) and returns the new key
// and the key version. This function encapsulates all the work required within
// a db.TxHandler and allows this capability to be shared with the iam repo.
func createTokenKeyTx(ctx context.Context, r db.Reader, w db.Writer, rkvWrapper wrapping.Wrapper, key []byte) (*TokenKey, *TokenKeyVersion, error) {
	const op = "kms.createTokenKeyTx"
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

	tk := AllocTokenKey()
	tv := AllocTokenKeyVersion()
	id, err := newTokenKeyId()
	if err != nil {
		return nil, nil, errors.Wrap(ctx, err, op)
	}
	tk.PrivateId = id
	tk.RootKeyId = rv.RootKeyId

	id, err = newTokenKeyVersionId()
	if err != nil {
		return nil, nil, errors.Wrap(ctx, err, op)
	}
	tv.PrivateId = id
	tv.TokenKeyId = tk.PrivateId
	tv.RootKeyVersionId = rootKeyVersionId
	tv.Key = key
	if err := tv.Encrypt(ctx, rkvWrapper); err != nil {
		return nil, nil, errors.Wrap(ctx, err, op)
	}

	// no token entries for keys
	if err := w.Create(ctx, &tk); err != nil {
		return nil, nil, errors.Wrap(ctx, err, op, errors.WithMsg("keys create"))
	}
	// no token entries for key versions
	if err := w.Create(ctx, &tv); err != nil {
		return nil, nil, errors.Wrap(ctx, err, op, errors.WithMsg("key versions create"))
	}

	return &tk, &tv, nil
}

// LookupTokenKey will look up a key in the repository.  If the key is not
// found, it will return nil, nil.
func (r *Repository) LookupTokenKey(ctx context.Context, privateId string, _ ...Option) (*TokenKey, error) {
	const op = "kms.(Repository).LookupTokenKey"
	if privateId == "" {
		return nil, errors.New(ctx, errors.InvalidParameter, op, "missing private id")
	}
	k := AllocTokenKey()
	k.PrivateId = privateId
	if err := r.reader.LookupById(ctx, &k); err != nil {
		return nil, errors.Wrap(ctx, err, op, errors.WithMsg(fmt.Sprintf("failed for %s", privateId)))
	}
	return &k, nil
}

// DeleteTokenKey deletes the key for the provided id from the
// repository returning a count of the number of records deleted.  All options
// are ignored.
func (r *Repository) DeleteTokenKey(ctx context.Context, privateId string, _ ...Option) (int, error) {
	const op = "kms.(Repository).DeleteTokenKey"
	if privateId == "" {
		return db.NoRowsAffected, errors.New(ctx, errors.InvalidParameter, op, "missing private id")
	}
	k := AllocTokenKey()
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
			// no token entries for root keys
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

// ListTokenKeys will list the keys.  Supports the WithLimit option.
func (r *Repository) ListTokenKeys(ctx context.Context, opt ...Option) ([]Dek, error) {
	const op = "kms.(Repository).ListTokenKeys"
	var keys []*TokenKey
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
