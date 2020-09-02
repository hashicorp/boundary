package kms

import (
	"context"
	"fmt"
	"strings"

	"github.com/hashicorp/boundary/internal/db"
	wrapping "github.com/hashicorp/go-kms-wrapping"
)

// CreateTokenKey inserts into the repository and returns the new key and the
// key version. There are no valid options at this time.
func (r *Repository) CreateTokenKey(ctx context.Context, rkvWrapper wrapping.Wrapper, key []byte, opt ...Option) (*TokenKey, *TokenKeyVersion, error) {
	var returnedDk, returnedDv interface{}
	_, err := r.writer.DoTx(
		ctx,
		db.StdRetryCnt,
		db.ExpBackoff{},
		func(reader db.Reader, w db.Writer) error {
			var err error
			if returnedDk, returnedDv, err = createTokenKeyTx(ctx, reader, w, rkvWrapper, key); err != nil {
				return err
			}
			return nil
		},
	)
	if err != nil {
		return nil, nil, fmt.Errorf("create token key: %w", err)
	}
	return returnedDk.(*TokenKey), returnedDv.(*TokenKeyVersion), err
}

// createTokenKeyTx inserts into the db (via db.Writer) and returns the new key
// and the key version. This function encapsulates all the work required within
// a db.TxHandler and allows this capability to be shared with the iam repo.
func createTokenKeyTx(ctx context.Context, r db.Reader, w db.Writer, rkvWrapper wrapping.Wrapper, key []byte) (*TokenKey, *TokenKeyVersion, error) {
	if rkvWrapper == nil {
		return nil, nil, fmt.Errorf("create token key: missing key wrapper: %w", db.ErrInvalidParameter)
	}
	if len(key) == 0 {
		return nil, nil, fmt.Errorf("create token key: missing key: %w", db.ErrInvalidParameter)
	}
	rootKeyVersionId := rkvWrapper.KeyID()
	switch {
	case !strings.HasPrefix(rootKeyVersionId, RootKeyVersionPrefix):
		return nil, nil, fmt.Errorf("create token key: root key version id %s doesn't start with prefix %s: %w", rootKeyVersionId, RootKeyVersionPrefix, db.ErrInvalidParameter)
	case rootKeyVersionId == "":
		return nil, nil, fmt.Errorf("create token key: missing root key version id: %w", db.ErrInvalidParameter)
	}
	rv := AllocRootKeyVersion()
	rv.PrivateId = rootKeyVersionId
	err := r.LookupById(ctx, &rv)
	if err != nil {
		return nil, nil, fmt.Errorf("create token key: unable to lookup root key version %s: %w", rootKeyVersionId, err)
	}

	tk := AllocTokenKey()
	tv := AllocTokenKeyVersion()
	id, err := newTokenKeyId()
	if err != nil {
		return nil, nil, fmt.Errorf("create token key: %w", err)
	}
	tk.PrivateId = id
	tk.RootKeyId = rv.RootKeyId

	id, err = newTokenKeyVersionId()
	if err != nil {
		return nil, nil, fmt.Errorf("create token key: %w", err)
	}
	tv.PrivateId = id
	tv.TokenKeyId = tk.PrivateId
	tv.RootKeyVersionId = rootKeyVersionId
	tv.Key = key
	if err := tv.Encrypt(ctx, rkvWrapper); err != nil {
		return nil, nil, fmt.Errorf("create token key: %w", err)
	}

	// no token entries for keys
	if err := w.Create(ctx, &tk); err != nil {
		return nil, nil, fmt.Errorf("create token key: key create: %w", err)
	}
	// no token entries for key versions
	if err := w.Create(ctx, &tv); err != nil {
		return nil, nil, fmt.Errorf("create token key: version create: %w", err)
	}

	return &tk, &tv, err
}

// LookupTokenKey will look up a key in the repository.  If the key is not
// found, it will return nil, nil.
func (r *Repository) LookupTokenKey(ctx context.Context, privateId string, opt ...Option) (*TokenKey, error) {
	if privateId == "" {
		return nil, fmt.Errorf("lookup token key: missing private id: %w", db.ErrInvalidParameter)
	}
	k := AllocTokenKey()
	k.PrivateId = privateId
	if err := r.reader.LookupById(ctx, &k); err != nil {
		return nil, fmt.Errorf("lookup token key: failed %w for %s", err, privateId)
	}
	return &k, nil
}

// DeleteTokenKey deletes the key for the provided id from the
// repository returning a count of the number of records deleted.  All options
// are ignored.
func (r *Repository) DeleteTokenKey(ctx context.Context, privateId string, opt ...Option) (int, error) {
	if privateId == "" {
		return db.NoRowsAffected, fmt.Errorf("delete token key: missing private id: %w", db.ErrInvalidParameter)
	}
	k := AllocTokenKey()
	k.PrivateId = privateId
	if err := r.reader.LookupById(ctx, &k); err != nil {
		return db.NoRowsAffected, fmt.Errorf("delete token key: failed %w for %s", err, privateId)
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
			if err == nil && rowsDeleted > 1 {
				return db.ErrMultipleRecords
			}
			return err
		},
	)
	if err != nil {
		return db.NoRowsAffected, fmt.Errorf("delete token key: %s: %w", privateId, err)
	}
	return rowsDeleted, nil
}

// ListTokenKeys will list the keys.  Supports the WithLimit option.
func (r *Repository) ListTokenKeys(ctx context.Context, opt ...Option) ([]*TokenKey, error) {
	var keys []*TokenKey
	err := r.list(ctx, &keys, "1=1", nil, opt...)
	if err != nil {
		return nil, fmt.Errorf("list token keys: %w", err)
	}
	return keys, nil
}
