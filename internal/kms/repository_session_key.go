package kms

import (
	"context"
	"fmt"
	"strings"

	"github.com/hashicorp/boundary/internal/db"
	wrapping "github.com/hashicorp/go-kms-wrapping"
)

// CreateSessionKey inserts into the repository and returns the new key and the
// key version. There are no valid options at this time.
func (r *Repository) CreateSessionKey(ctx context.Context, rkvWrapper wrapping.Wrapper, key []byte, opt ...Option) (*SessionKey, *SessionKeyVersion, error) {
	var returnedDk, returnedDv interface{}
	_, err := r.writer.DoTx(
		ctx,
		db.StdRetryCnt,
		db.ExpBackoff{},
		func(reader db.Reader, w db.Writer) error {
			var err error
			if returnedDk, returnedDv, err = createSessionKeyTx(ctx, reader, w, rkvWrapper, key); err != nil {
				return err
			}
			return nil
		},
	)
	if err != nil {
		return nil, nil, fmt.Errorf("create session key: %w", err)
	}
	return returnedDk.(*SessionKey), returnedDv.(*SessionKeyVersion), err
}

// createSessionKeyTx inserts into the db (via db.Writer) and returns the new key
// and the key version. This function encapsulates all the work required within
// a db.TxHandler and allows this capability to be shared with the iam repo.
func createSessionKeyTx(ctx context.Context, r db.Reader, w db.Writer, rkvWrapper wrapping.Wrapper, key []byte) (*SessionKey, *SessionKeyVersion, error) {
	if rkvWrapper == nil {
		return nil, nil, fmt.Errorf("create session key: missing key wrapper: %w", db.ErrInvalidParameter)
	}
	if len(key) == 0 {
		return nil, nil, fmt.Errorf("create session key: missing key: %w", db.ErrInvalidParameter)
	}
	rootKeyVersionId := rkvWrapper.KeyID()
	switch {
	case !strings.HasPrefix(rootKeyVersionId, RootKeyVersionPrefix):
		return nil, nil, fmt.Errorf("create session key: root key version id %s doesn't start with prefix %s: %w", rootKeyVersionId, RootKeyVersionPrefix, db.ErrInvalidParameter)
	case rootKeyVersionId == "":
		return nil, nil, fmt.Errorf("create session key: missing root key version id: %w", db.ErrInvalidParameter)
	}
	rv := AllocRootKeyVersion()
	rv.PrivateId = rootKeyVersionId
	err := r.LookupById(ctx, &rv)
	if err != nil {
		return nil, nil, fmt.Errorf("create session key: unable to lookup root key version %s: %w", rootKeyVersionId, err)
	}

	tk := AllocSessionKey()
	tv := AllocSessionKeyVersion()
	id, err := newSessionKeyId()
	if err != nil {
		return nil, nil, fmt.Errorf("create session key: %w", err)
	}
	tk.PrivateId = id
	tk.RootKeyId = rv.RootKeyId

	id, err = newSessionKeyVersionId()
	if err != nil {
		return nil, nil, fmt.Errorf("create session key: %w", err)
	}
	tv.PrivateId = id
	tv.SessionKeyId = tk.PrivateId
	tv.RootKeyVersionId = rootKeyVersionId
	tv.Key = key
	if err := tv.Encrypt(ctx, rkvWrapper); err != nil {
		return nil, nil, fmt.Errorf("create session key: %w", err)
	}

	// no session entries for keys
	if err := w.Create(ctx, &tk); err != nil {
		return nil, nil, fmt.Errorf("create session key: key create: %w", err)
	}
	// no session entries for key versions
	if err := w.Create(ctx, &tv); err != nil {
		return nil, nil, fmt.Errorf("create session key: version create: %w", err)
	}

	return &tk, &tv, err
}

// LookupSessionKey will look up a key in the repository.  If the key is not
// found, it will return nil, nil.
func (r *Repository) LookupSessionKey(ctx context.Context, privateId string, opt ...Option) (*SessionKey, error) {
	if privateId == "" {
		return nil, fmt.Errorf("lookup session key: missing private id: %w", db.ErrInvalidParameter)
	}
	k := AllocSessionKey()
	k.PrivateId = privateId
	if err := r.reader.LookupById(ctx, &k); err != nil {
		return nil, fmt.Errorf("lookup session key: failed %w for %s", err, privateId)
	}
	return &k, nil
}

// DeleteSessionKey deletes the key for the provided id from the
// repository returning a count of the number of records deleted.  All options
// are ignored.
func (r *Repository) DeleteSessionKey(ctx context.Context, privateId string, opt ...Option) (int, error) {
	if privateId == "" {
		return db.NoRowsAffected, fmt.Errorf("delete session key: missing private id: %w", db.ErrInvalidParameter)
	}
	k := AllocSessionKey()
	k.PrivateId = privateId
	if err := r.reader.LookupById(ctx, &k); err != nil {
		return db.NoRowsAffected, fmt.Errorf("delete session key: failed %w for %s", err, privateId)
	}

	var rowsDeleted int
	_, err := r.writer.DoTx(
		ctx,
		db.StdRetryCnt,
		db.ExpBackoff{},
		func(_ db.Reader, w db.Writer) (err error) {
			dk := k.Clone()
			// no session entries for root keys
			rowsDeleted, err = w.Delete(ctx, dk)
			if err == nil && rowsDeleted > 1 {
				return db.ErrMultipleRecords
			}
			return err
		},
	)
	if err != nil {
		return db.NoRowsAffected, fmt.Errorf("delete session key: %s: %w", privateId, err)
	}
	return rowsDeleted, nil
}

// ListSessionKeys will list the keys.  Supports the WithLimit option.
func (r *Repository) ListSessionKeys(ctx context.Context, opt ...Option) ([]Dek, error) {
	var keys []*SessionKey
	err := r.list(ctx, &keys, "1=1", nil, opt...)
	if err != nil {
		return nil, fmt.Errorf("list session keys: %w", err)
	}
	deks := make([]Dek, 0, len(keys))
	for _, key := range keys {
		deks = append(deks, key)
	}
	return deks, nil
}
