// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: BUSL-1.1

package cache

import (
	"context"
	"database/sql"
	"time"

	"github.com/hashicorp/boundary/internal/db"
	"github.com/hashicorp/boundary/internal/errors"
	"github.com/hashicorp/boundary/internal/util"
)

// AddToken adds a token to the repository.  If the token in the
// keyring doesn't match the id provided an error is returned.  If the number of
// tokens now exceed a limit, the token retrieved least recently is deleted.
func (r *Repository) AddKeyringToken(ctx context.Context, bAddr string, token KeyringToken) error {
	const op = "cache.(Repository).AddKeyringToken"
	switch {
	case token.TokenName == "":
		return errors.New(ctx, errors.InvalidParameter, op, "token name is empty")
	case token.KeyringType == "":
		return errors.New(ctx, errors.InvalidParameter, op, "keyring type is empty")
	case token.AuthTokenId == "":
		return errors.New(ctx, errors.InvalidParameter, op, "boundary auth token id is empty")
	case bAddr == "":
		return errors.New(ctx, errors.InvalidParameter, op, "boundary address is empty")
	}
	kt := token.clone()

	at := r.tokenLookupFn(kt.KeyringType, kt.TokenName)
	if at == nil {
		return errors.New(ctx, errors.InvalidParameter, op, "unable to find token in the keyring specified")
	}
	if kt.AuthTokenId != at.Id {
		return errors.New(ctx, errors.InvalidParameter, op, "provided auth token id doesn't match the one stored")
	}

	// Even though the auth token is already stored, we still call create so
	// the last accessed timestamps can get updated since calling this method
	// indicates that the token was used and is still valid.
	_, err := r.rw.DoTx(ctx, db.StdRetryCnt, db.ExpBackoff{}, func(reader db.Reader, writer db.Writer) error {
		{
			t := &AuthToken{
				Id: token.AuthTokenId,
			}
			err := reader.LookupById(ctx, t)
			switch {
			case err != nil && !errors.IsNotFoundError(err):
				return errors.Wrap(ctx, err, op)
			case errors.IsNotFoundError(err):
				// TODO: This is the first time this auth token is associated with
				// this keyring/token name, lookup the auth token from boundary to
				// verify that it is for the user specified.
			case t.UserId != at.UserId:
				return errors.New(ctx, errors.InvalidParameter, op, "user id doesn't match what is specified in the stored auth token")
			}
		}

		{
			// always make sure the user exists when adding a token
			u := &user{
				Id:      at.UserId,
				Address: bAddr,
			}
			onConflict := &db.OnConflict{
				Target: db.Columns{"id"},
				Action: db.DoNothing(true),
			}
			if err := writer.Create(ctx, u, db.WithOnConflict(onConflict)); err != nil {
				return errors.Wrap(ctx, err, op)
			}
		}

		{
			st := &AuthToken{
				Id:               at.Id,
				UserId:           at.UserId,
				LastAccessedTime: time.Now(),
			}
			onConflict := &db.OnConflict{
				Target: db.Columns{"id"},
				Action: db.SetColumns([]string{"last_accessed_time"}),
			}
			if err := writer.Create(ctx, st, db.WithOnConflict(onConflict)); err != nil {
				return errors.Wrap(ctx, err, op)
			}
		}

		{
			onConflict := &db.OnConflict{
				Target: db.Columns{"keyring_type", "token_name"},
				Action: db.SetColumns([]string{"auth_token_id"}),
			}
			if err := writer.Create(ctx, kt, db.WithOnConflict(onConflict)); err != nil {
				return errors.Wrap(ctx, err, op)
			}
		}

		var users []*user
		if err := reader.SearchWhere(ctx, &users, "true", []any{}, db.WithLimit(-1)); err != nil {
			return errors.Wrap(ctx, err, op)
		}
		if len(users) <= usersLimit {
			return nil
		}

		var oldestUser *user
		var oldestUsersTime *time.Time
		for _, u := range users {
			ats, err := listTokens(ctx, reader, u)
			if err != nil {
				return errors.Wrap(ctx, err, op)
			}
			for _, at := range ats {
				if oldestUsersTime == nil || oldestUsersTime.After(at.LastAccessedTime) {
					oldestUser = u
					oldestUsersTime = &at.LastAccessedTime
				}
			}
		}
		if oldestUser != nil {
			if _, err := deleteUser(ctx, writer, oldestUser); err != nil {
				return errors.Wrap(ctx, err, op)
			}
		}
		return nil
	})
	if err != nil {
		return err
	}

	return nil
}

// LookupToken returns the Token in the cache if one exists.
// Accepts withUpdateLastAccessedTime, WithAuthTokenId, and WithBoundaryAddress
// options.  If withUpdateLastAccessedTime is provided, the last update time
// of the returned token will be updated to the current time and reflected
// in the db. The returned AuthToken will not have the updated time.
func (r *Repository) LookupToken(ctx context.Context, authTokenId string, opt ...Option) (*AuthToken, error) {
	const op = "cache.(Repository).LookupToken"
	switch {
	case authTokenId == "":
		return nil, errors.New(ctx, errors.InvalidParameter, op, "auth token id is empty")
	}

	at := &AuthToken{
		Id: authTokenId,
	}
	if err := r.rw.LookupById(ctx, at); err != nil {
		if errors.IsNotFoundError(err) {
			return nil, nil
		}
		return nil, errors.Wrap(ctx, err, op)
	}

	opts, err := getOpts(opt...)
	if err != nil {
		return nil, errors.Wrap(ctx, err, op)
	}

	if opts.withUpdateLastAccessedTime {
		updatedT := &AuthToken{
			Id:               authTokenId,
			LastAccessedTime: time.Now(),
		}
		if _, err := r.rw.Update(ctx, updatedT, []string{"LastAccessedTime"}, nil); err != nil {
			return nil, errors.Wrap(ctx, err, op)
		}
	}
	return at, nil
}

// deleteKeyringToken deletes a keyring token
func (r *Repository) deleteKeyringToken(ctx context.Context, kt KeyringToken) (retErr error) {
	const op = "cache.(Repository).deleteKeyringToken"
	switch {
	case kt.KeyringType == "":
		return errors.New(ctx, errors.InvalidParameter, op, "missing keyring type")
	case kt.TokenName == "":
		return errors.New(ctx, errors.InvalidParameter, op, "token name type")
	}

	n, err := deleteKeyringToken(ctx, r.rw, kt)
	if err != nil {
		return errors.Wrap(ctx, err, op)
	}

	switch n {
	case 1:
		return nil
	case 0:
		return errors.New(ctx, errors.RecordNotFound, op, "token not found when attempting deletion")
	default:
		return errors.New(ctx, errors.MultipleRecords, op, "multiple tokens deleted when one was requested")
	}
}

// removeStaleTokens removes all tokens which are older than the staleness
func (r *Repository) removeStaleTokens(ctx context.Context, opt ...Option) error {
	const op = "cache.(Repository).removeStaleTokens"
	if _, err := r.rw.Exec(ctx, "delete from auth_token where last_accessed_time < @last_accessed_time",
		[]any{sql.Named("last_accessed_time", time.Now().Add(-tokenStalenessLimit))}); err != nil {
		return errors.Wrap(ctx, err, op)
	}
	return nil
}

// listUsers returns all known tokens in the cache
func (r *Repository) listUsers(ctx context.Context) ([]*user, error) {
	const op = "cache.(Repository).listUsers"
	var ret []*user
	if err := r.rw.SearchWhere(ctx, &ret, "true", nil); err != nil {
		return nil, errors.Wrap(ctx, err, op)
	}
	return ret, nil
}

// listKeyringTokens returns all known keyring tokens in the cache for the provided auth token
func (r *Repository) listKeyringTokens(ctx context.Context, at *AuthToken) ([]*KeyringToken, error) {
	const op = "cache.(Repository).listTokens"
	switch {
	case util.IsNil(at):
		return nil, errors.New(ctx, errors.InvalidParameter, op, "auth token is nil")
	case at.Id == "":
		return nil, errors.New(ctx, errors.InvalidParameter, op, "auth token id is empty")
	}
	var ret []*KeyringToken
	if err := r.rw.SearchWhere(ctx, &ret, "auth_token_id = ?", []any{at.Id}); err != nil {
		return nil, errors.Wrap(ctx, err, op)
	}
	return ret, nil
}

// listTokens returns all known tokens in the cache for the provided user
func (r *Repository) listTokens(ctx context.Context, u *user) ([]*AuthToken, error) {
	const op = "cache.(Repository).listTokens"
	ret, err := listTokens(ctx, r.rw, u)
	if err != nil {
		return nil, errors.Wrap(ctx, err, op)
	}
	return ret, nil
}

// listTokens returns all known tokens in the cache for the provided user using the provided reader
func listTokens(ctx context.Context, reader db.Reader, u *user) ([]*AuthToken, error) {
	const op = "cache.listTokens"
	switch {
	case util.IsNil(u):
		return nil, errors.New(ctx, errors.InvalidParameter, op, "user is nil")
	case u.Id == "":
		return nil, errors.New(ctx, errors.InvalidParameter, op, "user id is missing")
	}
	var ret []*AuthToken
	if err := reader.SearchWhere(ctx, &ret, "user_id = ?", []any{u.Id}); err != nil {
		return nil, errors.Wrap(ctx, err, op)
	}
	return ret, nil
}

// deleteKeyringToken executes a delete command using the provided db.Writer for the provided token.
func deleteKeyringToken(ctx context.Context, w db.Writer, kt KeyringToken) (int, error) {
	const op = "cache.deleteKeyringToken"
	switch {
	case util.IsNil(w):
		return db.NoRowsAffected, errors.New(ctx, errors.InvalidParameter, op, "writer is nil")
	case kt.KeyringType == "":
		return db.NoRowsAffected, errors.New(ctx, errors.InvalidParameter, op, "missing keyring type")
	case kt.TokenName == "":
		return db.NoRowsAffected, errors.New(ctx, errors.InvalidParameter, op, "token name type")
	}
	// TODO(https://github.com/go-gorm/gorm/issues/4879): Use the
	//   writer.Delete() function once the gorm bug is fixed. Until then
	//   the gorm driver for sqlite has an error which wont execute a
	//   delete correctly. as a work around we manually execute the
	//   query here.
	n, err := w.Exec(ctx, "delete from keyring_token where (keyring_type, token_name) = (?, ?)", []any{kt.KeyringType, kt.TokenName})
	if err != nil {
		err = errors.Wrap(ctx, err, op)
	}
	return n, err
}

// deleteUser executes a delete command using the provided db.Writer for the provided user.
func deleteUser(ctx context.Context, w db.Writer, u *user) (int, error) {
	const op = "cache.deleteUser"
	switch {
	case util.IsNil(w):
		return db.NoRowsAffected, errors.New(ctx, errors.InvalidParameter, op, "writer is nil")
	case u.Id == "":
		return db.NoRowsAffected, errors.New(ctx, errors.InvalidParameter, op, "missing id")
	}
	// TODO(https://github.com/go-gorm/gorm/issues/4879): Use the
	//   writer.Delete() function once the gorm bug is fixed. Until then
	//   the gorm driver for sqlite has an error which wont execute a
	//   delete correctly. as a work around we manually execute the
	//   query here.
	n, err := w.Exec(ctx, "delete from user where id = ?", []any{u.Id})
	if err != nil {
		err = errors.Wrap(ctx, err, op)
	}
	return n, err
}

// user is a gorm model for the user table.  It represents a user
type user struct {
	Id      string `gorm:"primaryKey"`
	Address string `gorm:"default:null"`
}

func (*user) TableName() string {
	return "user"
}

func (u *user) clone() *user {
	return &user{
		Id:      u.Id,
		Address: u.Address,
	}
}

// AuthToken is a gorm model for the token table and is an auth token known by the
// boundary client side cache daemon.
type AuthToken struct {
	Id               string    `gorm:"primaryKey"`
	UserId           string    `gorm:"default:null"`
	LastAccessedTime time.Time `gorm:"default:(strftime('%Y-%m-%d %H:%M:%f','now'))"`
}

func (*AuthToken) TableName() string {
	return "auth_token"
}

// KeyringToken is a gorm model for the keyring stored token
type KeyringToken struct {
	KeyringType string `gorm:"primaryKey"`
	TokenName   string `gorm:"primaryKey"`
	AuthTokenId string `gorm:"default:null"`
}

func (*KeyringToken) TableName() string {
	return "keyring_token"
}

func (kt *KeyringToken) clone() *KeyringToken {
	return &KeyringToken{
		KeyringType: kt.KeyringType,
		TokenName:   kt.TokenName,
		AuthTokenId: kt.AuthTokenId,
	}
}
