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
func (r *Repository) AddToken(ctx context.Context, bAddr, tokenName, keyringType, authTokId string) error {
	const op = "cache.(Repository).AddToken"
	switch {
	case tokenName == "":
		return errors.New(ctx, errors.InvalidParameter, op, "token name is empty")
	case keyringType == "":
		return errors.New(ctx, errors.InvalidParameter, op, "keyring type is empty")
	case bAddr == "":
		return errors.New(ctx, errors.InvalidParameter, op, "boundary address is empty")
	case authTokId == "":
		return errors.New(ctx, errors.InvalidParameter, op, "boundary auth token id is empty")
	}

	at := r.tokenLookupFn(keyringType, tokenName)
	if at == nil {
		return errors.New(ctx, errors.InvalidParameter, op, "unable to find token in the keyring specified")
	}
	if authTokId != at.Id {
		return errors.New(ctx, errors.InvalidParameter, op, "provided auth token id doesn't match the one stored")
	}

	// Even though the auth token is already stored, we still call create so
	// the last accessed timestamps can get updated since calling this method
	// indicates that the token was used and is still valid.
	_, err := r.rw.DoTx(ctx, db.StdRetryCnt, db.ExpBackoff{}, func(reader db.Reader, writer db.Writer) error {
		{
			var t []*Token
			err := reader.SearchWhere(ctx, &t, "auth_token_id = ?", []any{authTokId})
			switch {
			case err != nil:
				return errors.Wrap(ctx, err, op)
			case len(t) == 0:
				// TODO: This is the first time this auth token is associated with
				// this keyring/token name, lookup the auth token from boundary to
				// verify that it is for the user specified.
			case t[0].UserId != at.UserId:
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
			st := &Token{
				KeyringType:      keyringType,
				TokenName:        tokenName,
				UserId:           at.UserId,
				AuthTokenId:      at.Id,
				LastAccessedTime: time.Now(),
			}
			onConflict := &db.OnConflict{
				Target: db.Columns{"keyring_type", "token_name"},
				Action: db.SetColumns([]string{"auth_token_id", "user_id", "last_accessed_time"}),
			}
			if err := writer.Create(ctx, st, db.WithOnConflict(onConflict)); err != nil {
				return errors.Wrap(ctx, err, op)
			}
		}

		var tokens []*Token
		if err := reader.SearchWhere(ctx, &tokens, "", []any{}, db.WithLimit(-1)); err != nil {
			return errors.Wrap(ctx, err, op)
		}
		if len(tokens) <= tokensLimit {
			return nil
		}

		var oldestToken *Token
		for _, t := range tokens {
			if oldestToken == nil || oldestToken.LastAccessedTime.After(t.LastAccessedTime) {
				oldestToken = t
			}
		}
		if oldestToken != nil {
			if _, err := deleteToken(ctx, writer, oldestToken); err != nil {
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
// in the db. The returned Token will not have the updated time.
// If WithAuthTokenId or WithBoundaryAddress are provided the returned Token
// must have the matching AuthTokenId or BoundaryAddr respectively.
func (r *Repository) LookupToken(ctx context.Context, tokenName, keyringType string, opt ...Option) (*Token, error) {
	const op = "cache.(Repository).LookupToken"
	switch {
	case keyringType == "":
		return nil, errors.New(ctx, errors.InvalidParameter, op, "keyring type is empty")
	case tokenName == "":
		return nil, errors.New(ctx, errors.InvalidParameter, op, "token name is empty")
	}
	opts, err := getOpts(opt...)
	if err != nil {
		return nil, errors.Wrap(ctx, err, op)
	}

	p := &Token{
		KeyringType: keyringType,
		TokenName:   tokenName,
	}
	if err := r.rw.LookupById(ctx, p); err != nil {
		if errors.IsNotFoundError(err) {
			return nil, nil
		}
		return nil, errors.Wrap(ctx, err, op)
	}

	switch {
	case opts.withAuthTokenId != "" && opts.withAuthTokenId != p.AuthTokenId:
		// If we found a token that doesn't have the provided auth token id
		// is not the correct one, so the return should indicate the looked up
		// token could not be found.
		return nil, nil
	}

	if opts.withUpdateLastAccessedTime {
		updatedT := &Token{
			TokenName:        p.TokenName,
			KeyringType:      p.KeyringType,
			LastAccessedTime: time.Now(),
		}
		if _, err := r.rw.Update(ctx, updatedT, []string{"LastAccessedTime"}, nil); err != nil {
			return nil, errors.Wrap(ctx, err, op)
		}
	}
	return p, nil
}

// deleteToken deletes a token
func (r *Repository) deleteToken(ctx context.Context, t *Token) (retErr error) {
	const op = "cache.(Repository).deleteToken"
	switch {
	case t == nil:
		return errors.New(ctx, errors.InvalidParameter, op, "missing token")
	case t.TokenName == "":
		return errors.New(ctx, errors.InvalidParameter, op, "missing token name")
	case t.KeyringType == "":
		return errors.New(ctx, errors.InvalidParameter, op, "missing keyring type")
	}

	n, err := deleteToken(ctx, r.rw, t)
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
	if _, err := r.rw.Exec(ctx, "delete from token where last_accessed_time < @last_accessed_time",
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

// listTokens returns all known tokens in the cache
func (r *Repository) listTokens(ctx context.Context, u *user) ([]*Token, error) {
	const op = "cache.(Repository).listTokens"
	switch {
	case util.IsNil(u):
		return nil, errors.New(ctx, errors.InvalidParameter, op, "user is nil")
	case u.Id == "":
		return nil, errors.New(ctx, errors.InvalidParameter, op, "user id is empty")
	}
	var ret []*Token
	if err := r.rw.SearchWhere(ctx, &ret, "user_id = ?", []any{u.Id}); err != nil {
		return nil, errors.Wrap(ctx, err, op)
	}
	return ret, nil
}

// deleteToken executes a delete command using the provided db.Writer for the provided token.
func deleteToken(ctx context.Context, w db.Writer, st *Token) (int, error) {
	const op = "cache.deleteToken"
	switch {
	case util.IsNil(w):
		return db.NoRowsAffected, errors.New(ctx, errors.InvalidParameter, op, "writer is nil")
	case util.IsNil(st):
		return db.NoRowsAffected, errors.New(ctx, errors.InvalidParameter, op, "token is nil")
	}
	// TODO(https://github.com/go-gorm/gorm/issues/4879): Use the
	//   writer.Delete() function once the gorm bug is fixed. Until then
	//   the gorm driver for sqlite has an error which wont execute a
	//   delete correctly. as a work around we manually execute the
	//   query here.
	n, err := w.Exec(ctx, "delete from token where (keyring_type, token_name) = (?, ?)",
		[]any{st.KeyringType, st.TokenName})
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

// Token is a gorm model for the token table and is an auth token known by the
// boundary client side cache daemon.
type Token struct {
	KeyringType      string    `gorm:"primaryKey"`
	TokenName        string    `gorm:"primaryKey"`
	UserId           string    `gorm:"default:null"`
	AuthTokenId      string    `gorm:"default:null"`
	LastAccessedTime time.Time `gorm:"default:(strftime('%Y-%m-%d %H:%M:%f','now'))"`
}

func (*Token) TableName() string {
	return "token"
}

func (p *Token) clone() *Token {
	return &Token{
		KeyringType:      p.KeyringType,
		TokenName:        p.TokenName,
		UserId:           p.UserId,
		AuthTokenId:      p.AuthTokenId,
		LastAccessedTime: p.LastAccessedTime,
	}
}
