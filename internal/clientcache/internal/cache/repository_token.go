// Copyright IBM Corp. 2020, 2025
// SPDX-License-Identifier: BUSL-1.1

package cache

import (
	"context"
	"database/sql"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/hashicorp/boundary/api/authtokens"
	"github.com/hashicorp/boundary/internal/db"
	"github.com/hashicorp/boundary/internal/errors"
	"github.com/hashicorp/boundary/internal/util"
)

// AuthTokenIdSegmentCount are the number of segments, delineated by "_", that
// make up the auth token id inside an auth token.
// For example, an authtoken format should look something like at_1234567890_sometokenpayload
const AuthTokenIdSegmentCount = 2

// upsertUserAndAuthToken upserts a user and authToken using the data in the provided authtoken.
// If creating this user results in the number of users exceeding the limit of
// allowed users it deletes the oldest one.
func upsertUserAndAuthToken(ctx context.Context, reader db.Reader, writer db.Writer, bAddr string, at *authtokens.AuthToken) error {
	const op = "cache.upsertUserAndAuthToken"
	switch {
	case util.IsNil(reader):
		return errors.New(ctx, errors.InvalidParameter, op, "reader is nil")
	case util.IsNil(writer):
		return errors.New(ctx, errors.InvalidParameter, op, "writer is nil")
	case !writer.IsTx(ctx):
		return errors.New(ctx, errors.InvalidParameter, op, "writer isn't part of an inflight transaction")
	case util.IsNil(at):
		return errors.New(ctx, errors.InvalidParameter, op, "auth token is nil")
	case bAddr == "":
		return errors.New(ctx, errors.InvalidParameter, op, "boundary address is empty")
	case at.Id == "":
		return errors.New(ctx, errors.InvalidParameter, op, "auth token id is empty")
	case at.UserId == "":
		return errors.New(ctx, errors.InvalidParameter, op, "auth token user id is empty")
	}
	{
		// always make sure the user exists when adding a token
		u := &user{
			Id:      at.UserId,
			Address: bAddr,
		}
		onConflict := &db.OnConflict{
			Target: db.Columns{"id"},
			// Unset the deleted_at column if it was set to un-delete the user
			Action: db.SetColumnValues(map[string]any{"deleted_at": "infinity"}),
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
			ExpirationTime:   at.ExpirationTime,
		}
		onConflict := &db.OnConflict{
			Target: db.Columns{"id"},
			Action: db.SetColumns([]string{"last_accessed_time", "expiration_time"}),
		}
		if err := writer.Create(ctx, st, db.WithOnConflict(onConflict)); err != nil {
			return errors.Wrap(ctx, err, op)
		}
	}

	var users []*user
	// we only want users that have not been soft deleted
	if err := reader.SearchWhere(ctx, &users, "true", []any{}, db.WithLimit(-1), db.WithTable(activeUserTableName)); err != nil {
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
}

// AddRawToken upserts the auth token's user and auth token in the db and
// stores the actual raw auth token in the repositories in memory storage.
// The raw token must be valid and present in boundary and be for a user that
// has permission to send a Read request for itself to boundary.
func (r *Repository) AddRawToken(ctx context.Context, bAddr string, rawToken string) error {
	const op = "cache.(Repository).AddRawToken"
	switch {
	case rawToken == "":
		return errors.New(ctx, errors.InvalidParameter, op, "boundary auth token is empty", errors.WithoutEvent())
	case bAddr == "":
		return errors.New(ctx, errors.InvalidParameter, op, "boundary address is empty", errors.WithoutEvent())
	}

	// rawToken should look something like at_1234567890_someencryptedpayload
	atIdParts := strings.SplitN(rawToken, "_", 4)
	if len(atIdParts) != 3 {
		return errors.New(ctx, errors.InvalidParameter, op, "boundary auth token is is malformed", errors.WithoutEvent())
	}
	atId := strings.Join(atIdParts[:AuthTokenIdSegmentCount], "_")

	var at *authtokens.AuthToken
	{
		var inMemAuthToken *authtokens.AuthToken
		atV, inMem := r.idToKeyringlessAuthToken.Load(atId)
		if inMem {
			var ok bool
			inMemAuthToken, ok = atV.(*authtokens.AuthToken)
			if !ok {
				return errors.New(ctx, errors.Internal, op, "unable to cast in memory auth token to *authtoken.AuthToken", errors.WithoutEvent())
			}
		}
		t := &AuthToken{
			Id: atId,
		}
		err := r.rw.LookupById(ctx, t)
		switch {
		case err != nil && !errors.IsNotFoundError(err):
			return errors.Wrap(ctx, err, op)
		case errors.IsNotFoundError(err) || !inMem:
			// if we don't know about it in the cache or we don't know about
			// this auth token in memory, get it from boundary to sure up the
			// cache information about this auth token.
			at, err = r.tokenReadFromBoundaryFn(ctx, bAddr, rawToken)
			if err != nil {
				return errors.Wrap(ctx, err, op, errors.WithoutEvent())
			}
		case t.UserId != inMemAuthToken.UserId:
			return errors.New(ctx, errors.InvalidParameter, op, "user id doesn't match what is specified in the stored auth token", errors.WithoutEvent())
		case inMem:
			at = inMemAuthToken
		}
	}

	if at != nil {
		// The token is never returned from boundary except in the original auth
		// request so we must set the token.
		at.Token = rawToken
	}

	_, err := r.rw.DoTx(ctx, db.StdRetryCnt, db.ExpBackoff{}, func(reader db.Reader, writer db.Writer) error {
		if err := upsertUserAndAuthToken(ctx, reader, writer, bAddr, at); err != nil {
			return errors.Wrap(ctx, err, op, errors.WithoutEvent())
		}
		r.idToKeyringlessAuthToken.Store(at.Id, at)
		return nil
	})
	if err != nil {
		return err
	}

	return nil
}

// AddKeyringToken adds a token to the repository.  If the token's id in the
// keyring doesn't match the id provided an error is returned.
// The token must be valid and present in boundary and be for a user that
// has permission to send a self-Read request to boundary.  The user id
// stored in the keyring must also match the user id returned from boundary.
func (r *Repository) AddKeyringToken(ctx context.Context, bAddr string, token KeyringToken) error {
	const op = "cache.(Repository).AddKeyringToken"
	switch {
	case token.TokenName == "":
		return errors.New(ctx, errors.InvalidParameter, op, "token name is empty", errors.WithoutEvent())
	case token.KeyringType == "":
		return errors.New(ctx, errors.InvalidParameter, op, "keyring type is empty", errors.WithoutEvent())
	case token.AuthTokenId == "":
		return errors.New(ctx, errors.InvalidParameter, op, "boundary auth token id is empty", errors.WithoutEvent())
	case bAddr == "":
		return errors.New(ctx, errors.InvalidParameter, op, "boundary address is empty", errors.WithoutEvent())
	}
	kt := token.clone()
	keyringStoredAt, err := r.tokenKeyringFn(kt.KeyringType, kt.TokenName)
	if err != nil {
		return errors.Wrap(ctx, err, op, errors.WithMsg("unable to lookup token in keyring, keyring type: %q, token name: %q", kt.KeyringType, kt.TokenName), errors.WithoutEvent())
	}
	if keyringStoredAt == nil {
		return errors.New(ctx, errors.InvalidParameter, op, "unable to find token in the keyring specified", errors.WithoutEvent())
	}
	if kt.AuthTokenId != keyringStoredAt.Id {
		return errors.New(ctx, errors.InvalidParameter, op, "provided auth token id doesn't match the one stored", errors.WithoutEvent())
	}

	var at *authtokens.AuthToken
	{
		cachedAt := &AuthToken{
			Id: kt.AuthTokenId,
		}
		err := r.rw.LookupById(ctx, cachedAt)
		switch {
		case err != nil && !errors.IsNotFoundError(err):
			return errors.Wrap(ctx, err, op)
		case errors.IsNotFoundError(err):
			at, err = r.tokenReadFromBoundaryFn(ctx, bAddr, keyringStoredAt.Token)
			if err != nil {
				return errors.Wrap(ctx, err, op)
			}
		case cachedAt.UserId != keyringStoredAt.UserId:
			return errors.New(ctx, errors.InvalidParameter, op, "user id doesn't match what is specified in the stored auth token", errors.WithoutEvent())
		default:
			at = keyringStoredAt
		}
	}
	if _, err := r.rw.DoTx(ctx, db.StdRetryCnt, db.ExpBackoff{}, func(reader db.Reader, writer db.Writer) error {
		if err := upsertUserAndAuthToken(ctx, reader, writer, bAddr, at); err != nil {
			return errors.Wrap(ctx, err, op, errors.WithoutEvent())
		}
		onConflict := &db.OnConflict{
			Target: db.Columns{"keyring_type", "token_name"},
			Action: db.SetColumns([]string{"auth_token_id"}),
		}
		if err := writer.Create(ctx, kt, db.WithOnConflict(onConflict)); err != nil {
			return errors.Wrap(ctx, err, op, errors.WithoutEvent())
		}
		return nil
	}); err != nil {
		return err
	}

	return nil
}

// LookupToken returns the Token in the cache if one exists.
// Accepts withUpdateLastAccessedTime options.  If withUpdateLastAccessedTime
// is provided, the last update time of the returned token will be updated to
// the current time and reflected in the db. The returned AuthToken will not
// have the updated time.
func (r *Repository) LookupToken(ctx context.Context, authTokenId string, opt ...Option) (*AuthToken, error) {
	const op = "cache.(Repository).LookupToken"
	switch {
	case authTokenId == "":
		return nil, errors.New(ctx, errors.InvalidParameter, op, "auth token id is empty", errors.WithoutEvent())
	}

	at := &AuthToken{
		Id: authTokenId,
	}
	if err := r.rw.LookupById(ctx, at); err != nil {
		if errors.IsNotFoundError(err) {
			return nil, nil
		}
		return nil, errors.Wrap(ctx, err, op, errors.WithoutEvent())
	}

	opts, err := getOpts(opt...)
	if err != nil {
		return nil, errors.Wrap(ctx, err, op, errors.WithoutEvent())
	}

	if opts.withUpdateLastAccessedTime {
		updatedT := &AuthToken{
			Id:               authTokenId,
			LastAccessedTime: time.Now(),
		}
		if _, err := r.rw.Update(ctx, updatedT, []string{"LastAccessedTime"}, nil); err != nil {
			return nil, errors.Wrap(ctx, err, op, errors.WithoutEvent())
		}
	}
	return at, nil
}

// deleteKeyringToken deletes a keyring token
func (r *Repository) deleteKeyringToken(ctx context.Context, kt KeyringToken) error {
	const op = "cache.(Repository).deleteKeyringToken"
	switch {
	case kt.KeyringType == "":
		return errors.New(ctx, errors.InvalidParameter, op, "missing keyring type")
	case kt.TokenName == "":
		return errors.New(ctx, errors.InvalidParameter, op, "token name type")
	}

	_, err := r.rw.DoTx(ctx, db.StdRetryCnt, db.ExpBackoff{}, func(reader db.Reader, writer db.Writer) error {
		// TODO(https://github.com/go-gorm/gorm/issues/4879): Use the
		//   writer.Delete() function once the gorm bug is fixed. Until then
		//   the gorm driver for sqlite has an error which wont execute a
		//   delete correctly. as a work around we manually execute the
		//   query here.
		n, err := writer.Exec(ctx, "delete from keyring_token where (keyring_type, token_name) = (?, ?)", []any{kt.KeyringType, kt.TokenName})
		if err != nil {
			return errors.Wrap(ctx, err, op, errors.WithoutEvent())
		}

		switch n {
		case 1:
			if err := cleanExpiredOrOrphanedAuthTokens(ctx, writer, r.idToKeyringlessAuthToken); err != nil {
				return errors.Wrap(ctx, err, op, errors.WithoutEvent())
			}
			return nil
		case 0:
			return errors.New(ctx, errors.RecordNotFound, op, "token not found when attempting deletion", errors.WithoutEvent())
		default:
			return errors.New(ctx, errors.MultipleRecords, op, "multiple tokens deleted when one was requested", errors.WithoutEvent())
		}
	})
	if err != nil {
		return err
	}
	return nil
}

// cleanExpiredOrOrphanedAuthTokens removes all tokens which are older than the staleness limit
// or does not have either a keyring or keyringless reference to it.
func (r *Repository) cleanExpiredOrOrphanedAuthTokens(ctx context.Context) error {
	const op = "cache.Repository.cleanExpiredOrOrphanedAuthTokens"
	_, err := r.rw.DoTx(ctx, db.StdRetryCnt, db.ExpBackoff{}, func(reader db.Reader, writer db.Writer) error {
		if err := cleanExpiredOrOrphanedAuthTokens(ctx, writer, r.idToKeyringlessAuthToken); err != nil {
			return errors.Wrap(ctx, err, op, errors.WithoutEvent())
		}
		return nil
	})
	return err
}

// cleanExpiredOrOrphanedAuthTokens removes all tokens which are older than the staleness limit
// or does not have either a keyring or keyringless reference to it.
func cleanExpiredOrOrphanedAuthTokens(ctx context.Context, writer db.Writer, idToKeyringlessAuthToken *sync.Map) error {
	const op = "cache.cleanExpiredOrOrphanedAuthTokens"
	switch {
	case util.IsNil(writer):
		return errors.New(ctx, errors.InvalidParameter, op, "writer is nil")
	case idToKeyringlessAuthToken == nil:
		return errors.New(ctx, errors.InvalidParameter, op, "keyringless auth token map is nil")
	case !writer.IsTx(ctx):
		return errors.New(ctx, errors.InvalidParameter, op, "writer isn't part of an inflight transaction")
	}

	var keyringlessAuthTokens []string
	idToKeyringlessAuthToken.Range(func(key, _ any) bool {
		keyringlessAuthTokens = append(keyringlessAuthTokens, key.(string))
		return true
	})

	deleteOrphanedAuthTokens := `
	delete from auth_token
	where
		last_accessed_time < @last_accessed_time
	or
		-- sqlite stores expiration_time as a string in a format that might not match
		-- what is being used by current_timestamp.  Using datetime() makes the
		-- formats match which allow the string comparison performed here to work
		-- the same as a time comparison.
		datetime(expiration_time) < current_timestamp
	or
	%s
	`
	args := []any{sql.Named("last_accessed_time", time.Now().Add(-tokenStalenessLimit))}

	idInSection := "id not in (select auth_token_id from keyring_token)"
	if len(keyringlessAuthTokens) > 0 {
		// Note: We have to build the statement like this because if the slice of string
		// is empty this gets converted to a query that says " and id not in (NULL)"
		idInSection = fmt.Sprintf("(%s and id not in @keyringless_token_ids)", idInSection)
		args = append(args, sql.Named("keyringless_token_ids", keyringlessAuthTokens))
	}

	if _, err := writer.Exec(ctx, fmt.Sprintf(deleteOrphanedAuthTokens, idInSection), args); err != nil {
		return errors.Wrap(ctx, err, op)
	}
	return nil
}

const activeUserTableName = "user_active" // users that have not been soft deleted

// lookupUser returns a user if one is present in the repository or nil if not.
func (r *Repository) lookupUser(ctx context.Context, id string) (*user, error) {
	const op = "cache.(Repository).lookupUser"
	switch {
	case id == "":
		return nil, errors.New(ctx, errors.InvalidParameter, op, "empty id")
	}
	ret := &user{Id: id}
	// we only want users that have NOT been soft deleted
	if err := r.rw.LookupById(ctx, ret, db.WithTable(activeUserTableName)); err != nil {
		if errors.IsNotFoundError(err) {
			return nil, nil
		}
		return nil, errors.Wrap(ctx, err, op)
	}
	return ret, nil
}

// listUsers returns all known tokens in the cache
func (r *Repository) listUsers(ctx context.Context) ([]*user, error) {
	const op = "cache.(Repository).listUsers"
	var ret []*user
	// we only want users that have NOT been soft deleted
	if err := r.rw.SearchWhere(ctx, &ret, "true", nil, db.WithTable(activeUserTableName)); err != nil {
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

// syncKeyringlessTokensWithDb removes the in memory storage of auth tokens if
// they are no longer represented in the db.
func (r *Repository) syncKeyringlessTokensWithDb(ctx context.Context) error {
	const op = "cache.(Repository).syncKeyringlessTokensWithDb"
	var ret []*AuthToken
	if err := r.rw.SearchWhere(ctx, &ret, "true", nil); err != nil {
		return errors.Wrap(ctx, err, op)
	}
	authTokenIds := make(map[string]struct{})
	for _, at := range ret {
		authTokenIds[at.Id] = struct{}{}
	}
	r.idToKeyringlessAuthToken.Range(func(key, value any) bool {
		k := key.(string)
		if _, ok := authTokenIds[k]; !ok {
			r.idToKeyringlessAuthToken.Delete(key)
		}
		return true
	})
	return nil
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
	const (
		// delete the user if they don't have any refresh tokens which are
		// newer than 20 days (the refresh token expiration time)
		deleteStmt = "delete from user where id = ? and id not in (select user_id from refresh_token where DATETIME('now', '-20 days') < datetime(create_time) )"

		// fallback to soft deleting the user
		softDeleteStmt = "update user set deleted_at = (strftime('%Y-%m-%d %H:%M:%f','now')) where id = ?"
	)
	// see if we should delete the user
	rowsAffected, err := w.Exec(ctx, deleteStmt, []any{u.Id})
	switch {
	case err != nil:
		return db.NoRowsAffected, errors.Wrap(ctx, err, op)
	case rowsAffected > 0:
		// if we deleted the user, we're done.
		return rowsAffected, nil
	}

	// fallback to soft delete
	rowsAffected, err = w.Exec(ctx, softDeleteStmt, []any{u.Id})
	if err != nil {
		return db.NoRowsAffected, errors.Wrap(ctx, err, op)
	}

	return rowsAffected, nil
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
	ExpirationTime   time.Time
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
