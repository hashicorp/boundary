// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: BUSL-1.1

package cache

import (
	"context"
	"database/sql"
	"encoding/json"
	stderrors "errors"
	"fmt"

	"github.com/hashicorp/boundary/api"
	"github.com/hashicorp/boundary/api/aliases"
	"github.com/hashicorp/boundary/api/users"
	"github.com/hashicorp/boundary/internal/db"
	"github.com/hashicorp/boundary/internal/errors"
	"github.com/hashicorp/boundary/internal/event"
	"github.com/hashicorp/boundary/internal/util"
	"github.com/hashicorp/mql"
)

// ResolvableAliasRetrievalFunc is a function that retrieves aliases
// from the provided boundary addr using the provided token.
type ResolvableAliasRetrievalFunc func(ctx context.Context, addr, authTok, userId string, refreshTok RefreshTokenValue) (ret []*aliases.Alias, removedIds []string, refreshToken RefreshTokenValue, err error)

func defaultResolvableAliasFunc(ctx context.Context, addr, authTok, userId string, refreshTok RefreshTokenValue) ([]*aliases.Alias, []string, RefreshTokenValue, error) {
	const op = "cache.defaultResolvableAliasFunc"
	client, err := api.NewClient(&api.Config{
		Addr:  addr,
		Token: authTok,
	})
	if err != nil {
		return nil, nil, "", errors.Wrap(ctx, err, op)
	}
	aClient := users.NewClient(client)
	l, err := aClient.ListResolvableAliases(ctx, userId, users.WithListToken(string(refreshTok)))
	if err != nil {
		if api.ErrInvalidListToken.Is(err) {
			return nil, nil, "", err
		}
		return nil, nil, "", errors.Wrap(ctx, err, op)
	}
	if l.ResponseType == "" {
		return nil, nil, "", ErrRefreshNotSupported
	}
	return l.Items, l.RemovedIds, RefreshTokenValue(l.ListToken), nil
}

// refreshResolvableAliases attempts to refresh the resolvabl aliases for the
// provided user using the provided tokens. If available, it uses the refresh
// tokens in storage to retrieve and apply only the delta.
func (r *Repository) refreshResolvableAliases(ctx context.Context, u *user, tokens map[AuthToken]string, opt ...Option) error {
	const op = "cache.(Repository).refreshResolvableAliases"
	switch {
	case util.IsNil(u):
		return errors.New(ctx, errors.InvalidParameter, op, "user is nil")
	case u.Id == "":
		return errors.New(ctx, errors.InvalidParameter, op, "user id is missing")
	case u.Address == "":
		return errors.New(ctx, errors.InvalidParameter, op, "user boundary address is missing")
	}
	const resourceType = resolvableAliasResourceType

	opts, err := getOpts(opt...)
	if err != nil {
		return errors.Wrap(ctx, err, op)
	}
	if opts.withResolvableAliasRetrievalFunc == nil {
		opts.withResolvableAliasRetrievalFunc = defaultResolvableAliasFunc
	}
	var oldRefreshTokenVal RefreshTokenValue
	oldRefreshToken, err := r.lookupRefreshToken(ctx, u, resourceType)
	if err != nil {
		return errors.Wrap(ctx, err, op)
	}
	if oldRefreshToken != nil {
		oldRefreshTokenVal = oldRefreshToken.RefreshToken
	}

	// Find and use a token for retrieving aliases
	var gotResponse bool
	var resp []*aliases.Alias
	var newRefreshToken RefreshTokenValue
	var unsupportedCacheRequest bool
	var removedIds []string
	var retErr error
	for at, t := range tokens {
		resp, removedIds, newRefreshToken, err = opts.withResolvableAliasRetrievalFunc(ctx, u.Address, t, u.Id, oldRefreshTokenVal)
		if api.ErrInvalidListToken.Is(err) {
			event.WriteSysEvent(ctx, op, "old list token is no longer valid, starting new initial fetch", "user_id", u.Id)
			if err := r.deleteRefreshToken(ctx, u, resourceType); err != nil {
				return errors.Wrap(ctx, err, op)
			}
			// try again without the refresh token
			oldRefreshToken = nil
			resp, removedIds, newRefreshToken, err = opts.withResolvableAliasRetrievalFunc(ctx, u.Address, t, u.Id, "")
		}
		if err != nil {
			if err == ErrRefreshNotSupported {
				unsupportedCacheRequest = true
			} else {
				retErr = stderrors.Join(retErr, errors.Wrap(ctx, err, op, errors.WithMsg("for token %q", at.Id)))
				continue
			}
		}
		gotResponse = true
		break
	}

	if retErr != nil {
		if saveErr := r.saveError(r.serverCtx, u, resourceType, retErr); saveErr != nil {
			return stderrors.Join(err, errors.Wrap(ctx, saveErr, op))
		}
	}
	if !gotResponse {
		return retErr
	}

	var numDeleted int
	_, err = r.rw.DoTx(ctx, db.StdRetryCnt, db.ExpBackoff{}, func(_ db.Reader, w db.Writer) error {
		var err error
		switch {
		case oldRefreshToken == nil:
			if numDeleted, err = w.Exec(ctx, "delete from resolvable_alias where fk_user_id = @fk_user_id",
				[]any{sql.Named("fk_user_id", u.Id)}); err != nil {
				return err
			}
		case len(removedIds) > 0:
			if numDeleted, err = w.Exec(ctx, "delete from resolvable_alias where id in @ids",
				[]any{sql.Named("ids", removedIds)}); err != nil {
				return err
			}
		}
		switch {
		case unsupportedCacheRequest:
			if err := upsertRefreshToken(ctx, w, u, resourceType, sentinelNoRefreshToken); err != nil {
				return err
			}
		case newRefreshToken != "":
			if err := upsertResolvableAliases(ctx, w, u, resp); err != nil {
				return err
			}
			if err := upsertRefreshToken(ctx, w, u, resourceType, newRefreshToken); err != nil {
				return err
			}
		default:
			// controller supports caching, but doesn't have any resources
		}
		return nil
	})
	if err != nil {
		return errors.Wrap(ctx, err, op)
	}
	if unsupportedCacheRequest {
		return ErrRefreshNotSupported
	}
	event.WriteSysEvent(ctx, op, "resolvable-aliases updated", "deleted", numDeleted, "upserted", len(resp), "user_id", u.Id)
	return nil
}

// checkCachingResolvableAliases fetches all aliases for the provided user and sets the
// cache to match the values returned.  If the response includes a refresh
// token it will save that as well.
func (r *Repository) checkCachingResolvableAliases(ctx context.Context, u *user, tokens map[AuthToken]string, opt ...Option) error {
	const op = "cache.(Repository).checkCachingResolvableAliases"
	switch {
	case util.IsNil(u):
		return errors.New(ctx, errors.InvalidParameter, op, "user is nil")
	case u.Id == "":
		return errors.New(ctx, errors.InvalidParameter, op, "user id is missing")
	case u.Address == "":
		return errors.New(ctx, errors.InvalidParameter, op, "user boundary address is missing")
	}
	const resourceType = resolvableAliasResourceType

	opts, err := getOpts(opt...)
	if err != nil {
		return errors.Wrap(ctx, err, op)
	}
	if opts.withResolvableAliasRetrievalFunc == nil {
		opts.withResolvableAliasRetrievalFunc = defaultResolvableAliasFunc
	}

	// Find and use a token for retrieving aliases
	var gotResponse bool
	var resp []*aliases.Alias
	var newRefreshToken RefreshTokenValue
	var unsupportedCacheRequest bool
	var retErr error
	for at, t := range tokens {
		resp, _, newRefreshToken, err = opts.withResolvableAliasRetrievalFunc(ctx, u.Address, t, u.Id, "")
		if err != nil {
			if err == ErrRefreshNotSupported {
				unsupportedCacheRequest = true
			} else {
				retErr = stderrors.Join(retErr, errors.Wrap(ctx, err, op, errors.WithMsg("for token %q", at.Id)))
				continue
			}
		}
		gotResponse = true
		break
	}

	if retErr != nil {
		if saveErr := r.saveError(r.serverCtx, u, resourceType, retErr); saveErr != nil {
			return stderrors.Join(err, errors.Wrap(ctx, saveErr, op))
		}
	}
	if !gotResponse {
		return retErr
	}

	var numDeleted int
	_, err = r.rw.DoTx(ctx, db.StdRetryCnt, db.ExpBackoff{}, func(reader db.Reader, w db.Writer) error {
		switch {
		case unsupportedCacheRequest:
			if err := upsertRefreshToken(ctx, w, u, resourceType, sentinelNoRefreshToken); err != nil {
				return err
			}
		case newRefreshToken != "":
			var err error
			if numDeleted, err = w.Exec(ctx, "delete from resolvable_alias where fk_user_id = @fk_user_id",
				[]any{sql.Named("fk_user_id", u.Id)}); err != nil {
				return err
			}
			if err := upsertResolvableAliases(ctx, w, u, resp); err != nil {
				return err
			}
			if err := upsertRefreshToken(ctx, w, u, resourceType, newRefreshToken); err != nil {
				return err
			}
		default:
			// This is no longer flagged as not supported, but we dont have a
			// refresh token so clear out any refresh token we have stored.
			if err := deleteRefreshToken(ctx, w, u, resourceType); err != nil {
				return err
			}
		}
		return nil
	})
	if err != nil {
		return errors.Wrap(ctx, err, op)
	}
	if unsupportedCacheRequest {
		return ErrRefreshNotSupported
	}
	event.WriteSysEvent(ctx, op, "resolvable-aliases updated", "deleted", numDeleted, "upserted", len(resp), "user_id", u.Id)
	return nil
}

// upsertResolvableAliases upserts the provided aliases to be stored for the provided user.
func upsertResolvableAliases(ctx context.Context, w db.Writer, u *user, in []*aliases.Alias) error {
	const op = "cache.upsertResolvableAliases"
	switch {
	case util.IsNil(w):
		return errors.New(ctx, errors.InvalidParameter, op, "writer is nil")
	case !w.IsTx(ctx):
		return errors.New(ctx, errors.InvalidParameter, op, "writer isn't in a transaction")
	case util.IsNil(u):
		return errors.New(ctx, errors.InvalidParameter, op, "user is nil")
	}

	for _, s := range in {
		item, err := json.Marshal(s)
		if err != nil {
			return errors.Wrap(ctx, err, op)
		}
		newAlias := &ResolvableAlias{
			FkUserId:      u.Id,
			Id:            s.Id,
			Type:          s.Type,
			DestinationId: s.DestinationId,
			Value:         s.Value,
			Item:          string(item),
		}
		onConflict := db.OnConflict{
			Target: db.Columns{"fk_user_id", "id"},
			Action: db.SetColumns([]string{"type", "destination_id", "value", "item"}),
		}
		if err := w.Create(ctx, newAlias, db.WithOnConflict(&onConflict)); err != nil {
			return errors.Wrap(ctx, err, op)
		}
	}
	return nil
}

func (r *Repository) ListResolvableAliases(ctx context.Context, authTokenId string) ([]*aliases.Alias, error) {
	const op = "cache.(Repository).ListResolvableAliases"
	switch {
	case authTokenId == "":
		return nil, errors.New(ctx, errors.InvalidParameter, op, "auth token id is missing")
	}
	ret, err := r.searchResolvableAliases(ctx, "true", nil, withAuthTokenId(authTokenId))
	if err != nil {
		return nil, errors.Wrap(ctx, err, op)
	}
	return ret, nil
}

func (r *Repository) QueryResolvableAliases(ctx context.Context, authTokenId, query string) ([]*aliases.Alias, error) {
	const op = "cache.(Repository).QueryResolvableAliases"
	switch {
	case authTokenId == "":
		return nil, errors.New(ctx, errors.InvalidParameter, op, "auth token id is missing")
	case query == "":
		return nil, errors.New(ctx, errors.InvalidParameter, op, "query is missing")
	}

	w, err := mql.Parse(query, ResolvableAlias{}, mql.WithIgnoredFields("FkUserId", "Item"))
	if err != nil {
		return nil, errors.Wrap(ctx, err, op, errors.WithCode(errors.InvalidParameter))
	}
	ret, err := r.searchResolvableAliases(ctx, w.Condition, w.Args, withAuthTokenId(authTokenId))
	if err != nil {
		return nil, errors.Wrap(ctx, err, op)
	}
	return ret, nil
}

func (r *Repository) searchResolvableAliases(ctx context.Context, condition string, searchArgs []any, opt ...Option) ([]*aliases.Alias, error) {
	const op = "cache.(Repository).searchResolvableAliases"
	switch {
	case condition == "":
		return nil, errors.New(ctx, errors.InvalidParameter, op, "condition is missing")
	}

	opts, err := getOpts(opt...)
	if err != nil {
		return nil, errors.Wrap(ctx, err, op)
	}
	switch {
	case opts.withAuthTokenId != "" && opts.withUserId != "":
		return nil, errors.New(ctx, errors.InvalidParameter, op, "both user id and auth token id were provided")
	case opts.withAuthTokenId == "" && opts.withUserId == "":
		return nil, errors.New(ctx, errors.InvalidParameter, op, "neither user id nor auth token id were provided")
	case opts.withAuthTokenId != "":
		condition = fmt.Sprintf("%s and fk_user_id in (select user_id from auth_token where id = ?)", condition)
		searchArgs = append(searchArgs, opts.withAuthTokenId)
	case opts.withUserId != "":
		condition = fmt.Sprintf("%s and fk_user_id = ?", condition)
		searchArgs = append(searchArgs, opts.withUserId)
	}

	var cachedResolvableAliases []*ResolvableAlias
	if err := r.rw.SearchWhere(ctx, &cachedResolvableAliases, condition, searchArgs, db.WithLimit(-1)); err != nil {
		return nil, errors.Wrap(ctx, err, op)
	}

	retAliases := make([]*aliases.Alias, 0, len(cachedResolvableAliases))
	for _, cachedA := range cachedResolvableAliases {
		var a aliases.Alias
		if err := json.Unmarshal([]byte(cachedA.Item), &a); err != nil {
			return nil, errors.Wrap(ctx, err, op)
		}
		retAliases = append(retAliases, &a)
	}
	return retAliases, nil
}

type ResolvableAlias struct {
	FkUserId      string `gorm:"primaryKey"`
	Id            string `gorm:"primaryKey"`
	Type          string `gorm:"default:null"`
	DestinationId string `gorm:"default:null"`
	Value         string `gorm:"default:null"`
	Item          string `gorm:"default:null"`
}

func (*ResolvableAlias) TableName() string {
	return "resolvable_alias"
}
