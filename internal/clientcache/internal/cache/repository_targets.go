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
	"github.com/hashicorp/boundary/api/targets"
	"github.com/hashicorp/boundary/internal/db"
	"github.com/hashicorp/boundary/internal/errors"
	"github.com/hashicorp/boundary/internal/event"
	"github.com/hashicorp/boundary/internal/util"
	"github.com/hashicorp/mql"
)

// TargetRetrievalFunc is a function that retrieves targets
// from the provided boundary addr using the provided token.
type TargetRetrievalFunc func(ctx context.Context, addr, authTok string, refreshTok RefreshTokenValue) (ret []*targets.Target, removedIds []string, refreshToken RefreshTokenValue, err error)

func defaultTargetFunc(ctx context.Context, addr, authTok string, refreshTok RefreshTokenValue) ([]*targets.Target, []string, RefreshTokenValue, error) {
	const op = "cache.defaultTargetFunc"
	client, err := api.NewClient(&api.Config{
		Addr:  addr,
		Token: authTok,
	})
	if err != nil {
		return nil, nil, "", errors.Wrap(ctx, err, op)
	}
	tarClient := targets.NewClient(client)
	l, err := tarClient.List(ctx, "global", targets.WithRecursive(true), targets.WithListToken(string(refreshTok)))
	if err != nil {
		if api.ErrInvalidListToken.Is(err) {
			return nil, nil, "", err
		}
		return nil, nil, "", errors.Wrap(ctx, err, op)
	}
	return l.Items, l.RemovedIds, RefreshTokenValue(l.ListToken), nil
}

// refreshTargets uses attempts to refresh the targets for the provided user
// using the provided tokens. If available, it uses the refresh tokens in
// storage to retrieve and apply only the delta.
func (r *Repository) refreshTargets(ctx context.Context, u *user, tokens map[AuthToken]string, opt ...Option) error {
	const op = "cache.(Repository).refreshTargets"
	switch {
	case util.IsNil(u):
		return errors.New(ctx, errors.InvalidParameter, op, "user is nil")
	case u.Id == "":
		return errors.New(ctx, errors.InvalidParameter, op, "user id is missing")
	}
	const resourceType = targetResourceType

	opts, err := getOpts(opt...)
	if err != nil {
		return errors.Wrap(ctx, err, op)
	}
	if opts.withTargetRetrievalFunc == nil {
		opts.withTargetRetrievalFunc = defaultTargetFunc
	}

	var oldRefreshTokenVal RefreshTokenValue
	oldRefreshToken, err := r.lookupRefreshToken(ctx, u, resourceType)
	if err != nil {
		return errors.Wrap(ctx, err, op)
	}
	if oldRefreshToken != nil {
		oldRefreshTokenVal = oldRefreshToken.RefreshToken
	}

	// Find and use a token for retrieving targets
	var gotResponse bool
	var resp []*targets.Target
	var removedIds []string
	var newRefreshToken RefreshTokenValue
	var retErr error
	for at, t := range tokens {
		resp, removedIds, newRefreshToken, err = opts.withTargetRetrievalFunc(ctx, u.Address, t, oldRefreshTokenVal)
		if api.ErrInvalidListToken.Is(err) {
			if err := r.deleteRefreshToken(ctx, u, resourceType); err != nil {
				return errors.Wrap(ctx, err, op)
			}
			// try again without the refresh token
			oldRefreshToken = nil
			resp, removedIds, newRefreshToken, err = opts.withTargetRetrievalFunc(ctx, u.Address, t, "")
		}
		if err != nil {
			retErr = stderrors.Join(retErr, errors.Wrap(ctx, err, op, errors.WithMsg("for token %q", at.Id)))
			continue
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

	var unsupportedCacheRequest bool
	event.WriteSysEvent(ctx, op, fmt.Sprintf("updating %d targets for user %v", len(resp), u))
	_, err = r.rw.DoTx(ctx, db.StdRetryCnt, db.ExpBackoff{}, func(_ db.Reader, w db.Writer) error {
		switch {
		case oldRefreshToken == nil:
			if _, err := w.Exec(ctx, "delete from target where fk_user_id = @fk_user_id",
				[]any{sql.Named("fk_user_id", u.Id)}); err != nil {
				return err
			}
		case len(removedIds) > 0:
			if _, err := w.Exec(ctx, "delete from target where id in @ids",
				[]any{sql.Named("ids", removedIds)}); err != nil {
				return err
			}
		}
		switch {
		case newRefreshToken != "":
			if err := upsertTargets(ctx, w, u, resp); err != nil {
				return err
			}
			if err := upsertRefreshToken(ctx, w, u, resourceType, newRefreshToken); err != nil {
				return err
			}
		case len(resp) > 0:
			if err := upsertRefreshToken(ctx, w, u, resourceType, sentinelNoRefreshToken); err != nil {
				return err
			}
			unsupportedCacheRequest = true
		case len(resp) == 0:
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
		return errRefreshNotSupported
	}
	return nil
}

// checkCachingTargets fetches all targets for the provided user. If the
// response has at least one target and a refresh token, it makes the targets
// cachable and stores the refresh token. If there is no refresh token in the
// response it marks this user as unable to cache the data. If no data and no
// refresh token is stored it is unknown if the targets are cachable, the user
// is not marked as unknown.
func (r *Repository) checkCachingTargets(ctx context.Context, u *user, tokens map[AuthToken]string, opt ...Option) error {
	const op = "cache.(Repository).checkCachingTargets"
	switch {
	case util.IsNil(u):
		return errors.New(ctx, errors.InvalidParameter, op, "user is nil")
	case u.Id == "":
		return errors.New(ctx, errors.InvalidParameter, op, "user id is missing")
	}
	const resourceType = targetResourceType

	opts, err := getOpts(opt...)
	if err != nil {
		return errors.Wrap(ctx, err, op)
	}
	if opts.withTargetRetrievalFunc == nil {
		opts.withTargetRetrievalFunc = defaultTargetFunc
	}

	// Find and use a token for retrieving targets
	var gotResponse bool
	var resp []*targets.Target
	var newRefreshToken RefreshTokenValue
	var retErr error
	for at, t := range tokens {
		resp, _, newRefreshToken, err = opts.withTargetRetrievalFunc(ctx, u.Address, t, "")
		if err != nil {
			retErr = stderrors.Join(retErr, errors.Wrap(ctx, err, op, errors.WithMsg("for token %q", at.Id)))
			continue
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

	var unsupportedCacheRequest bool
	_, err = r.rw.DoTx(ctx, db.StdRetryCnt, db.ExpBackoff{}, func(reader db.Reader, w db.Writer) error {
		switch {
		case newRefreshToken != "":
			// Now that there is a refresh token, the data can be cached, so
			// cache it and store the refresh token for future refreshes.
			if _, err := w.Exec(ctx, "delete from target where fk_user_id = @fk_user_id",
				[]any{sql.Named("fk_user_id", u.Id)}); err != nil {
				return err
			}
			if err := upsertTargets(ctx, w, u, resp); err != nil {
				return err
			}
			if err := upsertRefreshToken(ctx, w, u, resourceType, newRefreshToken); err != nil {
				return err
			}
		case len(resp) > 0:
			// There is no refresh token but there is data, so we add the
			// sentinel refresh token which marks this user as unable to cache
			// this data.
			if err := upsertRefreshToken(ctx, w, u, resourceType, sentinelNoRefreshToken); err != nil {
				return err
			}
			unsupportedCacheRequest = true
		case len(resp) == 0:
			// removing all refresh tokens for this resource is equivalent to
			// saying we do not know if the data can be cached.
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
		return errRefreshNotSupported
	}
	return nil
}

// upsertTargets upserts the provided targets to be stored for the provided user.
func upsertTargets(ctx context.Context, w db.Writer, u *user, in []*targets.Target) error {
	const op = "cache.upsertTargets"
	switch {
	case util.IsNil(w):
		return errors.New(ctx, errors.InvalidParameter, op, "writer is nil")
	case !w.IsTx(ctx):
		return errors.New(ctx, errors.InvalidParameter, op, "writer isn't in a transaction")
	case util.IsNil(u):
		return errors.New(ctx, errors.InvalidParameter, op, "user is nil")
	}

	for _, t := range in {
		item, err := json.Marshal(t)
		if err != nil {
			return errors.Wrap(ctx, err, op)
		}
		newTarget := &Target{
			FkUserId:    u.Id,
			Id:          t.Id,
			Name:        t.Name,
			Description: t.Description,
			Address:     t.Address,
			ScopeId:     t.ScopeId,
			Type:        t.Type,
			Item:        string(item),
		}
		onConflict := db.OnConflict{
			Target: db.Columns{"fk_user_id", "id"},
			Action: db.SetColumns([]string{"name", "description", "address", "scope_id", "type", "item"}),
		}
		if err := w.Create(ctx, newTarget, db.WithOnConflict(&onConflict)); err != nil {
			return errors.Wrap(ctx, err, op)
		}
	}
	return nil
}

func (r *Repository) ListTargets(ctx context.Context, authTokenId string) ([]*targets.Target, error) {
	const op = "cache.(Repository).ListTargets"
	switch {
	case authTokenId == "":
		return nil, errors.New(ctx, errors.InvalidParameter, op, "auth token id is missing")
	}
	ret, err := r.searchTargets(ctx, "true", nil, withAuthTokenId(authTokenId))
	if err != nil {
		return nil, errors.Wrap(ctx, err, op)
	}
	return ret, nil
}

func (r *Repository) QueryTargets(ctx context.Context, authTokenId, query string) ([]*targets.Target, error) {
	const op = "cache.(Repository).QueryTargets"
	switch {
	case authTokenId == "":
		return nil, errors.New(ctx, errors.InvalidParameter, op, "auth token id is missing")
	case query == "":
		return nil, errors.New(ctx, errors.InvalidParameter, op, "query is missing")
	}

	w, err := mql.Parse(query, Target{}, mql.WithIgnoredFields("FkUserId", "Item"))
	if err != nil {
		return nil, errors.Wrap(ctx, err, op, errors.WithCode(errors.InvalidParameter))
	}
	ret, err := r.searchTargets(ctx, w.Condition, w.Args, withAuthTokenId(authTokenId))
	if err != nil {
		return nil, errors.Wrap(ctx, err, op)
	}
	return ret, nil
}

func (r *Repository) searchTargets(ctx context.Context, condition string, searchArgs []any, opt ...Option) ([]*targets.Target, error) {
	const op = "cache.(Repository).searchTargets"
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

	var cachedTargets []*Target
	if err := r.rw.SearchWhere(ctx, &cachedTargets, condition, searchArgs, db.WithLimit(-1)); err != nil {
		return nil, errors.Wrap(ctx, err, op)
	}

	retTargets := make([]*targets.Target, 0, len(cachedTargets))
	for _, cachedTar := range cachedTargets {
		var tar targets.Target
		if err := json.Unmarshal([]byte(cachedTar.Item), &tar); err != nil {
			return nil, errors.Wrap(ctx, err, op)
		}
		retTargets = append(retTargets, &tar)
	}
	return retTargets, nil
}

type Target struct {
	FkUserId    string `gorm:"primaryKey"`
	Id          string `gorm:"primaryKey"`
	Type        string `gorm:"default:null"`
	Name        string `gorm:"default:null"`
	Description string `gorm:"default:null"`
	Address     string `gorm:"default:null"`
	ScopeId     string `gorm:"default:null"`
	Item        string `gorm:"default:null"`
}

func (*Target) TableName() string {
	return "target"
}
