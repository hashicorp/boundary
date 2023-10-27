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
	l, err := tarClient.List(ctx, "global", targets.WithRecursive(true), targets.WithRefreshToken(string(refreshTok)))
	if err != nil {
		if api.ErrInvalidRefreshToken.Is(err) {
			return nil, nil, "", err
		}
		return nil, nil, "", errors.Wrap(ctx, err, op)
	}
	return l.Items, l.RemovedIds, RefreshTokenValue(l.RefreshToken), nil
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
	oldRefreshToken, err := r.lookupRefreshToken(ctx, u, resourceType)
	if err != nil {
		return errors.Wrap(ctx, err, op)
	}

	// Find and use a token for retrieving targets
	var gotResponse bool
	var resp []*targets.Target
	var removedIds []string
	var newRefreshToken RefreshTokenValue
	var retErr error
	for at, t := range tokens {
		resp, removedIds, newRefreshToken, err = opts.withTargetRetrievalFunc(ctx, u.Address, t, oldRefreshToken)
		if api.ErrInvalidRefreshToken.Is(err) {
			if err := r.deleteRefreshToken(ctx, u, resourceType); err != nil {
				return errors.Wrap(ctx, err, op)
			}
			// try again without the refresh token
			oldRefreshToken = ""
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
		if saveErr := r.SaveError(ctx, u, resourceType, retErr); saveErr != nil {
			return stderrors.Join(err, errors.Wrap(ctx, saveErr, op))
		}
	}
	if !gotResponse {
		return retErr
	}

	event.WriteSysEvent(ctx, op, fmt.Sprintf("updating %d targets for user %v", len(resp), u))
	_, err = r.rw.DoTx(ctx, db.StdRetryCnt, db.ExpBackoff{}, func(r db.Reader, w db.Writer) error {
		switch {
		case oldRefreshToken == "":
			if _, err := w.Exec(ctx, "delete from target where user_id = @user_id",
				[]any{sql.Named("user_id", u.Id)}); err != nil {
				return err
			}
		case len(removedIds) > 0:
			if _, err := w.Exec(ctx, "delete from target where id in @ids",
				[]any{sql.Named("ids", removedIds)}); err != nil {
				return err
			}
		}

		if err := upsertTargets(ctx, w, u, resp); err != nil {
			return err
		}
		if newRefreshToken != "" || oldRefreshToken != "" {
			if err := upsertRefreshToken(ctx, w, u, resourceType, newRefreshToken); err != nil {
				return err
			}
		}
		return nil
	})
	if err != nil {
		return errors.Wrap(ctx, err, op)
	}
	return nil
}

// fullFetchTargets fetches all targets for the provided user and sets the
// cache to match the values returned.  If the response includes a refresh
// token it will save that as well.
func (r *Repository) fullFetchTargets(ctx context.Context, u *user, tokens map[AuthToken]string, opt ...Option) error {
	const op = "cache.(Repository).fullFetchTargets"
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
		if saveErr := r.SaveError(ctx, u, resourceType, retErr); saveErr != nil {
			return stderrors.Join(err, errors.Wrap(ctx, saveErr, op))
		}
	}
	if !gotResponse {
		return retErr
	}

	event.WriteSysEvent(ctx, op, fmt.Sprintf("updating %d targets for user %v", len(resp), u))
	_, err = r.rw.DoTx(ctx, db.StdRetryCnt, db.ExpBackoff{}, func(r db.Reader, w db.Writer) error {
		if _, err := w.Exec(ctx, "delete from target where user_id = @user_id",
			[]any{sql.Named("user_id", u.Id)}); err != nil {
			return err
		}

		if err := upsertTargets(ctx, w, u, resp); err != nil {
			return err
		}
		if newRefreshToken != "" {
			if err := upsertRefreshToken(ctx, w, u, resourceType, newRefreshToken); err != nil {
				return err
			}
		}
		return nil
	})
	if err != nil {
		return errors.Wrap(ctx, err, op)
	}
	return nil
}

// upsertTargets upserts the provided targets to be stored for the provided user.
func upsertTargets(ctx context.Context, w db.Writer, u *user, in []*targets.Target) error {
	const op = "cache.upserTargets"
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
			UserId:      u.Id,
			Id:          t.Id,
			Name:        t.Name,
			Description: t.Description,
			Address:     t.Address,
			Item:        string(item),
		}
		onConflict := db.OnConflict{
			Target: db.Columns{"user_id", "id"},
			Action: db.UpdateAll(true),
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

	w, err := mql.Parse(query, Target{}, mql.WithIgnoredFields("UserId", "Item"))
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
		condition = fmt.Sprintf("%s and user_id in (select user_id from auth_token where id = ?)", condition)
		searchArgs = append(searchArgs, opts.withAuthTokenId)
	case opts.withUserId != "":
		condition = fmt.Sprintf("%s and user_id = ?", condition)
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
	UserId      string `gorm:"primaryKey"`
	Id          string `gorm:"primaryKey"`
	Name        string `gorm:"default:null"`
	Description string `gorm:"default:null"`
	Address     string `gorm:"default:null"`
	Item        string `gorm:"default:null"`
}

func (*Target) TableName() string {
	return "target"
}
