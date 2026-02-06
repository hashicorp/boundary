// Copyright IBM Corp. 2020, 2025
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
type TargetRetrievalFunc func(ctx context.Context, addr, authTok string, refreshTok RefreshTokenValue, inPage *targets.TargetListResult, opt ...Option) (ret *targets.TargetListResult, refreshToken RefreshTokenValue, err error)

func defaultTargetFunc(ctx context.Context, addr, authTok string, refreshTok RefreshTokenValue, inPage *targets.TargetListResult, opt ...Option) (*targets.TargetListResult, RefreshTokenValue, error) {
	const op = "cache.defaultTargetFunc"
	conf, err := api.DefaultConfig()
	if err != nil {
		return nil, "", errors.Wrap(ctx, err, op)
	}
	opts, err := getOpts(opt...)
	if err != nil {
		return nil, "", errors.Wrap(ctx, err, op)
	}
	conf.Addr = addr
	conf.Token = authTok
	client, err := api.NewClient(conf)
	if err != nil {
		return nil, "", errors.Wrap(ctx, err, op)
	}
	tarClient := targets.NewClient(client)
	var l *targets.TargetListResult
	switch inPage {
	case nil:
		l, err = tarClient.List(ctx, "global", targets.WithRecursive(true), targets.WithListToken(string(refreshTok)), targets.WithClientDirectedPagination(!opts.withUseNonPagedListing))
	default:
		l, err = tarClient.ListNextPage(ctx, inPage, targets.WithListToken(string(refreshTok)))
	}
	if err != nil {
		if api.ErrInvalidListToken.Is(err) {
			return nil, "", err
		}
		return nil, "", errors.Wrap(ctx, err, op)
	}
	if l.ResponseType == "" {
		return nil, "", ErrRefreshNotSupported
	}
	return l, RefreshTokenValue(l.ListToken), nil
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
	var currentPage *targets.TargetListResult
	var newRefreshToken RefreshTokenValue
	var foundAuthToken string
	var unsupportedCacheRequest bool
	var retErr error
	for at, t := range tokens {
		currentPage, newRefreshToken, err = opts.withTargetRetrievalFunc(ctx, u.Address, t, oldRefreshTokenVal, currentPage)
		if api.ErrInvalidListToken.Is(err) {
			event.WriteSysEvent(ctx, op, "old list token is no longer valid, starting new initial fetch", "user_id", u.Id)
			if err := r.deleteRefreshToken(ctx, u, resourceType); err != nil {
				return errors.Wrap(ctx, err, op)
			}
			// try again without the refresh token
			oldRefreshToken = nil
			currentPage, newRefreshToken, err = opts.withTargetRetrievalFunc(ctx, u.Address, t, "", currentPage)
		}
		if err != nil {
			if err == ErrRefreshNotSupported {
				unsupportedCacheRequest = true
			} else {
				retErr = stderrors.Join(retErr, errors.Wrap(ctx, err, op, errors.WithMsg("for token %q", at.Id)))
				continue
			}
		}
		foundAuthToken = t
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
	var numUpserted int
	var clearPerformed bool
	for {
		_, err = r.rw.DoTx(ctx, db.StdRetryCnt, db.ExpBackoff{}, func(_ db.Reader, w db.Writer) error {
			var err error
			if (oldRefreshToken == nil || unsupportedCacheRequest) && !clearPerformed {
				if numDeleted, err = w.Exec(ctx, "delete from target where fk_user_id = @fk_user_id",
					[]any{sql.Named("fk_user_id", u.Id)}); err != nil {
					return err
				}
				clearPerformed = true
			}
			switch {
			case unsupportedCacheRequest:
				if err := upsertRefreshToken(ctx, w, u, resourceType, sentinelNoRefreshToken); err != nil {
					return err
				}
			case newRefreshToken != "":
				if err := upsertTargets(ctx, w, u, currentPage.Items); err != nil {
					return err
				}
				numUpserted += len(currentPage.Items)
				if err := upsertRefreshToken(ctx, w, u, resourceType, newRefreshToken); err != nil {
					return err
				}
			default:
				// controller supports caching, but doesn't have any resources
			}
			if !unsupportedCacheRequest && len(currentPage.RemovedIds) > 0 {
				if numDeleted, err = w.Exec(ctx, "delete from target where id in @ids",
					[]any{sql.Named("ids", currentPage.RemovedIds)}); err != nil {
					return err
				}
			}
			return nil
		})
		if unsupportedCacheRequest || currentPage.ResponseType == "" || currentPage.ResponseType == "complete" {
			break
		}
		currentPage, newRefreshToken, err = opts.withTargetRetrievalFunc(ctx, u.Address, foundAuthToken, newRefreshToken, currentPage)
		if err != nil {
			break
		}
	}
	if err != nil {
		return errors.Wrap(ctx, err, op)
	}
	if unsupportedCacheRequest {
		return ErrRefreshNotSupported
	}
	event.WriteSysEvent(ctx, op, "targets updated", "deleted", numDeleted, "upserted", numUpserted, "user_id", u.Id)
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
	var resp *targets.TargetListResult
	var newRefreshToken RefreshTokenValue
	var unsupportedCacheRequest bool
	var retErr error
	for at, t := range tokens {
		resp, newRefreshToken, err = opts.withTargetRetrievalFunc(ctx, u.Address, t, "", nil, WithUseNonPagedListing(true))
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
			// Since we know the controller doesn't support caching, we mark the
			// user as unable to cache the data.
			if err := upsertRefreshToken(ctx, w, u, resourceType, sentinelNoRefreshToken); err != nil {
				return err
			}
		case newRefreshToken != "":
			// Now that there is a refresh token, the data can be cached, so
			// cache it and store the refresh token for future refreshes. First
			// remove any values, then add the new ones
			var err error
			if numDeleted, err = w.Exec(ctx, "delete from target where fk_user_id = @fk_user_id",
				[]any{sql.Named("fk_user_id", u.Id)}); err != nil {
				return err
			}
			if err := upsertTargets(ctx, w, u, resp.Items); err != nil {
				return err
			}
			if err := upsertRefreshToken(ctx, w, u, resourceType, newRefreshToken); err != nil {
				return err
			}
		default:
			// We know the controller supports caching, but doesn't have a
			// refresh token so clear out any refresh token we have for this resource.
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
	event.WriteSysEvent(ctx, op, "targets updated", "deleted", numDeleted, "upserted", len(resp.Items), "user_id", u.Id)
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

func (r *Repository) ListTargets(ctx context.Context, authTokenId string, opt ...Option) (*SearchResult, error) {
	const op = "cache.(Repository).ListTargets"
	switch {
	case authTokenId == "":
		return nil, errors.New(ctx, errors.InvalidParameter, op, "auth token id is missing")
	}
	ret, err := r.searchTargets(ctx, "true", nil, append(opt, withAuthTokenId(authTokenId))...)
	if err != nil {
		return nil, errors.Wrap(ctx, err, op)
	}
	return ret, nil
}

func (r *Repository) QueryTargets(ctx context.Context, authTokenId, query string, opt ...Option) (*SearchResult, error) {
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
	ret, err := r.searchTargets(ctx, w.Condition, w.Args, append(opt, withAuthTokenId(authTokenId))...)
	if err != nil {
		return nil, errors.Wrap(ctx, err, op)
	}
	return ret, nil
}

func (r *Repository) searchTargets(ctx context.Context, condition string, searchArgs []any, opt ...Option) (*SearchResult, error) {
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

	dbOpts := []db.Option{db.WithLimit(opts.withMaxResultSetSize + 1)}
	if opts.withSortBy != "" {
		sd := opts.withSortDirection
		if sd != Ascending && sd != Descending {
			sd = Ascending
		}
		orderClause := fmt.Sprintf("%s %s", opts.withSortBy, sd)
		dbOpts = append(dbOpts, db.WithOrder(orderClause))
	}

	var cachedTargets []*Target
	if err := r.rw.SearchWhere(ctx, &cachedTargets, condition, searchArgs, dbOpts...); err != nil {
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

	sr := &SearchResult{
		Targets: retTargets,
	}
	if opts.withMaxResultSetSize > 0 && len(sr.Targets) > opts.withMaxResultSetSize {
		sr.Targets = sr.Targets[:opts.withMaxResultSetSize]
		sr.Incomplete = true
	}
	return sr, nil
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
