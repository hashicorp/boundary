// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: BUSL-1.1

package cache

import (
	"context"
	"database/sql"
	"encoding/json"
	stderrors "errors"
	"fmt"
	"time"

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

// refreshTargetsDuringRefreshWindow refreshes the targets for the provided user
// using the provided auth tokens. This function is intended to be used during
// the refresh window for the user's current target refresh token. It will store
// the targets in the target_refresh_window table and then swap the resources in
// the target_refresh_window for the user's resources in the target table.
//
// IMPORTANT: the caller is responsible for ensuring that there's no inflight
// refresh into the target_refresh_window. See
// cache.RefreshService.syncSemaphore for how to ensure there's no inflight
// refresh into the target_refresh_window table
//
// if the existing refresh token is not within the refresh window, this function
// will return without doing anything.
//
// if controller list target doesn't support refresh token, we will not refresh
// and we will NOT return an error
func (r *Repository) refreshTargetsDuringRefreshWindow(ctx context.Context, u *user, tokens map[AuthToken]string, opt ...Option) error {
	const (
		refreshWindowLookBackInDays = -10
		op                          = "cache.(Repository).refreshTargetsIntoTmpTable"
		emptyRefreshToken           = ""
		deleteRemovedTargets        = "delete from %s where id in @ids"
	)
	switch {
	case util.IsNil(u):
		return errors.New(ctx, errors.InvalidParameter, op, "user is nil")
	case u.Id == "":
		return errors.New(ctx, errors.InvalidParameter, op, "user id is missing")
	}

	existingRefreshToken, err := r.lookupRefreshToken(ctx, u, targetResourceType)
	if err != nil {
		return errors.Wrap(ctx, err, op)
	}
	// check if existing refresh token will expire within the refresh window
	// look back (next 10 days) and if not then just return
	if existingRefreshToken != nil {
		fmt.Println("*********************")
		fmt.Println("existing...: ", existingRefreshToken.CreateTime)
		fmt.Println("10 days ago: ", time.Now().AddDate(0, 0, refreshWindowLookBackInDays))
		fmt.Println("expr.......: ", existingRefreshToken.CreateTime.After(time.Now().AddDate(0, 0, refreshWindowLookBackInDays)))
	}
	if existingRefreshToken != nil && !existingRefreshToken.CreateTime.After(time.Now().AddDate(0, 0, refreshWindowLookBackInDays)) {
		return nil
	}

	opts, err := getOpts(opt...)
	if err != nil {
		return errors.Wrap(ctx, err, op)
	}
	if opts.withTargetRetrievalFunc == nil {
		opts.withTargetRetrievalFunc = defaultTargetFunc
	}

	var gotResponse bool
	var currentPage *targets.TargetListResult
	var newRefreshToken RefreshTokenValue
	var foundAuthToken string
	var retErr error
	for at, t := range tokens {
		// we want to start from the beginning of the list using an empty refresh token
		currentPage, newRefreshToken, err = opts.withTargetRetrievalFunc(ctx, u.Address, t, emptyRefreshToken, currentPage)
		if err != nil {
			if err == ErrRefreshNotSupported {
				return nil // this particular controller doesn't support refresh tokens and it's not an error, so just return
			} else {
				retErr = stderrors.Join(retErr, errors.Wrap(ctx, err, op, errors.WithMsg("for token %q", at.Id)))
				continue
			}
		}
		foundAuthToken = t
		gotResponse = true
		break
	}
	// if we got an error, then we need to save it so it can be retrieved later
	// via the status API by users
	if retErr != nil {
		if saveErr := r.saveError(r.serverCtx, u, targetResourceType, retErr); saveErr != nil {
			return stderrors.Join(err, errors.Wrap(ctx, saveErr, op))
		}
	}
	if !gotResponse {
		return retErr
	}

	tmpTblName, err := tempTableName(ctx, &Target{})
	if err != nil {
		return errors.Wrap(ctx, err, op)
	}

	clearTmpTableFn := func(w db.Writer) error {
		if _, err := w.Exec(ctx, fmt.Sprintf("delete from %s where fk_user_id = @fk_user_id", tmpTblName),
			[]any{sql.Named("fk_user_id", u.Id)}); err != nil {
			return err
		}
		return nil
	}

	// first, clear out the temporary table
	if _, err := r.rw.DoTx(ctx, db.StdRetryCnt, db.ExpBackoff{}, func(reader db.Reader, w db.Writer) error {
		return clearTmpTableFn(w)
	}); err != nil {
		return errors.Wrap(ctx, err, op)
	}

	// okay we have the data, let's store it in a temporary table
	var numDeleted int
	var numUpserted int
	for {
		if _, err := r.rw.DoTx(ctx, db.StdRetryCnt, db.ExpBackoff{}, func(reader db.Reader, w db.Writer) error {
			switch {
			case newRefreshToken != "":
				if err := upsertTargets(ctx, w, u, currentPage.Items, WithTable(tmpTblName)); err != nil {
					return err
				}
				numUpserted += len(currentPage.Items)
				// we need to store the refresh token for the next page of
				// targets, it's okay to do this since we are the only inflight
				// refresh.  Note the caller must ensure there's no inflight
				// refresh! See the comment at the top of this function.
				if err := upsertRefreshToken(ctx, w, u, targetResourceType, newRefreshToken); err != nil {
					return err
				}
			default:
				// controller supports caching, but doesn't have any resources
			}
			if len(currentPage.RemovedIds) > 0 {
				if numDeleted, err = w.Exec(ctx, fmt.Sprintf(deleteRemovedTargets, tmpTblName),
					[]any{sql.Named("ids", currentPage.RemovedIds)}); err != nil {
					return err
				}
			}
			return nil // we're done with this DoTx(...) containing a "page" of targets
		}); err != nil {
			return errors.Wrap(ctx, err, op)
		}
		if currentPage.ResponseType == "" || currentPage.ResponseType == "complete" {
			break
		}
		currentPage, newRefreshToken, err = opts.withTargetRetrievalFunc(ctx, u.Address, foundAuthToken, newRefreshToken, currentPage)
		if err != nil {
			break
		}
	}

	// now that we have the data in the temporary table, let's swap it with the
	// user's target table
	_, err = r.rw.DoTx(ctx, db.StdRetryCnt, db.ExpBackoff{}, func(reader db.Reader, w db.Writer) error {
		// first, delete the existing targets which were cached for the user
		if _, err := w.Exec(ctx, "delete from target where fk_user_id = @fk_user_id",
			[]any{sql.Named("fk_user_id", u.Id)}); err != nil {
			return err
		}
		// now, insert the targets from the temporary table into the user's
		// target table
		var numMoved int
		if numMoved, err = w.Exec(ctx, fmt.Sprintf("insert into target select * from %s where fk_user_id = @fk_user_id", tmpTblName),
			[]any{sql.Named("fk_user_id", u.Id)}); err != nil {
			return err
		}
		if numMoved != numUpserted {
			return errors.New(ctx, errors.Internal, op, fmt.Sprintf("number of targets moved %d doesn't match number of targets upserted %d", numMoved, numUpserted))
		}
		// finally, delete the rows from the temporary table
		return clearTmpTableFn(w)
	})
	if err != nil {
		return errors.Wrap(ctx, err, op)
	}

	event.WriteSysEvent(ctx, op, "targets updated", "deleted", numDeleted, "upserted", numUpserted, "user_id", u.Id)
	return nil
}

// upsertTargets upserts the provided targets to be stored for the provided user.
func upsertTargets(ctx context.Context, w db.Writer, u *user, in []*targets.Target, opt ...Option) error {
	const op = "cache.upsertTargets"
	switch {
	case util.IsNil(w):
		return errors.New(ctx, errors.InvalidParameter, op, "writer is nil")
	case !w.IsTx(ctx):
		return errors.New(ctx, errors.InvalidParameter, op, "writer isn't in a transaction")
	case util.IsNil(u):
		return errors.New(ctx, errors.InvalidParameter, op, "user is nil")
	}

	opts, err := getOpts(opt...)
	if err != nil {
		return errors.Wrap(ctx, err, op)
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
		dbOpts := []db.Option{db.WithOnConflict(&onConflict)}
		if opts.withTable != "" {
			dbOpts = append(dbOpts, db.WithTable(opts.withTable))
		}
		if err := w.Create(ctx, newTarget, dbOpts...); err != nil {
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

	var cachedTargets []*Target
	if err := r.rw.SearchWhere(ctx, &cachedTargets, condition, searchArgs, db.WithLimit(opts.withMaxResultSetSize+1)); err != nil {
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
