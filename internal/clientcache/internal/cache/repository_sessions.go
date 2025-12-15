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
	"github.com/hashicorp/boundary/api/sessions"
	"github.com/hashicorp/boundary/internal/db"
	"github.com/hashicorp/boundary/internal/errors"
	"github.com/hashicorp/boundary/internal/event"
	"github.com/hashicorp/boundary/internal/util"
	"github.com/hashicorp/mql"
)

// SessionRetrievalFunc is a function that retrieves sessions
// from the provided boundary addr using the provided token.
type SessionRetrievalFunc func(ctx context.Context, addr, authTok string, refreshTok RefreshTokenValue, inPage *sessions.SessionListResult, opt ...Option) (ret *sessions.SessionListResult, refreshToken RefreshTokenValue, err error)

func defaultSessionFunc(ctx context.Context, addr, authTok string, refreshTok RefreshTokenValue, inPage *sessions.SessionListResult, opt ...Option) (ret *sessions.SessionListResult, refreshToken RefreshTokenValue, err error) {
	const op = "cache.defaultSessionFunc"
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
	sClient := sessions.NewClient(client)
	var l *sessions.SessionListResult
	switch inPage {
	case nil:
		l, err = sClient.List(ctx, "global", sessions.WithIncludeTerminated(true), sessions.WithRecursive(true), sessions.WithListToken(string(refreshTok)), sessions.WithClientDirectedPagination(!opts.withUseNonPagedListing))
	default:
		l, err = sClient.ListNextPage(ctx, inPage, sessions.WithListToken(string(refreshTok)))
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

// refreshSessions uses attempts to refresh the sessions for the provided user
// using the provided tokens. If available, it uses the refresh tokens in
// storage to retrieve and apply only the delta.
func (r *Repository) refreshSessions(ctx context.Context, u *user, tokens map[AuthToken]string, opt ...Option) error {
	const op = "cache.(Repository).refreshSessions"
	switch {
	case util.IsNil(u):
		return errors.New(ctx, errors.InvalidParameter, op, "user is nil")
	case u.Id == "":
		return errors.New(ctx, errors.InvalidParameter, op, "user id is missing")
	}
	const resourceType = sessionResourceType

	opts, err := getOpts(opt...)
	if err != nil {
		return errors.Wrap(ctx, err, op)
	}
	if opts.withSessionRetrievalFunc == nil {
		opts.withSessionRetrievalFunc = defaultSessionFunc
	}
	var oldRefreshTokenVal RefreshTokenValue
	oldRefreshToken, err := r.lookupRefreshToken(ctx, u, resourceType)
	if err != nil {
		return errors.Wrap(ctx, err, op)
	}
	if oldRefreshToken != nil {
		oldRefreshTokenVal = oldRefreshToken.RefreshToken
	}

	// Find and use a token for retrieving sessions
	var gotResponse bool
	var currentPage *sessions.SessionListResult
	var newRefreshToken RefreshTokenValue
	var foundAuthToken string
	var unsupportedCacheRequest bool
	var retErr error
	for at, t := range tokens {
		currentPage, newRefreshToken, err = opts.withSessionRetrievalFunc(ctx, u.Address, t, oldRefreshTokenVal, currentPage)
		if api.ErrInvalidListToken.Is(err) {
			event.WriteSysEvent(ctx, op, "old list token is no longer valid, starting new initial fetch", "user_id", u.Id)
			if err := r.deleteRefreshToken(ctx, u, resourceType); err != nil {
				return errors.Wrap(ctx, err, op)
			}
			// try again without the refresh token
			oldRefreshToken = nil
			currentPage, newRefreshToken, err = opts.withSessionRetrievalFunc(ctx, u.Address, t, "", currentPage)
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
				if numDeleted, err = w.Exec(ctx, "delete from session where fk_user_id = @fk_user_id",
					[]any{sql.Named("fk_user_id", u.Id)}); err != nil {
					return err
				}
			}
			switch {
			case unsupportedCacheRequest:
				if err := upsertRefreshToken(ctx, w, u, resourceType, sentinelNoRefreshToken); err != nil {
					return err
				}
			case newRefreshToken != "":
				numUpserted += len(currentPage.Items)
				if err := upsertSessions(ctx, w, u, currentPage.Items); err != nil {
					return err
				}
				if err := upsertRefreshToken(ctx, w, u, resourceType, newRefreshToken); err != nil {
					return err
				}
			default:
				// controller supports caching, but doesn't have any resources
			}
			if !unsupportedCacheRequest && len(currentPage.RemovedIds) > 0 {
				if numDeleted, err = w.Exec(ctx, "delete from session where id in @ids",
					[]any{sql.Named("ids", currentPage.RemovedIds)}); err != nil {
					return err
				}
			}
			return nil
		})
		if unsupportedCacheRequest || currentPage.ResponseType == "" || currentPage.ResponseType == "complete" {
			break
		}
		currentPage, newRefreshToken, err = opts.withSessionRetrievalFunc(ctx, u.Address, foundAuthToken, newRefreshToken, currentPage)
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
	event.WriteSysEvent(ctx, op, "sessions updated", "deleted", numDeleted, "upserted", numUpserted, "user id", u.Id)
	return nil
}

// checkCachingSessions fetches all sessions for the provided user and sets the
// cache to match the values returned.  If the response includes a refresh
// token it will save that as well.
func (r *Repository) checkCachingSessions(ctx context.Context, u *user, tokens map[AuthToken]string, opt ...Option) error {
	const op = "cache.(Repository).checkSessionsForSearchability"
	switch {
	case util.IsNil(u):
		return errors.New(ctx, errors.InvalidParameter, op, "user is nil")
	case u.Id == "":
		return errors.New(ctx, errors.InvalidParameter, op, "user id is missing")
	case u.Address == "":
		return errors.New(ctx, errors.InvalidParameter, op, "user boundary address is missing")
	}
	const resourceType = sessionResourceType

	opts, err := getOpts(opt...)
	if err != nil {
		return errors.Wrap(ctx, err, op)
	}
	if opts.withSessionRetrievalFunc == nil {
		opts.withSessionRetrievalFunc = defaultSessionFunc
	}

	// Find and use a token for retrieving sessions
	var gotResponse bool
	var resp *sessions.SessionListResult
	var newRefreshToken RefreshTokenValue
	var unsupportedCacheRequest bool
	var retErr error
	for at, t := range tokens {
		resp, newRefreshToken, err = opts.withSessionRetrievalFunc(ctx, u.Address, t, "", nil, WithUseNonPagedListing(true))
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
			if numDeleted, err = w.Exec(ctx, "delete from session where fk_user_id = @fk_user_id",
				[]any{sql.Named("fk_user_id", u.Id)}); err != nil {
				return err
			}
			if err := upsertSessions(ctx, w, u, resp.Items); err != nil {
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
	event.WriteSysEvent(ctx, op, "sessions updated", "deleted", numDeleted, "upserted", len(resp.Items), "user_id", u.Id)
	return nil
}

// upsertSessions upserts the provided sessions to be stored for the provided user.
func upsertSessions(ctx context.Context, w db.Writer, u *user, in []*sessions.Session) error {
	const op = "cache.upsertSessions"
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
		newSession := &Session{
			FkUserId: u.Id,
			Id:       s.Id,
			Type:     s.Type,
			Status:   s.Status,
			Endpoint: s.Endpoint,
			ScopeId:  s.ScopeId,
			TargetId: s.TargetId,
			UserId:   s.UserId,
			Item:     string(item),
		}
		onConflict := db.OnConflict{
			Target: db.Columns{"fk_user_id", "id"},
			Action: db.SetColumns([]string{"type", "status", "endpoint", "scope_id", "target_id", "user_id", "item"}),
		}
		if err := w.Create(ctx, newSession, db.WithOnConflict(&onConflict)); err != nil {
			return errors.Wrap(ctx, err, op)
		}
	}
	return nil
}

func (r *Repository) ListSessions(ctx context.Context, authTokenId string, opt ...Option) (*SearchResult, error) {
	const op = "cache.(Repository).ListSessions"
	switch {
	case authTokenId == "":
		return nil, errors.New(ctx, errors.InvalidParameter, op, "auth token id is missing")
	}
	ret, err := r.searchSessions(ctx, "true", nil, append(opt, withAuthTokenId(authTokenId))...)
	if err != nil {
		return nil, errors.Wrap(ctx, err, op)
	}
	return ret, nil
}

func (r *Repository) QuerySessions(ctx context.Context, authTokenId, query string, opt ...Option) (*SearchResult, error) {
	const op = "cache.(Repository).QuerySessions"
	switch {
	case authTokenId == "":
		return nil, errors.New(ctx, errors.InvalidParameter, op, "auth token id is missing")
	case query == "":
		return nil, errors.New(ctx, errors.InvalidParameter, op, "query is missing")
	}

	w, err := mql.Parse(query, Session{}, mql.WithIgnoredFields("FkUserId", "Item"))
	if err != nil {
		return nil, errors.Wrap(ctx, err, op, errors.WithCode(errors.InvalidParameter))
	}
	ret, err := r.searchSessions(ctx, w.Condition, w.Args, append(opt, withAuthTokenId(authTokenId))...)
	if err != nil {
		return nil, errors.Wrap(ctx, err, op)
	}
	return ret, nil
}

func (r *Repository) searchSessions(ctx context.Context, condition string, searchArgs []any, opt ...Option) (*SearchResult, error) {
	const op = "cache.(Repository).searchSessions"
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

	var cachedSessions []*Session
	if err := r.rw.SearchWhere(ctx, &cachedSessions, condition, searchArgs, db.WithLimit(opts.withMaxResultSetSize+1)); err != nil {
		return nil, errors.Wrap(ctx, err, op)
	}

	retSessions := make([]*sessions.Session, 0, len(cachedSessions))
	for _, cachedSess := range cachedSessions {
		var sess sessions.Session
		if err := json.Unmarshal([]byte(cachedSess.Item), &sess); err != nil {
			return nil, errors.Wrap(ctx, err, op)
		}
		retSessions = append(retSessions, &sess)
	}

	sr := &SearchResult{
		Sessions: retSessions,
	}
	if opts.withMaxResultSetSize > 0 && len(sr.Sessions) > opts.withMaxResultSetSize {
		sr.Sessions = sr.Sessions[:opts.withMaxResultSetSize]
		sr.Incomplete = true
	}
	return sr, nil
}

type Session struct {
	FkUserId string `gorm:"primaryKey"`
	Id       string `gorm:"primaryKey"`
	Type     string `gorm:"default:null"`
	Endpoint string `gorm:"default:null"`
	Status   string `gorm:"default:null"`
	ScopeId  string `gorm:"default:null"`
	TargetId string `gorm:"default:null"`
	UserId   string `gorm:"default:null"`
	Item     string `gorm:"default:null"`
}

func (*Session) TableName() string {
	return "session"
}
