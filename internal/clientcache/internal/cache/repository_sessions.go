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
	"github.com/hashicorp/boundary/api/sessions"
	"github.com/hashicorp/boundary/internal/db"
	"github.com/hashicorp/boundary/internal/errors"
	"github.com/hashicorp/boundary/internal/event"
	"github.com/hashicorp/boundary/internal/util"
	"github.com/hashicorp/mql"
)

// SessionRetrievalFunc is a function that retrieves sessions
// from the provided boundary addr using the provided token.
type SessionRetrievalFunc func(ctx context.Context, addr, authTok string, refreshTok RefreshTokenValue) (ret []*sessions.Session, removedIds []string, refreshToken RefreshTokenValue, err error)

func defaultSessionFunc(ctx context.Context, addr, authTok string, refreshTok RefreshTokenValue) ([]*sessions.Session, []string, RefreshTokenValue, error) {
	const op = "cache.defaultSessionFunc"
	client, err := api.NewClient(&api.Config{
		Addr:  addr,
		Token: authTok,
	})
	if err != nil {
		return nil, nil, "", errors.Wrap(ctx, err, op)
	}
	sClient := sessions.NewClient(client)
	l, err := sClient.List(ctx, "global", sessions.WithIncludeTerminated(true), sessions.WithRecursive(true), sessions.WithRefreshToken(string(refreshTok)))
	if err != nil {
		if api.ErrInvalidRefreshToken.Is(err) {
			return nil, nil, "", err
		}
		return nil, nil, "", errors.Wrap(ctx, err, op)
	}
	return l.Items, l.RemovedIds, RefreshTokenValue(l.RefreshToken), nil
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
	oldRefreshToken, err := r.lookupRefreshToken(ctx, u, resourceType)
	if err != nil {
		return errors.Wrap(ctx, err, op)
	}

	// Find and use a token for retrieving sessions
	var gotResponse bool
	var resp []*sessions.Session
	var newRefreshToken RefreshTokenValue
	var removedIds []string
	var retErr error
	for at, t := range tokens {
		resp, removedIds, newRefreshToken, err = opts.withSessionRetrievalFunc(ctx, u.Address, t, oldRefreshToken)
		if api.ErrInvalidRefreshToken.Is(err) {
			if err := r.deleteRefreshToken(ctx, u, resourceType); err != nil {
				return errors.Wrap(ctx, err, op)
			}
			// try again without the refresh token
			oldRefreshToken = ""
			resp, removedIds, newRefreshToken, err = opts.withSessionRetrievalFunc(ctx, u.Address, t, "")
		}
		if err != nil {
			retErr = stderrors.Join(retErr, errors.Wrap(ctx, err, op, errors.WithMsg("for token %q", at.Id)))
			continue
		}
		gotResponse = true
		break
	}

	if retErr != nil {
		if saveErr := r.saveError(ctx, u, resourceType, retErr); saveErr != nil {
			return stderrors.Join(err, errors.Wrap(ctx, saveErr, op))
		}
	}
	if !gotResponse {
		return retErr
	}

	event.WriteSysEvent(ctx, op, fmt.Sprintf("updating %d sessions for user %v", len(resp), u))
	_, err = r.rw.DoTx(ctx, db.StdRetryCnt, db.ExpBackoff{}, func(_ db.Reader, w db.Writer) error {
		switch {
		case oldRefreshToken == "":
			if _, err := w.Exec(ctx, "delete from session where user_id = @user_id",
				[]any{sql.Named("user_id", u.Id)}); err != nil {
				return err
			}
		case len(removedIds) > 0:
			if _, err := w.Exec(ctx, "delete from session where id in @ids",
				[]any{sql.Named("ids", removedIds)}); err != nil {
				return err
			}
		}

		if err := upsertSessions(ctx, w, u, resp); err != nil {
			return err
		}
		if err := upsertRefreshToken(ctx, w, u, resourceType, newRefreshToken); err != nil {
			return err
		}
		return nil
	})
	if err != nil {
		return errors.Wrap(ctx, err, op)
	}
	return nil
}

// fullFetchSessions fetches all sessions for the provided user and sets the
// cache to match the values returned.  If the response includes a refresh
// token it will save that as well.
func (r *Repository) fullFetchSessions(ctx context.Context, u *user, tokens map[AuthToken]string, opt ...Option) error {
	const op = "cache.(Repository).fullFetchSessions"
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
	var resp []*sessions.Session
	var newRefreshToken RefreshTokenValue
	var retErr error
	for at, t := range tokens {
		resp, _, newRefreshToken, err = opts.withSessionRetrievalFunc(ctx, u.Address, t, "")
		if err != nil {
			retErr = stderrors.Join(retErr, errors.Wrap(ctx, err, op, errors.WithMsg("for token %q", at.Id)))
			continue
		}
		gotResponse = true
		break
	}

	if retErr != nil {
		if saveErr := r.saveError(ctx, u, resourceType, retErr); saveErr != nil {
			return stderrors.Join(err, errors.Wrap(ctx, saveErr, op))
		}
	}
	if !gotResponse {
		return retErr
	}

	event.WriteSysEvent(ctx, op, fmt.Sprintf("updating %d sessions for user %v", len(resp), u))
	_, err = r.rw.DoTx(ctx, db.StdRetryCnt, db.ExpBackoff{}, func(_ db.Reader, w db.Writer) error {
		if _, err := w.Exec(ctx, "delete from session where user_id = @user_id",
			[]any{sql.Named("user_id", u.Id)}); err != nil {
			return err
		}

		if err := upsertSessions(ctx, w, u, resp); err != nil {
			return err
		}
		if err := upsertRefreshToken(ctx, w, u, resourceType, newRefreshToken); err != nil {
			return err
		}
		return nil
	})
	if err != nil {
		return errors.Wrap(ctx, err, op)
	}
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
			UserId:   u.Id,
			Id:       s.Id,
			Type:     s.Type,
			Status:   s.Status,
			Endpoint: s.Endpoint,
			ScopeId:  s.ScopeId,
			TargetId: s.TargetId,
			Item:     string(item),
		}
		onConflict := db.OnConflict{
			Target: db.Columns{"user_id", "id"},
			Action: db.UpdateAll(true),
		}
		if err := w.Create(ctx, newSession, db.WithOnConflict(&onConflict)); err != nil {
			return errors.Wrap(ctx, err, op)
		}
	}
	return nil
}

func (r *Repository) ListSessions(ctx context.Context, authTokenId string) ([]*sessions.Session, error) {
	const op = "cache.(Repository).ListSessions"
	switch {
	case authTokenId == "":
		return nil, errors.New(ctx, errors.InvalidParameter, op, "auth token id is missing")
	}
	ret, err := r.searchSessions(ctx, "true", nil, withAuthTokenId(authTokenId))
	if err != nil {
		return nil, errors.Wrap(ctx, err, op)
	}
	return ret, nil
}

func (r *Repository) QuerySessions(ctx context.Context, authTokenId, query string) ([]*sessions.Session, error) {
	const op = "cache.(Repository).QuerySessions"
	switch {
	case authTokenId == "":
		return nil, errors.New(ctx, errors.InvalidParameter, op, "auth token id is missing")
	case query == "":
		return nil, errors.New(ctx, errors.InvalidParameter, op, "query is missing")
	}

	w, err := mql.Parse(query, Session{}, mql.WithIgnoredFields("UserId", "Item"))
	if err != nil {
		return nil, errors.Wrap(ctx, err, op, errors.WithCode(errors.InvalidParameter))
	}
	ret, err := r.searchSessions(ctx, w.Condition, w.Args, withAuthTokenId(authTokenId))
	if err != nil {
		return nil, errors.Wrap(ctx, err, op)
	}
	return ret, nil
}

func (r *Repository) searchSessions(ctx context.Context, condition string, searchArgs []any, opt ...Option) ([]*sessions.Session, error) {
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
		condition = fmt.Sprintf("%s and user_id in (select user_id from auth_token where id = ?)", condition)
		searchArgs = append(searchArgs, opts.withAuthTokenId)
	case opts.withUserId != "":
		condition = fmt.Sprintf("%s and user_id = ?", condition)
		searchArgs = append(searchArgs, opts.withUserId)
	}

	var cachedSessions []*Session
	if err := r.rw.SearchWhere(ctx, &cachedSessions, condition, searchArgs, db.WithLimit(-1)); err != nil {
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
	return retSessions, nil
}

type Session struct {
	UserId   string `gorm:"primaryKey"`
	Id       string `gorm:"primaryKey"`
	Type     string `gorm:"default:null"`
	Endpoint string `gorm:"default:null"`
	Status   string `gorm:"default:null"`
	ScopeId  string `gorm:"default:null"`
	TargetId string `gorm:"default:null"`
	Item     string `gorm:"default:null"`
}

func (*Session) TableName() string {
	return "session"
}
