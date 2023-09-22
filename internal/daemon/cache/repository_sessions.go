// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: BUSL-1.1

package cache

import (
	"context"
	"database/sql"
	"encoding/json"
	stdErrors "errors"
	"fmt"

	"github.com/hashicorp/boundary/api/sessions"
	"github.com/hashicorp/boundary/internal/db"
	"github.com/hashicorp/boundary/internal/errors"
	"github.com/hashicorp/boundary/internal/types/resource"
	"github.com/hashicorp/boundary/internal/util"
	"github.com/hashicorp/mql"
)

func (r *Repository) refreshSessions(ctx context.Context, u *user, sessions []*sessions.Session) error {
	const op = "cache.(Repository).refreshSessions"
	switch {
	case util.IsNil(u):
		return errors.New(ctx, errors.InvalidParameter, op, "user is nil")
	case u.Id == "":
		return errors.New(ctx, errors.InvalidParameter, op, "user id is missing")
	}

	foundU := u.clone()
	if err := r.rw.LookupById(ctx, foundU); err != nil {
		// if this user isn't known, error out.
		return errors.Wrap(ctx, err, op, errors.WithMsg("looking up user"))
	}

	_, err := r.rw.DoTx(ctx, db.StdRetryCnt, db.ExpBackoff{}, func(r db.Reader, w db.Writer) error {
		// TODO: Instead of deleting everything, use refresh tokens and apply the delta
		if _, err := w.Exec(ctx, "delete from session where user_id = @user_id",
			[]any{sql.Named("user_id", foundU.Id)}); err != nil {
			return err
		}

		for _, s := range sessions {
			item, err := json.Marshal(s)
			if err != nil {
				return err
			}
			newSession := &Session{
				UserId:   foundU.Id,
				Id:       s.Id,
				Type:     s.Type,
				Status:   s.Status,
				Endpoint: s.Endpoint,
				Item:     string(item),
			}
			onConflict := db.OnConflict{
				Target: db.Columns{"user_id", "id"},
				Action: db.UpdateAll(true),
			}
			if err := w.Create(ctx, newSession, db.WithOnConflict(&onConflict)); err != nil {
				return err
			}
		}
		return nil
	})
	if err != nil {
		if saveErr := r.SaveError(ctx, u, resource.Session.String(), err); saveErr != nil {
			return stdErrors.Join(err, errors.Wrap(ctx, saveErr, op))
		}
		return errors.Wrap(ctx, err, op)
	}
	return nil
}

func (r *Repository) ListSessions(ctx context.Context, authTokenId string) ([]*sessions.Session, error) {
	const op = "cache.(Repository).ListSessions"
	switch {
	case authTokenId == "":
		return nil, errors.New(ctx, errors.InvalidParameter, op, "auth token id is missing")
	}
	ret, err := r.searchSessions(ctx, authTokenId, "true", nil)
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
	ret, err := r.searchSessions(ctx, authTokenId, w.Condition, w.Args)
	if err != nil {
		return nil, errors.Wrap(ctx, err, op)
	}
	return ret, nil
}

func (r *Repository) searchSessions(ctx context.Context, authTokenId, condition string, searchArgs []any) ([]*sessions.Session, error) {
	const op = "cache.(Repository).searchSessions"
	switch {
	case authTokenId == "":
		return nil, errors.New(ctx, errors.InvalidParameter, op, "auth token id is missing")
	case condition == "":
		return nil, errors.New(ctx, errors.InvalidParameter, op, "condition is missing")
	}

	condition = fmt.Sprintf("%s and user_id in (select user_id from auth_token where id = ?)", condition)
	args := append(searchArgs, authTokenId)
	var cachedSessions []*Session
	if err := r.rw.SearchWhere(ctx, &cachedSessions, condition, args, db.WithLimit(-1)); err != nil {
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
	Item     string `gorm:"default:null"`
}

func (*Session) TableName() string {
	return "session"
}
