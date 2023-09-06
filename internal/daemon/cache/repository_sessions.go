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

func (r *Repository) refreshCachedSessions(ctx context.Context, p *Persona, sessions []*sessions.Session) error {
	const op = "cache.(Repository).refreshSessions"
	switch {
	case util.IsNil(p):
		return errors.New(ctx, errors.InvalidParameter, op, "persona is nil")
	case p.TokenName == "":
		return errors.New(ctx, errors.InvalidParameter, op, "token name is missing")
	case p.KeyringType == "":
		return errors.New(ctx, errors.InvalidParameter, op, "keyring type is missing")
	case p.BoundaryAddr == "":
		return errors.New(ctx, errors.InvalidParameter, op, "boundary address is missing")
	case p.UserId == "":
		return errors.New(ctx, errors.InvalidParameter, op, "user id is missing")
	}

	foundP := p.clone()
	if err := r.rw.LookupById(ctx, foundP); err != nil {
		// if this persona isn't known, error out.
		return errors.Wrap(ctx, err, op, errors.WithMsg("looking up persona"))
	}

	_, err := r.rw.DoTx(ctx, db.StdRetryCnt, db.ExpBackoff{}, func(r db.Reader, w db.Writer) error {
		// TODO: Instead of deleting everything, use refresh tokens and apply the delta
		if _, err := w.Exec(ctx, "delete from cache_session where boundary_addr = @boundary_addr and token_name = @token_name and keyring_type = @keyring_type and boundary_user_id = @boundary_user_id",
			[]any{sql.Named("boundary_addr", foundP.BoundaryAddr), sql.Named("keyring_type", foundP.KeyringType), sql.Named("token_name", foundP.TokenName), sql.Named("boundary_user_id", foundP.UserId)}); err != nil {
			return err
		}

		for _, s := range sessions {
			item, err := json.Marshal(s)
			if err != nil {
				return err
			}
			newSession := Session{
				BoundaryAddr:   foundP.BoundaryAddr,
				KeyringType:    foundP.KeyringType,
				TokenName:      foundP.TokenName,
				BoundaryUserId: foundP.UserId,
				Id:             s.Id,
				Type:           s.Type,
				Status:         s.Status,
				Endpoint:       s.Endpoint,
				Item:           string(item),
			}
			onConflict := db.OnConflict{
				Target: db.Columns{"boundary_addr", "token_name", "keyring_type", "boundary_user_id", "id"},
				Action: db.UpdateAll(true),
			}
			if err := w.Create(ctx, newSession, db.WithOnConflict(&onConflict)); err != nil {
				return err
			}
		}
		return nil
	})
	if err != nil {
		if saveErr := r.SaveError(ctx, resource.Session.String(), err); saveErr != nil {
			return stdErrors.Join(err, errors.Wrap(ctx, saveErr, op))
		}
		return errors.Wrap(ctx, err, op)
	}
	return nil
}

func (r *Repository) ListSessions(ctx context.Context, p *Persona) ([]*sessions.Session, error) {
	const op = "cache.(Repository).ListSessions"
	switch {
	case util.IsNil(p):
		return nil, errors.New(ctx, errors.InvalidParameter, op, "persona is nil")
	case p.TokenName == "":
		return nil, errors.New(ctx, errors.InvalidParameter, op, "token name is missing")
	case p.KeyringType == "":
		return nil, errors.New(ctx, errors.InvalidParameter, op, "keyring type is missing")
	case p.BoundaryAddr == "":
		return nil, errors.New(ctx, errors.InvalidParameter, op, "boundary address is missing")
	case p.UserId == "":
		return nil, errors.New(ctx, errors.InvalidParameter, op, "user id is missing")
	}
	ret, err := r.searchSessions(ctx, p, "true", nil)
	if err != nil {
		return nil, errors.Wrap(ctx, err, op)
	}
	return ret, nil
}

func (r *Repository) QuerySessions(ctx context.Context, p *Persona, query string) ([]*sessions.Session, error) {
	const op = "cache.(Repository).QuerySessions"
	switch {
	case util.IsNil(p):
		return nil, errors.New(ctx, errors.InvalidParameter, op, "persona is nil")
	case p.TokenName == "":
		return nil, errors.New(ctx, errors.InvalidParameter, op, "token name is missing")
	case p.KeyringType == "":
		return nil, errors.New(ctx, errors.InvalidParameter, op, "keyring type is missing")
	case p.BoundaryAddr == "":
		return nil, errors.New(ctx, errors.InvalidParameter, op, "boundary address is missing")
	case p.UserId == "":
		return nil, errors.New(ctx, errors.InvalidParameter, op, "user id is missing")
	case query == "":
		return nil, errors.New(ctx, errors.InvalidParameter, op, "query is missing")
	}

	w, err := mql.Parse(query, Session{}, mql.WithIgnoredFields("BoundaryAddr", "KeyringType", "TokenName", "BoundaryUserId", "Item"))
	if err != nil {
		return nil, errors.Wrap(ctx, err, op, errors.WithCode(errors.InvalidParameter))
	}
	ret, err := r.searchSessions(ctx, p, w.Condition, w.Args)
	if err != nil {
		return nil, errors.Wrap(ctx, err, op)
	}
	return ret, nil
}

func (r *Repository) searchSessions(ctx context.Context, p *Persona, condition string, searchArgs []any) ([]*sessions.Session, error) {
	const op = "cache.(Repository).searchSessions"
	switch {
	case p == nil:
		return nil, errors.New(ctx, errors.InvalidParameter, op, "persona is missing")
	case p.UserId == "":
		return nil, errors.New(ctx, errors.InvalidParameter, op, "user id is missing")
	case p.TokenName == "":
		return nil, errors.New(ctx, errors.InvalidParameter, op, "token name is missing")
	case p.KeyringType == "":
		return nil, errors.New(ctx, errors.InvalidParameter, op, "keyring type is missing")
	case p.BoundaryAddr == "":
		return nil, errors.New(ctx, errors.InvalidParameter, op, "boundary address is missing")
	case condition == "":
		return nil, errors.New(ctx, errors.InvalidParameter, op, "condition is missing")
	}

	condition = fmt.Sprintf("%s and ((keyring_type, token_name, boundary_addr, boundary_user_id) = (?, ?, ?, ?))", condition)
	args := append(searchArgs, p.KeyringType, p.TokenName, p.BoundaryAddr, p.UserId)
	var cachedSessions []*Session
	if err := r.rw.SearchWhere(ctx, &cachedSessions, condition, args, db.WithLimit(-1)); err != nil {
		return nil, errors.Wrap(ctx, err, op)
	}

	retSessions := make([]*sessions.Session, 0, len(cachedSessions))
	for _, cachedTar := range cachedSessions {
		var sess sessions.Session
		if err := json.Unmarshal([]byte(cachedTar.Item), &sess); err != nil {
			return nil, errors.Wrap(ctx, err, op)
		}
		retSessions = append(retSessions, &sess)
	}
	return retSessions, nil
}

type Session struct {
	BoundaryAddr   string `gorm:"primaryKey"`
	KeyringType    string `gorm:"primaryKey"`
	TokenName      string `gorm:"primaryKey"`
	BoundaryUserId string `gorm:"primaryKey"`
	Id             string `gorm:"primaryKey"`
	Type           string
	Endpoint       string
	Status         string
	Item           string
}

func (*Session) TableName() string {
	return "cache_session"
}
