// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: BUSL-1.1

package cache

import (
	"context"
	"database/sql"
	"encoding/json"
	stdErrors "errors"
	"fmt"

	"github.com/hashicorp/boundary/api/targets"
	"github.com/hashicorp/boundary/internal/db"
	"github.com/hashicorp/boundary/internal/errors"
	"github.com/hashicorp/boundary/internal/types/resource"
	"github.com/hashicorp/boundary/internal/util"
	"github.com/hashicorp/mql"
)

func (r *Repository) refreshTargets(ctx context.Context, u *user, targets []*targets.Target) error {
	const op = "cache.(Repository).refreshTargets"
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
		if _, err := w.Exec(ctx, "delete from target where user_id = @user_id",
			[]any{sql.Named("user_id", foundU.Id)}); err != nil {
			return err
		}

		for _, t := range targets {
			item, err := json.Marshal(t)
			if err != nil {
				return err
			}
			newTarget := &Target{
				UserId:      foundU.Id,
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
				return err
			}
		}
		return nil
	})
	if err != nil {
		if saveErr := r.SaveError(ctx, resource.Target.String(), err); saveErr != nil {
			return stdErrors.Join(err, errors.Wrap(ctx, saveErr, op))
		}
		return errors.Wrap(ctx, err, op)
	}
	return nil
}

func (r *Repository) ListTargets(ctx context.Context, authTokenId string) ([]*targets.Target, error) {
	const op = "cache.(Repository).ListTargets"
	switch {
	case authTokenId == "":
		return nil, errors.New(ctx, errors.InvalidParameter, op, "auth token id is missing")
	}
	ret, err := r.searchTargets(ctx, authTokenId, "true", nil)
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
	ret, err := r.searchTargets(ctx, authTokenId, w.Condition, w.Args)
	if err != nil {
		return nil, errors.Wrap(ctx, err, op)
	}
	return ret, nil
}

func (r *Repository) searchTargets(ctx context.Context, authTokenId, condition string, searchArgs []any) ([]*targets.Target, error) {
	const op = "cache.(Repository).searchTargets"
	switch {
	case authTokenId == "":
		return nil, errors.New(ctx, errors.InvalidParameter, op, "user id is missing")
	case condition == "":
		return nil, errors.New(ctx, errors.InvalidParameter, op, "condition is missing")
	}

	condition = fmt.Sprintf("%s and user_id in (select user_id from auth_token where id = ?)", condition)
	args := append(searchArgs, authTokenId)
	var cachedTargets []*Target
	if err := r.rw.SearchWhere(ctx, &cachedTargets, condition, args, db.WithLimit(-1)); err != nil {
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
