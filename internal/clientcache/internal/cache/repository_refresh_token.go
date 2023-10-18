// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: BUSL-1.1

package cache

import (
	"context"
	"database/sql"
	"time"

	"github.com/hashicorp/boundary/internal/db"
	"github.com/hashicorp/boundary/internal/errors"
	"github.com/hashicorp/boundary/internal/util"
	"github.com/hashicorp/go-dbw"
)

// defaultRefreshTokenMaxAge is the amount of time we will ignore a refresh token
// since it was created when cleaning up expired ones.
const defaultRefreshTokenMaxAge time.Duration = 30 * 24 * time.Hour

// lookupRefreshToken returns the refresh token stored in the db unless it is
// to old in which case it does not return a refresh token.
func (r *Repository) lookupRefreshToken(ctx context.Context, u *user, resourceType resourceType) (string, error) {
	const op = "cache.(Repsoitory).lookupRefreshToken"
	switch {
	case util.IsNil(u):
		return "", errors.New(ctx, errors.InvalidParameter, op, "user is nil")
	case u.Id == "":
		return "", errors.New(ctx, errors.InvalidParameter, op, "user id is empty")
	case !resourceType.valid():
		return "", errors.New(ctx, errors.InvalidParameter, op, "resource type is invalid")
	}

	rt := &refreshToken{
		UserId:       u.Id,
		ResourceType: resourceType,
	}
	if err := r.rw.LookupById(ctx, rt); err != nil {
		if errors.Is(err, dbw.ErrRecordNotFound) {
			return "", nil
		}
		return "", errors.Wrap(ctx, err, op)
	}
	return rt.RefreshToken, nil
}

// deleteRefreshToken deletes the refresh token for the provided user and resource type
func (r *Repository) deleteRefreshToken(ctx context.Context, u *user, rType resourceType) error {
	const op = "cache.(Repository).deleteRefreshToken"
	switch {
	case util.IsNil(u):
		return errors.New(ctx, errors.InvalidParameter, op, "user is nil")
	case u.Id == "":
		return errors.New(ctx, errors.InvalidParameter, op, "user id is empty")
	case !rType.valid():
		return errors.New(ctx, errors.InvalidParameter, op, "resource type is invalid")
	}

	_, err := r.rw.DoTx(ctx, db.StdRetryCnt, db.ExpBackoff{}, func(r db.Reader, w db.Writer) error {
		rt := &refreshToken{
			UserId:       u.Id,
			ResourceType: rType,
		}
		n, err := w.Delete(ctx, rt)
		if err != nil {
			return errors.Wrap(ctx, err, op)
		}
		if n > 1 {
			return errors.New(ctx, errors.MultipleRecords, op, "attempted to delete a single resource but multiple were resource deletions were attempted")
		}
		return nil
	})
	if err != nil {
		return err
	}

	return nil
}

// clearExpiredRefreshTokens removes any refresh tokens which were created
// longer than 30 days ago.  WithDuration is the only Option allowed and, if not
// zero, will overwrite the 30 day expiration time.
func (r *Repository) clearExpiredRefreshTokens(ctx context.Context, opt ...Option) error {
	const op = "cache.(Repository).clearExpiredRefreshTokens"
	opts, err := getOpts(opt...)
	if err != nil {
		return errors.Wrap(ctx, err, op)
	}

	if opts.withDuration == 0 {
		opts.withDuration = defaultRefreshTokenMaxAge
	}
	_, err = r.rw.DoTx(ctx, db.StdRetryCnt, db.ExpBackoff{}, func(r db.Reader, w db.Writer) error {
		_, err := w.Exec(ctx, "delete from refresh_token where datetime(create_time) < datetime(@earliest)",
			[]any{sql.Named("earliest", time.Now().Add(-opts.withDuration))}, db.WithDebug(true))
		if err != nil {
			return errors.Wrap(ctx, err, op)
		}
		return nil
	})
	if err != nil {
		return err
	}
	return nil
}

func upsertRefreshToken(ctx context.Context, writer db.Writer, u *user, rt resourceType, tok string) error {
	const op = "cache.upsertRefreshToken"
	switch {
	case util.IsNil(writer):
		return errors.New(ctx, errors.InvalidParameter, op, "writer is nil")
	case !writer.IsTx(ctx):
		return errors.New(ctx, errors.InvalidParameter, op, "writer isn't in a transaction")
	case util.IsNil(u):
		return errors.New(ctx, errors.InvalidParameter, op, "user is nil")
	case u.Id == "":
		return errors.New(ctx, errors.InvalidParameter, op, "user id is empty")
	case !rt.valid():
		return errors.New(ctx, errors.InvalidParameter, op, "resource type is invalid")
	}

	refTok := &refreshToken{
		UserId:       u.Id,
		ResourceType: rt,
		RefreshToken: tok,
		UpdateTime:   time.Now(),
		CreateTime:   time.Now(),
	}

	switch tok {
	case "":
		writer.Delete(ctx, refTok)
	default:
		onConflict := &db.OnConflict{
			Target: db.Columns{"user_id", "resource_type"},
			Action: db.SetColumns([]string{"refresh_token", "update_time"}),
		}
		if err := writer.Create(ctx, refTok, db.WithOnConflict(onConflict)); err != nil {
			return errors.Wrap(ctx, err, op)
		}
	}

	return nil
}

type resourceType string

const (
	unknownResourceType resourceType = "unknown"
	targetResourceType  resourceType = "target"
	sessionResourceType resourceType = "session"
)

func (r resourceType) valid() bool {
	switch r {
	case targetResourceType, sessionResourceType:
		return true
	}
	return false
}

type refreshToken struct {
	UserId       string       `gorm:"primaryKey"`
	ResourceType resourceType `gorm:"primaryKey"`
	RefreshToken string
	UpdateTime   time.Time `gorm:"default:(strftime('%Y-%m-%d %H:%M:%f','now'))"`
	CreateTime   time.Time `gorm:"default:(strftime('%Y-%m-%d %H:%M:%f','now'))"`
}

func (*refreshToken) TableName() string {
	return "refresh_token"
}
