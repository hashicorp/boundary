// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: BUSL-1.1

package cache

import (
	"context"
	"time"

	"github.com/hashicorp/boundary/internal/db"
	"github.com/hashicorp/boundary/internal/errors"
	"github.com/hashicorp/boundary/internal/util"
	"github.com/hashicorp/go-dbw"
)

// RefreshTokenValue is the the type for the actual refresh token value handled
// by the client cache.
type RefreshTokenValue string

// lookupRefreshToken returns the refresh token stored in the db unless it is
// to old in which case it does not return a refresh token.
func (r *Repository) lookupRefreshToken(ctx context.Context, u *user, resourceType resourceType) (RefreshTokenValue, error) {
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

func upsertRefreshToken(ctx context.Context, writer db.Writer, u *user, rt resourceType, tok RefreshTokenValue) error {
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
	RefreshToken RefreshTokenValue
	UpdateTime   time.Time `gorm:"default:(strftime('%Y-%m-%d %H:%M:%f','now'))"`
	CreateTime   time.Time `gorm:"default:(strftime('%Y-%m-%d %H:%M:%f','now'))"`
}

func (*refreshToken) TableName() string {
	return "refresh_token"
}
