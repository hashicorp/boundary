// Copyright IBM Corp. 2020, 2025
// SPDX-License-Identifier: BUSL-1.1

package cache

import (
	"context"
	"database/sql"
	stderrors "errors"
	"time"

	"github.com/hashicorp/boundary/internal/db"
	"github.com/hashicorp/boundary/internal/errors"
	"github.com/hashicorp/boundary/internal/util"
)

// ErrRefreshNotSupported is returned whenever it is determined a boundary
// instance does not support refresh tokens.
var ErrRefreshNotSupported = stderrors.New("refresh tokens are not supported for this controller")

// RefreshTokenValue is the the type for the actual refresh token value handled
// by the client cache.
type RefreshTokenValue string

// sentinelNoRefreshToken is the value set in the refresh token table when
// Boundary returns resources but no refresh tokens. The presence of this value
// indicates that the boundary instance queried does not support refresh tokens.
const sentinelNoRefreshToken RefreshTokenValue = "__no_refresh_token_supported__"

// CacheSupport is an enum that identifies if a boundary instance can be supported
// by the client cache.
type CacheSupport string

const (
	UnknownCacheSupport      CacheSupport = "Unknown"
	SupportedCacheSupport    CacheSupport = "Supported"
	NotSupportedCacheSupport CacheSupport = "Not Supported"
)

// cacheSupportCheckedState contains the state of a cache support check.
type cacheSupportCheckedState struct {
	supported   CacheSupport
	lastChecked *time.Time
}

// cacheSupportState returns the cacheSupportCheckedState for the provided user
// which says if caching is supported for that user and when the last time it
// was checked.
func (r *Repository) cacheSupportState(ctx context.Context, u *user) (*cacheSupportCheckedState, error) {
	const op = "cache.(Repository).cacheSupportState"
	switch {
	case util.IsNil(u):
		return nil, errors.New(ctx, errors.InvalidParameter, op, "user is nil")
	case u.Id == "":
		return nil, errors.New(ctx, errors.InvalidParameter, op, "user id is empty")
	}
	var ret []*refreshToken
	if err := r.rw.SearchWhere(ctx, &ret, "user_id = @user_id", []any{sql.Named("user_id", u.Id)}); err != nil {
		return nil, errors.Wrap(ctx, err, op)
	}
	if len(ret) == 0 {
		return &cacheSupportCheckedState{supported: UnknownCacheSupport}, nil
	}

	lastChecked := time.Time{}
	supported := UnknownCacheSupport
	for _, rt := range ret {
		if rt.UpdateTime.After(lastChecked) {
			lastChecked = rt.UpdateTime
		}
		switch {
		case supported == NotSupportedCacheSupport || rt.RefreshToken == sentinelNoRefreshToken:
			supported = NotSupportedCacheSupport
		default:
			supported = SupportedCacheSupport
		}
	}
	return &cacheSupportCheckedState{supported: supported, lastChecked: &lastChecked}, nil
}

// lookupRefreshToken returns the last known valid refresh token or an empty
// string if one is unknown. No error is returned if no valid refresh token is
// found.
func (r *Repository) lookupRefreshToken(ctx context.Context, u *user, resourceType resourceType) (*refreshToken, error) {
	const op = "cache.(Repsoitory).lookupRefreshToken"
	switch {
	case util.IsNil(u):
		return nil, errors.New(ctx, errors.InvalidParameter, op, "user is nil")
	case u.Id == "":
		return nil, errors.New(ctx, errors.InvalidParameter, op, "user id is empty")
	case !resourceType.valid():
		return nil, errors.New(ctx, errors.InvalidParameter, op, "resource type is invalid")
	}

	rt := &refreshToken{
		UserId:       u.Id,
		ResourceType: resourceType,
	}
	if err := r.rw.LookupById(ctx, rt); err != nil {
		if errors.IsNotFoundError(err) {
			return nil, nil
		}
		return nil, errors.Wrap(ctx, err, op)
	}
	return rt, nil
}

// listRefreshTokens returns all refresh tokens associated with a specific user
func (r *Repository) listRefreshTokens(ctx context.Context, u *user) ([]*refreshToken, error) {
	const op = "cache.(Repository).listRefreshTokens"
	switch {
	case util.IsNil(u):
		return nil, errors.New(ctx, errors.InvalidParameter, op, "user is nil")
	case u.Id == "":
		return nil, errors.New(ctx, errors.InvalidParameter, op, "user id is empty")
	}
	var ret []*refreshToken
	if err := r.rw.SearchWhere(ctx, &ret, "user_id = @user_id and refresh_token != @sentinel",
		[]any{sql.Named("user_id", u.Id), sql.Named("sentinel", sentinelNoRefreshToken)}); err != nil {
		return nil, errors.Wrap(ctx, err, op)
	}
	return ret, nil
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

	_, err := r.rw.DoTx(ctx, db.StdRetryCnt, db.ExpBackoff{}, func(_ db.Reader, w db.Writer) error {
		return deleteRefreshToken(ctx, w, u, rType)
	})
	if err != nil {
		return errors.Wrap(ctx, err, op)
	}
	return nil
}

// deleteRefreshToken deletes the refresh token for the provided user and resource type
func deleteRefreshToken(ctx context.Context, w db.Writer, u *user, rType resourceType) error {
	const op = "cache.deleteRefreshToken"
	switch {
	case util.IsNil(w):
		return errors.New(ctx, errors.InvalidParameter, op, "writer is nil")
	case !w.IsTx(ctx):
		return errors.New(ctx, errors.InvalidParameter, op, "writer isn't in a transaction")
	case util.IsNil(u):
		return errors.New(ctx, errors.InvalidParameter, op, "user is nil")
	case u.Id == "":
		return errors.New(ctx, errors.InvalidParameter, op, "user id is empty")
	case !rType.valid():
		return errors.New(ctx, errors.InvalidParameter, op, "resource type is invalid")
	}
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
		_, err := writer.Delete(ctx, refTok)
		if err != nil {
			return errors.Wrap(ctx, err, op)
		}
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
	unknownResourceType         resourceType = "unknown"
	targetResourceType          resourceType = "target"
	sessionResourceType         resourceType = "session"
	resolvableAliasResourceType resourceType = "resolvable-alias"
)

func (r resourceType) ColumnName() string {
	switch r {
	case resolvableAliasResourceType:
		return "resolvable_alias"
	default:
		return string(r)
	}
}

func (r resourceType) valid() bool {
	switch r {
	case resolvableAliasResourceType, targetResourceType, sessionResourceType:
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
