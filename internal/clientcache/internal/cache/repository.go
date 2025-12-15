// Copyright IBM Corp. 2020, 2025
// SPDX-License-Identifier: BUSL-1.1

package cache

import (
	"context"
	"sync"
	"time"

	"github.com/hashicorp/boundary/api/authtokens"
	"github.com/hashicorp/boundary/internal/db"
	"github.com/hashicorp/boundary/internal/errors"
	"github.com/hashicorp/boundary/internal/util"
)

const (
	usersLimit          = 50
	tokenStalenessLimit = 36 * time.Hour
)

// KeyringTokenLookupFn takes a token name and returns the token from the keyring
type KeyringTokenLookupFn func(keyring string, tokenName string) (*authtokens.AuthToken, error)

// BoundaryTokenReaderFn reads an auth token's resource information from boundary
type BoundaryTokenReaderFn func(ctx context.Context, addr string, authToken string) (*authtokens.AuthToken, error)

type Repository struct {
	serverCtx               context.Context
	rw                      *db.Db
	tokenKeyringFn          KeyringTokenLookupFn
	tokenReadFromBoundaryFn BoundaryTokenReaderFn
	// idToKeyringlessAuthToken maps an auth token id to an *authtokens.AuthToken
	idToKeyringlessAuthToken *sync.Map
}

// NewRepository returns a cache repository.  The provided context is stored as
// the server context for purposes like storing boundary request errors.
func NewRepository(ctx context.Context, conn *db.DB, idToAuthToken *sync.Map, keyringFn KeyringTokenLookupFn, atReadFn BoundaryTokenReaderFn, opt ...Option) (*Repository, error) {
	const op = "cache.NewRepository"
	switch {
	case util.IsNil(conn):
		return nil, errors.New(ctx, errors.InvalidParameter, op, "missing store connection")
	case util.IsNil(idToAuthToken):
		return nil, errors.New(ctx, errors.InvalidParameter, op, "missing keyringless auth token map")
	case util.IsNil(keyringFn):
		return nil, errors.New(ctx, errors.InvalidParameter, op, "missing token keyring function")
	case util.IsNil(atReadFn):
		return nil, errors.New(ctx, errors.InvalidParameter, op, "missing auth token read function")
	}
	return &Repository{
		serverCtx:               ctx,
		rw:                      db.New(conn),
		tokenKeyringFn:          keyringFn,
		tokenReadFromBoundaryFn: atReadFn,
		// This is passed in instead of being fully owned by the repo so multiple
		// instances of the repo can operate on the same backing data
		idToKeyringlessAuthToken: idToAuthToken,
	}, nil
}

func (r *Repository) saveError(ctx context.Context, u *user, resourceType resourceType, err error) error {
	const op = "cache.(Repository).saveError"
	switch {
	case !resourceType.valid():
		return errors.New(ctx, errors.InvalidParameter, op, "resource type is invalid")
	case err == nil:
		return errors.New(ctx, errors.InvalidParameter, op, "error is nil")
	case u == nil:
		return errors.New(ctx, errors.InvalidParameter, op, "user is nil")
	case u.Id == "":
		return errors.New(ctx, errors.InvalidParameter, op, "user id is empty")
	}
	apiErr := &apiError{
		UserId:       u.Id,
		ResourceType: resourceType,
		Error:        err.Error(),
	}
	onConflict := db.OnConflict{
		Target: db.Columns{"user_id", "resource_type"},
		Action: db.SetColumns([]string{"error", "create_time"}),
	}
	if err := r.rw.Create(ctx, apiErr, db.WithOnConflict(&onConflict)); err != nil {
		return errors.Wrap(ctx, err, op)
	}
	return nil
}

func (r *Repository) lookupError(ctx context.Context, u *user, resourceType resourceType) (*apiError, error) {
	const op = "cache.(Repository).lookupError"
	switch {
	case !resourceType.valid():
		return nil, errors.New(ctx, errors.InvalidParameter, op, "resource type is invalid")
	case u == nil:
		return nil, errors.New(ctx, errors.InvalidParameter, op, "user is nil")
	case u.Id == "":
		return nil, errors.New(ctx, errors.InvalidParameter, op, "user id is empty")
	}
	apiErr := &apiError{
		UserId:       u.Id,
		ResourceType: resourceType,
	}
	err := r.rw.LookupById(ctx, apiErr)
	if err != nil {
		if errors.IsNotFoundError(err) {
			return nil, nil
		}
		return nil, errors.Wrap(ctx, err, op)
	}
	return apiErr, nil
}

type apiError struct {
	UserId       string       `gorm:"primaryKey"`
	ResourceType resourceType `gorm:"primaryKey"`
	Error        string       `gorm:"default:null"`
	CreateTime   time.Time    `gorm:"default:(strftime('%Y-%m-%d %H:%M:%f','now'))"`
}

func (*apiError) TableName() string {
	return "api_error"
}
