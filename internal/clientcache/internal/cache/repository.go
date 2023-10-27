// Copyright (c) HashiCorp, Inc.
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
type KeyringTokenLookupFn func(keyring string, tokenName string) *authtokens.AuthToken

// BoundaryTokenReaderFn reads an auth token's resource information from boundary
type BoundaryTokenReaderFn func(ctx context.Context, addr string, authToken string) (*authtokens.AuthToken, error)

type Repository struct {
	rw                      *db.Db
	tokenKeyringFn          KeyringTokenLookupFn
	tokenReadFromBoundaryFn BoundaryTokenReaderFn
	// idToKeyringlessAuthToken maps an auth token id to an *authtokens.AuthToken
	idToKeyringlessAuthToken *sync.Map
}

// NewRepository returns a cache repository. The provided Store must be
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
		rw:                      db.New(conn),
		tokenKeyringFn:          keyringFn,
		tokenReadFromBoundaryFn: atReadFn,
		// This is passed in instead of being fully owned by the repo so multiple
		// instances of the repo can operate on the same backing data
		idToKeyringlessAuthToken: idToAuthToken,
	}, nil
}

func (r *Repository) SaveError(ctx context.Context, u *user, resourceType resourceType, err error) error {
	const op = "cache.(Repository).StoreError"
	switch {
	case resourceType == "":
		return errors.New(ctx, errors.InvalidParameter, op, "resource type is empty")
	case err == nil:
		return errors.New(ctx, errors.InvalidParameter, op, "error is nil")
	case u == nil:
		return errors.New(ctx, errors.InvalidParameter, op, "user is nil")
	case u.Id == "":
		return errors.New(ctx, errors.InvalidParameter, op, "user id is empty")
	}
	apiErr := &ApiError{
		UserId:       u.Id,
		ResourceType: string(resourceType),
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

type ApiError struct {
	UserId       string `gorm:"primaryKey"`
	ResourceType string `gorm:"primaryKey"`
	Error        string
	CreateTime   time.Time
}

func (*ApiError) TableName() string {
	return "api_error"
}
