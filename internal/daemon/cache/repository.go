// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: BUSL-1.1

package cache

import (
	"context"
	"time"

	"github.com/hashicorp/boundary/api/authtokens"
	"github.com/hashicorp/boundary/internal/db"
	"github.com/hashicorp/boundary/internal/errors"
	"github.com/hashicorp/boundary/internal/util"
)

const (
	personaLimit          = 50
	personaStalenessLimit = 36 * time.Hour
)

// TokenKeyringFn takes a token name and returns the token
type TokenKeyringFn func(keyring string, tokenName string) *authtokens.AuthToken

// AuthTokenReadFn reads an auth token's resource information from boundary
type AuthTokenReadFn func(ctx context.Context, addr string, authToken string) (*authtokens.AuthToken, error)

type Repository struct {
	rw             *db.Db
	tokenKeyringFn TokenKeyringFn
	tokenReadFn    AuthTokenReadFn
	tokIdToTok     map[string]string
}

// NewRepository returns a cache repository.  The provided Store must be 
func NewRepository(ctx context.Context, s *Store, keyringFn TokenKeyringFn, atReadFn AuthTokenReadFn, opt ...Option) (*Repository, error) {
	const op = "cache.NewRepository"
	switch {
	case util.IsNil(s):
		return nil, errors.New(ctx, errors.InvalidParameter, op, "missing store")
	case util.IsNil(keyringFn):
		return nil, errors.New(ctx, errors.InvalidParameter, op, "missing token keyring function")
	case util.IsNil(atReadFn):
		return nil, errors.New(ctx, errors.InvalidParameter, op, "missing auth token read function")
	}

	return &Repository{
		rw:             db.New(s.conn),
		tokenKeyringFn: keyringFn,
		tokenReadFn:    atReadFn,
		tokIdToTok:     make(map[string]string),
	}, nil
}

func (r *Repository) SaveError(ctx context.Context, resourceType string, err error) error {
	const op = "cache.(Repository).StoreError"
	switch {
	case resourceType == "":
		return errors.New(ctx, errors.InvalidParameter, op, "resource type is empty")
	case err == nil:
		return errors.New(ctx, errors.InvalidParameter, op, "error is nil")
	}
	apiErr := &ApiError{
		ResourceType: resourceType,
		Error:        err.Error(),
	}
	onConflict := db.OnConflict{
		Target: db.Columns{"token_name", "resource_type"},
		Action: db.SetColumns([]string{"error", "create_time"}),
	}
	if err := r.rw.Create(ctx, apiErr, db.WithOnConflict(&onConflict)); err != nil {
		return errors.Wrap(ctx, err, op)
	}
	return nil
}

type ApiError struct {
	TokenName    string `gorm:"primaryKey"`
	ResourceType string `gorm:"primaryKey"`
	Error        string
	CreateTime   time.Time
}

func (*ApiError) TableName() string {
	return "cache_api_error"
}
