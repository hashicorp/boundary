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
	usersLimit          = 50
	tokenStalenessLimit = 36 * time.Hour
)

// TokenLookupFn takes a keyring type and token name and returns the token
type TokenLookupFn func(keyring string, tokenName string) *authtokens.AuthToken

type Repository struct {
	rw            *db.Db
	tokenLookupFn TokenLookupFn
}

func NewRepository(ctx context.Context, s *Store, tFn TokenLookupFn, opt ...Option) (*Repository, error) {
	const op = "cache.NewRepository"
	switch {
	case util.IsNil(s):
		return nil, errors.New(ctx, errors.InvalidParameter, op, "missing store")
	case util.IsNil(tFn):
		return nil, errors.New(ctx, errors.InvalidParameter, op, "missing token lookup function")
	}

	return &Repository{rw: db.New(s.conn), tokenLookupFn: tFn}, nil
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
	return "api_error"
}
