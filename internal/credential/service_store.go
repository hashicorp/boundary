// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: BUSL-1.1

package credential

import (
	"context"
	"time"

	"github.com/hashicorp/boundary/internal/db"
	"github.com/hashicorp/boundary/internal/errors"
	"github.com/hashicorp/boundary/internal/util"
)

// StoreRepository defines the interface expected
// to gather information about credential stores.
type StoreRepository interface {
	EstimatedStoreCount(context.Context) (int, error)
	ListDeletedStoreIds(context.Context, time.Time, ...Option) ([]string, error)
	ListCredentialStores(context.Context, []string, ...Option) ([]Store, error)
}

// StoreService coordinates calls across different subtype repositories
// to gather information about all credential stores.
type StoreService struct {
	repos  []StoreRepository
	writer db.Writer
}

// NewStoreService returns a new credential store service.
func NewStoreService(ctx context.Context, writer db.Writer, vaultRepo StoreRepository, staticRepo StoreRepository) (*StoreService, error) {
	const op = "credential.NewStoreService"
	switch {
	case util.IsNil(writer):
		return nil, errors.New(ctx, errors.InvalidParameter, op, "missing DB writer")
	case util.IsNil(vaultRepo):
		return nil, errors.New(ctx, errors.InvalidParameter, op, "missing vault repo")
	case util.IsNil(staticRepo):
		return nil, errors.New(ctx, errors.InvalidParameter, op, "missing static repo")
	}
	return &StoreService{
		repos:  []StoreRepository{vaultRepo, staticRepo},
		writer: writer,
	}, nil
}
