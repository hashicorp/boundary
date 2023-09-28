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
// to get the total number of credential stores and deleted ids.
type StoreRepository interface {
	EstimatedStoreCount(context.Context) (int, error)
	ListDeletedStoreIds(context.Context, time.Time, ...Option) ([]string, error)
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
		return nil, errors.New(ctx, errors.InvalidParameter, op, "missing vault repo")
	}
	return &StoreService{
		repos:  []StoreRepository{vaultRepo, staticRepo},
		writer: writer,
	}, nil
}

// StoreService coordinates calls to across different subtype repositories
// to gather information about all credential stores.
type StoreService struct {
	repos  []StoreRepository
	writer db.Writer
}

// EstimatedCount gets an estimate of the total number of credential stores across all types
func (s *StoreService) EstimatedCount(ctx context.Context) (int, error) {
	const op = "credential.(*StoreService).EstimatedCount"
	var totalNumStores int
	for _, repo := range s.repos {
		numStores, err := repo.EstimatedStoreCount(ctx)
		if err != nil {
			return 0, errors.Wrap(ctx, err, op)
		}
		totalNumStores += numStores
	}
	return totalNumStores, nil
}

// ListDeletedIds lists all deleted credential store IDs across all types,
// and returns the timestamp of the transaction, to be used in other ListDeletedIds transactions.
// This should ensure the correct list of deleted IDs is always returned.
func (s *StoreService) ListDeletedIds(ctx context.Context, since time.Time) ([]string, time.Time, error) {
	const op = "credential.(*StoreService).ListDeletedIds"
	var deletedIds []string
	var now time.Time
	_, err := s.writer.DoTx(ctx, db.StdRetryCnt, db.ExpBackoff{}, func(r db.Reader, w db.Writer) error {
		for _, repo := range s.repos {
			deletedStoreIds, err := repo.ListDeletedStoreIds(ctx, since, WithReaderWriter(r, w))
			if err != nil {
				return err
			}
			deletedIds = append(deletedIds, deletedStoreIds...)
		}
		var err error
		now, err = r.Now(ctx)
		if err != nil {
			return err
		}
		return nil
	})
	if err != nil {
		return nil, time.Time{}, errors.Wrap(ctx, err, op)
	}
	return deletedIds, now, nil
}
