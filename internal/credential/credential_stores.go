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
	EsimatedStoreCount(context.Context) (int, error)
	ListDeletedCredentialStoreIds(context.Context, time.Time, ...Option) ([]string, error)
}

// NewCredentialStoreService returns a new credential store service.
func NewCredentialStoreService(ctx context.Context, writer db.Writer, vaultRepo StoreRepository, staticRepo StoreRepository) (*CredentialStoreService, error) {
	const op = "credential.NewCredentialStoreService"
	switch {
	case util.IsNil(writer):
		return nil, errors.New(ctx, errors.InvalidParameter, op, "missing DB writer")
	case util.IsNil(vaultRepo):
		return nil, errors.New(ctx, errors.InvalidParameter, op, "missing vault repo")
	case util.IsNil(staticRepo):
		return nil, errors.New(ctx, errors.InvalidParameter, op, "missing vault repo")
	}
	return &CredentialStoreService{
		repos:  []StoreRepository{vaultRepo, staticRepo},
		writer: writer,
	}, nil
}

// CredentialStoreService coordinates calls to across different subtype repositories
// to gather information about all credential stores.
type CredentialStoreService struct {
	repos  []StoreRepository
	writer db.Writer
}

// EstimatedCount gets an estimate of the total number of credential stores across all types
func (s *CredentialStoreService) EstimatedCount(ctx context.Context) (int, error) {
	const op = "credential.(*StoreRepository).EstimatedCount"
	var totalNumStores int
	for _, repo := range s.repos {
		numStores, err := repo.EsimatedStoreCount(ctx)
		if err != nil {
			return 0, errors.Wrap(ctx, err, op)
		}
		totalNumStores += numStores
	}
	return totalNumStores, nil
}

// ListDeletedIds lists all deleted credential store IDs across all types
func (s *CredentialStoreService) ListDeletedIds(ctx context.Context, since time.Time) ([]string, error) {
	const op = "credential.(*StoreRepository).ListDeletedIds"
	var deletedIds []string
	_, err := s.writer.DoTx(ctx, db.StdRetryCnt, db.ExpBackoff{}, func(r db.Reader, w db.Writer) error {
		for _, repo := range s.repos {
			deletedStoreIds, err := repo.ListDeletedCredentialStoreIds(ctx, since, WithReaderWriter(r, w))
			if err != nil {
				return err
			}
			deletedIds = append(deletedIds, deletedStoreIds...)
		}
		// TODO: Get transaction timestamp too
		return nil
	})
	if err != nil {
		return nil, errors.Wrap(ctx, err, op)
	}
	return deletedIds, nil
}

// Temporary - will be replaced once generic function is refactored
func (s *CredentialStoreService) Now(ctx context.Context) (time.Time, error) {
	return time.Now(), nil
}
