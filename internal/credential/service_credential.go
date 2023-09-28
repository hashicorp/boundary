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

// CredentialRepository defines the interface expected
// to get the total number of credentials and deleted ids.
type CredentialRepository interface {
	EstimatedCredentialCount(context.Context) (int, error)
	ListDeletedCredentialIds(context.Context, time.Time, ...Option) ([]string, error)
}

// NewCredentialService returns a new credential service.
func NewCredentialService(ctx context.Context, writer db.Writer, repo CredentialRepository) (*CredentialService, error) {
	const op = "credential.NewCredentialService"
	switch {
	case util.IsNil(writer):
		return nil, errors.New(ctx, errors.InvalidParameter, op, "missing DB writer")
	case util.IsNil(repo):
		return nil, errors.New(ctx, errors.InvalidParameter, op, "missing credential repo")
	}
	return &CredentialService{
		repo:   repo,
		writer: writer,
	}, nil
}

// CredentialService coordinates calls to across different subtype repositories
// to gather information about all credentials.
type CredentialService struct {
	repo   CredentialRepository
	writer db.Writer
}

// EstimatedCount gets an estimate of the total number of credentials across all types
func (s *CredentialService) EstimatedCount(ctx context.Context) (int, error) {
	const op = "credential.(*CredentialService).EstimatedCount"
	numCreds, err := s.repo.EstimatedCredentialCount(ctx)
	if err != nil {
		return 0, errors.Wrap(ctx, err, op)
	}
	return numCreds, nil
}

// ListDeletedIds lists all deleted credential IDs across all types,
// and returns the timestamp of the transaction, to be used in other ListDeletedIds transactions.
// This should ensure the correct list of deleted IDs is always returned.
func (s *CredentialService) ListDeletedIds(ctx context.Context, since time.Time) ([]string, time.Time, error) {
	const op = "credential.(*CredentialService).ListDeletedIds"
	var deletedIds []string
	var now time.Time
	_, err := s.writer.DoTx(ctx, db.StdRetryCnt, db.ExpBackoff{}, func(r db.Reader, w db.Writer) error {
		deletedCredsIds, err := s.repo.ListDeletedCredentialIds(ctx, since, WithReaderWriter(r, w))
		if err != nil {
			return err
		}
		now, err = r.Now(ctx)
		if err != nil {
			return err
		}
		deletedIds = append(deletedIds, deletedCredsIds...)
		return nil
	})
	if err != nil {
		return nil, time.Time{}, errors.Wrap(ctx, err, op)
	}
	return deletedIds, now, nil
}
