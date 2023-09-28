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

// LibraryRepository defines the interface expected
// to get the total number of credential libraries and deleted ids.
type LibraryRepository interface {
	EstimatedLibraryCount(context.Context) (int, error)
	EstimatedSSHCertificateLibraryCount(context.Context) (int, error)
	ListDeletedCredentialLibraryIds(context.Context, time.Time, ...Option) ([]string, error)
	ListDeletedSSHCertificateCredentialLibraryIds(context.Context, time.Time, ...Option) ([]string, error)
}

// NewLibraryService returns a new credential library service.
func NewLibraryService(ctx context.Context, writer db.Writer, repo LibraryRepository) (*LibraryService, error) {
	const op = "credential.NewLibraryService"
	switch {
	case util.IsNil(writer):
		return nil, errors.New(ctx, errors.InvalidParameter, op, "missing DB writer")
	case util.IsNil(repo):
		return nil, errors.New(ctx, errors.InvalidParameter, op, "missing credential library repo")
	}
	return &LibraryService{
		repo:   repo,
		writer: writer,
	}, nil
}

// LibraryService coordinates calls to across different subtype repositories
// to gather information about all credential libraries.
type LibraryService struct {
	repo   LibraryRepository
	writer db.Writer
}

// EstimatedCount gets an estimate of the total number of credential libraries across all types
func (s *CredentialLibraryService) EstimatedCount(ctx context.Context) (int, error) {
	const op = "credential.(*LibraryRepository).EstimatedCount"
	numGenericLibs, err := s.repo.EstimatedLibraryCount(ctx)
	if err != nil {
		return 0, errors.Wrap(ctx, err, op)
	}
	numSSHCertLibs, err := s.repo.EstimatedSSHCertificateLibraryCount(ctx)
	if err != nil {
		return 0, errors.Wrap(ctx, err, op)
	}
	return numGenericLibs + numSSHCertLibs, nil
}

// ListDeletedIds lists all deleted credential library IDs across all types
func (s *CredentialLibraryService) ListDeletedIds(ctx context.Context, since time.Time) ([]string, error) {
	const op = "credential.(*LibraryRepository).ListDeletedIds"
	var deletedIds []string
	_, err := s.writer.DoTx(ctx, db.StdRetryCnt, db.ExpBackoff{}, func(r db.Reader, w db.Writer) error {
		deletedLibIds, err := s.repo.ListDeletedLibraryIds(ctx, since, WithReaderWriter(r, w))
		if err != nil {
			return err
		}
		deletedSSHCertLibIds, err := s.repo.ListDeletedSSHCertificateLibraryIds(ctx, since, WithReaderWriter(r, w))
		if err != nil {
			return err
		}
		deletedIds = append(deletedLibIds, deletedSSHCertLibIds...)
		// TODO: Get transaction timestamp too
		return nil
	})
	if err != nil {
		return nil, errors.Wrap(ctx, err, op)
	}
	return deletedIds, nil
}

// Temporary - will be replaced once generic function is refactored
func (s *LibraryService) Now(ctx context.Context) (time.Time, error) {
	return time.Now(), nil
}
