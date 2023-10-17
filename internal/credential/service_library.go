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

// VaultLibraryRepository defines the interface expected
// to get the total number of credential libraries and deleted ids.
type VaultLibraryRepository interface {
	EstimatedLibraryCount(context.Context) (int, error)
	EstimatedSSHCertificateLibraryCount(context.Context) (int, error)
	ListDeletedLibraryIds(context.Context, time.Time, ...Option) ([]string, error)
	ListDeletedSSHCertificateLibraryIds(context.Context, time.Time, ...Option) ([]string, error)
	ListCredentialLibraries(context.Context, string, ...Option) ([]Library, error)
	ListSSHCertificateCredentialLibraries(context.Context, string, ...Option) ([]Library, error)
}

// LibraryService coordinates calls to gather information about all credential libraries.
type LibraryService struct {
	repo   VaultLibraryRepository
	writer db.Writer
}

// NewLibraryService returns a new credential library service.
func NewLibraryService(ctx context.Context, writer db.Writer, repo VaultLibraryRepository) (*LibraryService, error) {
	const op = "credential.NewLibraryService"
	switch {
	case util.IsNil(writer):
		return nil, errors.New(ctx, errors.InvalidParameter, op, "missing DB writer")
	case util.IsNil(repo):
		return nil, errors.New(ctx, errors.InvalidParameter, op, "missing vault credential library repo")
	}
	return &LibraryService{
		repo:   repo,
		writer: writer,
	}, nil
}
