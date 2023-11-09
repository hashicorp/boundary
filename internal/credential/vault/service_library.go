// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: BUSL-1.1

package vault

import (
	"context"

	"github.com/hashicorp/boundary/internal/db"
	"github.com/hashicorp/boundary/internal/errors"
	"github.com/hashicorp/boundary/internal/util"
)

// LibraryListingService coordinates calls to gather information about all credential libraries.
type LibraryListingService struct {
	repo   *Repository
	writer db.Writer
}

// NewLibraryListingService returns a new credential library listing service.
func NewLibraryListingService(ctx context.Context, writer db.Writer, repo *Repository) (*LibraryListingService, error) {
	const op = "vault.NewLibraryListingService"
	switch {
	case util.IsNil(writer):
		return nil, errors.New(ctx, errors.InvalidParameter, op, "missing DB writer")
	case util.IsNil(repo):
		return nil, errors.New(ctx, errors.InvalidParameter, op, "missing vault repo")
	}
	return &LibraryListingService{
		repo:   repo,
		writer: writer,
	}, nil
}
