// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: BUSL-1.1

package vault

import (
	"context"

	"github.com/hashicorp/boundary/internal/db"
	"github.com/hashicorp/boundary/internal/errors"
	"github.com/hashicorp/boundary/internal/util"
)

// LibraryService coordinates calls to gather information about all credential libraries.
type LibraryService struct {
	repo   *Repository
	writer db.Writer
}

// NewLibraryService returns a new credential library service.
func NewLibraryService(ctx context.Context, writer db.Writer, repo *Repository) (*LibraryService, error) {
	const op = "vault.NewLibraryService"
	switch {
	case util.IsNil(writer):
		return nil, errors.New(ctx, errors.InvalidParameter, op, "missing DB writer")
	case util.IsNil(repo):
		return nil, errors.New(ctx, errors.InvalidParameter, op, "missing vault repo")
	}
	return &LibraryService{
		repo:   repo,
		writer: writer,
	}, nil
}
