// Copyright IBM Corp. 2020, 2025
// SPDX-License-Identifier: BUSL-1.1

package alias

import (
	"context"

	"github.com/hashicorp/boundary/internal/db"
	"github.com/hashicorp/boundary/internal/errors"
	"github.com/hashicorp/boundary/internal/kms"
	"github.com/hashicorp/boundary/internal/util"
)

// A Repository stores and retrieves the persistent types in the alias
// package. It is not safe to use a repository concurrently.
type Repository struct {
	txm db.TransactionManager
	kms *kms.Kms
}

// NewRepository creates a new Repository. The returned repository should
// only be used for one transaction and it is not safe for concurrent go
// routines to access it.
func NewRepository(ctx context.Context, txm db.TransactionManager, kms *kms.Kms) (*Repository, error) {
	const op = "alias.NewRepository"
	switch {
	case util.IsNil(txm):
		return nil, errors.New(ctx, errors.InvalidParameter, op, "missing transaction manager")
	case kms == nil:
		return nil, errors.New(ctx, errors.InvalidParameter, op, "missing kms")
	}

	return &Repository{
		txm: txm,
		kms: kms,
	}, nil
}
