// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: BUSL-1.1

package apptoken

import (
	"context"

	"github.com/hashicorp/boundary/internal/db"
	"github.com/hashicorp/boundary/internal/errors"
	"github.com/hashicorp/boundary/internal/iam"
	"github.com/hashicorp/boundary/internal/kms"
	"github.com/hashicorp/boundary/internal/perms"
	"github.com/hashicorp/boundary/internal/util"
)

// RepositoryFactory enables `apptoken.Repository` object instantiation,
// and is used by the various service packages/controller object to do so.
type RepositoryFactory func(...Option) (*Repository, error)

// grantFinder defines a single func interface which is implemented by iam.Repository.
type grantFinder interface {
	GrantsForUser(ctx context.Context, userId string, opt ...iam.Option) ([]perms.GrantTuple, error)
}

// Repository is the apptoken database repository
type Repository struct {
	reader      db.Reader
	writer      db.Writer
	kms         kms.GetWrapperer
	grantFinder grantFinder

	// defaultLimit provides a default for limiting the number of results returned from the repo.
	// If defaultLimit < 0, then unlimited results are returned. If defaultLimit == 0, then boundary
	// default limits are used for results
	defaultLimit int
}

// NewRepository creates a new apptoken Repository. Supports the options: WithLimit
// which sets a default limit on results returned by repo operations.
func NewRepository(ctx context.Context, r db.Reader, w db.Writer, kms kms.GetWrapperer, gf grantFinder, opt ...Option) (*Repository, error) {
	const op = "apptoken.NewRepository"
	if util.IsNil(r) {
		return nil, errors.New(ctx, errors.InvalidParameter, op, "nil reader")
	}
	if util.IsNil(w) {
		return nil, errors.New(ctx, errors.InvalidParameter, op, "nil writer")
	}
	if util.IsNil(kms) {
		return nil, errors.New(ctx, errors.InvalidParameter, op, "nil kms")
	}
	opts, err := getOpts(opt...)
	if err != nil {
		return nil, errors.Wrap(ctx, err, op)
	}
	if opts.withLimit == 0 {
		// zero signals the boundary defaults should be used.
		opts.withLimit = db.DefaultLimit
	}
	return &Repository{
		reader:       r,
		writer:       w,
		kms:          kms,
		grantFinder:  gf,
		defaultLimit: opts.withLimit,
	}, nil
}

type userHistory struct {
	PublicId  string
	HistoryId string
}

func (userHistory) TableName() string {
	return "iam_user_hst"
}

// ResolveUserHistoryId will lookup the userId and return its user history id
func (r *Repository) ResolveUserHistoryId(ctx context.Context, userId string) (string, error) {
	const op = "apptoken.(Repository).ResolveUserHistoryId"

	switch {
	case userId == "":
		return "", errors.New(ctx, errors.InvalidParameter, op, "missing user id")
	}
	var hst userHistory
	if err := r.reader.LookupWhere(ctx, &hst, "public_id = ?", []any{userId}, db.WithOrder("DESC valid_range")); err != nil {
		return "", errors.Wrap(ctx, err, op)
	}
	return hst.HistoryId, nil
}
