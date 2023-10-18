// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: BUSL-1.1

package target

import (
	"context"

	"github.com/hashicorp/boundary/internal/errors"
	"github.com/hashicorp/boundary/internal/refreshtoken"
)

// ListRefresh lists targets according to the page size
// and refresh token, filtering out entries that do not
// pass the filter item fn. It returns a new refresh token
// based on the old one, the grants hash, and the returned
// targets.
func ListRefresh(
	ctx context.Context,
	tok *refreshtoken.Token,
	repo *Repository,
	grantsHash []byte,
	pageSize int,
	filterItemFn func(Target) (bool, error),
) (*ListResponse, error) {
	const op = "target.ListRefresh"

	deletedIds, transactionTimestamp, err := repo.listDeletedIds(ctx, tok.UpdatedTime)
	if err != nil {
		return nil, errors.Wrap(ctx, err, op)
	}

	limit := pageSize + 1
	opts := []Option{
		WithLimit(limit),
		WithStartPageAfterItem(tok.ToPartialResource()),
	}

	targets := make([]Target, 0, pageSize+1)
dbLoop:
	for {
		// Request another page from the DB until we fill the final items
		page, err := repo.listTargets(ctx, opts...)
		if err != nil {
			return nil, errors.Wrap(ctx, err, op)
		}
		for _, item := range page {
			ok, err := filterItemFn(item)
			if err != nil {
				return nil, errors.Wrap(ctx, err, op)
			}
			if ok {
				targets = append(targets, item)
				// If we filled the items after filtering,
				// we're done.
				if len(targets) == cap(targets) {
					break dbLoop
				}
			}
		}
		// If the current page was shorter than the limit, stop iterating
		if len(page) < limit {
			break dbLoop
		}

		opts = []Option{
			WithLimit(limit),
			WithStartPageAfterItem(page[len(page)-1]),
		}
	}
	// If we couldn't fill the items, it was a complete listing.
	completeListing := len(targets) < cap(targets)
	if !completeListing {
		// Items is of size pageSize+1, so
		// truncate if it was filled.
		targets = targets[:pageSize]
	}

	totalItems, err := repo.estimatedCount(ctx)
	if err != nil {
		return nil, errors.Wrap(ctx, err, op)
	}

	resp := &ListResponse{
		Items:               targets,
		DeletedIds:          deletedIds,
		EstimatedTotalItems: totalItems,
		CompleteListing:     completeListing,
	}

	if len(targets) > 0 {
		resp.RefreshToken = tok.RefreshLastItem(targets[len(targets)-1], transactionTimestamp)
	} else {
		resp.RefreshToken = tok.Refresh(transactionTimestamp)
	}

	return resp, nil
}
