// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: BUSL-1.1

package target

import (
	"context"

	"github.com/hashicorp/boundary/internal/errors"
	"github.com/hashicorp/boundary/internal/refreshtoken"
)

// This function is a callback passed down from the application service layer
// used to filter out protobuf targets that don't match any user-supplied filter.
type ListFilterFunc func(Target) (bool, error)

// List lists targets according to the page size,
// filtering out entries that do not
// pass the filter item fn. It returns a new refresh token
// based on the grants hash and the returned targets.
func List(
	ctx context.Context,
	grantsHash []byte,
	pageSize int,
	filterItemFn ListFilterFunc,
	repo *Repository,
) (*ListResponse, error) {
	const op = "target.List"

	limit := pageSize + 1
	opts := []Option{
		WithLimit(limit),
	}

	targets := make([]Target, 0, limit)
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
				return nil, err
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
	totalItems := len(targets)
	if !completeListing {
		// Items is of size pageSize+1, so
		// truncate if it was filled.
		targets = targets[:pageSize]
		// If this was not a complete listing, get an estimate
		// of the total items from the DB.
		var err error
		totalItems, err = repo.estimatedCount(ctx)
		if err != nil {
			return nil, errors.Wrap(ctx, err, op)
		}
	}

	resp := &ListResponse{
		Items:               targets,
		EstimatedTotalItems: totalItems,
		CompleteListing:     completeListing,
	}

	if len(targets) > 0 {
		resp.RefreshToken = refreshtoken.FromResource(targets[len(targets)-1], grantsHash)
	}

	return resp, nil
}
