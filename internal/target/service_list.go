// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: BUSL-1.1

package target

import (
	"context"
	"time"

	"github.com/hashicorp/boundary/internal/errors"
	"github.com/hashicorp/boundary/internal/refreshtoken"
	"github.com/hashicorp/boundary/internal/types/resource"
)

func List(
	ctx context.Context,
	repo *Repository,
	grantsHash []byte,
	pageSize int,
	filterItemFn func(Target) (bool, error),
) (*ListResponse, error) {
	const op = "target.List"

	limit := pageSize + 1
	opts := []Option{
		WithLimit(limit),
	}

	// pagination magic
	targets := make([]Target, 0, limit)
dbLoop:
	for {
		// Request another page from the DB until we fill the final items
		page, err := repo.ListTargets(ctx, opts...)
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
			WithStartPageAfterItem(page[len(page)-1].GetPublicId(), page[len(page)-1].GetUpdateTime().AsTime()),
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
		resp.RefreshToken = &refreshtoken.RefreshToken{
			CreatedTime:         time.Now(),
			ResourceType:        resource.Target,
			GrantsHash:          grantsHash,
			LastItemId:          targets[len(targets)-1].GetPublicId(),
			LastItemUpdatedTime: targets[len(targets)-1].GetUpdateTime().AsTime(),
		}
	}

	return resp, nil
}
