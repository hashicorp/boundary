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

func ListUpdatedSince(
	ctx context.Context,
	tok *refreshtoken.RefreshToken,
	repo *Repository,
	grantsHash []byte,
	pageSize int,
	filterItemFn func(Target) (bool, error),
) (*ListResponse, error) {
	const op = "target.ListMore"

	deletedIds, transactionTimestamp, err := repo.listDeletedIds(ctx, tok.CreatedTime)
	if err != nil {
		return nil, errors.Wrap(ctx, err, op)
	}

	limit := pageSize + 1
	opts := []Option{
		WithLimit(limit),
		WithStartPageAfterItem(tok.LastItemId, tok.LastItemUpdatedTime),
	}

	// pagination magic
	targets := make([]Target, 0, pageSize+1)
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
			WithStartPageAfterItem(page[len(page)-1].GetPublicId(), page[len(page)-1].GetUpdateTime().AsTime()),
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
		RefreshToken: &refreshtoken.RefreshToken{
			// Use the timestamp of the deleted IDs transaction with a
			// buffer to account for overlapping transactions. It is okay
			// to return a deleted ID more than once. The buffer corresponds
			// to Postgres' default transaction timeout.
			CreatedTime:         transactionTimestamp.Add(-30 * time.Second),
			ResourceType:        resource.Target,
			GrantsHash:          grantsHash,
			LastItemId:          tok.LastItemId,
			LastItemUpdatedTime: tok.LastItemUpdatedTime,
		},
	}

	if len(targets) > 0 {
		resp.RefreshToken.LastItemId = targets[len(targets)-1].GetPublicId()
		resp.RefreshToken.LastItemUpdatedTime = targets[len(targets)-1].GetUpdateTime().AsTime()
	}

	return resp, nil
}
