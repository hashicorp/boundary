// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: BUSL-1.1

package target

import (
	"context"

	"github.com/hashicorp/boundary/internal/pagination"
)

// List lists targets according to the page size,
// filtering out entries that do not
// pass the filter item function. It returns a new refresh token
// based on the grants hash and the returned targets.
func List(
	ctx context.Context,
	repo *Repository,
	grantsHash []byte,
	pageSize int,
	filterItemFn pagination.ListFilterFunc[Target],
) (*pagination.ListResponse2[Target], error) {
	listItemsFn := func(ctx context.Context, lastPageItem Target, limit int) ([]Target, error) {
		opts := []Option{
			WithLimit(limit),
		}
		if lastPageItem != nil {
			opts = append(opts,
				WithStartPageAfterItem(lastPageItem.GetPublicId(), lastPageItem.GetUpdateTime().AsTime()),
			)
		}
		return repo.listTargets(ctx, opts...)
	}

	return pagination.List(ctx, grantsHash, pageSize, filterItemFn, listItemsFn, repo.estimatedCount)
}
