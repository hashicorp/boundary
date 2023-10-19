// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: BUSL-1.1

package target

import (
	"context"

	"github.com/hashicorp/boundary/internal/pagination"
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
	filterItemFn pagination.ListFilterFunc[Target],
) (*pagination.ListResponse2[Target], error) {
	listItemsFn := func(ctx context.Context, tok *refreshtoken.Token, lastPageItem Target, limit int) ([]Target, error) {
		opts := []Option{
			WithLimit(limit),
		}
		if lastPageItem != nil {
			opts = append(opts,
				WithStartPageAfterItem(lastPageItem.GetPublicId(), lastPageItem.GetUpdateTime().AsTime()),
			)
		} else {
			opts = append(opts,
				WithStartPageAfterItem(tok.LastItemId, tok.LastItemUpdatedTime),
			)
		}
		return repo.listTargets(ctx, opts...)
	}

	return pagination.ListRefresh(ctx, grantsHash, pageSize, filterItemFn, listItemsFn, repo.estimatedCount, repo.listDeletedIds, tok)
}
