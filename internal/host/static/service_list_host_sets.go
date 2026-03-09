// Copyright IBM Corp. 2020, 2025
// SPDX-License-Identifier: BUSL-1.1

package static

import (
	"context"
	"time"

	"github.com/hashicorp/boundary/internal/errors"
	"github.com/hashicorp/boundary/internal/host"
	"github.com/hashicorp/boundary/internal/pagination"
)

// ListHostSets lists up to page size host sets, filtering out entries that
// do not pass the filter item function. It will automatically request
// more host sets from the database, at page size chunks, to fill the page.
// It returns a new list token used to continue pagination or refresh items.
// Host sets are ordered by create time descending (most recently created first).
func ListHostSets(
	ctx context.Context,
	grantsHash []byte,
	pageSize int,
	filterItemFn pagination.ListFilterFunc[host.Set],
	repo *Repository,
	hostCatalogId string,
) (*pagination.ListResponse[host.Set], error) {
	const op = "plugin.ListHostSets"

	switch {
	case len(grantsHash) == 0:
		return nil, errors.New(ctx, errors.InvalidParameter, op, "missing grants hash")
	case pageSize < 1:
		return nil, errors.New(ctx, errors.InvalidParameter, op, "page size must be at least 1")
	case filterItemFn == nil:
		return nil, errors.New(ctx, errors.InvalidParameter, op, "missing filter item callback")
	case repo == nil:
		return nil, errors.New(ctx, errors.InvalidParameter, op, "missing repo")
	case hostCatalogId == "":
		return nil, errors.New(ctx, errors.InvalidParameter, op, "missing host catalog ID")
	}

	listItemsFn := func(ctx context.Context, lastPageItem host.Set, limit int) ([]host.Set, time.Time, error) {
		opts := []Option{
			WithLimit(limit),
		}
		if lastPageItem != nil {
			opts = append(opts, WithStartPageAfterItem(lastPageItem))
		}
		sSets, listTime, err := repo.listSets(ctx, hostCatalogId, opts...)
		if err != nil {
			return nil, time.Time{}, err
		}
		var sets []host.Set
		for _, set := range sSets {
			sets = append(sets, set)
		}
		return sets, listTime, nil
	}

	return pagination.List(ctx, grantsHash, pageSize, filterItemFn, listItemsFn, repo.estimatedSetCount)
}
