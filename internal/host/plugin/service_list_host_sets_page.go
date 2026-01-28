// Copyright IBM Corp. 2020, 2025
// SPDX-License-Identifier: BUSL-1.1

package plugin

import (
	"context"
	"time"

	"github.com/hashicorp/boundary/internal/errors"
	"github.com/hashicorp/boundary/internal/host"
	"github.com/hashicorp/boundary/internal/listtoken"
	"github.com/hashicorp/boundary/internal/pagination"
	ppagination "github.com/hashicorp/boundary/internal/pagination/plugin"
	"github.com/hashicorp/boundary/internal/plugin"
	"github.com/hashicorp/boundary/internal/types/resource"
)

// ListPage lists up to page size host sets, filtering out entries that
// do not pass the filter item function. It will automatically request
// more host sets from the database, at page size chunks, to fill the page.
// It will start its paging based on the information in the token.
// It returns a new list token used to continue pagination or refresh items.
// Host sets are ordered by create time descending (most recently created first).
func ListHostSetsPage(
	ctx context.Context,
	grantsHash []byte,
	pageSize int,
	filterItemFn ppagination.ListPluginFilterFunc[host.Set],
	tok *listtoken.Token,
	repo *Repository,
	hostCatalogId string,
) (*pagination.ListResponse[host.Set], *plugin.Plugin, error) {
	const op = "plugin.ListHostSetsPage"

	switch {
	case len(grantsHash) == 0:
		return nil, nil, errors.New(ctx, errors.InvalidParameter, op, "missing grants hash")
	case pageSize < 1:
		return nil, nil, errors.New(ctx, errors.InvalidParameter, op, "page size must be at least 1")
	case filterItemFn == nil:
		return nil, nil, errors.New(ctx, errors.InvalidParameter, op, "missing filter item callback")
	case tok == nil:
		return nil, nil, errors.New(ctx, errors.InvalidParameter, op, "missing token")
	case repo == nil:
		return nil, nil, errors.New(ctx, errors.InvalidParameter, op, "missing repo")
	case hostCatalogId == "":
		return nil, nil, errors.New(ctx, errors.InvalidParameter, op, "missing host catalog ID")
	case tok.ResourceType != resource.HostSet:
		return nil, nil, errors.New(ctx, errors.InvalidParameter, op, "token did not have a host set resource type")
	}
	if _, ok := tok.Subtype.(*listtoken.PaginationToken); !ok {
		return nil, nil, errors.New(ctx, errors.InvalidParameter, op, "token did not have a pagination token component")
	}

	listItemsFn := func(ctx context.Context, lastPageItem host.Set, limit int) ([]host.Set, *plugin.Plugin, time.Time, error) {
		opts := []Option{
			WithLimit(limit),
		}
		if lastPageItem != nil {
			opts = append(opts, WithStartPageAfterItem(lastPageItem))
		} else {
			lastItem, err := tok.LastItem(ctx)
			if err != nil {
				return nil, nil, time.Time{}, err
			}
			opts = append(opts, WithStartPageAfterItem(lastItem))
		}
		pSets, plg, listTime, err := repo.listSets(ctx, hostCatalogId, opts...)
		if err != nil {
			return nil, nil, time.Time{}, err
		}
		var sets []host.Set
		for _, set := range pSets {
			sets = append(sets, set)
		}
		return sets, plg, listTime, nil
	}

	return ppagination.ListPluginPage(ctx, grantsHash, pageSize, filterItemFn, listItemsFn, repo.estimatedSetCount, tok)
}
