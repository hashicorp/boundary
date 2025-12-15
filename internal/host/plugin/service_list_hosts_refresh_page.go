// Copyright IBM Corp. 2020, 2025
// SPDX-License-Identifier: BUSL-1.1

package plugin

import (
	"context"
	"time"

	"github.com/hashicorp/boundary/globals"
	"github.com/hashicorp/boundary/internal/errors"
	"github.com/hashicorp/boundary/internal/host"
	"github.com/hashicorp/boundary/internal/listtoken"
	"github.com/hashicorp/boundary/internal/pagination"
	ppagination "github.com/hashicorp/boundary/internal/pagination/plugin"
	"github.com/hashicorp/boundary/internal/plugin"
	"github.com/hashicorp/boundary/internal/types/resource"
)

// ListHostsRefreshPage lists up to page size hosts, filtering out entries that
// do not pass the filter item function. It will automatically request
// more hosts from the database, at page size chunks, to fill the page.
// It will start its paging based on the information in the token.
// It returns a new list token used to continue pagination or refresh items.
// Hosts are ordered by update time descending (most recently updated first).
// Hosts may contain items that were already returned during the initial
// pagination phase. It also returns a list of any hosts deleted since the
// last response.
func ListHostsRefreshPage(
	ctx context.Context,
	grantsHash []byte,
	pageSize int,
	filterItemFn ppagination.ListPluginFilterFunc[host.Host],
	tok *listtoken.Token,
	repo *Repository,
	hostCatalogId string,
) (*pagination.ListResponse[host.Host], *plugin.Plugin, error) {
	const op = "credential.ListHostsRefreshPage"

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
	case tok.ResourceType != resource.Host:
		return nil, nil, errors.New(ctx, errors.InvalidParameter, op, "token did not have a host resource type")
	}
	rt, ok := tok.Subtype.(*listtoken.RefreshToken)
	if !ok {
		return nil, nil, errors.New(ctx, errors.InvalidParameter, op, "token did not have a refresh token component")
	}

	listItemsFn := func(ctx context.Context, lastPageItem host.Host, limit int) ([]host.Host, *plugin.Plugin, time.Time, error) {
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
		// Add the database read timeout to account for any creations missed due to concurrent
		// transactions in the original list pagination phase.
		pHosts, plg, listTime, err := repo.listHostsRefresh(ctx, hostCatalogId, rt.PhaseLowerBound.Add(-globals.RefreshReadLookbackDuration), opts...)
		if err != nil {
			return nil, nil, time.Time{}, err
		}
		var hosts []host.Host
		for _, host := range pHosts {
			hosts = append(hosts, host)
		}
		return hosts, plg, listTime, nil
	}
	listDeletedIdsFn := func(ctx context.Context, since time.Time) ([]string, time.Time, error) {
		// Add the database read timeout to account for any deletes missed due to concurrent
		// transactions in the original list pagination phase.
		return repo.listDeletedHostIds(ctx, since.Add(-globals.RefreshReadLookbackDuration))
	}

	return ppagination.ListPluginRefreshPage(ctx, grantsHash, pageSize, filterItemFn, listItemsFn, repo.estimatedHostCount, listDeletedIdsFn, tok)
}
