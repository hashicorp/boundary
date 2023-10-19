// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: BUSL-1.1

package static

import (
	"context"

	"github.com/hashicorp/boundary/internal/errors"
	"github.com/hashicorp/boundary/internal/host"
	"github.com/hashicorp/boundary/internal/pagination"
	"github.com/hashicorp/boundary/internal/refreshtoken"
)

// ListHostsRefresh lists hosts according to the page size
// and refresh token, filtering out entries that do not
// pass the filter item fn. It returns a new refresh token
// based on the old one, the grants hash, and the returned
// hosts.
func ListHostsRefresh(
	ctx context.Context,
	grantsHash []byte,
	pageSize int,
	filterItemFn pagination.ListFilterFunc[host.Host],
	tok *refreshtoken.Token,
	repo *Repository,
	hostCatalogId string,
) (*pagination.ListResponse[host.Host], error) {
	const op = "static.ListRefresh"

	if len(grantsHash) == 0 {
		return nil, errors.New(ctx, errors.InvalidParameter, op, "missing grants hash")
	}
	if pageSize < 1 {
		return nil, errors.New(ctx, errors.InvalidParameter, op, "page size must be at least 1")
	}
	if filterItemFn == nil {
		return nil, errors.New(ctx, errors.InvalidParameter, op, "missing filter item callback")
	}
	if tok == nil {
		return nil, errors.New(ctx, errors.InvalidParameter, op, "missing token")
	}
	if repo == nil {
		return nil, errors.New(ctx, errors.InvalidParameter, op, "missing repo")
	}
	if hostCatalogId == "" {
		return nil, errors.New(ctx, errors.InvalidParameter, op, "missing host catalog id")
	}

	listItemsFn := func(ctx context.Context, tok *refreshtoken.Token, lastPageItem host.Host, limit int) ([]host.Host, error) {
		opts := []Option{
			WithLimit(limit),
		}
		if lastPageItem != nil {
			opts = append(opts, WithStartPageAfterItem(lastPageItem))
		} else {
			opts = append(opts, WithStartPageAfterItem(tok.LastItem()))
		}
		pHosts, err := repo.listHosts(ctx, hostCatalogId, opts...)
		if err != nil {
			return nil, err
		}
		var hosts []host.Host
		for _, host := range pHosts {
			hosts = append(hosts, host)
		}
		return hosts, nil
	}

	return pagination.ListRefresh(ctx, grantsHash, pageSize, filterItemFn, listItemsFn, repo.estimatedHostCount, repo.listDeletedHostIds, tok)
}
