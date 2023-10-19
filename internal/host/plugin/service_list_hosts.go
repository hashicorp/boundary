// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: BUSL-1.1

package plugin

import (
	"context"

	"github.com/hashicorp/boundary/internal/errors"
	"github.com/hashicorp/boundary/internal/host"
	"github.com/hashicorp/boundary/internal/pagination"
	"github.com/hashicorp/boundary/internal/plugin"
)

// FilterHostFunc defines the signature of the callback used to filter items after
// retrieval from the DB.
type FilterHostFunc func(ctx context.Context, item host.Host, plg *plugin.Plugin) (bool, error)

// ListHosts lists hosts according to the page size,
// filtering out entries that do not
// pass the filter item function. It returns a new refresh token
// based on the grants hash and the returned hosts.
func ListHosts(
	ctx context.Context,
	grantsHash []byte,
	pageSize int,
	filterHostFn FilterHostFunc,
	repo *Repository,
	hostCatalogId string,
) (*pagination.ListResponse[host.Host], *plugin.Plugin, error) {
	const op = "plugin.ListHosts"

	if len(grantsHash) == 0 {
		return nil, nil, errors.New(ctx, errors.InvalidParameter, op, "missing grants hash")
	}
	if pageSize < 1 {
		return nil, nil, errors.New(ctx, errors.InvalidParameter, op, "page size must be at least 1")
	}
	if filterHostFn == nil {
		return nil, nil, errors.New(ctx, errors.InvalidParameter, op, "missing filter host callback")
	}
	if repo == nil {
		return nil, nil, errors.New(ctx, errors.InvalidParameter, op, "missing repo")
	}
	if hostCatalogId == "" {
		return nil, nil, errors.New(ctx, errors.InvalidParameter, op, "missing host catalog id")
	}

	var plg *plugin.Plugin
	listItemsFn := func(ctx context.Context, lastPageItem host.Host, limit int) ([]host.Host, error) {
		opts := []Option{
			WithLimit(limit),
		}
		if lastPageItem != nil {
			opts = append(opts, WithStartPageAfterItem(lastPageItem))
		}
		var sHosts []*Host
		var err error
		sHosts, plg, err = repo.listHostsByCatalogId(ctx, hostCatalogId, opts...)
		if err != nil {
			return nil, err
		}
		var hosts []host.Host
		for _, host := range sHosts {
			hosts = append(hosts, host)
		}
		return hosts, nil
	}
	// Wrap the filter function in a callback that captures the plugin returned from
	// the list operation, so the plugin can be used when filtering.
	filterItemFn := func(ctx context.Context, item host.Host) (bool, error) {
		return filterHostFn(ctx, item, plg)
	}

	resp, err := pagination.List(ctx, grantsHash, pageSize, filterItemFn, listItemsFn, repo.estimatedHostCount)
	if err != nil {
		return nil, nil, err
	}

	return resp, plg, nil
}
