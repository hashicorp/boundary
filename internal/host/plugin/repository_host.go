// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: BUSL-1.1


package plugin

import (
	"context"
	"fmt"

	"github.com/hashicorp/boundary/internal/db"
	"github.com/hashicorp/boundary/internal/errors"
	"github.com/hashicorp/boundary/internal/plugin"
)

// LookupHost will look up a host in the repository. If the host is not
// found, it will return nil, nil. All options are ignored.
func (r *Repository) LookupHost(ctx context.Context, publicId string, opt ...Option) (*Host, *plugin.Plugin, error) {
	const op = "plugin.(Repository).LookupHost"
	if publicId == "" {
		return nil, nil, errors.New(ctx, errors.InvalidParameter, op, "no public id")
	}
	ha := &hostAgg{
		PublicId: publicId,
	}
	if err := r.reader.LookupByPublicId(ctx, ha); err != nil {
		if errors.IsNotFoundError(err) {
			return nil, nil, nil
		}
		return nil, nil, errors.Wrap(ctx, err, op, errors.WithMsg(fmt.Sprintf("failed for %s", publicId)))
	}
	plg, err := r.getPlugin(ctx, ha.PluginId)
	if err != nil {
		return nil, nil, errors.Wrap(ctx, err, op)
	}
	return ha.toHost(), plg, nil
}

// ListHostsByCatalogId returns a slice of Hosts for the catalogId.
// WithLimit is the only option supported.
func (r *Repository) ListHostsByCatalogId(ctx context.Context, catalogId string, opt ...Option) ([]*Host, *plugin.Plugin, error) {
	const op = "plugin.(Repository).ListHostsByCatalogId"
	if catalogId == "" {
		return nil, nil, errors.New(ctx, errors.InvalidParameter, op, "no catalog id")
	}
	opts := getOpts(opt...)
	limit := r.defaultLimit
	if opts.withLimit != 0 {
		// non-zero signals an override of the default limit for the repo.
		limit = opts.withLimit
	}
	var hostAggs []*hostAgg
	err := r.reader.SearchWhere(ctx, &hostAggs, "catalog_id = ?", []any{catalogId}, db.WithLimit(limit))

	switch {
	case err != nil:
		return nil, nil, errors.Wrap(ctx, err, op)
	case len(hostAggs) == 0:
		return nil, nil, nil
	}

	pluginId := hostAggs[0].PluginId
	plg, err := r.getPlugin(ctx, pluginId)
	if err != nil {
		return nil, nil, errors.Wrap(ctx, err, op)
	}

	hosts := make([]*Host, 0, len(hostAggs))
	for _, ha := range hostAggs {
		hosts = append(hosts, ha.toHost())
	}

	return hosts, plg, nil
}

// ListHostsBySetId returns a slice of Hosts for the given set IDs.
// WithLimit is the only option supported.
func (r *Repository) ListHostsBySetIds(ctx context.Context, setIds []string, opt ...Option) ([]*Host, error) {
	const op = "plugin.(Repository).ListHostsBySetIds"
	if len(setIds) == 0 {
		return nil, errors.New(ctx, errors.InvalidParameter, op, "no set ids")
	}
	opts := getOpts(opt...)
	limit := r.defaultLimit
	if opts.withLimit != 0 {
		// non-zero signals an override of the default limit for the repo.
		limit = opts.withLimit
	}
	hs, err := listHostBySetIds(ctx, r.reader, setIds, WithLimit(limit))
	if err != nil {
		return nil, errors.Wrap(ctx, err, op)
	}
	return hs, nil
}

func listHostBySetIds(ctx context.Context, reader db.Reader, setIds []string, opt ...Option) ([]*Host, error) {
	const op = "plugin.listHostsBySetIds"
	opts := getOpts(opt...)
	query := `
public_id in
	(select distinct host_id
		from host_plugin_set_member
		where set_id in (?))
`

	var hostAggs []*hostAgg
	err := reader.SearchWhere(ctx, &hostAggs, query, []any{setIds}, db.WithLimit(opts.withLimit))

	switch {
	case err != nil:
		return nil, errors.Wrap(ctx, err, op)
	case hostAggs == nil:
		return nil, nil
	}

	hosts := make([]*Host, 0, len(hostAggs))
	for _, ha := range hostAggs {
		hosts = append(hosts, ha.toHost())
	}

	return hosts, nil
}
