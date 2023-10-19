// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: BUSL-1.1

package plugin

import (
	"context"
	"database/sql"
	"fmt"
	"time"

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

// listHostsByCatalogId returns a slice of Hosts for the catalogId.
// Supported options:
//   - WithLimit which overrides the limit set in the Repository object
//   - WithStartPageAfterItem which sets where to start listing from
func (r *Repository) listHostsByCatalogId(ctx context.Context, catalogId string, opt ...Option) ([]*Host, *plugin.Plugin, error) {
	const op = "plugin.(Repository).listHostsByCatalogId"
	if catalogId == "" {
		return nil, nil, errors.New(ctx, errors.InvalidParameter, op, "no catalog id")
	}
	opts := getOpts(opt...)
	limit := r.defaultLimit
	if opts.withLimit != 0 {
		// non-zero signals an override of the default limit for the repo.
		limit = opts.withLimit
	}
	whereClause := "catalog_id = @catalog_id"
	args := []any{sql.Named("catalog_id", catalogId)}
	// Ordering and pagination are tightly coupled.
	// We order by update_time ascending so that new
	// and updated items appear at the end of the pagination.
	// We need to further order by public_id to distinguish items
	// with identical update times.
	withOrder := "update_time asc, public_id asc"
	if opts.withStartPageAfterItem != nil {
		// Now that the order is defined, we can use a simple where
		// clause to only include items updated since the specified
		// start of the page. We use greater than or equal for the update
		// time as there may be items with identical update_times. We
		// then use public_id as a tiebreaker.
		args = append(args,
			sql.Named("after_item_update_time", opts.withStartPageAfterItem.GetUpdateTime()),
			sql.Named("after_item_id", opts.withStartPageAfterItem.GetPublicId()),
		)
		whereClause = "(" + whereClause + ") and (update_time > @after_item_update_time or (update_time = @after_item_update_time and public_id > @after_item_id))"
	}
	var hostAggs []*hostAgg
	err := r.reader.SearchWhere(ctx, &hostAggs, whereClause, args, db.WithLimit(limit), db.WithOrder(withOrder))

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

// listDeletedHostIds lists the public IDs of any hosts deleted since the timestamp provided,
// and the timestamp of the transaction within which the hosts were listed.
func (r *Repository) listDeletedHostIds(ctx context.Context, since time.Time) ([]string, time.Time, error) {
	const op = "static.(Repository).listDeletedHostIds"
	var deleteHosts []*deletedHost
	var transactionTimestamp time.Time
	if _, err := r.writer.DoTx(ctx, db.StdRetryCnt, db.ExpBackoff{}, func(r db.Reader, _ db.Writer) error {
		if err := r.SearchWhere(ctx, &deleteHosts, "delete_time >= ?", []any{since}); err != nil {
			return errors.Wrap(ctx, err, op, errors.WithMsg("failed to query deleted hosts"))
		}
		var err error
		transactionTimestamp, err = r.Now(ctx)
		if err != nil {
			return errors.Wrap(ctx, err, op, errors.WithMsg("failed to get transaction timestamp"))
		}
		return nil
	}); err != nil {
		return nil, time.Time{}, err
	}
	var hostIds []string
	for _, t := range deleteHosts {
		hostIds = append(hostIds, t.PublicId)
	}
	return hostIds, transactionTimestamp, nil
}

// estimatedHostCount returns an estimate of the total number of plugin hosts.
func (r *Repository) estimatedHostCount(ctx context.Context) (int, error) {
	const op = "plugin.(Repository).estimatedHostCount"
	rows, err := r.reader.Query(ctx, estimateCountHosts, nil)
	if err != nil {
		return 0, errors.Wrap(ctx, err, op, errors.WithMsg("failed to query plugin hosts"))
	}
	var count int
	for rows.Next() {
		if err := r.reader.ScanRows(ctx, rows, &count); err != nil {
			return 0, errors.Wrap(ctx, err, op, errors.WithMsg("failed to query plugin hosts"))
		}
	}
	return count, nil
}
