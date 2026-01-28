// Copyright IBM Corp. 2020, 2025
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

// listHosts returns a slice of Hosts for the catalogId and the associated plugin.
// Supported options:
//   - WithLimit which overrides the limit set in the Repository object
//   - WithStartPageAfterItem which sets where to start listing from
func (r *Repository) listHosts(ctx context.Context, catalogId string, opt ...Option) ([]*Host, *plugin.Plugin, time.Time, error) {
	const op = "plugin.(Repository).listHosts"
	if catalogId == "" {
		return nil, nil, time.Time{}, errors.New(ctx, errors.InvalidParameter, op, "no catalog id")
	}
	opts := getOpts(opt...)
	limit := r.defaultLimit
	if opts.withLimit != 0 {
		// non-zero signals an override of the default limit for the repo.
		limit = opts.withLimit
	}
	query := fmt.Sprintf(listHostsTemplate, limit)
	args := []any{sql.Named("catalog_id", catalogId)}
	if opts.withStartPageAfterItem != nil {
		query = fmt.Sprintf(listHostsPageTemplate, limit)
		args = append(args,
			sql.Named("last_item_create_time", opts.withStartPageAfterItem.GetCreateTime()),
			sql.Named("last_item_id", opts.withStartPageAfterItem.GetPublicId()),
		)
	}

	return r.queryHosts(ctx, query, args)
}

// listHostsRefresh returns a slice of Hosts for the catalogId and the associated plugin.
// Supported options:
//   - WithLimit which overrides the limit set in the Repository object
//   - WithStartPageAfterItem which sets where to start listing from
func (r *Repository) listHostsRefresh(ctx context.Context, catalogId string, updatedAfter time.Time, opt ...Option) ([]*Host, *plugin.Plugin, time.Time, error) {
	const op = "plugin.(Repository).listHostsRefresh"
	switch {
	case catalogId == "":
		return nil, nil, time.Time{}, errors.New(ctx, errors.InvalidParameter, op, "no catalog id")
	case updatedAfter.IsZero():
		return nil, nil, time.Time{}, errors.New(ctx, errors.InvalidParameter, op, "missing updated after time")
	}
	opts := getOpts(opt...)
	limit := r.defaultLimit
	if opts.withLimit != 0 {
		// non-zero signals an override of the default limit for the repo.
		limit = opts.withLimit
	}
	query := fmt.Sprintf(listHostsRefreshTemplate, limit)
	args := []any{
		sql.Named("catalog_id", catalogId),
		sql.Named("updated_after_time", updatedAfter),
	}
	if opts.withStartPageAfterItem != nil {
		query = fmt.Sprintf(listHostsRefreshPageTemplate, limit)
		args = append(args,
			sql.Named("last_item_update_time", opts.withStartPageAfterItem.GetUpdateTime()),
			sql.Named("last_item_id", opts.withStartPageAfterItem.GetPublicId()),
		)
	}

	return r.queryHosts(ctx, query, args)
}

func (r *Repository) queryHosts(ctx context.Context, query string, args []any) ([]*Host, *plugin.Plugin, time.Time, error) {
	const op = "plugin.(Repository).queryHosts"

	var hosts []*Host
	var plg *plugin.Plugin
	var transactionTimestamp time.Time
	if _, err := r.writer.DoTx(ctx, db.StdRetryCnt, db.ExpBackoff{}, func(r db.Reader, w db.Writer) error {
		rows, err := r.Query(ctx, query, args)
		if err != nil {
			return err
		}
		defer rows.Close()
		var foundHosts []*hostAgg
		for rows.Next() {
			if err := r.ScanRows(ctx, rows, &foundHosts); err != nil {
				return err
			}
		}
		if err := rows.Err(); err != nil {
			return err
		}
		if len(foundHosts) != 0 {
			plg = plugin.NewPlugin()
			plg.PublicId = foundHosts[0].PluginId
			if err := r.LookupByPublicId(ctx, plg); err != nil {
				return err
			}
			hosts = make([]*Host, 0, len(foundHosts))
			for _, ha := range foundHosts {
				hosts = append(hosts, ha.toHost())
			}
		}
		transactionTimestamp, err = r.Now(ctx)
		return err
	}); err != nil {
		return nil, nil, time.Time{}, errors.Wrap(ctx, err, op)
	}
	return hosts, plg, transactionTimestamp, nil
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
	if err := rows.Err(); err != nil {
		return 0, errors.Wrap(ctx, err, op, errors.WithMsg("failed to query plugin hosts"))
	}
	return count, nil
}
