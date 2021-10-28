package plugin

import (
	"context"
	"fmt"

	"github.com/hashicorp/boundary/internal/db"
	"github.com/hashicorp/boundary/internal/errors"
	"github.com/hashicorp/boundary/internal/kms"
	"github.com/hashicorp/boundary/internal/oplog"
	plgpb "github.com/hashicorp/boundary/sdk/pbs/plugin"
)

// UpsertHost inserts phs into the repository or updates its current
// attributes/set memberships and returns Hosts. h is not changed. hc must
// contain a valid public ID and scope ID. Each ph in phs must not contain a
// PublicId but must contain an external ID. The PublicId is generated and
// assigned by this method.
//
// NOTE: If phs is empty, this assumes that there are simply no hosts that
// matched the given sets! Which means it will remove all hosts from the given
// sets.
func (r *SetSyncJob) UpsertHosts(
	ctx context.Context,
	hc *HostCatalog,
	setIds []string,
	phs []*plgpb.ListHostsResponseHost,
	_ ...Option) ([]*Host, error) {
	const op = "plugin.(Repository).UpsertHosts"
	if phs == nil {
		return nil, errors.New(ctx, errors.InvalidParameter, op, "nil plugin hosts")
	}
	for _, ph := range phs {
		if ph.GetExternalId() == "" {
			return nil, errors.New(ctx, errors.InvalidParameter, op, "missing host external id")
		}
	}
	if hc == nil {
		return nil, errors.New(ctx, errors.InvalidParameter, op, "nil host catalog")
	}
	if hc.GetPublicId() == "" {
		return nil, errors.New(ctx, errors.InvalidParameter, op, "no catalog id")
	}
	if hc.GetScopeId() == "" {
		return nil, errors.New(ctx, errors.InvalidParameter, op, "no scope id")
	}
	if setIds == nil {
		return nil, errors.New(ctx, errors.InvalidParameter, op, "nil sets")
	}
	if len(setIds) == 0 { // At least one must have been given to the plugin
		return nil, errors.New(ctx, errors.InvalidParameter, op, "empty sets")
	}

	oplogWrapper, err := r.kms.GetWrapper(ctx, hc.GetScopeId(), kms.KeyPurposeOplog)
	if err != nil {
		return nil, errors.Wrap(ctx, err, op, errors.WithMsg("unable to get oplog wrapper"))
	}

	// First, fetch existing hosts for the set IDs passed in, and organize them
	// into a lookup map by host ID for later usage
	var currentHosts []*Host
	var currentHostMap map[string]*Host
	{
		var err error
		currentHosts, err = listHostBySetIds(ctx, r.reader, setIds)
		if err != nil {
			return nil, errors.Wrap(ctx, err, op, errors.WithMsg("looking up current hosts for returned sets"))
		}

		currentHostMap = make(map[string]*Host, len(currentHosts))
		for _, h := range currentHosts {
			currentHostMap[h.PublicId] = h
		}
	}

	// Now, parse the externally defined hosts into hostInfo values, which
	// stores info useful for later comparisons
	newHostMap, err := createNewHostMap(ctx, hc, phs, currentHostMap)
	if err != nil {
		return nil, errors.Wrap(ctx, err, op, errors.WithMsg("unable to create new host map"))
	}

	var returnedHosts []*Host
	// Iterate over hosts and add or update them
	for _, hi := range newHostMap {
		ret := hi.h.clone()

		if !hi.dirtyHost &&
			len(hi.ipsToAdd) == 0 &&
			len(hi.ipsToRemove) == 0 &&
			len(hi.dnsNamesToAdd) == 0 &&
			len(hi.dnsNamesToRemove) == 0 {
			returnedHosts = append(returnedHosts, ret)
			continue
		}
		_, err = r.writer.DoTx(
			ctx,
			db.StdRetryCnt,
			db.ExpBackoff{},
			func(r db.Reader, w db.Writer) error {
				msgs := make([]*oplog.Message, 0)
				ticket, err := w.GetTicket(hi.h)
				if err != nil {
					return errors.Wrap(ctx, err, op, errors.WithMsg("unable to get ticket"))
				}

				if hi.dirtyHost {
					var hOplogMsg oplog.Message
					onConflict := &db.OnConflict{
						Target: db.Constraint("host_plugin_host_pkey"),
						Action: db.SetColumns([]string{"name", "description"}),
					}
					if err := w.Create(ctx, ret, db.NewOplogMsg(&hOplogMsg), db.WithOnConflict(onConflict)); err != nil {
						return errors.Wrap(ctx, err, op)
					}
					msgs = append(msgs, &hOplogMsg)
				}

				// IP handling
				{
					if len(hi.ipsToRemove) > 0 {
						oplogMsgs := make([]*oplog.Message, 0, len(hi.ipsToRemove))
						count, err := w.DeleteItems(ctx, hi.ipsToRemove.toArray(), db.NewOplogMsgs(&oplogMsgs))
						if err != nil {
							return err
						}
						if count != len(hi.ipsToRemove) {
							return errors.New(ctx, errors.UnexpectedRowsAffected, op, fmt.Sprintf("expected to remove %d ips from host %s, removed %d", len(hi.ipsToRemove), hi.h.PublicId, count))
						}
						msgs = append(msgs, oplogMsgs...)
					}
					if len(hi.ipsToAdd) > 0 {
						oplogMsgs := make([]*oplog.Message, 0, len(hi.ipsToAdd))
						if err := w.CreateItems(ctx, hi.ipsToAdd.toArray(), db.NewOplogMsgs(&oplogMsgs)); err != nil {
							return err
						}
						msgs = append(msgs, oplogMsgs...)
					}
				}

				// DNS handling
				{
					if len(hi.dnsNamesToRemove) > 0 {
						oplogMsgs := make([]*oplog.Message, 0, len(hi.dnsNamesToRemove))
						count, err := w.DeleteItems(ctx, hi.dnsNamesToRemove.toArray(), db.NewOplogMsgs(&oplogMsgs))
						if err != nil {
							return err
						}
						if count != len(hi.dnsNamesToRemove) {
							return errors.New(ctx, errors.UnexpectedRowsAffected, op, fmt.Sprintf("expected to remove %d dns names from host %s, removed %d", len(hi.dnsNamesToRemove), hi.h.PublicId, count))
						}
						msgs = append(msgs, oplogMsgs...)
					}
					if len(hi.dnsNamesToAdd) > 0 {
						oplogMsgs := make([]*oplog.Message, 0, len(hi.dnsNamesToAdd))
						if err := w.CreateItems(ctx, hi.dnsNamesToAdd.toArray(), db.NewOplogMsgs(&oplogMsgs)); err != nil {
							return err
						}
						msgs = append(msgs, oplogMsgs...)
					}
				}

				metadata := hi.h.oplog(oplog.OpType_OP_TYPE_UPDATE)
				if err := w.WriteOplogEntryWith(ctx, oplogWrapper, ticket, metadata, msgs); err != nil {
					return errors.Wrap(ctx, err, op, errors.WithMsg("unable to write oplog"))
				}

				returnedHosts = append(returnedHosts, ret)
				return nil
			},
		)
		if err != nil {
			return nil, errors.Wrap(ctx, err, op)
		}
	}

	// Now, check set membership changes
	setMembershipsToAdd, setMembershipsToRemove, allSetIds := getSetChanges(currentHostMap, newHostMap)

	// Iterate through the sets and update memberships, one transaction per set
	for setId := range allSetIds {
		hs, err := NewHostSet(ctx, hc.PublicId)
		if err != nil {
			return nil, errors.Wrap(ctx, err, op)
		}
		hs.PublicId = setId

		_, err = r.writer.DoTx(
			ctx,
			db.StdRetryCnt,
			db.ExpBackoff{},
			func(r db.Reader, w db.Writer) error {
				msgs := make([]*oplog.Message, 0)

				ticket, err := w.GetTicket(hs)
				if err != nil {
					return errors.Wrap(ctx, err, op, errors.WithMsg("unable to get ticket"))
				}

				// Perform additions
				for _, hostId := range setMembershipsToAdd[hs.PublicId] {
					membership, err := NewHostSetMember(ctx, hs.PublicId, hostId)
					if err != nil {
						return errors.Wrap(ctx, err, op)
					}

					var hOplogMsg oplog.Message
					if err := w.Create(ctx, membership, db.NewOplogMsg(&hOplogMsg)); err != nil {
						return errors.Wrap(ctx, err, op)
					}
					msgs = append(msgs, &hOplogMsg)
				}

				// Perform removals
				for _, hostId := range setMembershipsToRemove[hs.PublicId] {
					membership, err := NewHostSetMember(ctx, hs.PublicId, hostId)
					if err != nil {
						return errors.Wrap(ctx, err, op)
					}

					var hOplogMsg oplog.Message
					rows, err := w.Delete(ctx, membership, db.NewOplogMsg(&hOplogMsg))
					if err != nil {
						return errors.Wrap(ctx, err, op)
					}
					if rows != 1 {
						return errors.New(ctx, errors.RecordNotFound, op, "record not found when deleting set membership")
					}
					msgs = append(msgs, &hOplogMsg)
				}

				metadata := hc.oplog(oplog.OpType_OP_TYPE_UPDATE)
				if err := w.WriteOplogEntryWith(ctx, oplogWrapper, ticket, metadata, msgs); err != nil {
					return errors.Wrap(ctx, err, op, errors.WithMsg("unable to write oplog"))
				}

				return nil
			},
		)
		if err != nil {
			return nil, errors.Wrap(ctx, err, op)
		}
	}

	return returnedHosts, nil
}

// LookupHost will look up a host in the repository. If the host is not
// found, it will return nil, nil. All options are ignored.
func (r *Repository) LookupHost(ctx context.Context, publicId string, opt ...Option) (*Host, error) {
	const op = "plugin.(Repository).LookupHost"
	if publicId == "" {
		return nil, errors.New(ctx, errors.InvalidParameter, op, "no public id")
	}
	ha := &hostAgg{
		PublicId: publicId,
	}
	if err := r.reader.LookupByPublicId(ctx, ha); err != nil {
		if errors.IsNotFoundError(err) {
			return nil, nil
		}
		return nil, errors.Wrap(ctx, err, op, errors.WithMsg(fmt.Sprintf("failed for %s", publicId)))
	}
	return ha.toHost(), nil
}

// ListHostsByCatalogId returns a slice of Hosts for the catalogId.
// WithLimit is the only option supported.
func (r *Repository) ListHostsByCatalogId(ctx context.Context, catalogId string, opt ...Option) ([]*Host, error) {
	const op = "plugin.(Repository).ListHostsByCatalogId"
	if catalogId == "" {
		return nil, errors.New(ctx, errors.InvalidParameter, op, "no catalog id")
	}
	opts := getOpts(opt...)
	limit := r.defaultLimit
	if opts.withLimit != 0 {
		// non-zero signals an override of the default limit for the repo.
		limit = opts.withLimit
	}
	var hostAggs []*hostAgg
	err := r.reader.SearchWhere(ctx, &hostAggs, "catalog_id = ?", []interface{}{catalogId}, db.WithLimit(limit))

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
	err := reader.SearchWhere(ctx, &hostAggs, query, []interface{}{setIds}, db.WithLimit(opts.withLimit))

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

// deleteOrphanedHosts deletes any hosts that no longer belong to any set.
// WithLimit is the only option supported. No options are currently supported.
func (r *OrphanedHostCleanupJob) deleteOrphanedHosts(ctx context.Context, _ ...Option) (int, error) {
	const op = "plugin.(OrphanedHostCleanupJob).deleteOrphanedHosts"

	query := `
public_id in
	(select public_id
		from host_plugin_host
		where public_id not in
			(select host_id from host_plugin_set_member))
`

	var hostAggs []*hostAgg
	err := r.reader.SearchWhere(ctx, &hostAggs, query, nil)
	switch {
	case err != nil:
		return db.NoRowsAffected, errors.Wrap(ctx, err, op)
	case len(hostAggs) == 0:
		return db.NoRowsAffected, nil
	}

	scopeToHost := make(map[string][]*Host)
	for _, ha := range hostAggs {
		h := allocHost()
		h.PublicId = ha.PublicId
		scopeToHost[ha.ScopeId] = append(scopeToHost[ha.ScopeId], h)
	}

	_, err = r.writer.DoTx(
		ctx,
		db.StdRetryCnt,
		db.ExpBackoff{},
		func(_ db.Reader, w db.Writer) error {
			for scopeId, hosts := range scopeToHost {
				oplogWrapper, err := r.kms.GetWrapper(ctx, scopeId, kms.KeyPurposeOplog)
				if err != nil {
					return errors.Wrap(ctx, err, op, errors.WithMsg("unable to get oplog wrapper"))
				}
				for _, h := range hosts {
					metadata := h.oplog(oplog.OpType_OP_TYPE_DELETE)
					dHost := h.clone()
					if _, err := w.Delete(ctx, dHost, db.WithOplog(oplogWrapper, metadata)); err != nil {
						return errors.Wrap(ctx, err, op)
					}
				}
			}
			return nil
		})
	if err != nil {
		return db.NoRowsAffected, errors.Wrap(ctx, err, op)
	}

	return len(hostAggs), nil
}
