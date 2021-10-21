package plugin

import (
	"context"
	"fmt"
	"sort"

	"github.com/hashicorp/boundary/internal/db"
	"github.com/hashicorp/boundary/internal/errors"
	"github.com/hashicorp/boundary/internal/host"
	"github.com/hashicorp/boundary/internal/kms"
	"github.com/hashicorp/boundary/internal/oplog"
	plgpb "github.com/hashicorp/boundary/sdk/pbs/plugin"
	"github.com/hashicorp/go-secure-stdlib/strutil"
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
func (r *Repository) UpsertHosts(
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

	// hostInfo stores the info we need for figuring out host, set membership,
	// and value object differences. It also stores dirty flags to indicate
	// whether we need to update value objects or the host itself.
	type hostInfo struct {
		h                *Host
		ipsToAdd         []interface{}
		ipsToRemove      []interface{}
		dnsNamesToAdd    []interface{}
		dnsNamesToRemove []interface{}
		dirtyHost        bool
	}

	// First, fetch existing hosts for the set IDs passed in, and organize them
	// into a lookup map by host ID for later usage
	var currentHosts []*Host
	var currentHostMap map[string]*Host
	{
		var err error
		currentHosts, err = r.ListHostsBySetIds(ctx, setIds)
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
	newHostMap := make(map[string]*hostInfo, len(phs))
	{
		var err error
		for _, ph := range phs {
			newHost := NewHost(ctx,
				hc.GetPublicId(),
				ph.GetExternalId(),
				WithName(ph.GetName()),
				WithDescription(ph.GetDescription()),
				withIpAddresses(ph.GetIpAddresses()),
				withDnsNames(ph.GetDnsNames()),
				withPluginId(hc.GetPluginId()))
			newHost.PublicId, err = newHostId(ctx, hc.GetPublicId(), ph.GetExternalId())
			if err != nil {
				return nil, errors.Wrap(ctx, err, op)
			}
			newHost.SetIds = ph.SetIds
			hi := &hostInfo{
				h: newHost,
			}
			newHostMap[newHost.PublicId] = hi

			// Check if the host is dirty; that is, we need to perform an upsert
			// operation. If the host isn't dirty, we have nothing to do. Note
			// that we don't check every value exhaustively; for instance, we
			// assume catalog ID and external ID don't change because if they do
			// the public ID will be different as well.
			currHost := currentHostMap[newHost.PublicId]
			switch {
			case currHost == nil,
				currHost.Name != newHost.Name,
				currHost.Description != newHost.Description:
				hi.dirtyHost = true
			}

			// Get the current set of host IPs/DNS names for comparison. These
			// will be in sorted order since ordering is kept in the database
			// and they will have been sorted before insertion.
			var currHostIps []string
			var currHostDnsNames []string
			if currHost != nil {
				currHostIps = currHost.IpAddresses
				currHostDnsNames = currHost.DnsNames
			}

			// Sort these here before comparison. We always use a priority order
			// based on the behavior of sort.Strings so that we can check for
			// equivalency.
			sort.Strings(newHost.IpAddresses)
			sort.Strings(newHost.DnsNames)

			// IPs
			{
				switch {
				case strutil.EquivalentSlices(currHostIps, newHost.GetIpAddresses()):
					// Nothing to do...don't remove or add anything

				default:
					// No match, so we need to remove the old ones and add the new

					// First, build up removals
					hi.ipsToRemove = make([]interface{}, 0, len(currHostIps))
					for i, a := range currHostIps {
						obj, err := host.NewIpAddress(ctx, newHost.PublicId, uint32(i+1), a)
						if err != nil {
							return nil, errors.Wrap(ctx, err, op)
						}
						hi.ipsToRemove = append(hi.ipsToRemove, obj)
					}

					// Now build up additions
					hi.ipsToAdd = make([]interface{}, 0, len(newHost.GetIpAddresses()))
					for i, a := range newHost.GetIpAddresses() {
						obj, err := host.NewIpAddress(ctx, newHost.PublicId, uint32(i+1), a)
						if err != nil {
							return nil, errors.Wrap(ctx, err, op)
						}
						hi.ipsToAdd = append(hi.ipsToAdd, obj)
					}
				}
			}

			// DNS names
			{
				switch {
				case strutil.EquivalentSlices(currHostDnsNames, newHost.GetDnsNames()):
					// Nothing to do...don't remove or add anything

				default:
					// No match, so we need to remove the old ones and add the new

					// First, build up removals
					hi.dnsNamesToRemove = make([]interface{}, 0, len(currHostDnsNames))
					for i, a := range currHostDnsNames {
						obj, err := host.NewDnsName(ctx, newHost.PublicId, uint32(i+1), a)
						if err != nil {
							return nil, errors.Wrap(ctx, err, op)
						}
						hi.dnsNamesToRemove = append(hi.dnsNamesToRemove, obj)
					}

					// Now build up additions
					hi.dnsNamesToAdd = make([]interface{}, 0, len(newHost.GetIpAddresses()))
					for i, a := range newHost.GetDnsNames() {
						obj, err := host.NewDnsName(ctx, newHost.PublicId, uint32(i+1), a)
						if err != nil {
							return nil, errors.Wrap(ctx, err, op)
						}
						hi.dnsNamesToAdd = append(hi.dnsNamesToAdd, obj)
					}
				}
			}
		}
	}

	oplogWrapper, err := r.kms.GetWrapper(ctx, hc.GetScopeId(), kms.KeyPurposeOplog)
	if err != nil {
		return nil, errors.Wrap(ctx, err, op, errors.WithMsg("unable to get oplog wrapper"))
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
						count, err := w.DeleteItems(ctx, hi.ipsToRemove, db.NewOplogMsgs(&oplogMsgs))
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
						if err := w.CreateItems(ctx, hi.ipsToAdd, db.NewOplogMsgs(&oplogMsgs)); err != nil {
							return err
						}
						msgs = append(msgs, oplogMsgs...)
					}
				}

				// DNS handling
				{
					if len(hi.dnsNamesToRemove) > 0 {
						oplogMsgs := make([]*oplog.Message, 0, len(hi.dnsNamesToRemove))
						count, err := w.DeleteItems(ctx, hi.dnsNamesToRemove, db.NewOplogMsgs(&oplogMsgs))
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
						if err := w.CreateItems(ctx, hi.dnsNamesToAdd, db.NewOplogMsgs(&oplogMsgs)); err != nil {
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
	setMembershipsToAdd := make(map[string][]string)    // Map of set id to host ids
	setMembershipsToRemove := make(map[string][]string) // Map of set id to host ids
	totalSetIds := make(map[string]struct{})            // Stores the total set IDs we'll need to iterate over
	{
		// First, find sets that hosts should be added to: hosts that are new or
		// have new set IDs returned.
		for newHostId, newHost := range newHostMap {
			var setsToAdd []string
			currentHost, ok := currentHostMap[newHostId]
			if !ok {
				// If the host was not known about before now, any sets the host
				// matches will need to be added
				setsToAdd = newHost.h.SetIds
			} else {
				// Otherwise, add to any it doesn't currently match
				for _, setId := range newHost.h.SetIds {
					if !strutil.StrListContains(currentHost.SetIds, setId) {
						setsToAdd = append(setsToAdd, setId)
					}
				}
			}
			// Add to the total set
			for _, setToAdd := range setsToAdd {
				setMembershipsToAdd[setToAdd] = append(setMembershipsToAdd[setToAdd], newHostId)
				totalSetIds[setToAdd] = struct{}{}
			}
		}

		// Now, do the inverse: remove hosts from sets that appear there now but no
		// longer have that set ID in their current list.
		for currentHostId, currentHost := range currentHostMap {
			var setsToRemove []string
			newHost, ok := newHostMap[currentHostId]
			if !ok {
				// If the host doesn't even appear now, we obviously want to remove
				// it from all existing set memberships
				setsToRemove = currentHost.SetIds
			} else {
				// Otherwise, remove it from any it doesn't currently have
				for _, setId := range currentHost.SetIds {
					if !strutil.StrListContains(newHost.h.SetIds, setId) {
						setsToRemove = append(setsToRemove, setId)
					}
				}
			}
			// Add to the total set
			for _, setToRemove := range setsToRemove {
				setMembershipsToRemove[setToRemove] = append(setMembershipsToRemove[setToRemove], currentHostId)
				totalSetIds[setToRemove] = struct{}{}
			}
		}
	}

	// Iterate through the sets and update memberships, one transaction per set
	for setId := range totalSetIds {
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
					membership, err := NewHostSetMember(hs.PublicId, hostId)
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
					membership, err := NewHostSetMember(hs.PublicId, hostId)
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
	h, err := ha.toHost(ctx)
	if err != nil {
		return nil, errors.Wrap(ctx, err, op, errors.WithMsg(fmt.Sprintf("failed to convert host agg for %s", publicId)))
	}
	return h, nil
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
		host, err := ha.toHost(ctx)
		if err != nil {
			return nil, errors.Wrap(ctx, err, op)
		}
		hosts = append(hosts, host)
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

	query := `
public_id in
	(select distinct host_id
		from host_plugin_set_member
		where set_id in (?))
`

	var hostAggs []*hostAgg
	err := r.reader.SearchWhere(ctx, &hostAggs, query, []interface{}{setIds}, db.WithLimit(limit))

	switch {
	case err != nil:
		return nil, errors.Wrap(ctx, err, op)
	case hostAggs == nil:
		return nil, nil
	}

	hosts := make([]*Host, 0, len(hostAggs))
	for _, ha := range hostAggs {
		host, err := ha.toHost(ctx)
		if err != nil {
			return nil, errors.Wrap(ctx, err, op)
		}
		hosts = append(hosts, host)
	}

	return hosts, nil
}

// DeleteOphanedHosts deletes any hosts that no longer belong to any set.
// WithLimit is the only option supported. No options are currently supported.
func (r *Repository) DeleteOrphanedHosts(ctx context.Context, _ ...Option) error {
	const op = "plugin.(Repository).DeleteOrphanedHosts"

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
		return errors.Wrap(ctx, err, op)
	case len(hostAggs) == 0:
		return nil
	}

	_, err = r.writer.DoTx(
		ctx,
		db.StdRetryCnt,
		db.ExpBackoff{},
		func(r db.Reader, w db.Writer) error {
			for _, ha := range hostAggs {
				h := NewHost(ctx, ha.CatalogId, ha.ExternalId)
				h.PublicId = ha.PublicId
				if _, err := w.Delete(ctx, h); err != nil {
					return errors.Wrap(ctx, err, op)
				}
			}
			return nil
		})
	if err != nil {
		return errors.Wrap(ctx, err, op)
	}

	return nil
}
