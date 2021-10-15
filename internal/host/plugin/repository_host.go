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
	sets []string,
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
	if sets == nil {
		return nil, errors.New(ctx, errors.InvalidParameter, op, "nil sets")
	}
	if len(sets) == 0 { // At least one must have been given to the plugin
		return nil, errors.New(ctx, errors.InvalidParameter, op, "empty sets")
	}

	// hostInfo stores the info we need for the transaction below as well as
	// which sets they matched
	type hostInfo struct {
		h     *Host
		ips   []interface{}
		names []interface{}
		sets  map[string]struct{}
	}
	hostMapping := make(map[string]hostInfo, len(phs))
	var err error
	var totalMsgs uint32

	for _, ph := range phs {
		totalMsgs += 2 // delete and create

		h := newHost(ctx,
			hc.GetPublicId(),
			ph.GetExternalId(),
			withIpAddresses(ph.GetIpAddresses()),
			withDnsNames(ph.GetDnsNames()),
			withPluginId(hc.GetPluginId()))
		h.PublicId, err = newHostId(ctx, hc.GetPublicId(), ph.GetExternalId())
		if err != nil {
			return nil, errors.Wrap(ctx, err, op)
		}

		var ipAddresses []interface{}
		if len(h.GetIpAddresses()) > 0 {
			sort.Strings(h.IpAddresses)
			ipAddresses = make([]interface{}, 0, len(h.GetIpAddresses()))
			for i, a := range h.GetIpAddresses() {
				obj, err := host.NewIpAddress(ctx, h.PublicId, uint32(i+1), a)
				if err != nil {
					return nil, errors.Wrap(ctx, err, op)
				}
				ipAddresses = append(ipAddresses, obj)
			}
		}

		var dnsNames []interface{}
		if len(h.GetDnsNames()) > 0 {
			sort.Strings(h.DnsNames)
			dnsNames = make([]interface{}, 0, len(h.GetDnsNames()))
			for i, n := range h.GetDnsNames() {
				obj, err := host.NewDnsName(ctx, h.PublicId, uint32(i+1), n)
				if err != nil {
					return nil, errors.Wrap(ctx, err, op)
				}
				dnsNames = append(dnsNames, obj)
			}
		}

		hi := hostInfo{
			h:     h,
			ips:   ipAddresses,
			names: dnsNames,
		}

		for _, id := range ph.GetSetIds() {
			if hi.sets == nil {
				hi.sets = make(map[string]struct{})
			}
			hi.sets[id] = struct{}{}
		}

		hostMapping[h.PublicId] = hi

		totalMsgs += uint32(len(ipAddresses) + len(dnsNames))
	}

	oplogWrapper, err := r.kms.GetWrapper(ctx, hc.GetScopeId(), kms.KeyPurposeOplog)
	if err != nil {
		return nil, errors.Wrap(ctx, err, op, errors.WithMsg("unable to get oplog wrapper"))
	}

	var returnedHosts []*Host

	// Here's what this function does: first it deletes a host, which causes
	// cascading deletes on ip addresses and dns names (but all within the DB).
	// Then the host is recreated, which uses the same public ID (since it's
	// based on the host catalog/external ID), along with new/updated
	// information.
	//
	// If we ever do start allowing hosts directly in targets this may cause a
	// problem because the host deletion would probably cascade to the target
	// and remove it from the target host sources, but at this point there are
	// several issues with that scenario so it's not soon...
	//
	// The main reason I'm doing it this way is because I'm not sure how to do
	// oplogs with custom queries. Otherwise a custom insert/on conflict query
	// could replace the initial deletion. @jimlambrt @mgaffney help? :-D
	_, err = r.writer.DoTx(
		ctx,
		db.StdRetryCnt,
		db.ExpBackoff{},
		func(r db.Reader, w db.Writer) error {
			// FIXME: We need to ensure hosts no longer found have their
			// memberships removed. To do this, first list all set memberships.
			// This is waiting on membership to be plumbed through to gorm,
			// which in turn is waiting on figuring out whether or not we can
			// share that between static and plugin.
			//
			// Next, for each set, check whether a given host ID is in the
			// hostMapping and if so, if the set ID is in the host's sets. If
			// not, queue that membership entry for deletion.
			msgs := make([]*oplog.Message, 0, totalMsgs+3)
			ticket, err := w.GetTicket(hc)
			if err != nil {
				return errors.Wrap(ctx, err, op, errors.WithMsg("unable to get ticket"))
			}

			for _, hi := range hostMapping {
				ret := hi.h.clone()

				var hOplogMsg oplog.Message
				// We don't need to check whether something was deleted because
				// it's okay if it fails
				if _, err := w.Delete(ctx, ret, db.NewOplogMsg(&hOplogMsg)); err != nil {
					return errors.Wrap(ctx, err, op)
				}
				msgs = append(msgs, &hOplogMsg)

				hOplogMsg = oplog.Message{}
				if err := w.Create(ctx, ret, db.NewOplogMsg(&hOplogMsg)); err != nil {
					return errors.Wrap(ctx, err, op)
				}
				msgs = append(msgs, &hOplogMsg)

				if len(hi.ips) > 0 {
					ipOplogMsgs := make([]*oplog.Message, 0, len(hi.ips))
					if err := w.CreateItems(ctx, hi.ips, db.NewOplogMsgs(&ipOplogMsgs)); err != nil {
						return err
					}
					msgs = append(msgs, ipOplogMsgs...)
				}

				if len(hi.names) > 0 {
					dnsOplogMsgs := make([]*oplog.Message, 0, len(hi.names))
					if err := w.CreateItems(ctx, hi.names, db.NewOplogMsgs(&dnsOplogMsgs)); err != nil {
						return err
					}
					msgs = append(msgs, dnsOplogMsgs...)
				}

				// FIXME: Add set memberships here

				returnedHosts = append(returnedHosts, ret)
			}

			metadata := hc.oplog(oplog.OpType_OP_TYPE_CREATE)
			if err := w.WriteOplogEntryWith(ctx, oplogWrapper, ticket, metadata, msgs); err != nil {
				return errors.Wrap(ctx, err, op, errors.WithMsg("unable to write oplog"))
			}

			return nil
		},
	)

	if err != nil {
		if errors.IsCheckConstraintError(err) || errors.IsNotNullError(err) {
			return nil, errors.New(ctx,
				errors.InvalidAddress,
				op,
				fmt.Sprintf("in catalog: %s", hc.GetPublicId()),
				errors.WithWrap(err),
			)
		}
		return nil, errors.Wrap(ctx, err, op, errors.WithMsg(fmt.Sprintf("in catalog: %s", hc.PublicId)))
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

// ListHosts returns a slice of Hosts for the catalogId.
// WithLimit is the only option supported.
func (r *Repository) ListHosts(ctx context.Context, catalogId string, opt ...Option) ([]*Host, error) {
	const op = "plugin.(Repository).ListHosts"
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
