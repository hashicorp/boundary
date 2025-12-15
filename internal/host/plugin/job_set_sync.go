// Copyright IBM Corp. 2020, 2025
// SPDX-License-Identifier: BUSL-1.1

package plugin

import (
	"context"
	"fmt"
	"time"

	"github.com/hashicorp/boundary/internal/db"
	"github.com/hashicorp/boundary/internal/errors"
	"github.com/hashicorp/boundary/internal/event"
	"github.com/hashicorp/boundary/internal/kms"
	"github.com/hashicorp/boundary/internal/libs/endpoint"
	"github.com/hashicorp/boundary/internal/oplog"
	"github.com/hashicorp/boundary/internal/scheduler"
	hcpb "github.com/hashicorp/boundary/sdk/pbs/controller/api/resources/hostcatalogs"
	pb "github.com/hashicorp/boundary/sdk/pbs/controller/api/resources/hostsets"
	plgpb "github.com/hashicorp/boundary/sdk/pbs/plugin"
	"github.com/hashicorp/go-secure-stdlib/strutil"
	ua "go.uber.org/atomic"
)

const (
	setSyncJobName        = "plugin_host_set_sync"
	setSyncJobRunInterval = 10 * time.Minute
)

// SetSyncJob is the recurring job that syncs hosts from sets that are.
// The SetSyncJob is not thread safe,
// an attempt to Run the job concurrently will result in an JobAlreadyRunning error.
type SetSyncJob struct {
	reader  db.Reader
	writer  db.Writer
	kms     *kms.Kms
	plugins map[string]plgpb.HostPluginServiceClient
	limit   int

	running      ua.Bool
	numSets      int
	numProcessed int
}

// newSetSyncJob creates a new in-memory SetSyncJob.
//
// WithLimit is the only supported option.
func newSetSyncJob(ctx context.Context, r db.Reader, w db.Writer, kms *kms.Kms, plgm map[string]plgpb.HostPluginServiceClient, opt ...Option) (*SetSyncJob, error) {
	const op = "plugin.newSetSyncJob"
	switch {
	case r == nil:
		return nil, errors.New(ctx, errors.InvalidParameter, op, "missing db.Reader")
	case w == nil:
		return nil, errors.New(ctx, errors.InvalidParameter, op, "missing db.Writer")
	case kms == nil:
		return nil, errors.New(ctx, errors.InvalidParameter, op, "missing kms")
	case plgm == nil:
		return nil, errors.New(ctx, errors.InvalidParameter, op, "missing plugin manager")
	}

	opts := getOpts(opt...)
	if opts.withLimit == 0 {
		// zero signals the boundary defaults should be used.
		opts.withLimit = db.DefaultLimit
	}
	return &SetSyncJob{
		reader:  r,
		writer:  w,
		kms:     kms,
		plugins: plgm,
		limit:   opts.withLimit,
	}, nil
}

// Status returns the current status of the set sync job.  Total is the total number
// of sets that are to be synced. Completed is the number of sets already synced.
func (r *SetSyncJob) Status() scheduler.JobStatus {
	return scheduler.JobStatus{
		Completed: r.numProcessed,
		Total:     r.numSets,
	}
}

// Run queries the plugin host repo for sets that need to be synced, it then
// creates a plugin client and syncs each set.  Can not be run in parallel, if
// Run is invoked while already running an error with code JobAlreadyRunning
// will be returned.
func (r *SetSyncJob) Run(ctx context.Context, _ time.Duration) error {
	const op = "plugin.(SetSyncJob).Run"
	if !r.running.CompareAndSwap(r.running.Load(), true) {
		return errors.New(ctx, errors.JobAlreadyRunning, op, "job already running")
	}
	defer r.running.Store(false)

	// Verify context is not done before running
	if err := ctx.Err(); err != nil {
		return errors.Wrap(ctx, err, op)
	}

	var setAggs []*hostSetAgg
	// Fetch all sets that will reach their sync point within the syncWindow.
	// This is done to avoid constantly scheduling the set sync job when there
	// are multiple sets to sync in sequence.
	err := r.reader.SearchWhere(ctx, &setAggs, setSyncJobQuery, []any{-1 * setSyncJobRunInterval.Seconds()}, db.WithLimit(r.limit))
	if err != nil {
		return errors.Wrap(ctx, err, op)
	}

	// Set numProcessed and numHosts for status report
	r.numProcessed, r.numSets = 0, len(setAggs)
	if len(setAggs) == 0 {
		// Nothing to do, return early
		return nil
	}

	return r.syncSets(ctx, setAggs)
}

// NextRunIn queries the plugin host set db to determine when the next set should be synced.
func (r *SetSyncJob) NextRunIn(ctx context.Context) (time.Duration, error) {
	const op = "plugin.(SetSyncJob).NextRunIn"
	next, err := nextSync(ctx, r)
	if err != nil {
		return setSyncJobRunInterval, errors.Wrap(ctx, err, op)
	}
	return next, nil
}

// Name is the unique name of the job.
func (r *SetSyncJob) Name() string {
	return setSyncJobName
}

// Description is the human readable description of the job.
func (r *SetSyncJob) Description() string {
	return "Periodically syncs plugin based catalog hosts and host set memberships."
}

func nextSync(ctx context.Context, j scheduler.Job) (time.Duration, error) {
	const op = "plugin.nextSync"
	var query string
	var r db.Reader
	switch job := j.(type) {
	case *SetSyncJob:
		query = setSyncNextRunInQuery
		r = job.reader
	default:
		return 0, errors.New(ctx, errors.Unknown, op, "unknown job")
	}

	rows, err := r.Query(context.Background(), query, []any{setSyncJobRunInterval})
	if err != nil {
		return 0, errors.Wrap(ctx, err, op)
	}
	defer rows.Close()

	if !rows.Next() {
		return setSyncJobRunInterval, nil
	}
	if err := rows.Err(); err != nil {
		return 0, errors.Wrap(ctx, err, op)
	}

	type NextResync struct {
		SyncNow             bool
		SyncIntervalSeconds int32
		ResyncIn            time.Duration
	}
	var n NextResync
	err = r.ScanRows(ctx, rows, &n)
	if err != nil {
		return 0, errors.Wrap(ctx, err, op)
	}
	switch {
	case n.SyncNow:
		// Immediate
		return 0, nil
	case n.SyncIntervalSeconds < 0:
		// In this case automatic syncing is disabled; we still sync if SyncNow
		// but otherwise do not. We schedule the job at the default cadence but
		// it will do nothing, just calculate a next run time to ensure it
		// should stay disabled.
		return setSyncJobRunInterval, nil
	case n.ResyncIn < 0:
		// Immediate
		return 0, nil
	}
	return n.ResyncIn * time.Second, nil
}

// syncSets retrieves from their plugins all the host and membership information
// for the provided host sets and updates their values in the database.
func (r *SetSyncJob) syncSets(ctx context.Context, setAggs []*hostSetAgg) error {
	const op = "plugin.(SetSyncJob).syncSets"
	if len(setAggs) == 0 {
		return nil
	}

	type setInfo struct {
		preferredEndpoint endpoint.Option
		plgSet            *pb.HostSet
	}

	type catalogInfo struct {
		publicId  string                        // ID of the catalog
		plg       plgpb.HostPluginServiceClient // plugin client for the catalog
		setInfos  map[string]*setInfo           // map of set IDs to set information
		plgCat    *hcpb.HostCatalog             // plugin host catalog
		storeCat  *HostCatalog
		persisted *plgpb.HostCatalogPersisted // host catalog persisted (secret) data
	}

	// Next, look up the distinct catalog info and assign set infos to it.
	// Notably, this does not include persisted info.
	catalogInfos := make(map[string]*catalogInfo)
	for _, ag := range setAggs {
		ci, ok := catalogInfos[ag.CatalogId]
		if !ok {
			ci = &catalogInfo{
				publicId: ag.CatalogId,
				setInfos: make(map[string]*setInfo),
			}
		}

		s, err := ag.toHostSet(ctx)
		if err != nil {
			return errors.Wrap(ctx, err, op)
		}
		si, ok := ci.setInfos[s.GetPublicId()]
		if !ok {
			si = &setInfo{}
		}
		si.preferredEndpoint = endpoint.WithPreferenceOrder(s.PreferredEndpoints)
		si.plgSet, err = toPluginSet(ctx, s)
		if err != nil {
			return errors.Wrap(ctx, err, op, errors.WithMsg(fmt.Sprintf("converting set %q to plugin set", s.GetPublicId())))
		}

		ci.setInfos[s.GetPublicId()] = si
		catalogInfos[ag.CatalogId] = ci
	}

	// Now, look up the catalog persisted (secret) information. Additionally,
	// find the correct plugin to use.
	catIds := make([]string, 0, len(catalogInfos))
	for k := range catalogInfos {
		catIds = append(catIds, k)
	}
	var catAggs []*catalogAgg
	if err := r.reader.SearchWhere(ctx, &catAggs, "public_id in (?)", []any{catIds}); err != nil {
		return errors.Wrap(ctx, err, op, errors.WithMsg(fmt.Sprintf("can't retrieve catalogs %v", catIds)))
	}
	if len(catAggs) == 0 {
		return errors.New(ctx, errors.NotSpecificIntegrity, op, "no catalogs returned for retrieved sets")
	}
	for _, ca := range catAggs {
		c, s := ca.toCatalogAndPersisted()
		ci, ok := catalogInfos[c.GetPublicId()]
		if !ok {
			return errors.New(ctx, errors.NotSpecificIntegrity, op, "catalog returned when no set requested it")
		}
		plgCat, err := toPluginCatalog(ctx, c, ca.plugin())
		if err != nil {
			return errors.Wrap(ctx, err, op, errors.WithMsg("storage to plugin catalog conversion"))
		}
		ci.plgCat = plgCat
		ci.storeCat = c

		ci.plg, err = pluginClientFactoryFn(ctx, ci.plgCat, r.plugins)
		if err != nil {
			return errors.Wrap(ctx, err, op, errors.WithMsg("failed to get plugin client"))
		}

		per, err := toPluginPersistedData(ctx, r.kms, c.GetProjectId(), s)
		if err != nil {
			return errors.Wrap(ctx, err, op)
		}
		ci.persisted = per
		catalogInfos[c.GetPublicId()] = ci
	}

	// For each distinct catalog, list all sets at once
	for _, ci := range catalogInfos {
		var sets []*pb.HostSet
		var catSetIds []string
		for id, si := range ci.setInfos {
			sets = append(sets, si.plgSet)
			catSetIds = append(catSetIds, id)
		}

		resp, err := ci.plg.ListHosts(ctx, &plgpb.ListHostsRequest{
			Catalog:   ci.plgCat,
			Sets:      sets,
			Persisted: ci.persisted,
		})
		if err != nil {
			event.WriteError(ctx, op, err, event.WithInfoMsg("listing hosts", "catalog id", ci.publicId))
			r.numProcessed += len(catSetIds)
			continue
		}

		if _, err := r.upsertAndCleanHosts(ctx, ci.storeCat, catSetIds, resp.GetHosts()); err != nil {
			event.WriteError(ctx, op, err, event.WithInfoMsg("upserting hosts", "catalog id", ci.publicId))
			r.numProcessed += len(catSetIds)
			continue
		}
		r.numProcessed += len(catSetIds)
	}
	return nil
}

// upsertAndCleanHosts inserts phs into the repository or updates its current
// attributes/set memberships and returns Hosts. h is not changed. hc must
// contain a valid public ID and project ID. Each ph in phs must not contain a
// PublicId but must contain an external ID. The PublicId is generated and
// assigned by this method.
//
// NOTE: If phs is empty, this assumes that there are simply no hosts that
// matched the given sets! Which means it will remove all hosts from the given
// sets.
func (r *SetSyncJob) upsertAndCleanHosts(
	ctx context.Context,
	hc *HostCatalog,
	setIds []string,
	phs []*plgpb.ListHostsResponseHost,
	_ ...Option,
) ([]*Host, error) {
	const op = "plugin.(SetSyncJob).upsertAndCleanHosts"
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
	if hc.GetProjectId() == "" {
		return nil, errors.New(ctx, errors.InvalidParameter, op, "no project id")
	}
	if len(setIds) == 0 { // At least one must have been given to the plugin
		return nil, errors.New(ctx, errors.InvalidParameter, op, "empty sets")
	}

	oplogWrapper, err := r.kms.GetWrapper(ctx, hc.GetProjectId(), kms.KeyPurposeOplog)
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
				ticket, err := w.GetTicket(ctx, ret)
				if err != nil {
					return errors.Wrap(ctx, err, op, errors.WithMsg("unable to get ticket"))
				}

				// We always write the host itself as we need to update version
				// for optimistic locking for any value object update.
				var hOplogMsg oplog.Message
				onConflict := &db.OnConflict{
					Target: db.Constraint("host_plugin_host_pkey"),
					Action: db.SetColumns([]string{"name", "external_name", "description", "version"}),
				}
				var rowsAffected int64
				dbOpts := []db.Option{
					db.NewOplogMsg(&hOplogMsg),
					db.WithOnConflict(onConflict),
					db.WithReturnRowsAffected(&rowsAffected),
				}
				version := ret.Version
				if version > 0 {
					dbOpts = append(dbOpts, db.WithVersion(&version))
					ret.Version += 1
				}
				// This check is the logical counterpart of the database
				// constraints on the external_name field. By replicating the
				// checks as closely as possible in code, we reduce the risk of
				// this transaction failing due to a bad external name.
				if !strutil.Printable(ret.ExternalName) || len(ret.ExternalName) > 256 {
					event.WriteError(ctx, op,
						fmt.Errorf("ignoring host id %q external name %q due to its length (greater than 256 characters) or the presence of unsupported unicode characters",
							ret.PublicId,
							ret.ExternalName),
					)
					ret.ExternalName = ""
				}
				if err := w.Create(ctx, ret, dbOpts...); err != nil {
					return errors.Wrap(ctx, err, op)
				}
				if rowsAffected != 1 {
					return errors.New(ctx, errors.UnexpectedRowsAffected, op, "no rows affected during upsert")
				}
				msgs = append(msgs, &hOplogMsg)

				// IP handling
				{
					if len(hi.ipsToRemove) > 0 {
						oplogMsgs := make([]*oplog.Message, 0, len(hi.ipsToRemove))
						count, err := w.DeleteItems(ctx, hi.ipsToRemove.toSlice(), db.NewOplogMsgs(&oplogMsgs))
						if err != nil {
							return err
						}
						if count != len(hi.ipsToRemove) {
							return errors.New(ctx, errors.UnexpectedRowsAffected, op, fmt.Sprintf("expected to remove %d ips from host %s, removed %d", len(hi.ipsToRemove), ret.PublicId, count))
						}
						msgs = append(msgs, oplogMsgs...)
					}
					if len(hi.ipsToAdd) > 0 {
						oplogMsgs := make([]*oplog.Message, 0, len(hi.ipsToAdd))
						onConflict := &db.OnConflict{
							Target: db.Constraint("host_ip_address_pkey"),
							Action: db.DoNothing(true),
						}
						if err := w.CreateItems(ctx, hi.ipsToAdd.toSlice(), db.NewOplogMsgs(&oplogMsgs), db.WithOnConflict(onConflict)); err != nil {
							return errors.Wrap(ctx, err, op, errors.WithMsg(fmt.Sprintf("adding ips %v for host %q", hi.ipsToAdd.toSlice(), ret.GetPublicId())))
						}
						msgs = append(msgs, oplogMsgs...)
					}
				}

				// DNS handling
				{
					if len(hi.dnsNamesToRemove) > 0 {
						oplogMsgs := make([]*oplog.Message, 0, len(hi.dnsNamesToRemove))
						count, err := w.DeleteItems(ctx, hi.dnsNamesToRemove.toSlice(), db.NewOplogMsgs(&oplogMsgs))
						if err != nil {
							return err
						}
						if count != len(hi.dnsNamesToRemove) {
							return errors.New(ctx, errors.UnexpectedRowsAffected, op, fmt.Sprintf("expected to remove %d dns names from host %s, removed %d", len(hi.dnsNamesToRemove), ret.PublicId, count))
						}
						msgs = append(msgs, oplogMsgs...)
					}
					if len(hi.dnsNamesToAdd) > 0 {
						oplogMsgs := make([]*oplog.Message, 0, len(hi.dnsNamesToAdd))
						onConflict := &db.OnConflict{
							Target: db.Constraint("host_dns_name_pkey"),
							Action: db.DoNothing(true),
						}
						if err := w.CreateItems(ctx, hi.dnsNamesToAdd.toSlice(), db.NewOplogMsgs(&oplogMsgs), db.WithOnConflict(onConflict)); err != nil {
							return err
						}
						msgs = append(msgs, oplogMsgs...)
					}
				}

				metadata := ret.oplog(oplog.OpType_OP_TYPE_UPDATE)
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
	setMembershipsToAdd, setMembershipsToRemove := getSetChanges(currentHostMap, newHostMap)

	// Iterate through all sets and update memberships, one transaction per set
	for _, setId := range setIds {
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

				// Oplog
				if len(msgs) > 0 {
					ticket, err := w.GetTicket(ctx, hs)
					if err != nil {
						return errors.Wrap(ctx, err, op, errors.WithMsg("unable to get ticket"))
					}

					metadata := hc.oplog(oplog.OpType_OP_TYPE_UPDATE)
					if err := w.WriteOplogEntryWith(ctx, oplogWrapper, ticket, metadata, msgs); err != nil {
						return errors.Wrap(ctx, err, op, errors.WithMsg("unable to write oplog"))
					}
				}

				// Update last sync time
				numRows, err := w.Exec(ctx, updateSyncDataQuery, []any{setId})
				if err != nil {
					return errors.Wrap(ctx, err, op, errors.WithMsg("updating last sync time"))
				}
				if numRows != 1 {
					return errors.New(ctx, errors.Internal, op, fmt.Sprintf("host set (%v) synced, but failed to update repo", setId))
				}

				return nil
			},
		)
		if err != nil {
			event.WriteError(ctx, op, err, event.WithInfoMsg("failed to update membership", "set id", setId))
		}
	}

	return returnedHosts, nil
}
