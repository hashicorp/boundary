package plugin

import (
	"context"
	"fmt"
	"time"

	"github.com/hashicorp/boundary/internal/db"
	"github.com/hashicorp/boundary/internal/errors"
	"github.com/hashicorp/boundary/internal/kms"
	"github.com/hashicorp/boundary/internal/libs/endpoint"
	"github.com/hashicorp/boundary/internal/oplog"
	"github.com/hashicorp/boundary/internal/scheduler"
	hcpb "github.com/hashicorp/boundary/sdk/pbs/controller/api/resources/hostcatalogs"
	pb "github.com/hashicorp/boundary/sdk/pbs/controller/api/resources/hostsets"
	plgpb "github.com/hashicorp/boundary/sdk/pbs/plugin"
	ua "go.uber.org/atomic"
)

const (
	setSyncJobName = "plugin_host_set_sync"
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
	case len(plgm) == 0:
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
func (r *SetSyncJob) Run(ctx context.Context) error {
	const op = "plugin.(SetSyncJob).Run"
	if !r.running.CAS(r.running.Load(), true) {
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
	err := r.reader.SearchWhere(ctx, &setAggs, `need_sync or last_sync_time <= wt_add_seconds_to_now(?)`, []interface{}{-1 * setSyncJobRunInterval.Seconds()}, db.WithLimit(r.limit))
	if err != nil {
		return errors.Wrap(ctx, err, op)
	}

	// Set numProcessed and numHosts for status report
	r.numProcessed, r.numSets = 0, len(setAggs)
	if len(setAggs) == 0 {
		return nil
	}

	setIds := make([]string, 0, len(setAggs))
	for _, sa := range setAggs {
		setIds = append(setIds, sa.PublicId)
	}
	return r.syncSets(ctx, setIds)
}

// NextRunIn queries the plugin host set db to determine when the next set should be synced.
func (r *SetSyncJob) NextRunIn() (time.Duration, error) {
	const op = "plugin.(SetSyncJob).NextRunIn"
	next, err := nextSync(r)
	if err != nil {
		return setSyncJobRunInterval, errors.WrapDeprecated(err, op)
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

func nextSync(j scheduler.Job) (time.Duration, error) {
	const op = "plugin.nextSync"
	var query string
	var r db.Reader
	switch job := j.(type) {
	case *SetSyncJob:
		query = setSyncNextRunInQuery
		r = job.reader
	default:
		return 0, errors.NewDeprecated(errors.Unknown, op, "unknown job")
	}

	rows, err := r.Query(context.Background(), query, []interface{}{setSyncJobRunInterval})
	if err != nil {
		return 0, errors.WrapDeprecated(err, op)
	}
	defer rows.Close()

	for rows.Next() {
		type NextResync struct {
			SyncNow  bool
			ResyncIn time.Duration
		}
		var n NextResync
		err = r.ScanRows(rows, &n)
		if err != nil {
			return 0, errors.WrapDeprecated(err, op)
		}
		if n.SyncNow || n.ResyncIn < 0 {
			// If we are past the next renewal time, return 0 to schedule immediately
			return 0, nil
		}
		return n.ResyncIn * time.Second, nil
	}
	return setSyncJobRunInterval, nil
}

// syncSets retrieves from their plugins all the host and membership information
// for the provided host sets and updates their values in the database.
func (r *SetSyncJob) syncSets(ctx context.Context, setIds []string) error {
	const op = "plugin.(Repository).Endpoints"
	if len(setIds) == 0 {
		return errors.New(ctx, errors.InvalidParameter, op, "no set ids")
	}

	// Fist, look up the sets corresponding to the set IDs
	var setAggs []*hostSetAgg
	if err := r.reader.SearchWhere(ctx, &setAggs, "public_id in (?)", []interface{}{setIds}); err != nil {
		return errors.Wrap(ctx, err, op, errors.WithMsg(fmt.Sprintf("can't retrieve sets %v", setIds)))
	}
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
		ci.plg, ok = r.plugins[ag.PluginId]
		if !ok {
			return errors.New(ctx, errors.Internal, op, fmt.Sprintf("expected plugin %q not available", ag.PluginId))
		}

		s, err := ag.toHostSet(ctx)
		if err != nil {
			return errors.Wrap(ctx, err, op)
		}
		si, ok := ci.setInfos[s.GetPublicId()]
		if !ok {
			si = &setInfo{}
		}
		si.preferredEndpoint = endpoint.WithPreferenceOrder(s.GetPreferredEndpoints())
		si.plgSet, err = toPluginSet(ctx, s)
		if err != nil {
			return errors.Wrap(ctx, err, op, errors.WithMsg(fmt.Sprintf("converting set %q to plugin set", s.GetPublicId())))
		}

		ci.setInfos[s.GetPublicId()] = si
		catalogInfos[ag.CatalogId] = ci
	}

	// Now, look up the catalog persisted (secret) information
	catIds := make([]string, 0, len(catalogInfos))
	for k := range catalogInfos {
		catIds = append(catIds, k)
	}
	var cats []*HostCatalog
	if err := r.reader.SearchWhere(ctx, &cats, "public_id in (?)", []interface{}{catIds}); err != nil {
		return errors.Wrap(ctx, err, op, errors.WithMsg(fmt.Sprintf("can't retrieve catalogs %v", catIds)))
	}
	if len(cats) == 0 {
		return errors.New(ctx, errors.NotSpecificIntegrity, op, "no catalogs returned for retrieved sets")
	}
	for _, c := range cats {
		ci, ok := catalogInfos[c.GetPublicId()]
		if !ok {
			return errors.New(ctx, errors.NotSpecificIntegrity, op, "catalog returned when no set requested it")
		}
		plgCat, err := toPluginCatalog(ctx, c)
		if err != nil {
			return errors.Wrap(ctx, err, op, errors.WithMsg("storage to plugin catalog conversion"))
		}
		ci.plgCat = plgCat
		ci.storeCat = c

		// TODO: Do these lookups from the DB in bulk instead of individually.
		per, err := getPersistedDataForCatalog(ctx, r.reader, r.kms, c)
		if err != nil {
			return errors.Wrap(ctx, err, op, errors.WithMsg("persisted catalog lookup failed"))
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
			return errors.Wrap(ctx, err, op)
		}

		if _, err := r.upsertHosts(ctx, ci.storeCat, catSetIds, resp.GetHosts()); err != nil {
			errors.Wrap(ctx, err, op, errors.WithMsg("upserting hosts"))
		}

		// update last sync time on the sets
		i, err := r.writer.Exec(ctx, "update host_plugin_set set last_sync_time = current_timestamp where public_id in (?)", []interface{}{catSetIds})
		if err != nil {
			return errors.Wrap(ctx, err, op, errors.WithMsg("updating last sync time"))
		}
		if i != len(catSetIds) {
			return errors.New(ctx, errors.Internal, op, "mismatched number of sets updated and synced")
		}
		r.numProcessed += len(catSetIds)
	}
	return nil
}

// upsertHosts inserts phs into the repository or updates its current
// attributes/set memberships and returns Hosts. h is not changed. hc must
// contain a valid public ID and scope ID. Each ph in phs must not contain a
// PublicId but must contain an external ID. The PublicId is generated and
// assigned by this method.
//
// NOTE: If phs is empty, this assumes that there are simply no hosts that
// matched the given sets! Which means it will remove all hosts from the given
// sets.
func (r *SetSyncJob) upsertHosts(
	ctx context.Context,
	hc *HostCatalog,
	setIds []string,
	phs []*plgpb.ListHostsResponseHost,
	_ ...Option) ([]*Host, error) {
	const op = "plugin.(Repository).upsertHosts"
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