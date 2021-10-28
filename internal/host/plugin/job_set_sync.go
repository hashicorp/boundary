package plugin

import (
	"context"
	"fmt"
	"time"

	"github.com/hashicorp/boundary/internal/db"
	"github.com/hashicorp/boundary/internal/errors"
	"github.com/hashicorp/boundary/internal/kms"
	"github.com/hashicorp/boundary/internal/libs/endpoint"
	"github.com/hashicorp/boundary/internal/scheduler"
	hcpb "github.com/hashicorp/boundary/sdk/pbs/controller/api/resources/hostcatalogs"
	pb "github.com/hashicorp/boundary/sdk/pbs/controller/api/resources/hostsets"
	plgpb "github.com/hashicorp/boundary/sdk/pbs/plugin"
	ua "go.uber.org/atomic"
)

const (
	setSyncJobName = "plugin_host_set_sync"
	setSyncJobRunInterval = 5 * time.Minute
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

		if _, err := r.UpsertHosts(ctx, ci.storeCat, catSetIds, resp.GetHosts()); err != nil {
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
