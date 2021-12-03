package plugin

import (
	"context"
	"fmt"
	"time"

	"github.com/hashicorp/boundary/internal/db"
	"github.com/hashicorp/boundary/internal/errors"
	"github.com/hashicorp/boundary/internal/kms"
	"github.com/hashicorp/boundary/internal/oplog"
	"github.com/hashicorp/boundary/internal/scheduler"
	plgpb "github.com/hashicorp/boundary/sdk/pbs/plugin"
	ua "go.uber.org/atomic"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

const (
	refreshHostCatalogPersistedJobName     = "plugin_host_catalog_refresh_persisted"
	refreshHostCatalogPersistedJobInterval = 10 * time.Minute
)

// RefreshHostCatalogPersistedJob is a recurring job that calls out
// to a plugin to allow its credentials to be refreshed. This can be
// used to facilitate periodic rotation of credentials or removal or
// outdated ones.
type RefreshHostCatalogPersistedJob struct {
	reader  db.Reader
	writer  db.Writer
	kms     *kms.Kms
	plugins map[string]plgpb.HostPluginServiceClient
	limit   int

	running      ua.Bool
	numProcessed int
	numCatalogs  int
}

// newRefreshHostCatalogPersistedJob creates a new in-memory
// RefreshHostCatalogPersistedJob.
//
// WithLimit is the only supported option.
func newRefreshHostCatalogPersistedJob(ctx context.Context, r db.Reader, w db.Writer, kms *kms.Kms, plgm map[string]plgpb.HostPluginServiceClient, opt ...Option) (*RefreshHostCatalogPersistedJob, error) {
	const op = "plugin.newRefreshHostCatalogPersistedJob"
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
	return &RefreshHostCatalogPersistedJob{
		reader:  r,
		writer:  w,
		kms:     kms,
		plugins: plgm,
		limit:   opts.withLimit,
	}, nil
}

// Status returns the current status of the set sync job. Total is
// the total number of catalogs that are to be refreshed. Completed
// is the number of sets already refreshed.
func (j *RefreshHostCatalogPersistedJob) Status() scheduler.JobStatus {
	return scheduler.JobStatus{
		Completed: j.numProcessed,
		Total:     j.numCatalogs,
	}
}

// Run queries the plugin host repo for catalogs that need their
// credentials refreshed. It then creates a plugin client and invokes
// the RefreshHostCatalogPersisted RPC call. The updated persisted
// state (ie: secrets) are then saved.
func (j *RefreshHostCatalogPersistedJob) Run(ctx context.Context) error {
	const op = "plugin.(RefreshHostCatalogPersistedJob).Run"
	if !j.running.CAS(j.running.Load(), true) {
		return errors.New(ctx, errors.JobAlreadyRunning, op, "job already running")
	}
	defer j.running.Store(false)

	// Verify context is not done before running
	if err := ctx.Err(); err != nil {
		return errors.Wrap(ctx, err, op)
	}

	// Get all host catalogs.
	var aggs []*catalogAgg
	if err := j.reader.SearchWhere(ctx, &aggs, "", nil, db.WithLimit(j.limit)); err != nil {
		return errors.Wrap(ctx, err, op)
	}

	// Set numProcessed and numHosts for status report
	j.numProcessed, j.numCatalogs = 0, len(aggs)
	if len(aggs) == 0 {
		return nil
	}

	for _, agg := range aggs {
		if err := j.refreshHostCatalogPersisted(ctx, agg); err != nil {
			return errors.Wrap(ctx, err, op)
		}

		j.numProcessed++
	}

	return nil
}

func (j *RefreshHostCatalogPersistedJob) refreshHostCatalogPersisted(ctx context.Context, agg *catalogAgg) error {
	const op = "plugin.(RefreshHostCatalogPersistedJob).refreshHostCatalogPersisted"
	if agg == nil {
		return errors.New(ctx, errors.InvalidParameter, op, "catalog aggregate is nil")
	}

	// Split out the catalog and persisted data
	catalog, secret := agg.toCatalogAndPersisted()
	var persisted *plgpb.HostCatalogPersisted
	if secret != nil {
		var err error
		persisted, err = toPluginPersistedData(ctx, j.kms, catalog.GetScopeId(), secret)
		if err != nil {
			return errors.Wrap(ctx, err, op)
		}
	}

	// Look up the plugin for the catalog. If the plugin is not loaded,
	// it's an error.
	plgClient, ok := j.plugins[catalog.PluginId]
	if !ok {
		return errors.New(ctx, errors.Internal, op, fmt.Sprintf("plugin id %q not loaded", catalog.GetPluginId()))
	}

	// Convert to protobuf
	catalogProto, err := toPluginCatalog(ctx, catalog)
	if err != nil {
		return errors.Wrap(ctx, err, op)
	}

	// Get the oplog wrapper
	oplogWrapper, err := j.kms.GetWrapper(ctx, catalog.ScopeId, kms.KeyPurposeOplog)
	if err != nil {
		return errors.Wrap(ctx, err, op, errors.WithMsg("unable to get oplog wrapper"))
	}

	// Invoke the plugin's RefreshHostCatalogPersisted RPC call.
	plgResp, err := plgClient.RefreshHostCatalogPersisted(ctx, &plgpb.RefreshHostCatalogPersistedRequest{
		Catalog:   catalogProto,
		Persisted: persisted,
	})
	if err != nil {
		if status.Code(err) != codes.Unimplemented {
			return errors.Wrap(ctx, err, op)
		}
	}

	// From here we treat the secrets similar to how we would in an
	// OnUpdateCatalog response:
	//
	// * We only act if the secrets field is non-nil in the reply.
	// * If there is a valid zero-length secret response, we delete the
	// secrets outright.
	// * Otherwise it's an upsert operation where we either
	// create/update depending on if there were secrets already
	// present.
	if plgResp != nil && plgResp.GetPersisted().GetSecrets() != nil {
		if len(plgResp.GetPersisted().GetSecrets().GetFields()) == 0 {
			// Delete the secret.
			hcSecret, err := newHostCatalogSecret(ctx, catalog.PublicId, plgResp.GetPersisted().GetSecrets())
			if err != nil {
				return errors.Wrap(ctx, err, op)
			}
			secretsDeleted, err := j.writer.Delete(ctx, hcSecret, db.WithOplog(oplogWrapper, hcSecret.oplog(oplog.OpType_OP_TYPE_DELETE)))
			if err != nil {
				return errors.Wrap(ctx, err, op)
			}
			if secretsDeleted != 1 {
				return errors.New(ctx, errors.MultipleRecords, op, fmt.Sprintf("expected 1 catalog secret to be deleted, got %d", secretsDeleted))
			}
		} else {
			// Upsert the secret.
			hcSecret, err := newHostCatalogSecret(ctx, catalog.GetPublicId(), plgResp.GetPersisted().GetSecrets())
			if err != nil {
				return errors.Wrap(ctx, err, op)
			}
			dbWrapper, err := j.kms.GetWrapper(ctx, catalog.ScopeId, kms.KeyPurposeDatabase)
			if err != nil {
				return errors.Wrap(ctx, err, op, errors.WithMsg("unable to get db wrapper"))
			}
			if err := hcSecret.encrypt(ctx, dbWrapper); err != nil {
				return errors.Wrap(ctx, err, op)
			}

			if err := j.writer.Create(
				ctx,
				hcSecret,
				db.WithOnConflict(&db.OnConflict{
					Target: db.Columns{"catalog_id"},
					Action: db.SetColumns([]string{"secret", "key_id"}),
				}),
				db.WithOplog(oplogWrapper, hcSecret.oplog(oplog.OpType_OP_TYPE_CREATE)),
			); err != nil {
				return errors.Wrap(ctx, err, op)
			}
		}
	}

	// done
	return nil
}
