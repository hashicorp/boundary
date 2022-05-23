package servers

import (
	"context"
	"fmt"

	"github.com/hashicorp/boundary/internal/db"
	"github.com/hashicorp/boundary/internal/errors"
	"github.com/hashicorp/boundary/internal/servers/store"
	"github.com/hashicorp/boundary/internal/types/scope"
)

// ListWorkers is a passthrough to listWorkersWithReader that uses the repo's normal reader.
func (r *Repository) ListWorkers(ctx context.Context, opt ...Option) ([]*Worker, error) {
	return r.listWorkersWithReader(ctx, r.reader, opt...)
}

// listWorkersWithReader will return a listing of resources and honor the WithLimit option or the repo
// defaultLimit. It accepts a reader, allowing it to be used within a transaction or without.
func (r *Repository) listWorkersWithReader(ctx context.Context, reader db.Reader, opt ...Option) ([]*Worker, error) {
	const op = "workers.listWorkersWithReader"
	opts := getOpts(opt...)
	liveness := opts.withLiveness
	if liveness == 0 {
		liveness = DefaultLiveness
	}

	var where string
	if liveness > 0 {
		where = fmt.Sprintf("worker_status_update_time > now() - interval '%d seconds'", uint32(liveness.Seconds()))
	}

	var wAggs []*workerAggregate
	if err := reader.SearchWhere(
		ctx,
		&wAggs,
		where,
		[]interface{}{},
		db.WithLimit(-1),
	); err != nil {
		return nil, errors.Wrap(ctx, err, op, errors.WithMsg("error searching for workers"))
	}

	workers := make([]*Worker, 0, len(wAggs))
	for _, a := range wAggs {
		w, err := a.toWorker(ctx)
		if err != nil {
			return nil, errors.Wrap(ctx, err, op, errors.WithMsg("error converting workerAggregate to Worker"))
		}
		workers = append(workers, w)
	}
	return workers, nil
}

// ListTagsForWorkers returns a map from the worker's id to the list of Tags
// that are for that worker.  All options are ignored.
func (r *Repository) ListTagsForWorkers(ctx context.Context, workerIds []string, _ ...Option) (map[string][]*Tag, error) {
	const op = "servers.ListTagsForWorkers"
	var workerTags []*store.WorkerTag
	if err := r.reader.SearchWhere(
		ctx,
		&workerTags,
		"worker_id in (?)",
		[]interface{}{workerIds},
		db.WithLimit(-1),
	); err != nil {
		return nil, errors.Wrap(ctx, err, op, errors.WithMsg(fmt.Sprintf("worker IDs %v", workerIds)))
	}

	ret := make(map[string][]*Tag, len(workerIds))
	for _, t := range workerTags {
		ret[t.WorkerId] = append(ret[t.WorkerId], &Tag{Key: t.Key, Value: t.Value})
	}
	return ret, nil
}

// UpsertWorkerStatus creates a new worker if one with the provided public id doesn't
// already exist. If it does, UpsertWorkerStatus updates the worker. The
// WithUpdateTags option is the only one used. All others are ignored.
func (r *Repository) UpsertWorkerStatus(ctx context.Context, wStatus *WorkerStatus, opt ...Option) ([]*store.Controller, int, error) {
	const op = "servers.UpsertWorkerStatus"

	switch {
	case wStatus == nil:
		return nil, db.NoRowsAffected, errors.New(ctx, errors.InvalidParameter, op, "wStatus is nil")
	case wStatus.Address == "":
		return nil, db.NoRowsAffected, errors.New(ctx, errors.InvalidParameter, op, "address is empty")
	case wStatus.WorkerId == "":
		return nil, db.NoRowsAffected, errors.New(ctx, errors.InvalidParameter, op, "worker id is empty")
	}

	opts := getOpts(opt...)

	var rowsUpdated int64
	var controllers []*store.Controller
	_, err := r.writer.DoTx(
		ctx,
		db.StdRetryCnt,
		db.ExpBackoff{},
		func(read db.Reader, w db.Writer) error {
			workerOps := []Option{WithPublicId(wStatus.GetWorkerId())}
			if wStatus.GetName() != "" {
				// If this worker doesn't exist yet, that means it is a KMS only worker.
				// KMS workers have their resource name set to the name provided in the config at
				// creation time.
				// TODO (talanknight): Decide if this is actually the desired behavior.
				workerOps = append(workerOps, WithName(wStatus.GetName()))
			}
			worker := NewWorker(scope.Global.String(), workerOps...)
			workerCreateConflict := &db.OnConflict{
				Target: db.Columns{"public_id"},
				Action: db.DoNothing(true),
			}
			if err := w.Create(ctx, worker, db.WithOnConflict(workerCreateConflict)); err != nil {
				return errors.Wrap(ctx, err, op, errors.WithMsg("error creating a worker"))
			}

			var err error
			onConfigConflict := &db.OnConflict{
				Target: db.Columns{"worker_id"},
				Action: append(db.SetColumns([]string{"name", "address"}), db.SetColumnValues(map[string]interface{}{"update_time": "now()"})...),
			}
			err = w.Create(ctx, wStatus, db.WithOnConflict(onConfigConflict), db.WithReturnRowsAffected(&rowsUpdated))
			if err != nil {
				return errors.Wrap(ctx, err, op+":Upsert")
			}

			// Fetch current controllers to feed to the workers
			controllers, err = r.listControllersWithReader(ctx, read)
			if err != nil {
				return errors.Wrap(ctx, err, op+":ListController")
			}

			// If we've been told to update tags, we need to clean out old
			// ones and add new ones. Within the current transaction, simply
			// delete all tags for the given worker, then add the new ones
			// we've been sent.
			if opts.withUpdateTags {
				_, err = w.Exec(ctx, deleteTagsByWorkerIdSql, []interface{}{wStatus.GetWorkerId()})
				if err != nil {
					return errors.Wrap(ctx, err, op+":DeleteTags", errors.WithMsg(wStatus.GetWorkerId()))
				}

				// If tags were cleared out entirely, then we'll have nothing
				// to do here, e.g., it will result in deletion of all tags.
				// Otherwise, go through and stage each tuple for insertion
				// below.
				if len(wStatus.Tags) > 0 {
					tags := make([]interface{}, 0, len(wStatus.Tags))
					for _, v := range wStatus.Tags {
						if v == nil {
							return errors.New(ctx, errors.InvalidParameter, op+":RangeTags", fmt.Sprintf("found nil tag value for worker %s", wStatus.GetWorkerId()))
						}
						tags = append(tags, &store.WorkerTag{
							WorkerId: wStatus.GetWorkerId(),
							Key:      v.Key,
							Value:    v.Value,
							Source:   string(ConfigurationTagSource),
						})
					}
					if err = w.CreateItems(ctx, tags); err != nil {
						return errors.Wrap(ctx, err, op+":CreateTags", errors.WithMsg(wStatus.GetWorkerId()))
					}
				}
			}

			return nil
		},
	)
	if err != nil {
		return nil, db.NoRowsAffected, err
	}

	return controllers, int(rowsUpdated), nil
}
