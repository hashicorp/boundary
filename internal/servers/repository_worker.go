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

// listWorkersWithReader will return a listing of resources and honor the
// WithLimit option. If WithLiveness is zero the default liveness value is used,
// if it is negative then the last status update time is ignored. This method
// accepts a reader, allowing it to be used within a transaction or without.
func (r *Repository) listWorkersWithReader(ctx context.Context, reader db.Reader, opt ...Option) ([]*Worker, error) {
	const op = "workers.listWorkersWithReader"
	switch {
	case isNil(reader):
		return nil, errors.New(ctx, errors.InvalidParameter, op, "reader is nil")
	}
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
		db.WithLimit(opts.withLimit),
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
// Workers are intentionally not oplogged.
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
		func(reader db.Reader, w db.Writer) error {
			worker := NewWorker(scope.Global.String(), WithPublicId(wStatus.GetWorkerId()))
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
			controllers, err = r.listControllersWithReader(ctx, reader)
			if err != nil {
				return errors.Wrap(ctx, err, op+":ListController")
			}

			// If we've been told to update tags, we need to clean out old
			// ones and add new ones. Within the current transaction, simply
			// delete all tags for the given worker, then add the new ones
			// we've been sent.
			if opts.withUpdateTags {
				setWorkerTags(ctx, w, wStatus.GetWorkerId(), ConfigurationTagSource, wStatus.Tags)
			}

			return nil
		},
	)
	if err != nil {
		return nil, db.NoRowsAffected, err
	}

	return controllers, int(rowsUpdated), nil
}

// setWorkerTags removes all existing tags from the same source and worker id
// and creates new ones based on the ones provided.  This function should be
// called from inside a db transaction.
// Workers/worker tags are intentionally not oplogged.
func setWorkerTags(ctx context.Context, w db.Writer, id string, ts TagSource, tags []*Tag) error {
	const op = "servers.setWorkerTags"
	switch {
	case !ts.isValid():
		return errors.New(ctx, errors.InvalidParameter, op, "invalid tag source provided")
	case id == "":
		return errors.New(ctx, errors.InvalidParameter, op, "worker id is empty")
	case isNil(w):
		return errors.New(ctx, errors.InvalidParameter, op, "db.Writer is nil")
	}
	_, err := w.Exec(ctx, deleteTagsByWorkerIdSql, []interface{}{ts.String(), id})
	if err != nil {
		return errors.Wrap(ctx, err, op, errors.WithMsg(fmt.Sprintf("couldn't delete exist tags for worker %q", id)))
	}

	// If tags were cleared out entirely, then we'll have nothing
	// to do here, e.g., it will result in deletion of all tags.
	// Otherwise, go through and stage each tuple for insertion
	// below.
	if len(tags) > 0 {
		uTags := make([]interface{}, 0, len(tags))
		for _, v := range tags {
			if v == nil {
				return errors.New(ctx, errors.InvalidParameter, op, fmt.Sprintf("found nil tag value for worker %s", id))
			}
			uTags = append(uTags, &store.WorkerTag{
				WorkerId: id,
				Key:      v.Key,
				Value:    v.Value,
				Source:   ts.String(),
			})
		}
		if err = w.CreateItems(ctx, uTags); err != nil {
			return errors.Wrap(ctx, err, op, errors.WithMsg(fmt.Sprintf("error creating tags for worker %q", id)))
		}
	}

	return nil
}

// CreateWorker will create a worker in the repository and return the written
// worker.  Creating a worker is intentionally oplogged.  A worker's
// ReportedStatus and Tags are intentionally ignored when creating a worker (not
// included).  Currently, a worker can only be created in the global scope
//
// Options supported: WithNewIdFunc
func (r *Repository) CreateWorker(ctx context.Context, worker *Worker, opt ...Option) (*Worker, error) {
	const op = "servers.CreateWorker"
	switch {
	case worker == nil:
		return nil, errors.New(ctx, errors.InvalidParameter, op, "missing worker")
	case worker.PublicId != "":
		return nil, errors.New(ctx, errors.InvalidParameter, op, "public id is not empty")
	case worker.ScopeId == "":
		return nil, errors.New(ctx, errors.InvalidParameter, op, "missing scope id")
	case worker.ScopeId != scope.Global.String():
		return nil, errors.New(ctx, errors.InvalidParameter, op, fmt.Sprintf("scope id must be %q", scope.Global.String()))
	}

	opts := getOpts(opt...)
	var err error
	if worker.PublicId, err = opts.withNewIdFunc(ctx); err != nil {
		return nil, errors.Wrap(ctx, err, op, errors.WithMsg("unable to generate worker id"))
	}

	var returnedWorker *Worker
	_, err = r.writer.DoTx(
		ctx,
		db.StdRetryCnt,
		db.ExpBackoff{},
		func(_ db.Reader, w db.Writer) error {
			returnedWorker = worker.clone()
			err := w.Create(
				ctx,
				returnedWorker,
			)
			if err != nil {
				return errors.Wrap(ctx, err, op)
			}
			return nil
		},
	)
	if err != nil {
		return nil, errors.Wrap(ctx, err, op, errors.WithMsg("unable to create worker"))
	}
	return returnedWorker, nil
}
