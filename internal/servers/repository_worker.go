package servers

import (
	"context"
	"fmt"

	"github.com/hashicorp/boundary/internal/db"
	"github.com/hashicorp/boundary/internal/errors"
	"github.com/hashicorp/boundary/internal/servers/store"
	"github.com/hashicorp/boundary/internal/types/scope"
)

// DeleteWorker will delete a worker from the repository.
func (r *Repository) DeleteWorker(ctx context.Context, publicId string, _ ...Option) (int, error) {
	const op = "servers.(Repository).DeleteWorker"
	if publicId == "" {
		return db.NoRowsAffected, errors.New(ctx, errors.InvalidParameter, op, "missing public id")
	}
	worker := allocWorker()
	worker.Worker.PublicId = publicId

	var rowsDeleted int
	_, err := r.writer.DoTx(
		ctx,
		db.StdRetryCnt,
		db.ExpBackoff{},
		func(_ db.Reader, w db.Writer) error {
			deleteWorker := worker.clone()
			var err error
			rowsDeleted, err = w.Delete(
				ctx,
				deleteWorker,
			)
			if err != nil {
				return errors.Wrap(ctx, err, op)
			}
			if rowsDeleted > 1 {
				// return err, which will result in a rollback of the delete
				return errors.New(ctx, errors.MultipleRecords, op, "more than 1 resource would have been deleted")
			}
			return nil
		},
	)
	if err != nil {
		return db.NoRowsAffected, errors.Wrap(ctx, err, op, errors.WithMsg(fmt.Sprintf("failed for %s", publicId)))
	}
	if rowsDeleted == 0 {
		return db.NoRowsAffected, errors.Wrap(ctx, err, op, errors.WithMsg(fmt.Sprintf("delete failed for worker with workerId: %s", publicId)))
	}
	return rowsDeleted, nil
}

// LookupWorkerByWorkerReportedName returns the worker which has had a status update
// where the worker has reported this name.  This is different from the name
// on the resource itself which is set over the API.  In the event that no
// worker is found that matches then nil, nil will be returned.
func (r *Repository) LookupWorkerByWorkerReportedName(ctx context.Context, name string) (*Worker, error) {
	const op = "servers.(Repository).LookupWorkerByWorkerReportedName"
	// we derive the id instead of doing a query to be consistant with the
	// UpsertWorkerStatus flow which uses this function to upsert a worker.
	id, err := newWorkerIdFromName(ctx, name)
	if err != nil {
		return nil, errors.Wrap(ctx, err, op, errors.WithMsg("error while calculating the worker's id"))
	}
	w, err := lookupWorker(ctx, r.reader, id)
	if err != nil {
		return nil, errors.Wrap(ctx, err, op)
	}
	return w, nil
}

// LookupWorker returns the worker for the provided publicId.  This returns
// nil nil in the situation where no worker can be found with that public id.
func (r *Repository) LookupWorker(ctx context.Context, publicId string, _ ...Option) (*Worker, error) {
	const op = "servers.(Repository).LookupWorker"
	w, err := lookupWorker(ctx, r.reader, publicId)
	if err != nil {
		return nil, errors.Wrap(ctx, err, op)
	}
	return w, nil
}

// lookupWorker returns the worker for the provided id.  This returns
// nil nil in the situation where no worker can be found with that public id.
func lookupWorker(ctx context.Context, reader db.Reader, id string) (*Worker, error) {
	const op = "servers.lookupWorker"
	wAgg := &workerAggregate{}
	wAgg.PublicId = id
	err := reader.LookupById(ctx, wAgg)
	if err != nil {
		if errors.IsNotFoundError(err) {
			return nil, nil
		}
		return nil, errors.Wrap(ctx, err, op)
	}
	w, err := wAgg.toWorker(ctx)
	if err != nil {
		return nil, errors.Wrap(ctx, err, op)
	}
	return w, nil
}

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
		where = fmt.Sprintf("last_status_time > now() - interval '%d seconds'", uint32(liveness.Seconds()))
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

// UpsertWorkerStatus creates a new worker if one with the provided public id
// doesn't already exist. If it does, UpsertWorkerStatus updates the worker
// status.  This returns the Worker object with the updated WorkerStatus applied.
// The WithUpdateTags option is the only ones used. All others are ignored.
// Workers are intentionally not oplogged.
func (r *Repository) UpsertWorkerStatus(ctx context.Context, worker *Worker, opt ...Option) (*Worker, error) {
	const op = "servers.UpsertWorkerStatus"

	switch {
	case worker == nil:
		return nil, errors.New(ctx, errors.InvalidParameter, op, "worker is nil")
	case worker.GetWorkerReportedAddress() == "":
		return nil, errors.New(ctx, errors.InvalidParameter, op, "worker reported address is empty")
	case worker.ScopeId == "":
		return nil, errors.New(ctx, errors.InvalidParameter, op, "scope id is empty")
	case worker.PublicId != "":
		return nil, errors.New(ctx, errors.InvalidParameter, op, "worker id is not empty")
	case worker.GetWorkerReportedName() == "":
		return nil, errors.New(ctx, errors.InvalidParameter, op, "worker reported name is empty")
	case len(worker.apiTags) > 0:
		return nil, errors.New(ctx, errors.InvalidParameter, op, "api tags is not empty")
	}

	// Only retain the worker reported fields.
	worker = NewWorkerForStatus(worker.GetScopeId(),
		WithName(worker.GetWorkerReportedName()),
		WithAddress(worker.GetWorkerReportedAddress()),
		WithWorkerTags(worker.configTags...))

	opts := getOpts(opt...)

	var err error
	worker.PublicId, err = newWorkerIdFromName(ctx, worker.GetWorkerReportedName())
	if err != nil {
		return nil, errors.Wrap(ctx, err, op, errors.WithMsg("error generating worker id"))
	}

	var ret *Worker
	_, err = r.writer.DoTx(
		ctx,
		db.StdRetryCnt,
		db.ExpBackoff{},
		func(reader db.Reader, w db.Writer) error {
			workerCreateConflict := &db.OnConflict{
				Target: db.Columns{"public_id"},
				Action: append(db.SetColumns([]string{"worker_reported_name", "worker_reported_address"}),
					db.SetColumnValues(map[string]interface{}{"last_status_time": "now()"})...),
			}
			if err := w.Create(ctx, worker, db.WithOnConflict(workerCreateConflict)); err != nil {
				return errors.Wrap(ctx, err, op, errors.WithMsg("error creating a worker"))
			}

			// If we've been told to update tags, we need to clean out old
			// ones and add new ones. Within the current transaction, simply
			// delete all tags for the given worker, then add the new ones
			// we've been sent.
			if opts.withUpdateTags {
				setWorkerTags(ctx, w, worker.GetPublicId(), ConfigurationTagSource, worker.configTags)
			}

			wAgg := &workerAggregate{PublicId: worker.GetPublicId()}
			if err := reader.LookupById(ctx, wAgg); err != nil {
				return errors.Wrap(ctx, err, op, errors.WithMsg("error looking up worker aggregate"))
			}
			ret, err = wAgg.toWorker(ctx)
			if err != nil {
				return errors.Wrap(ctx, err, op, errors.WithMsg("error converting worker aggregate to worker"))
			}

			return nil
		},
	)
	if err != nil {
		return nil, err
	}

	return ret, nil
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
// worker.  Creating a worker is not intentionally oplogged.  A worker's
// ReportedStatus and Tags are intentionally ignored when creating a worker (not
// included).  Currently, a worker can only be created in the global scope
//
// Options supported: WithNewIdFunc (this option is likely only useful for tests)
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
	case worker.WorkerReportedAddress != "":
		return nil, errors.New(ctx, errors.InvalidParameter, op, "worker reported address is not empty")
	case worker.WorkerReportedName != "":
		return nil, errors.New(ctx, errors.InvalidParameter, op, "worker reported name is not empty")
	case worker.LastStatusTime != nil:
		return nil, errors.New(ctx, errors.InvalidParameter, op, "last status time is not nil")
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
