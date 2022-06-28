package server

import (
	"context"
	"fmt"
	"strings"

	"github.com/hashicorp/boundary/internal/db"
	dbcommon "github.com/hashicorp/boundary/internal/db/common"
	"github.com/hashicorp/boundary/internal/errors"
	"github.com/hashicorp/boundary/internal/kms"
	"github.com/hashicorp/boundary/internal/server/store"
	"github.com/hashicorp/boundary/internal/types/scope"
	wrapping "github.com/hashicorp/go-kms-wrapping/v2"
	"github.com/hashicorp/nodeenrollment"
	"github.com/hashicorp/nodeenrollment/registration"
	"google.golang.org/protobuf/types/known/structpb"
)

// DeleteWorker will delete a worker from the repository.
func (r *Repository) DeleteWorker(ctx context.Context, publicId string, _ ...Option) (int, error) {
	const op = "server.(Repository).DeleteWorker"
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

// LookupWorkerByName returns the worker with the provided name. In the event
// that no worker is found that matches then nil, nil will be returned.
func (r *Repository) LookupWorkerByName(ctx context.Context, name string) (*Worker, error) {
	const op = "server.(Repository).LookupWorkerByName"
	switch {
	case name == "":
		return nil, errors.New(ctx, errors.InvalidParameter, op, "name is empty")
	}
	w, err := lookupWorkerByName(ctx, r.reader, name)
	if err != nil {
		return nil, errors.Wrap(ctx, err, op)
	}
	return w, nil
}

func lookupWorkerByName(ctx context.Context, reader db.Reader, name string) (*Worker, error) {
	const op = "server.lookupWorkerByName"
	switch {
	case isNil(reader):
		return nil, errors.New(ctx, errors.InvalidParameter, op, "reader is nil")
	case name == "":
		return nil, errors.New(ctx, errors.InvalidParameter, op, "name is empty")
	}

	wAgg := &workerAggregate{}
	err := reader.LookupWhere(ctx, &wAgg, "name = ?", []interface{}{name})
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

func (r *Repository) LookupWorkerIdByKeyId(ctx context.Context, keyId string) (string, error) {
	const op = "server.(Repository).LookupWorkerIdByKeyId"
	switch {
	case keyId == "":
		return "", errors.New(ctx, errors.InvalidParameter, op, "keyId is empty")
	}

	// We're searching for a workerAuth record based on worker id
	worker := allocWorkerAuth()
	worker.WorkerKeyIdentifier = keyId

	err := r.reader.LookupById(ctx, worker)
	if err != nil {
		if errors.IsNotFoundError(err) {
			return "", nil
		}
		return "", errors.Wrap(ctx, err, op)
	}

	return worker.WorkerId, nil
}

// LookupWorker returns the worker for the provided publicId.  This returns
// nil nil in the situation where no worker can be found with that public id.
func (r *Repository) LookupWorker(ctx context.Context, publicId string, _ ...Option) (*Worker, error) {
	const op = "server.(Repository).LookupWorker"
	switch {
	case publicId == "":
		return nil, errors.New(ctx, errors.InvalidParameter, op, "publicId is empty")
	}
	w, err := lookupWorker(ctx, r.reader, publicId)
	if err != nil {
		return nil, errors.Wrap(ctx, err, op)
	}
	return w, nil
}

// lookupWorker returns the worker for the provided id.  This returns
// nil nil in the situation where no worker can be found with that public id.
func lookupWorker(ctx context.Context, reader db.Reader, id string) (*Worker, error) {
	const op = "server.lookupWorker"
	switch {
	case id == "":
		return nil, errors.New(ctx, errors.InvalidParameter, op, "id is empty")
	}
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

// ListWorkers will return a listing of Workers and honor the WithLimit option.
// If WithLiveness is zero the default liveness value is used, if it is negative
// then the last status update time is ignored.
// If WithLimit < 0, then unlimited results are returned. If WithLimit == 0, then
// default limits are used for results.
func (r *Repository) ListWorkers(ctx context.Context, scopeIds []string, opt ...Option) ([]*Worker, error) {
	const op = "server.(Repository).ListWorkers"
	switch {
	case len(scopeIds) == 0:
		return nil, errors.New(ctx, errors.InvalidParameter, op, "no scope ids set")
	}

	opts := getOpts(opt...)
	liveness := opts.withLiveness
	if liveness == 0 {
		liveness = DefaultLiveness
	}

	var where []string
	var whereArgs []interface{}
	if liveness > 0 {
		where = append(where, fmt.Sprintf("last_status_time > now() - interval '%d seconds'", uint32(liveness.Seconds())))
	}
	if len(scopeIds) > 0 {
		where = append(where, "scope_id in (?)")
		whereArgs = append(whereArgs, scopeIds)
	}

	limit := r.defaultLimit
	if opts.withLimit != 0 {
		// non-zero signals an override of the default limit for the repo.
		limit = opts.withLimit
	}

	var wAggs []*workerAggregate
	if err := r.reader.SearchWhere(
		ctx,
		&wAggs,
		strings.Join(where, " and "),
		whereArgs,
		db.WithLimit(limit),
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

// UpsertWorkerStatus will update the address and last status time for a worker.
// If the worker is a kms worker that hasn't been seen yet, it'll attempt to
// create a new one, but will return an error if another worker (kms or other)
// has the same name.  This returns the Worker object with the changes applied.
// The WithPublicId, WithKeyId, and WithUpdateTags options are
// the only ones used. All others are ignored.
// Workers are intentionally not oplogged.
func (r *Repository) UpsertWorkerStatus(ctx context.Context, worker *Worker, opt ...Option) (*Worker, error) {
	const op = "server.UpsertWorkerStatus"

	opts := getOpts(opt...)
	switch {
	case worker == nil:
		return nil, errors.New(ctx, errors.InvalidParameter, op, "worker is nil")
	case worker.GetAddress() == "":
		return nil, errors.New(ctx, errors.InvalidParameter, op, "worker reported address is empty")
	case worker.ScopeId == "":
		return nil, errors.New(ctx, errors.InvalidParameter, op, "scope id is empty")
	case worker.PublicId != "":
		return nil, errors.New(ctx, errors.InvalidParameter, op, "worker id is not empty")
	case worker.GetName() == "" && opts.withKeyId == "":
		return nil, errors.New(ctx, errors.InvalidParameter, op, "worker keyId and reported name are both empty; one is required")
	case worker.GetName() != "" && opts.withKeyId != "":
		return nil, errors.New(ctx, errors.InvalidParameter, op, "worker keyId and reported name are both set; no more than one is allowed")
	}

	var workerId string
	var err error
	switch {
	case opts.withPublicId != "":
		workerId = opts.withPublicId
	case opts.withKeyId != "":
		workerId, err = r.LookupWorkerIdByKeyId(ctx, opts.withKeyId)
		if err != nil || workerId == "" {
			return nil, errors.Wrap(ctx, err, op, errors.WithMsg("error finding worker by keyId"))
		}
	default:
		// generating the worker id based off of the scope and name ensures
		// that if 2 kms workers are making requests with the same name they
		// are treated as the same worker.  Allowing this only for kms workers
		// also ensures that we maintain the unique name constraint between pki
		// workers and kms workers.
		workerId, err = newWorkerIdFromScopeAndName(ctx, worker.GetScopeId(), worker.GetName())
		if err != nil || workerId == "" {
			return nil, errors.Wrap(ctx, err, op, errors.WithMsg("error creating a worker id"))
		}
	}

	var ret *Worker
	_, err = r.writer.DoTx(
		ctx,
		db.StdRetryCnt,
		db.ExpBackoff{},
		func(reader db.Reader, w db.Writer) error {
			workerClone := worker.clone()
			workerClone.PublicId = workerId
			switch {
			case opts.withKeyId != "":
				// This case goes first in case we want to relax the restriction
				// around both name and key ID being supplied to account for
				// e.g. config processing bugs. In that case, a key ID being
				// supplied should be a clear indicator that we are working with
				// a PKI workerClone, and a lack of one a clear indication we are
				// working with a KMS workerClone.
				//
				// Note: unlike in the below case, this purposefully leaves out
				// "description" since we want description changes for PKI-based
				// workers to come via API only. We can't really guard on this
				// in the DB so we need to be sure to not include it here.
				n, err := w.Update(ctx, workerClone, []string{"address"}, nil)
				if err != nil {
					return errors.Wrap(ctx, err, op, errors.WithMsg("unable to update status of pki worker"))
				}
				switch n {
				case 0:
					return errors.New(ctx, errors.RecordNotFound, op, fmt.Sprintf("failed to find worker with key id %q", opts.withKeyId))
				case 1:
					break
				default:
					return errors.New(ctx, errors.MultipleRecords, op, fmt.Sprintf("multiple records found when updating worker with id %q", workerClone.GetPublicId()))
				}

			case workerClone.GetName() != "":
				workerClone.Type = KmsWorkerType.String()
				workerCreateConflict := &db.OnConflict{
					Target: db.Columns{"public_id"},
					Action: append(db.SetColumns([]string{"address"}),
						db.SetColumnValues(map[string]interface{}{"last_status_time": "now()"})...),
				}
				var withRowsAffected int64
				err := w.Create(ctx, workerClone, db.WithOnConflict(workerCreateConflict), db.WithReturnRowsAffected(&withRowsAffected),
					// The intent of this WithWhere option is to operate with the OnConflict such that the action
					// taken by the OnConflict only applies if the conflict is on a row that is returned by this where
					// statement, otherwise it should error out.
					db.WithWhere("server_worker.type = 'kms'"))
				if err == nil && workerClone.Description != worker.Description {
					_, err = w.Update(ctx, workerClone, []string{"description"}, nil)
				}
				switch {
				case err != nil:
					return errors.Wrap(ctx, err, op, errors.WithMsg("error creating a worker"))
				case withRowsAffected == 0:
					return errors.New(ctx, errors.NotUnique, op, "error updating worker")
				}
			}

			// If we've been told to update tags, we need to clean out old
			// ones and add new ones. Within the current transaction, simply
			// delete all tags for the given worker, then add the new ones
			// we've been sent.
			if opts.withUpdateTags {
				if err := setWorkerTags(ctx, w, workerClone.GetPublicId(), ConfigurationTagSource, workerClone.inputTags); err != nil {
					return errors.Wrap(ctx, err, op, errors.WithMsg("error setting worker tags"))
				}
			}

			wAgg := &workerAggregate{PublicId: workerClone.GetPublicId()}
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
	const op = "server.setWorkerTags"
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

// UpdateWorker will update a worker in the repository and return the resulting
// worker. fieldMaskPaths provides field_mask.proto paths for fields that should
// be updated.  Fields will be set to NULL if the field is a zero value and
// included in fieldMask. Name, Description, and Address are the only updatable
// fields, if no updatable fields are included in the fieldMaskPaths, then an
// error is returned.  If any paths besides those listed above are included in
// the path then an error is returned.
func (r *Repository) UpdateWorker(ctx context.Context, worker *Worker, version uint32, fieldMaskPaths []string, opt ...Option) (*Worker, int, error) {
	const (
		nameField = "name"
		descField = "description"
	)
	const op = "server.(Repository).UpdateWorker"
	switch {
	case worker == nil:
		return nil, db.NoRowsAffected, errors.New(ctx, errors.InvalidParameter, op, "worker is nil")
	case worker.PublicId == "":
		return nil, db.NoRowsAffected, errors.New(ctx, errors.InvalidParameter, op, "missing public id")
	case version == 0:
		return nil, db.NoRowsAffected, errors.New(ctx, errors.InvalidParameter, op, "version is zero")
	}

	for _, f := range fieldMaskPaths {
		switch {
		case strings.EqualFold(nameField, f):
		case strings.EqualFold(descField, f):
		default:
			return nil, db.NoRowsAffected, errors.New(ctx, errors.InvalidFieldMask, op, fmt.Sprintf("invalid field mask: %s", f))
		}
	}

	var dbMask, nullFields []string
	dbMask, nullFields = dbcommon.BuildUpdatePaths(
		map[string]interface{}{
			nameField: worker.Name,
			descField: worker.Description,
		},
		fieldMaskPaths,
		nil,
	)
	if len(dbMask) == 0 && len(nullFields) == 0 {
		return nil, db.NoRowsAffected, errors.New(ctx, errors.EmptyFieldMask, op, "no fields to update")
	}

	var rowsUpdated int
	var ret *Worker
	var err error
	_, err = r.writer.DoTx(
		ctx,
		db.StdRetryCnt,
		db.ExpBackoff{},
		func(reader db.Reader, w db.Writer) error {
			worker := worker.clone()
			rowsUpdated, err = w.Update(ctx, worker, dbMask, nullFields, db.WithVersion(&version),
				db.WithWhere("server_worker.type = 'pki'"))
			if err != nil {
				return errors.Wrap(ctx, err, op)
			}
			if worker.Type == KmsWorkerType.String() {
				return errors.New(ctx, errors.InvalidParameter, op, "cannot update a KMS worker")
			}
			if rowsUpdated > 1 {
				// return err, which will result in a rollback of the update
				return errors.New(ctx, errors.MultipleRecords, op, "more than 1 resource would have been updated")
			}

			wAgg := &workerAggregate{PublicId: worker.GetPublicId()}
			if err := reader.LookupById(ctx, wAgg); err != nil {
				return errors.Wrap(ctx, err, op)
			}
			if ret, err = wAgg.toWorker(ctx); err != nil {
				return err
			}
			return nil
		},
	)
	if err != nil {
		if errors.IsUniqueError(err) {
			return nil, db.NoRowsAffected, errors.New(ctx, errors.NotUnique, op, fmt.Sprintf("worker with name %q already exists", worker.Name))
		}
		return nil, db.NoRowsAffected, errors.Wrap(ctx, err, op, errors.WithMsg(fmt.Sprintf("for %s", worker.GetPublicId())))
	}
	return ret, rowsUpdated, nil
}

// CreateWorker will create a worker in the repository and return the written
// worker.  Creating a worker is not intentionally oplogged.  A worker's
// ReportedStatus and Tags are intentionally ignored when creating a worker (not
// included).  Currently, a worker can only be created in the global scope
//
// Options supported: WithFetchNodeCredentialsRequest and WithNewIdFunc (this
// option is likely only useful for tests)
func (r *Repository) CreateWorker(ctx context.Context, worker *Worker, opt ...Option) (*Worker, error) {
	const op = "server.CreateWorker"
	switch {
	case worker == nil:
		return nil, errors.New(ctx, errors.InvalidParameter, op, "missing worker")
	case worker.PublicId != "":
		return nil, errors.New(ctx, errors.InvalidParameter, op, "public id is not empty")
	case worker.ScopeId == "":
		return nil, errors.New(ctx, errors.InvalidParameter, op, "missing scope id")
	case worker.ScopeId != scope.Global.String():
		return nil, errors.New(ctx, errors.InvalidParameter, op, fmt.Sprintf("scope id must be %q", scope.Global.String()))
	case worker.Address != "":
		return nil, errors.New(ctx, errors.InvalidParameter, op, "address is not empty")
	case worker.LastStatusTime != nil:
		return nil, errors.New(ctx, errors.InvalidParameter, op, "last status time is not nil")
	}

	opts := getOpts(opt...)
	var err error
	if worker.PublicId, err = opts.withNewIdFunc(ctx); err != nil {
		return nil, errors.Wrap(ctx, err, op, errors.WithMsg("unable to generate worker id"))
	}
	state, err := structpb.NewStruct(map[string]any{
		"worker_id": worker.PublicId,
	})
	if err != nil {
		return nil, errors.Wrap(ctx, err, op, errors.WithMsg("error generating state struct", err))
	}

	var databaseWrapper wrapping.Wrapper
	var workerAuthRepo *WorkerAuthRepositoryStorage
	if opts.withFetchNodeCredentialsRequest != nil {
		// used to encrypt the privKey within the NodeInformation
		databaseWrapper, err = r.kms.GetWrapper(ctx, scope.Global.String(), kms.KeyPurposeDatabase)
		if err != nil {
			return nil, errors.Wrap(ctx, err, op)
		}
	}

	var returnedWorker *Worker
	if _, err := r.writer.DoTx(
		ctx,
		db.StdRetryCnt,
		db.ExpBackoff{},
		func(read db.Reader, w db.Writer) error {
			returnedWorker = worker.clone()
			returnedWorker.Type = PkiWorkerType.String()
			if err := w.Create(
				ctx,
				returnedWorker,
			); err != nil {
				return errors.Wrap(ctx, err, op, errors.WithMsg("unable to create worker"))
			}
			if opts.withFetchNodeCredentialsRequest != nil {
				workerAuthRepo, err = NewRepositoryStorage(ctx, read, w, r.kms)
				if err != nil {
					return errors.Wrap(ctx, err, op, errors.WithMsg("unable to create worker auth repository"))
				}
				nodeInfo, err := registration.AuthorizeNode(ctx, workerAuthRepo, opts.withFetchNodeCredentialsRequest, nodeenrollment.WithSkipStorage(true))
				if err != nil {
					return errors.Wrap(ctx, err, op, errors.WithMsg("unable to authorize node"))
				}
				nodeInfo.State = state
				if err := StoreNodeInformationTx(ctx, w, databaseWrapper, nodeInfo); err != nil {
					return errors.Wrap(ctx, err, op, errors.WithMsg("unable to store node information"))
				}
			}
			return nil
		},
	); err != nil {
		return nil, errors.Wrap(ctx, err, op)
	}
	return returnedWorker, nil
}
