// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: BUSL-1.1

package server

import (
	"context"
	"database/sql"
	stderrors "errors"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/hashicorp/boundary/internal/db"
	"github.com/hashicorp/boundary/internal/errors"
	"github.com/hashicorp/boundary/internal/kms"
	"github.com/hashicorp/boundary/internal/server/store"
	"github.com/hashicorp/boundary/internal/types/scope"
	"github.com/hashicorp/go-dbw"
	"github.com/hashicorp/nodeenrollment"
	"github.com/hashicorp/nodeenrollment/registration"
	"github.com/hashicorp/nodeenrollment/types"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/structpb"
	"google.golang.org/protobuf/types/known/timestamppb"
)

var ErrCannotUpdateKmsWorkerViaApi = stderrors.New("cannot update a kms worker's basic information via api")

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
	err := reader.LookupWhere(ctx, &wAgg, "name = ?", []any{name})
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

// ListWorkersUnpaginated will return a listing of Workers and honor the WithLimit option.
// Supported options: WithWorkerType, WithActiveWorkers, WithLiveness,
// WithWorkerPool, WithLimit, WithStartPageAfterItem.
//
// If WithLiveness is zero the default liveness value is used, if it is negative
// then the last status update time is ignored.
// If WithLimit < 0, then unlimited results are returned. If WithLimit == 0, then
// default limits are used for results.  WithWorkerPool can be provided with a
// non-zero length slice of worker ids to restrict the returned workers to only
// ones with the ids provided.
func (r *Repository) ListWorkersUnpaginated(ctx context.Context, scopeIds []string, opt ...Option) ([]*Worker, error) {
	const op = "server.(Repository).ListWorkersUnpaginated"

	opts := GetOpts(opt...)
	newOpts := []Option{}
	// handle the WithLimit default for the repo
	switch {
	case opts.withLimit != 0:
		newOpts = append(newOpts, WithLimit(opts.withLimit))
	default:
		newOpts = append(newOpts, WithLimit(r.defaultLimit))
	}
	// handle the WithLiveness default
	switch {
	case opts.withLiveness != 0:
		newOpts = append(newOpts, WithLiveness(opts.withLiveness))
	default:
		newOpts = append(newOpts, WithLiveness(DefaultLiveness))

	}
	newOpts = append(newOpts, WithWorkerType(opts.withWorkerType))
	newOpts = append(newOpts, WithActiveWorkers(opts.withActiveWorkers))
	newOpts = append(newOpts, WithWorkerPool(opts.withWorkerPool))
	newOpts = append(newOpts, WithStartPageAfterItem(opts.withStartPageAfterItem))
	return ListWorkersUnpaginated(ctx, r.reader, scopeIds, newOpts...)
}

// ListWorkersUnpaginated will return a listing of Workers and honor the WithLimit option.
// Supported options: WithWorkerType, WithActiveWorkers, WithLiveness,
// WithWorkerPool, WithLimit, WithStartPageAfterItem
//
// If WithLiveness is zero the default liveness value is used, if it is negative
// then the last status update time is ignored.
// If WithLimit < 0, then unlimited results are returned. If WithLimit == 0, then
// default limits are used for results.  WithWorkerPool can be provided with a
// non-zero length slice of worker ids to restrict the returned workers to only
// ones with the ids provided.
func ListWorkersUnpaginated(ctx context.Context, reader db.Reader, scopeIds []string, opt ...Option) ([]*Worker, error) {
	const op = "server.ListWorkersUnpaginated"
	switch {
	case len(scopeIds) == 0:
		return nil, errors.New(ctx, errors.InvalidParameter, op, "no scope ids set")
	}

	opts := GetOpts(opt...)
	liveness := opts.withLiveness
	if liveness == 0 {
		liveness = DefaultLiveness
	}

	var where []string
	var whereArgs []any
	if liveness > 0 {
		where = append(where, fmt.Sprintf("last_status_time > now() - interval '%d seconds'", uint32(liveness.Seconds())))
	}
	var scopeArgs []string
	for i, scopeId := range scopeIds {
		arg := "scope_id_" + strconv.Itoa(i)
		scopeArgs = append(scopeArgs, "@"+arg)
		whereArgs = append(whereArgs, sql.Named(arg, scopeId))
	}
	if len(scopeArgs) > 0 {
		where = append(where, fmt.Sprintf("scope_id in (%s)", strings.Join(scopeArgs, ", ")))
	}

	switch opts.withWorkerType {
	case "":
	case KmsWorkerType, PkiWorkerType:
		where = append(where, "type = @worker_type")
		whereArgs = append(whereArgs, sql.Named("worker_type", opts.withWorkerType.String()))
	default:
		return nil, errors.New(ctx, errors.InvalidParameter, op, fmt.Sprintf("unknown worker type %v", opts.withWorkerType))
	}

	if opts.withActiveWorkers {
		where = append(where, "operational_state = @operational_state")
		whereArgs = append(whereArgs, sql.Named("operational_state", ActiveOperationalState.String()))
	}

	var workerArgs []string
	for i, worker := range opts.withWorkerPool {
		arg := "public_id_" + strconv.Itoa(i)
		workerArgs = append(workerArgs, "@"+arg)
		whereArgs = append(whereArgs, sql.Named(arg, worker))
	}
	if len(workerArgs) > 0 {
		where = append(where, fmt.Sprintf("public_id in (%s)", strings.Join(workerArgs, ", ")))
	}

	limit := db.DefaultLimit
	if opts.withLimit != 0 {
		// non-zero signals an override of the default limit for the repo.
		limit = opts.withLimit
	}

	// Ordering and pagination are tightly coupled.
	// We order by update_time ascending so that new
	// and updated items appear at the end of the pagination.
	// We need to further order by public_id to distinguish items
	// with identical update times.
	withOrder := "update_time asc, public_id asc"
	if opts.withStartPageAfterItem != nil {
		// Now that the order is defined, we can use a simple where
		// clause to only include items updated since the specified
		// start of the page. We use greater than or equal for the update
		// time as there may be items with identical update_times. We
		// then use public_id as a tiebreaker.
		whereArgs = append(whereArgs,
			sql.Named("after_item_update_time", opts.withStartPageAfterItem.GetUpdateTime()),
			sql.Named("after_item_id", opts.withStartPageAfterItem.GetPublicId()),
		)
		where = append(where, "(update_time > @after_item_update_time or (update_time = @after_item_update_time and public_id > @after_item_id))")
	}

	var wAggs []*workerAggregate
	if err := reader.SearchWhere(
		ctx,
		&wAggs,
		strings.Join(where, " and "),
		whereArgs,
		db.WithLimit(limit),
		db.WithOrder(withOrder),
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

	opts := GetOpts(opt...)
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
	case worker.OperationalState == "":
		return nil, errors.New(ctx, errors.InvalidParameter, op, "worker operational state is empty")
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
		workerId, err = NewWorkerIdFromScopeAndName(ctx, worker.GetScopeId(), worker.GetName())
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
				// This case goes first because a key ID being supplied should
				// be a clear indicator that we are working with a PKI (or
				// KMS-PKI) workerClone, and a lack of one a clear indication we
				// are working with a KMS workerClone.
				//
				// Note: unlike in the below case, this purposefully leaves out
				// "description" since we want description changes for (non
				// KMS-PKI) PKI-based workers to come via API only. We can't
				// really guard on this in the DB so we need to be sure to not
				// include it here.
				n, err := w.Update(ctx, workerClone, []string{"address", "ReleaseVersion", "OperationalState"}, nil)
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
					Action: append(db.SetColumns([]string{"address", "release_version", "operational_state"}),
						db.SetColumnValues(map[string]any{"last_status_time": "now()"})...),
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
	_, err := w.Exec(ctx, deleteTagsByWorkerIdSql, []any{ts.String(), id})
	if err != nil {
		return errors.Wrap(ctx, err, op, errors.WithMsg(fmt.Sprintf("couldn't delete existing tags for worker %q", id)))
	}

	// If tags were cleared out entirely, then we'll have nothing
	// to do here, e.g., it will result in deletion of all tags.
	// Otherwise, go through and stage each tuple for insertion
	// below.
	if len(tags) > 0 {
		uTags := make([]any, 0, len(tags))
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
// be updated. Fields will be set to NULL if the field is a zero value and
// included in fieldMask. Name, Description, and Address are the only updatable
// fields, if no updatable fields are included in the fieldMaskPaths, then an
// error is returned. If any paths besides those listed above are included in
// the path then an error is returned. If the worker is a KMS worker (whether
// via the old registration method or pki-kms) name updates will be disallowed.
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
	dbMask, nullFields = dbw.BuildUpdatePaths(
		map[string]any{
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
			// First we need to do a lookup so we can validate that this
			// function is not being used for workers registered via KMS-PKI
			// means
			wAgg := &workerAggregate{PublicId: worker.GetPublicId()}
			if err := reader.LookupById(ctx, wAgg); err != nil {
				return errors.Wrap(ctx, err, op)
			}
			// If it's a KMS-PKI worker we do not want to allow
			// name/description/other updates via the API, it should only come
			// in via the upsert mechanism via status updates. If the public ID
			// is predictably generated in the KMS fashion, it's a KMS-PKI
			// worker.
			workerId, err := NewWorkerIdFromScopeAndName(ctx, wAgg.ScopeId, wAgg.Name)
			if err != nil {
				return errors.Wrap(ctx, err, op, errors.WithMsg("error generating worker id in kms-pki name check case"))
			}
			if workerId == worker.PublicId {
				return errors.Wrap(ctx, ErrCannotUpdateKmsWorkerViaApi, op, errors.WithCode(errors.InvalidParameter))
			}

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

			wAgg = &workerAggregate{PublicId: worker.GetPublicId()}
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
// Options supported: WithNewIdFunc (this option is likely only useful for
// tests), WithFetchNodeCredentialsRequest,
// WithCreateControllerLedActivationToken. The latter two are mutually
// exclusive.
func (r *Repository) CreateWorker(ctx context.Context, worker *Worker, opt ...Option) (*Worker, error) {
	const op = "server.CreateWorker"

	opts := GetOpts(opt...)

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
	case opts.WithFetchNodeCredentialsRequest != nil && opts.WithCreateControllerLedActivationToken:
		return nil, errors.New(ctx, errors.InvalidParameter, op, "fetch node credentials request and controller led activation token option cannot both be set")
	}

	worker.OperationalState = UnknownOperationalState.String()

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

	var workerAuthRepo *WorkerAuthRepositoryStorage

	databaseWrapper, err := r.kms.GetWrapper(context.Background(), worker.ScopeId, kms.KeyPurposeDatabase)
	if err != nil {
		return nil, errors.Wrap(ctx, err, op, errors.WithMsg("unable to get database wrapper"))
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

			switch {
			case opts.WithFetchNodeCredentialsRequest != nil:
				workerAuthRepo, err = NewRepositoryStorage(ctx, read, w, r.kms)
				if err != nil {
					return errors.Wrap(ctx, err, op, errors.WithMsg("unable to create worker auth repository"))
				}
				nodeInfo, err := registration.AuthorizeNode(ctx, workerAuthRepo, opts.WithFetchNodeCredentialsRequest, nodeenrollment.WithSkipStorage(true))
				if err != nil {
					return errors.Wrap(ctx, err, op, errors.WithMsg("unable to authorize node"))
				}
				nodeInfo.State = state
				if err := StoreNodeInformationTx(ctx, read, w, r.kms, worker.ScopeId, nodeInfo); err != nil {
					return errors.Wrap(ctx, err, op, errors.WithMsg("unable to store node information"))
				}

			case opts.WithCreateControllerLedActivationToken:
				tokenId, activationToken, err := registration.CreateServerLedActivationToken(ctx, nil, &types.ServerLedRegistrationRequest{},
					nodeenrollment.WithSkipStorage(true),
					nodeenrollment.WithState(state))
				if err != nil {
					return errors.Wrap(ctx, err, op, errors.WithMsg("unable to create controller-led activation token"))
				}
				creationTime := timestamppb.Now()
				creationTimeBytes, err := proto.Marshal(creationTime)
				if err != nil {
					return errors.Wrap(ctx, err, op, errors.WithMsg("unable to marshal timestamp for activation token"))
				}
				activationTokenEntry, err := newWorkerAuthServerLedActivationToken(ctx, worker.PublicId, tokenId, creationTimeBytes)
				if err != nil {
					return errors.Wrap(ctx, err, op, errors.WithMsg("unable to create in-memory activation token"))
				}
				if err := activationTokenEntry.encrypt(ctx, databaseWrapper); err != nil {
					return errors.Wrap(ctx, err, op)
				}
				if err := w.Create(
					ctx,
					activationTokenEntry,
				); err != nil {
					return errors.Wrap(ctx, err, op, errors.WithMsg("unable to create worker activation token in storage"))
				}
				returnedWorker.ControllerGeneratedActivationToken = activationToken
			}

			return nil
		},
	); err != nil {
		return nil, errors.Wrap(ctx, err, op)
	}
	return returnedWorker, nil
}

// AddWorkerTags adds specified api tags to the repo worker and returns its new tags.
// No options are currently supported.
func (r *Repository) AddWorkerTags(ctx context.Context, workerId string, workerVersion uint32, tags []*Tag, _ ...Option) ([]*Tag, error) {
	const op = "server.(Repository).AddWorkerTags"
	switch {
	case workerId == "":
		return nil, errors.New(ctx, errors.InvalidParameter, op, "worker public id is empty")
	case workerVersion == 0:
		return nil, errors.New(ctx, errors.InvalidParameter, op, "missing version")
	case len(tags) == 0:
		return nil, errors.New(ctx, errors.InvalidParameter, op, "no tags provided")
	}

	worker, err := lookupWorker(ctx, r.reader, workerId)
	if err != nil {
		return nil, errors.Wrap(ctx, err, op)
	}
	if worker == nil {
		return nil, errors.New(ctx, errors.InvalidParameter, op, fmt.Sprintf("no worker found with public id %s", workerId))
	}

	newTags := append(worker.apiTags, tags...)
	_, err = r.writer.DoTx(ctx, db.StdRetryCnt, db.ExpBackoff{}, func(reader db.Reader, w db.Writer) error {
		worker := worker.clone()
		worker.PublicId = workerId
		worker.Version = workerVersion + 1
		rowsUpdated, err := w.Update(ctx, worker, []string{"Version"}, nil, db.WithVersion(&workerVersion))
		if err != nil {
			return errors.Wrap(ctx, err, op, errors.WithMsg("unable to update worker version"))
		}
		if rowsUpdated != 1 {
			return errors.New(ctx, errors.MultipleRecords, op, fmt.Sprintf("updated worker version and %d rows updated", rowsUpdated))
		}
		err = setWorkerTags(ctx, w, workerId, ApiTagSource, newTags)
		if err != nil {
			return errors.Wrap(ctx, err, op)
		}
		return nil
	})
	if err != nil {
		return nil, errors.Wrap(ctx, err, op)
	}
	return newTags, nil
}

// SetWorkerTags clears the current repo worker's api tags and sets them from the input parameters.
// Returns the current repo worker tags. No options are currently supported.
func (r *Repository) SetWorkerTags(ctx context.Context, workerId string, workerVersion uint32, tags []*Tag, _ ...Option) ([]*Tag, error) {
	const op = "server.(Repository).SetWorkerTags"
	switch {
	case workerId == "":
		return nil, errors.New(ctx, errors.InvalidParameter, op, "worker public id is empty")
	case workerVersion == 0:
		return nil, errors.New(ctx, errors.InvalidParameter, op, "missing version")
	}

	worker, err := lookupWorker(ctx, r.reader, workerId)
	if err != nil {
		return nil, errors.Wrap(ctx, err, op)
	}
	if worker == nil {
		return nil, errors.New(ctx, errors.InvalidParameter, op, fmt.Sprintf("no worker found with public id %s", workerId))
	}

	_, err = r.writer.DoTx(ctx, db.StdRetryCnt, db.ExpBackoff{}, func(reader db.Reader, w db.Writer) error {
		worker := worker.clone()
		worker.PublicId = workerId
		worker.Version = workerVersion + 1
		rowsUpdated, err := w.Update(ctx, worker, []string{"Version"}, nil, db.WithVersion(&workerVersion))
		if err != nil {
			return errors.Wrap(ctx, err, op, errors.WithMsg("unable to update worker version"))
		}
		if rowsUpdated != 1 {
			return errors.New(ctx, errors.MultipleRecords, op, fmt.Sprintf("updated worker version and %d rows updated", rowsUpdated))
		}
		err = setWorkerTags(ctx, w, workerId, ApiTagSource, tags)
		if err != nil {
			return errors.Wrap(ctx, err, op)
		}
		return nil
	})
	if err != nil {
		return nil, errors.Wrap(ctx, err, op)
	}
	return tags, nil
}

// DeleteWorkerTags deletes specified api worker tags from the repo. Returns the number of rows deleted.
// No options are currently supported.
func (r *Repository) DeleteWorkerTags(ctx context.Context, workerId string, workerVersion uint32, tags []*Tag, _ ...Option) (int, error) {
	const op = "server.(Repository).DeleteWorkerTags"
	switch {
	case workerId == "":
		return db.NoRowsAffected, errors.New(ctx, errors.InvalidParameter, op, "worker public id is empty")
	case workerVersion == 0:
		return db.NoRowsAffected, errors.New(ctx, errors.InvalidParameter, op, "missing version")
	case len(tags) == 0:
		return db.NoRowsAffected, errors.New(ctx, errors.InvalidParameter, op, "no tags provided")
	}

	worker, err := lookupWorker(ctx, r.reader, workerId)
	if err != nil {
		return db.NoRowsAffected, errors.Wrap(ctx, err, op)
	}
	if worker == nil {
		return db.NoRowsAffected, errors.New(ctx, errors.InvalidParameter, op, fmt.Sprintf("no worker found with public id %s", workerId))
	}

	rowsDeleted := 0
	deleteTags := make([]any, 0, len(tags))
	for _, t := range tags {
		if t == nil {
			return db.NoRowsAffected, errors.New(ctx, errors.InvalidParameter, op, "found nil tag value in input")
		}
		deleteTags = append(deleteTags, &store.WorkerTag{
			WorkerId: workerId,
			Key:      t.Key,
			Value:    t.Value,
			Source:   ApiTagSource.String(),
		})
	}

	_, err = r.writer.DoTx(ctx, db.StdRetryCnt, db.ExpBackoff{}, func(reader db.Reader, w db.Writer) error {
		worker := worker.clone()
		worker.PublicId = workerId
		worker.Version = workerVersion + 1
		rowsUpdated, err := w.Update(ctx, worker, []string{"Version"}, nil, db.WithVersion(&workerVersion))
		if err != nil {
			return errors.Wrap(ctx, err, op, errors.WithMsg("unable to update worker version"))
		}
		if rowsUpdated != 1 {
			return errors.New(ctx, errors.MultipleRecords, op, fmt.Sprintf("updated worker version and %d rows updated", rowsUpdated))
		}

		rowsDeleted, err = w.DeleteItems(ctx, deleteTags)
		if err != nil {
			return errors.Wrap(ctx, err, op, errors.WithMsg("unable to delete worker tags"))
		}
		if rowsDeleted != len(deleteTags) {
			return errors.New(ctx, errors.MultipleRecords, op,
				fmt.Sprintf("unable to delete specified tag: tags deleted %d did not match request for %d", rowsDeleted, len(tags)))
		}
		return nil
	})

	if err != nil {
		return db.NoRowsAffected, errors.Wrap(ctx, err, op)
	}
	return rowsDeleted, nil
}

// listDeletedWorkerIds lists the public IDs of any workers deleted since the timestamp provided,
// and the timestamp of the transaction within which the workers were listed.
func (r *Repository) listDeletedWorkerIds(ctx context.Context, since time.Time) ([]string, time.Time, error) {
	const op = "worker.(Repository).listDeletedWorkerIds"
	var deletedWorkers []*deletedWorker
	var transactionTimestamp time.Time
	if _, err := r.writer.DoTx(ctx, db.StdRetryCnt, db.ExpBackoff{}, func(r db.Reader, _ db.Writer) error {
		if err := r.SearchWhere(ctx, &deletedWorkers, "delete_time >= ?", []any{since}); err != nil {
			return errors.Wrap(ctx, err, op, errors.WithMsg("failed to query deleted workers"))
		}
		var err error
		transactionTimestamp, err = r.Now(ctx)
		if err != nil {
			return errors.Wrap(ctx, err, op, errors.WithMsg("failed to get transaction timestamp"))
		}
		return nil
	}); err != nil {
		return nil, time.Time{}, err
	}
	var workerIds []string
	for _, t := range deletedWorkers {
		workerIds = append(workerIds, t.PublicId)
	}
	return workerIds, transactionTimestamp, nil
}

// estimatedWorkerCount returns an estimate of the total number of workers.
func (r *Repository) estimatedWorkerCount(ctx context.Context) (int, error) {
	const op = "worker.(Repository).estimatedCount"
	rows, err := r.reader.Query(ctx, estimateCountWorkers, nil)
	if err != nil {
		return 0, errors.Wrap(ctx, err, op, errors.WithMsg("failed to query total workers"))
	}
	var count int
	for rows.Next() {
		if err := r.reader.ScanRows(ctx, rows, &count); err != nil {
			return 0, errors.Wrap(ctx, err, op, errors.WithMsg("failed to query total workers"))
		}
	}
	return count, nil
}
