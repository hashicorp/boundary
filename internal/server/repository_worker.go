// Copyright IBM Corp. 2020, 2025
// SPDX-License-Identifier: BUSL-1.1

package server

import (
	"context"
	"database/sql"
	stderrors "errors"
	"fmt"
	"strings"
	"time"

	"github.com/hashicorp/boundary/internal/daemon/controller/downstream"
	"github.com/hashicorp/boundary/internal/db"
	"github.com/hashicorp/boundary/internal/errors"
	"github.com/hashicorp/boundary/internal/globals"
	"github.com/hashicorp/boundary/internal/kms"
	"github.com/hashicorp/boundary/internal/server/store"
	"github.com/hashicorp/boundary/internal/target"
	"github.com/hashicorp/boundary/internal/types/scope"
	"github.com/hashicorp/go-bexpr"
	"github.com/hashicorp/go-dbw"
	"github.com/hashicorp/nodeenrollment"
	"github.com/hashicorp/nodeenrollment/registration"
	"github.com/hashicorp/nodeenrollment/types"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/structpb"
	"google.golang.org/protobuf/types/known/timestamppb"
)

var (
	ErrCannotUpdateKmsWorkerViaApi = stderrors.New("cannot update a kms worker's basic information via api")

	FilterWorkersFn = filterWorkers
)

// StorageBucketFilterCredIdFn is a function that gets and returns a storage
// bucket's worker filter and credential id.
type StorageBucketFilterCredIdFn func(ctx context.Context, ce globals.ControllerExtension, sbId string) (filter string, credId string, err error)

// WorkerAddress contains a worker's public id and address.
type WorkerAddress struct {
	PublicId string
	Address  string
}

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
	if w == nil {
		return nil, nil
	}
	w.RemoteStorageStates, err = r.ListWorkerStorageBucketCredentialState(ctx, w.GetPublicId())
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

	rows, err := reader.Query(ctx, lookupWorkerQuery, []any{sql.Named("worker_id", id)})
	if err != nil {
		return nil, errors.Wrap(ctx, err, op)
	}
	defer rows.Close()
	var worker *Worker
	for rows.Next() {
		if err := reader.ScanRows(ctx, rows, &worker); err != nil {
			return nil, err
		}
	}
	return worker, nil
}

// ListHcpbManagedWorkers lists all HCPb managed workers' ids and addresses.
func (r *Repository) ListHcpbManagedWorkers(ctx context.Context, liveness time.Duration) ([]WorkerAddress, error) {
	const op = "server.(Repository).ListHcpbManagedWorkers"

	if liveness <= 0 {
		liveness = DefaultLiveness
	}
	liveness = liveness.Truncate(time.Second)

	query := fmt.Sprintf(listHcpbManagedWorkersQuery, uint32(liveness.Seconds()))
	rows, err := r.reader.Query(ctx, query, []any{})
	if err != nil {
		return nil, errors.Wrap(ctx, err, op)
	}
	defer rows.Close()

	var ret []WorkerAddress
	for rows.Next() {
		var result WorkerAddress
		err = r.reader.ScanRows(ctx, rows, &result)
		if err != nil {
			return nil, errors.Wrap(ctx, err, op)
		}
		ret = append(ret, result)
	}
	if err := rows.Err(); err != nil {
		return nil, errors.Wrap(ctx, err, op)
	}

	return ret, nil
}

// ListWorkers will return a listing of Workers and honor the WithLimit option.
// Supported options: WithLimit
//
// If WithLimit < 0, then unlimited results are returned. If WithLimit == 0, then
// default limits are used for results.
//
// Please note the cost of calling ListWorkers, as the underlying query calculates a connection count
// for each worker by joining with the session connection table. Instead of using this function to get
// worker information, create a domain-specific function that only returns the information you need.
// The purpose of ListWorkers is to return a list of workers for the API.
func (r *Repository) ListWorkers(ctx context.Context, scopeIds []string, opt ...Option) ([]*Worker, error) {
	const op = "server.(Repository).ListWorkers"

	opts := GetOpts(opt...)
	newOpts := []Option{}
	// handle the WithLimit default for the repo
	switch {
	case opts.withLimit != 0:
		newOpts = append(newOpts, WithLimit(opts.withLimit))
	default:
		newOpts = append(newOpts, WithLimit(r.defaultLimit))
	}

	return ListWorkers(ctx, r.reader, scopeIds, newOpts...)
}

// ListWorkers will return a listing of Workers and honor the WithLimit option.
// Supported options: WithLimit
//
// If WithLimit < 0, then unlimited results are returned. If WithLimit == 0, then
// default limits are used for results.
//
// Please note the cost of calling ListWorkers, as the underlying query calculates a connection count
// for each worker by joining with the session connection table. Instead of using this function to get
// worker information, create a domain-specific function that only returns the information you need.
// The purpose of ListWorkers is to return a list of workers for the API.
func ListWorkers(ctx context.Context, reader db.Reader, scopeIds []string, opt ...Option) ([]*Worker, error) {
	const op = "server.ListWorkers"
	switch {
	case len(scopeIds) == 0:
		return nil, errors.New(ctx, errors.InvalidParameter, op, "no scope ids set")
	}

	opts := GetOpts(opt...)

	query := listWorkersQuery
	var whereArgs []any

	if len(scopeIds) > 0 {
		query = fmt.Sprintf("%s where scope_id in (?)", query)
		whereArgs = append(whereArgs, scopeIds)
	}

	limit := db.DefaultLimit
	if opts.withLimit != 0 {
		// non-zero signals an override of the default limit for the repo.
		limit = opts.withLimit
	}

	if limit > 0 {
		query = fmt.Sprintf("%s limit %d", query, limit)
	}

	var workers []*Worker
	rows, err := reader.Query(ctx, query, whereArgs)
	if err != nil {
		return nil, errors.Wrap(ctx, err, op, errors.WithMsg("error searching for workers"))
	}
	defer rows.Close()
	for rows.Next() {
		var worker Worker
		if err := reader.ScanRows(ctx, rows, &worker); err != nil {
			return nil, err
		}
		workers = append(workers, &worker)
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
func (r *Repository) UpsertWorkerStatus(ctx context.Context, worker *Worker, opt ...Option) (string, error) {
	const op = "server.(Repository).UpsertWorkerStatus"

	opts := GetOpts(opt...)
	switch {
	case worker == nil:
		return "", errors.New(ctx, errors.InvalidParameter, op, "worker is nil")
	case worker.GetAddress() == "":
		return "", errors.New(ctx, errors.InvalidParameter, op, "worker reported address is empty")
	case worker.ScopeId == "":
		return "", errors.New(ctx, errors.InvalidParameter, op, "scope id is empty")
	case worker.PublicId != "":
		return "", errors.New(ctx, errors.InvalidParameter, op, "worker id is not empty")
	case worker.GetName() == "" && opts.withKeyId == "" && opts.withPublicId == "":
		return "", errors.New(ctx, errors.InvalidParameter, op, "worker keyId, name and public are all empty; one is required")
	case worker.OperationalState == "":
		return "", errors.New(ctx, errors.InvalidParameter, op, "worker operational state is empty")
	case worker.LocalStorageState == "":
		return "", errors.New(ctx, errors.InvalidParameter, op, "worker local storage state is empty")
	}

	var workerId string
	var err error
	switch {
	case opts.withPublicId != "":
		workerId = opts.withPublicId
	case opts.withKeyId != "":
		workerId, err = r.LookupWorkerIdByKeyId(ctx, opts.withKeyId)
		if err != nil || workerId == "" {
			return "", errors.Wrap(ctx, err, op, errors.WithMsg("error finding worker by keyId"))
		}
	default:
		// generating the worker id based off of the scope and name ensures
		// that if 2 kms workers are making requests with the same name they
		// are treated as the same worker.  Allowing this only for kms workers
		// also ensures that we maintain the unique name constraint between pki
		// workers and kms workers.
		workerId, err = NewWorkerIdFromScopeAndName(ctx, worker.GetScopeId(), worker.GetName())
		if err != nil || workerId == "" {
			return "", errors.Wrap(ctx, err, op, errors.WithMsg("error creating a worker id"))
		}
	}

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
				n, err := w.Update(ctx, workerClone, []string{"address", "ReleaseVersion", "OperationalState", "LocalStorageState"}, nil)
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
					Action: append(db.SetColumns([]string{"address", "release_version", "operational_state", "local_storage_state"}),
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
			// delete all config tags for the given worker, then add the new ones
			// we've been sent.
			if opts.withUpdateTags {
				if err := setWorkerConfigTags(ctx, w, workerClone.GetPublicId(), workerClone.inputTags); err != nil {
					return errors.Wrap(ctx, err, op, errors.WithMsg("error setting worker tags"))
				}
			}

			return nil
		},
	)
	if err != nil {
		return "", err
	}

	return workerId, nil
}

// VerifyKnownWorkers checks that the passed worker IDs are found in the repository and returns
// the public IDs of the workers that are found.
func (r *Repository) VerifyKnownWorkers(ctx context.Context, ids []string) ([]string, error) {
	const op = "server.(Repository).VerifyKnownWorkers"

	if len(ids) == 0 {
		return nil, nil
	}

	rows, err := r.reader.Query(ctx, verifyKnownWorkersQuery, []any{ids})
	if err != nil {
		return nil, errors.Wrap(ctx, err, op)
	}
	defer rows.Close()

	type rowsResult struct {
		PublicId string
	}
	var ret []string
	for rows.Next() {
		var result rowsResult
		err = r.reader.ScanRows(ctx, rows, &result)
		if err != nil {
			return nil, errors.Wrap(ctx, err, op)
		}
		ret = append(ret, result.PublicId)
	}
	if err := rows.Err(); err != nil {
		return nil, errors.Wrap(ctx, err, op)
	}

	return ret, nil
}

// setWorkerConfigTags removes all existing config tags from the same source and worker id
// and creates new ones based on the ones provided.  This function should be
// called from inside a db transaction.
// Workers/worker tags are intentionally not oplogged.
func setWorkerConfigTags(ctx context.Context, w db.Writer, id string, tags []*Tag) error {
	const op = "server.setWorkerConfigTags"
	switch {
	case id == "":
		return errors.New(ctx, errors.InvalidParameter, op, "worker id is empty")
	case isNil(w):
		return errors.New(ctx, errors.InvalidParameter, op, "db.Writer is nil")
	}
	_, err := w.Exec(ctx, deleteConfigTagsByWorkerIdSql, []any{id})
	if err != nil {
		return errors.Wrap(ctx, err, op, errors.WithMsg(fmt.Sprintf("couldn't delete existing tags for worker %q", id)))
	}

	// If tags were cleared out entirely, then we'll have nothing
	// to do here, e.g., it will result in deletion of all tags.
	// Otherwise, go through and stage each tuple for insertion
	// below.
	if len(tags) > 0 {
		uTags := make([]*store.ConfigTag, 0, len(tags))
		for _, v := range tags {
			if v == nil {
				return errors.New(ctx, errors.InvalidParameter, op, fmt.Sprintf("found nil tag value for worker %s", id))
			}
			uTags = append(uTags, &store.ConfigTag{
				WorkerId: id,
				Key:      v.Key,
				Value:    v.Value,
			})
		}
		if err = w.CreateItems(ctx, uTags); err != nil {
			return errors.Wrap(ctx, err, op, errors.WithMsg(fmt.Sprintf("error creating tags for worker %q", id)))
		}
	}

	return nil
}

// setWorkerApiTags removes all existing API tags from the same source and worker id
// and creates new ones based on the ones provided.  This function should be
// called from inside a db transaction.
// Workers/worker tags are intentionally not oplogged.
func setWorkerApiTags(ctx context.Context, w db.Writer, id string, tags []*Tag) error {
	const op = "server.setWorkerApiTags"
	switch {
	case id == "":
		return errors.New(ctx, errors.InvalidParameter, op, "worker id is empty")
	case isNil(w):
		return errors.New(ctx, errors.InvalidParameter, op, "db.Writer is nil")
	}
	_, err := w.Exec(ctx, deleteApiTagsByWorkerIdSql, []any{id})
	if err != nil {
		return errors.Wrap(ctx, err, op, errors.WithMsg(fmt.Sprintf("couldn't delete existing tags for worker %q", id)))
	}

	// If tags were cleared out entirely, then we'll have nothing
	// to do here, e.g., it will result in deletion of all tags.
	// Otherwise, go through and stage each tuple for insertion
	// below.
	if len(tags) > 0 {
		uTags := make([]*store.ApiTag, 0, len(tags))
		for _, v := range tags {
			if v == nil {
				return errors.New(ctx, errors.InvalidParameter, op, fmt.Sprintf("found nil tag value for worker %s", id))
			}
			uTags = append(uTags, &store.ApiTag{
				WorkerId: id,
				Key:      v.Key,
				Value:    v.Value,
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
		op        = "server.(Repository).UpdateWorker"
		nameField = "name"
		descField = "description"
	)
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
			wLookup, err := lookupWorker(ctx, reader, worker.GetPublicId())
			if err != nil {
				return errors.Wrap(ctx, err, op)
			}
			if wLookup == nil {
				return errors.New(ctx, errors.RecordNotFound, op, fmt.Sprintf("failed to find worker %q", worker.GetPublicId()))
			}
			// If it's a KMS-PKI worker we do not want to allow
			// name/description/other updates via the API, it should only come
			// in via the upsert mechanism via status updates. If the public ID
			// is predictably generated in the KMS fashion, it's a KMS-PKI
			// worker.
			workerId, err := NewWorkerIdFromScopeAndName(ctx, wLookup.ScopeId, wLookup.Name)
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

			ret, err = lookupWorker(ctx, reader, worker.GetPublicId())
			if err != nil {
				return errors.Wrap(ctx, err, op)
			}
			ret.RemoteStorageStates, err = r.ListWorkerStorageBucketCredentialState(ctx, ret.GetPublicId(), WithReaderWriter(reader, w))
			if err != nil {
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
// Options supported:
// WithNewIdFunc (this option is likely only useful for tests),
// withLocalStorageState (this option is likely only useful for tests),
// WithFetchNodeCredentialsRequest,
// WithCreateControllerLedActivationToken. The latter two are mutually
// exclusive.
func (r *Repository) CreateWorker(ctx context.Context, worker *Worker, opt ...Option) (*Worker, error) {
	const op = "server.(Repository).CreateWorker"

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
	worker.LocalStorageState = UnknownLocalStorageState.String()

	if opts.withLocalStorageState != "" {
		validLocalStorageState := ValidLocalStorageState(opts.withLocalStorageState)
		if !validLocalStorageState {
			return nil, errors.New(ctx, errors.InvalidParameter, op, "invalid local storage state")
		}
		worker.LocalStorageState = opts.withLocalStorageState
	}

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
func (r *Repository) AddWorkerTags(ctx context.Context, workerId string, workerVersion uint32, tags []*Tag, _ ...Option) (Tags, error) {
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

	newTags := make(Tags)
	for _, tag := range tags {
		newTags[tag.Key] = append(newTags[tag.Key], tag.Value)
	}
	for k, v := range worker.ApiTags {
		newTags[k] = append(newTags[k], v...)
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
		err = setWorkerApiTags(ctx, w, workerId, newTags.convertToTag())
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
		err = setWorkerApiTags(ctx, w, workerId, tags)
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
	deleteTags := make([]*store.ApiTag, 0, len(tags))
	for _, t := range tags {
		if t == nil {
			return db.NoRowsAffected, errors.New(ctx, errors.InvalidParameter, op, "found nil tag value in input")
		}
		deleteTags = append(deleteTags, &store.ApiTag{
			WorkerId: workerId,
			Key:      t.Key,
			Value:    t.Value,
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

// SelectSessionWorkers attempts to select suitable workers for a given session.
// Additionally, it returns the data for the the protocol-aware worker that can
// handle recording operations, if enabled.
func (r *Repository) SelectSessionWorkers(ctx context.Context,
	workerRPCGracePeriod time.Duration,
	t target.Target,
	host string,
	ce globals.ControllerExtension,
	sbFn StorageBucketFilterCredIdFn,
	ds downstream.Graph,
) ([]WorkerAddress, string, error) {
	const op = "server.(Repository).SelectSessionWorkers"

	if workerRPCGracePeriod <= 0 {
		workerRPCGracePeriod = DefaultLiveness
	}
	workerRPCGracePeriod = workerRPCGracePeriod.Truncate(time.Second)

	query := fmt.Sprintf(listSelectSessionWorkers, uint32(workerRPCGracePeriod.Seconds()))
	var livingWorkers []*Worker
	_, err := r.writer.DoTx(
		ctx,
		db.StdRetryCnt,
		db.ExpBackoff{},
		func(reader db.Reader, w db.Writer) error {
			rows, err := reader.Query(ctx, query, []any{})
			if err != nil {
				return err
			}
			defer rows.Close()
			for rows.Next() {
				// Note: The Worker objects scanned here do not contain all data
				// a Worker object can hold, only a subset. Check the query to
				// learn exactly what fields are present.
				var worker Worker
				if err := reader.ScanRows(ctx, rows, &worker); err != nil {
					return err
				}
				livingWorkers = append(livingWorkers, &worker)
			}
			return nil
		},
	)
	if err != nil {
		return nil, "", errors.Wrap(ctx, err, op, errors.WithMsg("error searching for workers"))
	}
	if len(livingWorkers) == 0 {
		return nil, "", errors.New(ctx, errors.WorkerNotFoundForRequest, op, "No workers are available to handle this session.")
	}

	wl, protoWorker, err := FilterWorkersFn(ctx, r, t, livingWorkers, host, ce, sbFn, ds)
	if err != nil {
		return nil, "", errors.Wrap(ctx, err, op)
	}

	was := make([]WorkerAddress, 0, len(wl))
	for _, w := range wl {
		was = append(was, WorkerAddress{PublicId: w.GetPublicId(), Address: w.GetAddress()})
	}

	if protoWorker != nil {
		return was, protoWorker.GetPublicId(), nil
	}
	return was, "", nil
}

// If set, use the worker_filter or egress_worker_filter to filter the selected workers
// and ensure we have workers available to service this request. The second return
// argument is always nil.
func filterWorkers(
	ctx context.Context,
	_ *Repository,
	t target.Target,
	selectedWorkers WorkerList,
	_ string,
	_ globals.ControllerExtension,
	_ StorageBucketFilterCredIdFn,
	_ downstream.Graph,
	_ ...target.Option,
) (WorkerList, *Worker, error) {
	const op = "server.filterWorkers"

	if len(selectedWorkers) > 0 {
		var eval *bexpr.Evaluator
		var err error
		switch {
		case len(t.GetEgressWorkerFilter()) > 0:
			eval, err = bexpr.CreateEvaluator(t.GetEgressWorkerFilter())
		case len(t.GetWorkerFilter()) > 0:
			eval, err = bexpr.CreateEvaluator(t.GetWorkerFilter())
		default: // No filter
			return selectedWorkers, nil, nil
		}
		if err != nil {
			return nil, nil, err
		}

		selectedWorkers, err = selectedWorkers.Filtered(eval)
		if err != nil {
			return nil, nil, err
		}
	}

	if len(selectedWorkers) == 0 {
		return nil, nil, errors.New(ctx, errors.WorkerNotFoundForRequest, op, "No workers are available to handle this session, or all have been filtered.")
	}

	return selectedWorkers, nil, nil
}
