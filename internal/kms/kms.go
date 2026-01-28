// Copyright IBM Corp. 2020, 2025
// SPDX-License-Identifier: BUSL-1.1

package kms

import (
	"context"
	"database/sql"
	"fmt"
	"io"
	"reflect"
	"slices"
	"sync"
	"time"

	"github.com/hashicorp/boundary/internal/db"
	"github.com/hashicorp/boundary/internal/errors"
	"github.com/hashicorp/boundary/internal/types/scope"
	"github.com/hashicorp/go-dbw"
	wrappingKms "github.com/hashicorp/go-kms-wrapping/extras/kms/v2"
	wrapping "github.com/hashicorp/go-kms-wrapping/v2"
)

// Kms is a way to access wrappers for a given scope and purpose. Since keys can
// never change, only be added or (eventually) removed, it opportunistically
// caches, going to the database as needed.
type Kms struct {
	underlying          *wrappingKms.Kms
	underlyingForOplog  *wrappingKms.Kms // Yep, this kms is only used for oplog DEKs
	reader              db.Reader
	writer              db.Writer
	derivedPurposeCache sync.Map
}

// New creates a Kms using the provided reader and writer.  No options are
// currently supported.
func New(ctx context.Context, reader *db.Db, writer *db.Db, _ ...Option) (*Kms, error) {
	const op = "kms.(Kms).New"
	if isNil(reader) {
		return nil, errors.New(ctx, errors.InvalidParameter, op, "missing reader")
	}
	if isNil(writer) {
		return nil, errors.New(ctx, errors.InvalidParameter, op, "missing writer")
	}
	purposes := stdNewKmsPurposes()

	k, err := wrappingKms.New(db.NewChangeSafeDbwReader(reader), db.NewChangeSafeDbwWriter(writer), purposes)
	if err != nil {
		return nil, errors.Wrap(ctx, err, op, errors.WithMsg("error creating new in-memory kms"))
	}

	oplogK, err := wrappingKms.New(
		db.NewChangeSafeDbwReader(reader),
		db.NewChangeSafeDbwWriter(writer),
		[]wrappingKms.KeyPurpose{wrappingKms.KeyPurpose(KeyPurposeOplog.String())},
		wrappingKms.WithTableNamePrefix("kms_oplog"),
	)
	if err != nil {
		return nil, errors.Wrap(ctx, err, op, errors.WithMsg("error creating new in-memory kms"))
	}

	return &Kms{
		underlying:         k,
		underlyingForOplog: oplogK,
		reader:             reader,
		writer:             writer,
	}, nil
}

// NewUsingReaderWriter creates a Kms using the provided reader and writer.  No
// options are currently supported.
func NewUsingReaderWriter(ctx context.Context, reader db.Reader, writer db.Writer, _ ...Option) (*Kms, error) {
	const op = "kms.(Kms).New"
	if isNil(reader) {
		return nil, errors.New(ctx, errors.InvalidParameter, op, "missing reader")
	}
	if isNil(writer) {
		return nil, errors.New(ctx, errors.InvalidParameter, op, "missing writer")
	}
	purposes := stdNewKmsPurposes()

	r, ok := reader.(*db.Db)
	if !ok {
		return nil, errors.New(ctx, errors.InvalidParameter, op, "unable to convert reader to db.Db")
	}
	w, ok := writer.(*db.Db)
	if !ok {
		return nil, errors.New(ctx, errors.InvalidParameter, op, "unable to convert writer to db.Db")
	}
	k, err := wrappingKms.New(db.NewChangeSafeDbwReader(r), db.NewChangeSafeDbwWriter(w), purposes)
	if err != nil {
		return nil, errors.Wrap(ctx, err, op, errors.WithMsg("error creating new in-memory kms"))
	}
	oplogK, err := wrappingKms.New(
		db.NewChangeSafeDbwReader(r),
		db.NewChangeSafeDbwWriter(w),
		[]wrappingKms.KeyPurpose{wrappingKms.KeyPurpose(KeyPurposeOplog.String())},
		wrappingKms.WithTableNamePrefix("kms_oplog"),
	)
	if err != nil {
		return nil, errors.Wrap(ctx, err, op, errors.WithMsg("error creating new in-memory kms"))
	}
	return &Kms{
		underlying:         k,
		underlyingForOplog: oplogK,
		reader:             reader,
	}, nil
}

// AddExternalWrappers allows setting the external keys.
func (k *Kms) AddExternalWrappers(ctx context.Context, opt ...Option) error {
	const op = "kms.(Kms).AddExternalWrappers"

	opts := getOpts(opt...)
	if opts.withRootWrapper != nil {
		if err := k.underlying.AddExternalWrapper(ctx, wrappingKms.KeyPurpose(KeyPurposeRootKey.String()), opts.withRootWrapper); err != nil {
			return errors.Wrap(ctx, err, op, errors.WithMsg("unable to add root wrapper"))
		}
		// we need this external wrapper for the oplog KMS
		if err := k.underlyingForOplog.AddExternalWrapper(ctx, wrappingKms.KeyPurpose(KeyPurposeRootKey.String()), opts.withRootWrapper); err != nil {
			return errors.Wrap(ctx, err, op, errors.WithMsg("unable to add root wrapper to kms_oplog"))
		}
	}
	if opts.withWorkerAuthWrapper != nil {
		if err := k.underlying.AddExternalWrapper(ctx, wrappingKms.KeyPurpose(KeyPurposeWorkerAuth.String()), opts.withWorkerAuthWrapper); err != nil {
			return errors.Wrap(ctx, err, op, errors.WithMsg("unable to add worker auth wrapper"))
		}
	}
	if opts.withRecoveryWrapper != nil {
		if err := k.underlying.AddExternalWrapper(ctx, wrappingKms.KeyPurpose(KeyPurposeRecovery.String()), opts.withRecoveryWrapper); err != nil {
			return errors.Wrap(ctx, err, op, errors.WithMsg("unable to add recovery wrapper"))
		}
	}
	if opts.withBsrWrapper != nil {
		if err := k.underlying.AddExternalWrapper(ctx, wrappingKms.KeyPurpose(KeyPurposeBsr.String()), opts.withBsrWrapper); err != nil {
			return errors.Wrap(ctx, err, op, errors.WithMsg("unable to add bsr wrapper"))
		}
	}
	return nil
}

// GetWrapper returns a wrapper for the given scope and purpose. When a keyId is
// passed, it will ensure that the returning wrapper has that key ID in the
// multiwrapper. This is not necessary for encryption but should be supplied for
// decryption.
func (k *Kms) GetWrapper(ctx context.Context, scopeId string, purpose KeyPurpose, opt ...Option) (wrapping.Wrapper, error) {
	const op = "kms.(Kms).GetWrapper"
	if scopeId == "" {
		return nil, errors.New(ctx, errors.InvalidParameter, op, "missing scope id")
	}
	if purpose == KeyPurposeUnknown {
		return nil, errors.New(ctx, errors.InvalidParameter, op, "missing purpose")
	}
	opts := getOpts(opt...)
	var underlying *wrappingKms.Kms
	switch purpose {
	case KeyPurposeOplog:
		underlying = k.underlyingForOplog
	default:
		underlying = k.underlying
	}
	w, err := underlying.GetWrapper(ctx, scopeId, wrappingKms.KeyPurpose(purpose.String()), wrappingKms.WithKeyId(opts.withKeyId))
	if err != nil {
		return nil, errors.Wrap(ctx, err, op, errors.WithMsg("unable to get wrapper"))
	}
	return w, err
}

// GetExternalWrappers returns the Kms' ExternalWrappers
func (k *Kms) GetExternalWrappers(ctx context.Context) *ExternalWrappers {
	const op = "kms.(Kms).GetExternalWrappers"
	ret := &ExternalWrappers{}
	if root, err := k.underlying.GetExternalRootWrapper(); err == nil {
		ret.root = root
	}
	if workerAuth, err := k.underlying.GetExternalWrapper(ctx, wrappingKms.KeyPurpose(KeyPurposeWorkerAuth.String())); err == nil {
		ret.workerAuth = workerAuth
	}
	if recovery, err := k.underlying.GetExternalWrapper(ctx, wrappingKms.KeyPurpose(KeyPurposeRecovery.String())); err == nil {
		ret.recovery = recovery
	}
	if bsr, err := k.underlying.GetExternalWrapper(ctx, wrappingKms.KeyPurpose(KeyPurposeBsr.String())); err == nil {
		ret.bsr = bsr
	}
	return ret
}

// GetDerivedPurposeCache returns the raw derived purpose cache
func (k *Kms) GetDerivedPurposeCache() *sync.Map {
	return &k.derivedPurposeCache
}

// ReconcileKeys will reconcile the keys in the kms against known possible
// issues.  This function reconciles the global scope unless the
// WithScopeIds(...) option is provided
func (k *Kms) ReconcileKeys(ctx context.Context, randomReader io.Reader, opt ...Option) error {
	const op = "kms.ReconcileKeys"
	if isNil(randomReader) {
		return errors.New(ctx, errors.InvalidParameter, op, "missing rand reader")
	}
	// it's possible that the global audit key was created after this instance's
	// database was initialized... so check if the audit wrapper is available
	// for the global scope and if not, then add one to the global scope
	if _, err := k.GetWrapper(ctx, scope.Global.String(), KeyPurposeAudit); err != nil {
		if err := k.underlying.ReconcileKeys(
			ctx,
			[]string{scope.Global.String()},
			[]wrappingKms.KeyPurpose{wrappingKms.KeyPurpose(KeyPurposeAudit.String())},
			wrappingKms.WithRandomReader(randomReader),
		); err != nil {
			return errors.Wrap(ctx, err, op, errors.WithMsg(fmt.Sprintf("error creating audit key in scope %s", scope.Global.String())))
		}
	}

	opts := getOpts(opt...)
	if len(opts.withScopeIds) > 0 {
		if err := k.underlying.ReconcileKeys(
			ctx,
			opts.withScopeIds,
			// just add additional purposes as needed going forward to reconcile
			// new keys as they are added.
			[]wrappingKms.KeyPurpose{wrappingKms.KeyPurpose(KeyPurposeOidc.String())},
			wrappingKms.WithRandomReader(randomReader),
		); err != nil {
			return errors.Wrap(ctx, err, op, errors.WithMsg(fmt.Sprintf("error creating keys in scopes %s", opts.withScopeIds)))
		}
	}
	return nil
}

// CreateKeys creates the root key and DEKs.
// Supports the WithRandomReader(...) and WithReaderWriter(...) options.
// When WithReaderWriter(...) is used the caller is responsible for managing the
// transaction which allows this capability to be shared with the iam repo when
// it's creating Scopes.
func (k *Kms) CreateKeys(ctx context.Context, scopeId string, opt ...Option) error {
	const op = "kms.(Kms).CreateKeys"
	if scopeId == "" {
		return errors.New(ctx, errors.InvalidParameter, op, "missing scope id")
	}
	opts := getOpts(opt...)
	kmsOpts := []wrappingKms.Option{wrappingKms.WithRandomReader(opts.withRandomReader)}
	switch {
	case !isNil(opts.withReader) && isNil(opts.withWriter):
		return errors.New(ctx, errors.InvalidParameter, op, "missing writer")
	case isNil(opts.withReader) && !isNil(opts.withWriter):
		return errors.New(ctx, errors.InvalidParameter, op, "missing reader")
	case !isNil(opts.withReader) && !isNil(opts.withWriter):
		r, ok := opts.withReader.(*db.Db)
		if !ok {
			return errors.New(ctx, errors.InvalidParameter, op, "unable to convert reader to db.Db")
		}
		w, ok := opts.withWriter.(*db.Db)
		if !ok {
			return errors.New(ctx, errors.InvalidParameter, op, "unable to convert writer to db.Db")
		}
		kmsOpts = append(kmsOpts, wrappingKms.WithReaderWriter(db.NewChangeSafeDbwReader(r), db.NewChangeSafeDbwWriter(w)))
	}
	purposes := make([]wrappingKms.KeyPurpose, 0, len(ValidDekPurposes())-1) // -1 because it's all of the DEKs except for the oplog DEK
	for _, p := range ValidDekPurposes() {
		switch p {
		case KeyPurposeOplog:
			continue
		default:
			purposes = append(purposes, wrappingKms.KeyPurpose(p.String()))
		}
	}

	{
		switch {
		case isNil(opts.withWriter) && isNil(opts.withReader):
			// it appears we don't have an inflight transaction, so we'll create
			// our own to ensure that all keys are created successfully or
			// they're rolled back.
			_, err := k.writer.DoTx(ctx, db.StdRetryCnt,
				db.ExpBackoff{},
				func(txReader db.Reader, txWriter db.Writer) error {
					r, ok := txReader.(*db.Db)
					if !ok {
						return errors.New(ctx, errors.InvalidParameter, op, "unable to convert reader to db.Db")
					}
					w, ok := txWriter.(*db.Db)
					if !ok {
						return errors.New(ctx, errors.InvalidParameter, op, "unable to convert writer to db.Db")
					}
					kmsOpts = append(kmsOpts,
						wrappingKms.WithRandomReader(opts.withRandomReader),
						wrappingKms.WithReaderWriter(
							db.NewChangeSafeDbwReader(r),
							db.NewChangeSafeDbwWriter(w),
						),
					)
					if err := k.underlying.CreateKeys(ctx, scopeId, purposes, kmsOpts...); err != nil {
						return err
					}
					if err := k.underlyingForOplog.CreateKeys(ctx, scopeId, []wrappingKms.KeyPurpose{wrappingKms.KeyPurpose(KeyPurposeOplog.String())}, kmsOpts...); err != nil {
						return err
					}
					return nil
				})
			if err != nil {
				return errors.Wrap(ctx, err, op)
			}
		default:
			// it appears we have an inflight transaction, so we can just
			// make multiple calls to CreateKeys(...) and let the caller's
			// transaction rollback when needed.
			if err := k.underlying.CreateKeys(ctx, scopeId, purposes, kmsOpts...); err != nil {
				return errors.Wrap(ctx, err, op)
			}
			if err := k.underlyingForOplog.CreateKeys(ctx, scopeId, []wrappingKms.KeyPurpose{wrappingKms.KeyPurpose(KeyPurposeOplog.String())}, kmsOpts...); err != nil {
				return errors.Wrap(ctx, err, op)
			}
		}
	}
	return nil
}

// ListKeys lists all keys in the scope.
// Options are ignored.
func (k *Kms) ListKeys(ctx context.Context, scopeId string, _ ...Option) ([]wrappingKms.Key, error) {
	const op = "kms.(Kms).ListKeys"
	keys, err := k.underlying.ListKeys(ctx, scopeId)
	if err != nil {
		if errors.Is(err, dbw.ErrRecordNotFound) {
			return nil, errors.E(ctx, errors.WithCode(errors.RecordNotFound), errors.WithOp(op))
		}
		return nil, errors.Wrap(ctx, err, op)
	}
	oplogKeys, err := k.underlyingForOplog.ListKeys(ctx, scopeId)
	if err != nil {
		if errors.Is(err, dbw.ErrRecordNotFound) {
			return nil, errors.E(ctx, errors.WithCode(errors.RecordNotFound), errors.WithOp(op))
		}
		return nil, errors.Wrap(ctx, err, op)
	}
	for _, k := range oplogKeys {
		if k.Purpose == wrappingKms.KeyPurpose(KeyPurposeOplog.String()) {
			keys = append(keys, k)
		}
	}
	return keys, nil
}

// RotateKeys rotates all keys in a given scope.
// Options supported: withRandomReader, withRewrap, withReader, withWriter
// When withReader or withWriter is used, both must be passed and the caller will
// be responsible for managing the underlying db transactions.
func (k *Kms) RotateKeys(ctx context.Context, scopeId string, opt ...Option) error {
	const op = "kms.(Kms).RotateKeys"

	opts := getOpts(opt...)
	kmsOpts := []wrappingKms.Option{
		wrappingKms.WithRandomReader(opts.withRandomReader),
		wrappingKms.WithRewrap(opts.withRewrap),
	}

	switch {
	case !isNil(opts.withReader) && isNil(opts.withWriter):
		return errors.New(ctx, errors.InvalidParameter, op, "missing writer")
	case isNil(opts.withReader) && !isNil(opts.withWriter):
		return errors.New(ctx, errors.InvalidParameter, op, "missing reader")
	case !isNil(opts.withReader) && !isNil(opts.withWriter):
		r, ok := opts.withReader.(*db.Db)
		if !ok {
			return errors.New(ctx, errors.InvalidParameter, op, "unable to convert reader to db.Db")
		}
		w, ok := opts.withWriter.(*db.Db)
		if !ok {
			return errors.New(ctx, errors.InvalidParameter, op, "unable to convert writer to db.Db")
		}
		kmsOpts = append(kmsOpts, wrappingKms.WithReaderWriter(db.NewChangeSafeDbwReader(r), db.NewChangeSafeDbwWriter(w)))
	}

	err := k.underlying.RotateKeys(ctx, scopeId, kmsOpts...)
	if err != nil {
		return errors.Wrap(ctx, err, op)
	}
	err = k.underlyingForOplog.RotateKeys(ctx, scopeId, kmsOpts...)
	if err != nil {
		return errors.Wrap(ctx, err, op)
	}
	return nil
}

// ListDataKeyVersionReferencers will list the names of all tables
// referencing the private_id column of the data key version table.
// Supported options:
//   - WithReader (requires WithWriter)
//   - WithWriter (requires WithReader)
func (k *Kms) ListDataKeyVersionReferencers(ctx context.Context, opt ...Option) ([]string, error) {
	const op = "kms.(Kms).ListDataKeyVersionReferencers"

	opts := getOpts(opt...)
	kmsOpts := []wrappingKms.Option{}

	switch {
	case !isNil(opts.withReader) && isNil(opts.withWriter):
		return nil, errors.New(ctx, errors.InvalidParameter, op, "missing writer")
	case isNil(opts.withReader) && !isNil(opts.withWriter):
		return nil, errors.New(ctx, errors.InvalidParameter, op, "missing reader")
	case !isNil(opts.withReader) && !isNil(opts.withWriter):
		r, ok := opts.withReader.(*db.Db)
		if !ok {
			return nil, errors.New(ctx, errors.InvalidParameter, op, "unable to convert reader to db.Db")
		}
		w, ok := opts.withWriter.(*db.Db)
		if !ok {
			return nil, errors.New(ctx, errors.InvalidParameter, op, "unable to convert writer to db.Db")
		}
		kmsOpts = append(kmsOpts, wrappingKms.WithReaderWriter(db.NewChangeSafeDbwReader(r), db.NewChangeSafeDbwWriter(w)))
	}

	refs, err := k.underlying.ListDataKeyVersionReferencers(ctx, kmsOpts...)
	if err != nil {
		return nil, errors.Wrap(ctx, err, op)
	}
	return refs, nil
}

// ListDataKeyVersionDestructionJobs lists any in-progress data key destruction jobs in the scope.
// Options are ignored.
func (k *Kms) ListDataKeyVersionDestructionJobs(ctx context.Context, scopeId string, _ ...Option) ([]*DataKeyVersionDestructionJobProgress, error) {
	const op = "kms.(Kms).ListDataKeyVersionDestructionJobs"
	if scopeId == "" {
		return nil, errors.New(ctx, errors.InvalidParameter, op, "missing scope id")
	}
	var jobs []*DataKeyVersionDestructionJobProgress
	if err := k.reader.SearchWhere(ctx, &jobs, "scope_id=?", []any{scopeId}); err != nil {
		return nil, errors.Wrap(ctx, err, op)
	}
	return jobs, nil
}

// MonitorTableRewrappingRuns checks for pending rewrapping job runs for the
// specified table name, and attempts to execute each job run and start rewrapping
// data in the specified table. This may be a long running operation.
// Options are ignored.
func (k *Kms) MonitorTableRewrappingRuns(ctx context.Context, tableName string, _ ...Option) (retErr error) {
	const op = "kms.(Kms).MonitorTableRewrappingRuns"
	if tableName == "" {
		return errors.New(ctx, errors.InvalidParameter, op, "missing table name")
	}

	rewrapFn, ok := tableNameToRewrapFn[tableName]
	if !ok {
		return errors.E(ctx, errors.WithMsg("no rewrapper for table %q", tableName), errors.WithOp(op))
	}

	run := allocDataKeyVersionDestructionJobRun()
	// Check if there is already another run running for another table name. If so,
	// we exit early since we are limited to 1 run at a time. Note that we exclude
	// our own table name from the search, since if there is a running run for our
	// table name, thanks to the scheduler guaranteeing that only one instance of a job
	// is running at a time, it means we were interrupted in our processing last time
	// and should simply resume that running run.
	err := k.reader.LookupWhere(ctx, &run, "is_running=true and table_name!=?", []any{tableName})
	switch {
	case err == nil:
		// Another run was already running
		return nil
	case errors.Match(errors.T(errors.RecordNotFound), err):
		// Great, no running run, lets continue
	default:
		return errors.Wrap(ctx, err, op, errors.WithMsg("failed to find any running runs"))
	}
	// Find the oldest or currently running run for our tablename
	run = allocDataKeyVersionDestructionJobRun()
	rows, err := k.reader.Query(ctx, oldestPendingOrRunningRun, []any{tableName})
	if err != nil {
		return errors.Wrap(ctx, err, op, errors.WithMsg("failed to query pending runs for %q", tableName))
	}
	defer rows.Close()
	for rows.Next() {
		if err := k.reader.ScanRows(ctx, rows, &run); err != nil {
			return errors.Wrap(ctx, err, op, errors.WithMsg("failed to scan pending run for %q", tableName))
		}
	}
	if err := rows.Err(); err != nil {
		return errors.Wrap(ctx, err, op, errors.WithMsg("failed to get next pending runs for %q", tableName))
	}
	if run.KeyId == "" {
		// No queued runs, lets try again later
		return nil
	}
	if !run.IsRunning {
		// No running job, lets try to become the running job
		run.IsRunning = true
		if _, err := k.writer.Update(ctx, &run, []string{"IsRunning"}, nil); err != nil {
			// Unique error means some other run started running since we last checked.
			if errors.Match(errors.T(errors.NotUnique), err) {
				return nil
			}
			return errors.Wrap(ctx, err, op, errors.WithMsg("failed to become running run for %q", tableName))
		}
	}

	defer func() {
		if retErr != nil {
			// Create new context in case we failed because the context was canceled
			var cancel context.CancelFunc
			ctx, cancel = context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
		}
		// Update the progress of this run
		args := []any{
			sql.Named("key_id", run.KeyId),
			sql.Named("table_name", tableName),
		}
		if _, err := k.writer.Exec(ctx, fmt.Sprintf(updateCompletedCountQueryTemplate, tableName), args); err != nil {
			if retErr != nil {
				// Just emit an error, don't mutate the returned error
				_ = errors.E(ctx, errors.WithWrap(err))
			} else {
				retErr = err
			}
		}
	}()

	rows, err = k.reader.Query(ctx, dataKeyVersionIdScopeIdQuery, []any{run.KeyId})
	if err != nil {
		return errors.Wrap(ctx, err, op, errors.WithMsg("failed to get scope id for data key version"))
	}
	defer rows.Close()
	var scopeId string
	for rows.Next() {
		if err := k.reader.ScanRows(ctx, rows, &scopeId); err != nil {
			return errors.Wrap(ctx, err, op, errors.WithMsg("failed to scan scope id for data key version"))
		}
	}
	if err := rows.Err(); err != nil {
		return errors.Wrap(ctx, err, op, errors.WithMsg("failed to get next scope id for data key version"))
	}

	// Call the function to rewrap the data in the table. The progress will be automatically
	// updated by the deferred function.
	if err := rewrapFn(ctx, run.KeyId, scopeId, k.reader, k.writer, k); err != nil {
		return errors.Wrap(ctx, err, op)
	}
	return nil
}

// MonitorDataKeyVersionDestruction monitors any pending destruction jobs. If
// a job has finished rewrapping all rows, it will destroy the key version
// by calling RevokeKeyVersion on the underlying kms.
func (k *Kms) MonitorDataKeyVersionDestruction(ctx context.Context) error {
	const op = "kms.(Kms).MonitorDataKeyVersionDestruction"

	rows, err := k.reader.Query(ctx, finishedDestructionJobsQuery, nil)
	if err != nil {
		return errors.Wrap(ctx, err, op, errors.WithMsg("failed to find completed destruction jobs"))
	}
	defer rows.Close()
	var completedDataKeyVersionIds []string
	for rows.Next() {
		if err := k.reader.ScanRows(ctx, rows, &completedDataKeyVersionIds); err != nil {
			return errors.Wrap(ctx, err, op)
		}
	}
	if err := rows.Err(); err != nil {
		return errors.Wrap(ctx, err, op)
	}
	for _, dataKeyVersionId := range completedDataKeyVersionIds {
		// Finally, revoke the key, deleting it from the database.
		// This will error if anything still references it that isn't
		// meant to be cascade deleted.
		if err := k.underlying.RevokeKeyVersion(ctx, dataKeyVersionId); err != nil {
			return errors.Wrap(ctx, err, op)
		}
	}
	return nil
}

// DestroyKeyVersion starts the process of destroying a key version in the scope.
// If the key version is a KEK, this simply rewraps any existing DEK version's encrypted with
// the KEK and destroys the key version. If the key version is a DEK, this creates a
// key version destruction job, which will rewrap existing data and destroy the key
// asynchronously. As a special case, if the DEK currently encrypts no data, the DEK is
// immediately destroyed. The boolean return value indicates whether the key was immediately
// destroyed.
// Options are ignored.
func (k *Kms) DestroyKeyVersion(ctx context.Context, scopeId string, keyVersionId string, _ ...Option) (bool, error) {
	const op = "kms.(Kms).DestroyKeyVersion"
	if scopeId == "" {
		return false, errors.New(ctx, errors.InvalidParameter, op, "missing scope id")
	}
	if keyVersionId == "" {
		return false, errors.New(ctx, errors.InvalidParameter, op, "missing key version id")
	}

	scopeKeys, err := k.underlying.ListKeys(ctx, scopeId)
	if err != nil {
		if errors.Is(err, dbw.ErrRecordNotFound) {
			return false, errors.New(ctx, errors.RecordNotFound, op, "scope ID not found")
		}
		return false, errors.Wrap(ctx, err, op)
	}
	var foundKey *wrappingKms.Key
keyLoop:
	for _, key := range scopeKeys {
		for _, version := range key.Versions {
			if version.Id == keyVersionId {
				foundKey = &key
				break keyLoop
			}
		}
	}
	if foundKey == nil {
		return false, errors.New(ctx, errors.KeyNotFound, op, "key version was not found in the scope")
	}
	// Sort versions just in case they aren't already sorted
	slices.SortFunc(foundKey.Versions, func(i, j wrappingKms.KeyVersion) int {
		return int(i.Version) - int(j.Version)
	})
	if foundKey.Versions[len(foundKey.Versions)-1].Id == keyVersionId {
		// Attempted to destroy currently active key
		return false, errors.New(ctx, errors.InvalidParameter, op, "cannot destroy a currently active key version")
	}
	switch foundKey.Purpose {
	case wrappingKms.KeyPurpose(KeyPurposeOplog.String()):
		return false, errors.New(ctx, errors.InvalidParameter, op, "oplog key versions cannot be destroyed")
	case wrappingKms.KeyPurposeRootKey:
		// Simple case, just rewrap and destroy synchronously
		if err := k.underlying.RewrapKeys(ctx, scopeId); err != nil {
			return false, errors.Wrap(ctx, err, op)
		}
		if err := k.underlying.RevokeKeyVersion(ctx, keyVersionId); err != nil {
			return false, errors.Wrap(ctx, err, op)
		}
		return true, nil
	}

	tablesNeedingRewrapping := 0
	if _, err := k.writer.DoTx(ctx, db.StdRetryCnt, db.ExpBackoff{}, func(r db.Reader, w db.Writer) error {
		var tables []*DataKeyVersionDestructionJobRunAllowedTableName
		if err := r.SearchWhere(ctx, &tables, "1=1", nil, db.WithLimit(-1)); err != nil {
			return errors.Wrap(ctx, err, op, errors.WithMsg("failed to look up allowed table names"))
		}
		// Start by adding any job runs necessary by looking up the number of
		// rows encrypted with the key that's being destroyed.
		for _, table := range tables {
			rows, err := r.Query(ctx, fmt.Sprintf(findAffectedRowsForKeyQueryTemplate, table.GetTableName()), []any{keyVersionId})
			if err != nil {
				return errors.Wrap(ctx, err, op, errors.WithMsg("failed to get affected rows for %q", table.GetTableName()))
			}
			defer rows.Close()
			var numRows uint
			for rows.Next() {
				if err := r.ScanRows(ctx, rows, &numRows); err != nil {
					return errors.Wrap(ctx, err, op, errors.WithMsg("failed to scan number of rows for %q", table.GetTableName()))
				}
			}
			if err := rows.Err(); err != nil {
				return errors.Wrap(ctx, err, op, errors.WithMsg("failed to get next number of rows for %q", table.GetTableName()))
			}
			if numRows == 0 {
				// No rows to rewrap 🎉
				continue
			}
			run := allocDataKeyVersionDestructionJobRun()
			run.KeyId = keyVersionId
			run.DataKeyVersionDestructionJobRun.TableName = table.GetTableName()
			run.TotalCount = int64(numRows)
			if err := w.Create(ctx, &run); err != nil {
				// Unique error means the key version ID already existed
				if errors.Match(errors.T(errors.NotUnique), err) {
					return errors.New(ctx, errors.InvalidParameter, op, "key version is already destroying", errors.WithWrap(err))
				}
				return errors.Wrap(ctx, err, op, errors.WithMsg("failed to insert new key version destruction job run"))
			}
			tablesNeedingRewrapping++
		}
		if tablesNeedingRewrapping == 0 {
			// Data key encrypted no data, just return
			return nil
		}
		job := allocDataKeyVersionDestructionJob()
		job.KeyId = keyVersionId
		// Create the destruction job since we know we have at least one job run.
		if err := w.Create(ctx, &job); err != nil {
			return errors.Wrap(ctx, err, op, errors.WithMsg("failed to insert new key version destruction job"))
		}
		return nil
	}); err != nil {
		return false, err
	}
	if tablesNeedingRewrapping == 0 {
		// DEK encrypted no data, just destroy synchronously
		if err := k.underlying.RevokeKeyVersion(ctx, keyVersionId); err != nil {
			return false, errors.Wrap(ctx, err, op)
		}
		return true, nil
	}
	return false, err
}

// VerifyGlobalRoot will verify that the global root wrapper is reasonable.
func (k *Kms) VerifyGlobalRoot(ctx context.Context) error {
	const op = "kms.(Kms).VerifyGlobalRoot"
	var keys []*rootKey
	if err := k.reader.SearchWhere(ctx, &keys, "1=1", nil, db.WithLimit(1), db.WithOrder("create_time asc")); err != nil {
		return errors.Wrap(ctx, err, op)
	}
	for _, rk := range keys {
		if rk.ScopeId == scope.Global.String() {
			return nil
		}
	}
	return errors.New(ctx, errors.MigrationIntegrity, op, "can't find global scoped root key")
}

func stdNewKmsPurposes() []wrappingKms.KeyPurpose {
	purposes := make([]wrappingKms.KeyPurpose, 0, len(ValidDekPurposes()))
	for _, p := range ValidDekPurposes() {
		switch p {
		case KeyPurposeOplog:
			continue
		default:
			purposes = append(purposes, wrappingKms.KeyPurpose(p.String()))
		}
	}
	purposes = append(purposes,
		wrappingKms.KeyPurpose(KeyPurposeWorkerAuth.String()),
		wrappingKms.KeyPurpose(KeyPurposeWorkerAuthStorage.String()),
		wrappingKms.KeyPurpose(KeyPurposeRecovery.String()),
		wrappingKms.KeyPurpose(KeyPurposeBsr.String()),
	)
	return purposes
}

func isNil(i any) bool {
	if i == nil {
		return true
	}
	switch reflect.TypeOf(i).Kind() {
	case reflect.Ptr, reflect.Map, reflect.Array, reflect.Chan, reflect.Slice:
		return reflect.ValueOf(i).IsNil()
	}
	return false
}

type rootKey struct {
	PrivateId  string    `gorm:"primary_key"`
	ScopeId    string    `gorm:"default:null"`
	CreateTime time.Time `gorm:"default:current_timestamp"`
}

func (*rootKey) TableName() string { return "kms_root_key" }

type rootOplogKey struct {
	PrivateId  string    `gorm:"primary_key"`
	ScopeId    string    `gorm:"default:null"`
	CreateTime time.Time `gorm:"default:current_timestamp"`
}

func (*rootOplogKey) TableName() string { return "kms_oplog_root_key" }
