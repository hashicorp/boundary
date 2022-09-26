package kms

import (
	"context"
	"fmt"
	"io"
	"reflect"
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
	reader              db.Reader
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
	return &Kms{
		underlying: k,
		reader:     reader,
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
	return &Kms{
		underlying: k,
		reader:     reader,
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
	w, err := k.underlying.GetWrapper(ctx, scopeId, wrappingKms.KeyPurpose(purpose.String()), wrappingKms.WithKeyId(opts.withKeyId))
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
	const op = "kms.(Kms).CreateKeysTx"
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
	purposes := make([]wrappingKms.KeyPurpose, 0, len(ValidDekPurposes()))
	for _, p := range ValidDekPurposes() {
		purposes = append(purposes, wrappingKms.KeyPurpose(p.String()))
	}
	if err := k.underlying.CreateKeys(ctx, scopeId, purposes, kmsOpts...); err != nil {
		return errors.Wrap(ctx, err, op)
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
	return keys, nil
}

// RotateKeys rotates all keys in a given scope.
// Options supported: withRandomReader, withTx, withRewrap, withReader, withWriter
// When withReader or withWriter is used, both must be passed and the caller will
// be responsible for managing the underlying db transactions.
func (k *Kms) RotateKeys(ctx context.Context, scopeId string, opt ...Option) error {
	const op = "kms.(Kms).RotateKeys"

	opts := getOpts(opt...)
	kmsOpts := []wrappingKms.Option{
		wrappingKms.WithRandomReader(opts.withRandomReader),
		wrappingKms.WithTx(opts.withTx),
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
	return nil
}

// ListDataKeyVersionDestructionJobs lists any in-progress data key destruction jobs in the scope.
// Options are ignored.
func (k *Kms) ListDataKeyVersionDestructionJobs(ctx context.Context, scopeId string, _ ...Option) ([]*DataKeyVersionDestructionJobProgress, error) {
	var jobs []*DataKeyVersionDestructionJobProgress
	if err := k.reader.SearchWhere(ctx, &jobs, "scope_id=?", []interface{}{scopeId}); err != nil {
		return nil, err
	}
	return jobs, nil
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
		purposes = append(purposes, wrappingKms.KeyPurpose(p.String()))
	}
	purposes = append(purposes, wrappingKms.KeyPurpose(KeyPurposeWorkerAuth.String()), wrappingKms.KeyPurpose(KeyPurposeWorkerAuthStorage.String()),
		wrappingKms.KeyPurpose(KeyPurposeRecovery.String()))
	return purposes
}

func isNil(i interface{}) bool {
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
