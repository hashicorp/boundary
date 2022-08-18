package kms

import (
	"context"
	"fmt"
	"io"
	"reflect"
	"strings"
	"sync"
	"time"

	"github.com/hashicorp/boundary/internal/db"
	"github.com/hashicorp/boundary/internal/errors"
	"github.com/hashicorp/boundary/internal/kms/store"
	"github.com/hashicorp/boundary/internal/types/scope"
	"github.com/hashicorp/go-dbw"
	wrappingKms "github.com/hashicorp/go-kms-wrapping/extras/kms/v2"
	wrapping "github.com/hashicorp/go-kms-wrapping/v2"
	"golang.org/x/exp/slices"
)

// Kms is a way to access wrappers for a given scope and purpose. Since keys can
// never change, only be added or (eventually) removed, it opportunistically
// caches, going to the database as needed.
type Kms struct {
	underlying          *wrappingKms.Kms
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

	r := dbw.New(reader.UnderlyingDB())
	w := dbw.New(writer.UnderlyingDB())
	k, err := wrappingKms.New(r, w, purposes)
	if err != nil {
		return nil, errors.Wrap(ctx, err, op, errors.WithMsg("error creating new in-memory kms"))
	}
	return &Kms{
		underlying: k,
		reader:     reader,
		writer:     writer,
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

	r, err := convertToRW(ctx, reader)
	if err != nil {
		return nil, errors.Wrap(ctx, err, op)
	}
	w, err := convertToRW(ctx, writer)
	if err != nil {
		return nil, errors.Wrap(ctx, err, op)
	}
	k, err := wrappingKms.New(r, w, purposes)
	if err != nil {
		return nil, errors.Wrap(ctx, err, op, errors.WithMsg("error creating new in-memory kms"))
	}
	return &Kms{
		underlying: k,
		reader:     reader,
	}, nil
}

func convertToRW(ctx context.Context, r interface{}) (*dbw.RW, error) {
	const op = "kms.convertToDb"
	d, ok := r.(*db.Db)
	if !ok {
		return nil, errors.New(ctx, errors.InvalidParameter, op, "unable to convert to db.DB")
	}
	return dbw.New(d.UnderlyingDB()), nil
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
		r, err := convertToRW(ctx, opts.withReader)
		if err != nil {
			return errors.Wrap(ctx, err, op, errors.WithMsg("unable to convert reader"))
		}
		w, err := convertToRW(ctx, opts.withWriter)
		if err != nil {
			return errors.Wrap(ctx, err, op, errors.WithMsg("unable to convert writer"))
		}
		kmsOpts = append(kmsOpts, wrappingKms.WithReaderWriter(r, w))
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
		r, err := convertToRW(ctx, opts.withReader)
		if err != nil {
			return errors.Wrap(ctx, err, op, errors.WithMsg("unable to convert reader"))
		}
		w, err := convertToRW(ctx, opts.withWriter)
		if err != nil {
			return errors.Wrap(ctx, err, op, errors.WithMsg("unable to convert writer"))
		}
		kmsOpts = append(kmsOpts, wrappingKms.WithReaderWriter(r, w))
	}

	err := k.underlying.RotateKeys(ctx, scopeId, kmsOpts...)
	if err != nil {
		return errors.Wrap(ctx, err, op)
	}
	return nil
}

// QueueKeyRevocation revokes a key in the scope.
// Options are ignored.
func (k *Kms) QueueKeyRevocation(ctx context.Context, scopeId string, keyId string, _ ...Option) (wrappingKms.Key, error) {
	const op = "kms.(Kms).QueueKeyRevocation"

	scopeKeys, err := k.underlying.ListKeys(ctx, scopeId)
	if err != nil {
		return wrappingKms.Key{}, errors.Wrap(ctx, err, op)
	}
	// Build a map from purpose to slice of keys ordered by version.
	// This will be used later to determine when if and when our key
	// became inactive.
	purposeToKeys := map[wrappingKms.KeyPurpose][]wrappingKms.Key{}
	keySearchFn := func(i, j wrappingKms.Key) int {
		if i.Version == j.Version {
			return 0
		}
		if i.Version < j.Version {
			return -1
		}
		return 1
	}
	foundKey := wrappingKms.Key{}
	found := false
	for _, key := range scopeKeys {
		// The keys will hopefully come back in version order from the database,
		// but lets not assume anything.
		purposeKeys := purposeToKeys[key.Purpose]
		index, _ := slices.BinarySearchFunc(purposeKeys, key, keySearchFn)
		purposeKeys = slices.Insert(purposeKeys, index, key)
		purposeToKeys[key.Purpose] = purposeKeys

		if key.Id == keyId {
			foundKey = key
			found = true
		}
	}
	if !found {
		return wrappingKms.Key{}, errors.New(ctx, errors.KeyNotFound, op, "key was not found in the scope")
	}
	if foundKey.Purpose == wrappingKms.KeyPurpose(KeyPurposeOplog.String()) {
		return wrappingKms.Key{}, errors.New(ctx, errors.InvalidParameter, op, "oplog keys cannot be revoked")
	}
	keysByPurpose := purposeToKeys[foundKey.Purpose]
	if keysByPurpose[len(keysByPurpose)-1].Id == foundKey.Id {
		// Attempted to revoke currently active key
		return wrappingKms.Key{}, errors.New(ctx, errors.KeyActive, op, "cannot revoke a currently active key")
	}
	index, ok := slices.BinarySearchFunc(keysByPurpose, foundKey, keySearchFn)
	if !ok {
		// This should be impossible, we inserted this key in the loop above
		return wrappingKms.Key{}, errors.New(ctx, errors.Internal, op, "key was not found in list of keys")
	}
	// Our key became inactive the moment the next key version was created
	keyInactivetime := keysByPurpose[index+1].CreateTime

	_, err = k.writer.DoTx(ctx, db.StdRetryCnt, db.ExpBackoff{},
		func(r db.Reader, w db.Writer) error {
			// Check that we haven't already tried revoking this key.
			// Allow retries if a previous attempt failed
			var krs []*KeyRevocation
			if err := r.SearchWhere(ctx, &krs, "key_id=? and status!=?", []interface{}{keyId, KeyRevocationStatusFailed.String()}, db.WithLimit(1)); err != nil {
				return errors.Wrap(ctx, err, op)
			}
			if len(krs) != 0 {
				return errors.New(ctx, errors.KeyAlreadyRevoked, op, "key was already revoked")
			}

			privateId, err := db.NewPrivateId("kr")
			if err != nil {
				errors.Wrap(ctx, err, op)
			}
			if _, err := w.Exec(
				ctx,
				"insert into kms_key_revocation(private_id, key_id, status, create_time, inactive_time) values (?, ?, ?, ?, ?)",
				[]interface{}{
					privateId,
					keyId,
					KeyRevocationStatusPending.String(),
					foundKey.CreateTime,
					keyInactivetime,
				}); err != nil {
				return errors.Wrap(ctx, err, op)
			}
			return nil
		},
	)
	return foundKey, err
}

// RunKeyRevocation revokes a key in the scope. This may be a long running operation
// and should not be invoked directly in handlers. Instead, prefer the
// QueueKeyRevocation method, which will queue a key revocation and return.
// Options are ignored.
func (k *Kms) RunKeyRevocation(ctx context.Context, keyRevocation *KeyRevocation, _ ...Option) (retErr error) {
	const op = "kms.(Kms).RevokeKey"

	defer func() {
		// Create new context in case the context is canceled
		failedCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if _, err := k.writer.DoTx(failedCtx, db.StdRetryCnt, db.ExpBackoff{},
			func(r db.Reader, w db.Writer) error {
				status := KeyRevocationStatusCompleted
				if retErr != nil {
					// If the operation failed, set the status to failed.
					status = KeyRevocationStatusFailed
				}
				if _, err := w.Exec(failedCtx, "update kms_key_revocation set status=?, revocation_end_time=current_timestamp where private_id=?", []interface{}{status.String(), keyRevocation.PrivateId}); err != nil {
					return err
				}
				return nil
			},
		); err != nil {
			// Just emit an error, don't mutate the returned error
			_ = errors.E(failedCtx, errors.WithWrap(err))
		}
	}()

	// Check if there are any other running jobs,
	// Find the requested key revocation,
	// Check that it is pending and
	// Update it to be running
	if _, err := k.writer.DoTx(ctx, db.StdRetryCnt, db.ExpBackoff{},
		func(r db.Reader, w db.Writer) error {
			var krs []*KeyRevocation
			if err := r.SearchWhere(ctx, &krs, "status=?", []interface{}{KeyRevocationStatusRunning.String()}, db.WithLimit(1)); err != nil {
				return err
			}
			if len(krs) > 0 {
				return errors.E(ctx, errors.WithCode(errors.KeyRevocationAlreadyRunning), errors.WithMsg("another key revocation is already running"), errors.WithoutEvent())
			}
			kr := &KeyRevocation{
				KeyRevocation: &store.KeyRevocation{
					PrivateId: keyRevocation.PrivateId,
				},
			}
			if err := r.LookupById(ctx, kr); err != nil {
				return err
			}
			if kr.Status != KeyRevocationStatusPending.String() {
				return errors.E(ctx, errors.WithCode(errors.InvalidKeyRevocationRunState), errors.WithMsg("key revocation is not pending"), errors.WithoutEvent())
			}
			if _, err := w.Exec(ctx, "update kms_key_revocation set status=? where private_id=?", []interface{}{KeyRevocationStatusRunning.String(), kr.PrivateId}); err != nil {
				return err
			}
			return nil
		},
	); err != nil {
		return errors.Wrap(ctx, err, op)
	}

	switch {
	case strings.HasPrefix(keyRevocation.KeyId, "krkv"):
		// Root key, rewrap keys in scope
		// TODO: A better way to get scope_id from key version private id
		// kms doesn't export the type.
		rows, err := k.reader.Query(ctx, "select scope_id from kms_root_key_version where private_id=?", []interface{}{keyRevocation.KeyId})
		if err != nil {
			return errors.Wrap(ctx, err, op)
		}
		defer rows.Close()
		if !rows.Next() {
			return errors.Wrap(ctx, rows.Err(), op)
		}
		var scopeId string
		if err := rows.Scan(&scopeId); err != nil {
			return errors.Wrap(ctx, err, op)
		}
		if err := rows.Err(); err != nil {
			return errors.Wrap(ctx, err, op)
		}
		if err := k.underlying.RewrapKeys(ctx, scopeId); err != nil {
			return errors.Wrap(ctx, err, op)
		}
	case strings.HasPrefix(keyRevocation.KeyId, "kdkv"):
		// Data key, rewrap all data
		for _, rewrapFn := range tableNameToRewrappingFn {
			if err := rewrapFn(ctx, keyRevocation.KeyId, k.reader, k.writer, k); err != nil {
				return errors.Wrap(ctx, err, op)
			}
		}
	}

	if err := k.underlying.RevokeKey(ctx, keyRevocation.KeyId); err != nil {
		return errors.Wrap(ctx, err, op)
	}

	return nil
}

// ListKeyRevocations lists any key revocations
// Options are ignored.
func (k *Kms) ListKeyRevocations(ctx context.Context, _ ...Option) ([]*KeyRevocation, error) {
	var kr []*KeyRevocation
	if err := k.reader.SearchWhere(ctx, &kr, "1=1", nil); err != nil {
		return nil, err
	}
	return kr, nil
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
