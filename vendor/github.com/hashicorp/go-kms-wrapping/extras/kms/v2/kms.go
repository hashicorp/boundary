// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package kms

import (
	"context"
	"errors"
	"fmt"
	"reflect"
	"strings"
	"sync"
	"sync/atomic"

	"github.com/hashicorp/go-dbw"
	wrapping "github.com/hashicorp/go-kms-wrapping/v2"
	"github.com/hashicorp/go-kms-wrapping/v2/aead"
	"github.com/hashicorp/go-kms-wrapping/v2/extras/multi"
	"github.com/hashicorp/go-multierror"
)

// cachePurpose defines an enum for wrapper cache purposes
type cachePurpose int

const (
	// unknownWrapperCache is the default, and indicates that a purpose wasn't
	// specified
	unknownWrapperCache cachePurpose = iota

	// externalWrapperCache defines an external wrapper cache
	externalWrapperCache

	// scopeWrapperCache defines an scope wrapper cache
	scopeWrapperCache

	// DefaultTableNamePrefix defines the default prefix that will be add to
	// every table name when an optional WithTableNamePrefix is not used when
	// calling New(...). For example the root table name might be "data_key" and
	// then the default is added to form "kms_data_key"
	DefaultTableNamePrefix = "kms"
)

// Kms is a way to access wrappers for a given scope and purpose. Since keys can
// never change, only be added or (eventually) removed, it opportunistically
// caches, going to the database as needed.
type Kms struct {
	// scopedWrapperCache holds a per-scope-purpose multiwrapper containing the
	// current encrypting key and all previous key versions, for decryption
	scopedWrapperCache sync.Map

	externalWrapperCache sync.Map

	collectionVersion uint64

	purposes []KeyPurpose
	repo     *repository

	// tableNamePrefix defines the prefix to use before the table name and
	// allows us to support custom prefixes as well as multi KMSs within a
	// single schema.
	tableNamePrefix string
}

// New takes in a reader, writer and a list of key purposes it will support.
// Every kms will support a KeyPurposeRootKey by default and it doesn't need to
// be passed in as one of the supported purposes.
//
// Supported options: WithTableNamePrefix.
func New(r dbw.Reader, w dbw.Writer, purposes []KeyPurpose, opt ...Option) (*Kms, error) {
	const op = "kms.New"
	repo, err := newRepository(r, w, opt...)
	if err != nil {
		return nil, fmt.Errorf("%s: unable to initialize repository: %w", op, err)
	}
	purposes = append(purposes, KeyPurposeRootKey)
	removeDuplicatePurposes(purposes)

	opts := getOpts(opt...)
	return &Kms{
		purposes:        purposes,
		repo:            repo,
		tableNamePrefix: opts.withTableNamePrefix,
	}, nil
}

// clearCache clears the cached DEK wrappers and by default the DEK wrappers for all
// scopes are cleared from the cache.  The WithScopeIds(...) allows the caller
// to limit which scoped DEK wrappers are cleared from the cache.
func (k *Kms) clearCache(ctx context.Context, opt ...Option) error {
	const op = "kms.(Kms).ResetCache"
	opts := getOpts(opt...)
	switch {
	case len(opts.withScopeIds) > 0:
		for _, p := range k.purposes {
			for _, id := range opts.withScopeIds {
				k.scopedWrapperCache.Delete(scopedPurpose(id, p))
			}
		}
		return nil
	default:
		k.scopedWrapperCache = sync.Map{}
		return nil
	}
}

// addKey will add a key to the appropriate cache.  This is a no-op, when the cachePurpose is
// scopeWrapperCache and k.withCache is false
func (k *Kms) addKey(ctx context.Context, cPurpose cachePurpose, kPurpose KeyPurpose, wrapper wrapping.Wrapper, opt ...Option) error {
	const (
		op        = "kms.addKey"
		missingId = ""
	)
	if kPurpose == KeyPurposeUnknown {
		return fmt.Errorf("%s: missing purpose: %w", op, ErrInvalidParameter)
	}
	if isNil(wrapper) {
		return fmt.Errorf("%s: missing wrapper: %w", op, ErrInvalidParameter)
	}
	if !purposeListContains(k.purposes, kPurpose) {
		return fmt.Errorf("%s: not a supported key purpose %q: %w", op, kPurpose, ErrInvalidParameter)
	}

	opts := getOpts(opt...)

	switch cPurpose {
	case externalWrapperCache:
		k.externalWrapperCache.Store(kPurpose, wrapper)
	case scopeWrapperCache:
		if opts.withKeyVersionId == "" {
			return fmt.Errorf("%s: missing key version id for scoped wrapper cache: %w", op, ErrInvalidParameter)
		}
		k.scopedWrapperCache.Store(opts.withKeyVersionId, wrapper)
	default:
		return fmt.Errorf("%s: unsupported cache purpose %q: %w", op, cPurpose, ErrInvalidParameter)
	}
	return nil
}

// Purposes returns a copy of the key purposes for the kms
func (k *Kms) Purposes() []KeyPurpose {
	cp := make([]KeyPurpose, len(k.purposes))
	copy(cp, k.purposes)
	return cp
}

// AddExternalWrapper allows setting the external keys which are defined outside
// of the kms (e.g. in a configuration file).
func (k *Kms) AddExternalWrapper(ctx context.Context, purpose KeyPurpose, wrapper wrapping.Wrapper) error {
	// TODO: If we support more than one, e.g. for encrypting against many in case
	// of a key loss, there will need to be some refactoring here to have the values
	// being stored in the struct be a multiwrapper, but that's for a later project.
	return k.addKey(ctx, externalWrapperCache, purpose, wrapper)
}

// GetExternalWrapper returns the external wrapper for a given purpose and
// returns ErrKeyNotFound when a key for the given purpose is not found.
func (k *Kms) GetExternalWrapper(_ context.Context, purpose KeyPurpose) (wrapping.Wrapper, error) {
	const op = "kms.(Kms).GetExternalWrapper"
	if purpose == KeyPurposeUnknown {
		return nil, fmt.Errorf("%s: missing purpose: %w", op, ErrInvalidParameter)
	}
	if !purposeListContains(k.purposes, purpose) {
		return nil, fmt.Errorf("%s: not a supported key purpose %q: %w", op, purpose, ErrInvalidParameter)
	}
	if k, ok := k.externalWrapperCache.Load(purpose); ok {
		w, ok := k.(wrapping.Wrapper)
		if !ok {
			return nil, fmt.Errorf("%s: external wrapper is not a wrapping.Wrapper: %w", op, ErrInternal)
		}
		return w, nil
	}
	return nil, fmt.Errorf("%s: missing external wrapper for %q: %w", op, purpose, ErrKeyNotFound)
}

// GetExternalRootWrapper returns the external wrapper for KeyPurposeRootKey is
// is just a convenience function for GetExternalWrapper(...) and returns
// ErrKeyNotFound when a root key is not found.
func (k *Kms) GetExternalRootWrapper() (wrapping.Wrapper, error) {
	const op = "kms.(Kms).GetRootWrapper"
	if k, err := k.GetExternalWrapper(context.Background(), KeyPurposeRootKey); err == nil {
		return k, nil
	}
	return nil, fmt.Errorf("%s: missing external root wrapper: %w", op, ErrKeyNotFound)
}

// GetWrapper returns a wrapper for the given scope and purpose.  The
// WithReader(...) option is supported for getting a wrapper.
//
// If an optional WithKeyVersionId(...) or WithKeyId(...) is
// passed, it will ensure that the returning wrapper has that key version ID in the
// multiwrapper. This is not necessary for encryption but should be supplied for
// decryption. WithKeyVersionId(...) and WithKeyId(...) are equivalent options,
// describing the key version ID requested in the wrapper.
//
// Note: getting a wrapper for KeyPurposeRootKey is supported, but a root
// wrapper is a KEK and should never be used for data encryption.
func (k *Kms) GetWrapper(ctx context.Context, scopeId string, purpose KeyPurpose, opt ...Option) (wrapping.Wrapper, error) {
	const op = "kms.(Kms).GetWrapper"
	if scopeId == "" {
		return nil, fmt.Errorf("%s: missing scope id: %w", op, ErrInvalidParameter)
	}
	if purpose == KeyPurposeUnknown {
		return nil, fmt.Errorf("%s: missing purpose: %w", op, ErrInvalidParameter)
	}
	if !purposeListContains(k.purposes, purpose) {
		return nil, fmt.Errorf("%s: not a supported key purpose %q: %w", op, purpose, ErrInvalidParameter)
	}
	opts := getOpts(opt...)
	// Fast-path: we have a valid key at the scope/purpose. Verify the key with
	// that ID is in the multiwrapper; if not, fall through to reload from the
	// DB.
	currVersion, err := currentCollectionVersion(ctx, k.repo.reader, k.tableNamePrefix)
	if err != nil {
		return nil, fmt.Errorf("%s: unable to determine current version of the kms collection: %w", op, err)
	}
	switch {
	case currVersion != atomic.LoadUint64(&k.collectionVersion):
		k.clearCache(ctx)
		atomic.StoreUint64(&k.collectionVersion, currVersion)
	default:
		val, ok := k.scopedWrapperCache.Load(scopedPurpose(scopeId, purpose))
		if ok {
			wrapper, ok := val.(*multi.PooledWrapper)
			if !ok {
				return nil, fmt.Errorf("%s: scoped wrapper is not a multi.PooledWrapper: %w", op, ErrInternal)
			}
			if opts.withKeyVersionId == "" {
				return wrapper, nil
			}
			if keyIdVersionWrapper := wrapper.WrapperForKeyId(opts.withKeyVersionId); keyIdVersionWrapper != nil {
				return keyIdVersionWrapper, nil
			}
			// Fall through to refresh our multiwrapper for this scope/purpose from the DB
		}
	}

	// We don't have it cached, so we'll need to read from the database. Get the
	// root for the scope as we'll need it to decrypt the value coming from the
	// DB. We don't cache the roots as we expect that after a few calls the
	// scope-purpose cache will catch everything in steady-state.
	rootWrapper, rootKeyId, err := k.loadRoot(ctx, scopeId, WithReader(opts.withReader))
	if err != nil {
		return nil, fmt.Errorf("%s: error loading root key for scope %q: %w", op, scopeId, err)
	}
	if isNil(rootWrapper) {
		return nil, fmt.Errorf("%s: got nil root wrapper for scope %q: %w", op, scopeId, ErrInvalidParameter)
	}

	if purpose == KeyPurposeRootKey {
		return rootWrapper, nil
	}

	wrapper, err := k.loadDek(ctx, scopeId, purpose, rootWrapper, rootKeyId, WithReader(opts.withReader))
	if err != nil {
		return nil, fmt.Errorf("%s: error loading %q for scope %q: %w", op, purpose, scopeId, err)
	}
	if err := k.addKey(ctx, scopeWrapperCache, purpose, wrapper, WithKeyVersionId(scopeId+string(purpose))); err != nil {
		return nil, fmt.Errorf("%s: error adding key to cache: %w", op, err)
	}

	if opts.withKeyVersionId != "" {
		if keyIdVersionWrapper := wrapper.WrapperForKeyId(opts.withKeyVersionId); keyIdVersionWrapper != nil {
			return keyIdVersionWrapper, nil
		}
		return nil, fmt.Errorf("%s: unable to find specified key version ID: %w", op, ErrKeyNotFound)
	}

	return wrapper, nil
}

// ListKeys returns the current list of kms keys.
func (k *Kms) ListKeys(ctx context.Context, scopeId string) ([]Key, error) {
	const op = "kms.(Kms).ListKeys"
	switch {
	case scopeId == "":
		return nil, fmt.Errorf("%s: missing scope id: %w", op, ErrInvalidParameter)
	}
	dbKey, err := k.repo.LookupRootKeyByScope(ctx, scopeId)
	if err != nil {
		return nil, fmt.Errorf("%s: unable to lookup root key: %w", op, err)
	}
	rkv := rootKeyVersion{
		tableNamePrefix: k.tableNamePrefix,
	}
	var rkVersions []*rootKeyVersion
	// we don't need to decrypt their keys, so we'll get them directly from the repo.list(...)
	if err := k.repo.list(ctx, &rkVersions, "root_key_id = ?", []interface{}{dbKey.PrivateId}, withOrderByVersion(ascendingOrderBy), withTableName(rkv.TableName())); err != nil {
		return nil, fmt.Errorf("%s: unable to list root key versions: %w", op, err)
	}
	rk := newKeyFromRootKey(dbKey)
	for _, rkv := range rkVersions {
		rk.Versions = append(rk.Versions, KeyVersion{
			Id:         rkv.PrivateId,
			Version:    uint(rkv.Version),
			CreateTime: rkv.CreateTime,
		})
	}

	dataKeys, err := k.repo.ListDataKeys(ctx, withRootKeyId(rk.Id))
	if err != nil {
		return nil, fmt.Errorf("%s: unable to list data keys: %w", op, err)
	}
	dkv := dataKeyVersion{
		tableNamePrefix: k.tableNamePrefix,
	}
	keys := []Key{rk}
	for _, dk := range dataKeys {
		dataKey := newKeyFromDataKey(dk, rk.Scope)
		var versions []*dataKeyVersion
		// we don't need to decrypt their keys, so we'll get them directly from the repo.list(...)
		err := k.repo.list(ctx, &versions, "data_key_id = ?", []interface{}{dk.GetPrivateId()}, withOrderByVersion(ascendingOrderBy), withTableName(dkv.TableName()))
		if err != nil {
			return nil, fmt.Errorf("%s: %w", op, err)
		}
		for _, dkv := range versions {
			dataKey.Versions = append(dataKey.Versions, KeyVersion{
				Id:         dkv.PrivateId,
				Version:    uint(dkv.Version),
				CreateTime: dkv.CreateTime,
			})
		}
		keys = append(keys, dataKey)
	}
	return keys, nil
}

// CreateKeys creates the root key and DEKs for the given scope id.  By
// default, CreateKeys manages its own transaction (begin/rollback/commit).
//
// It's valid to provide no KeyPurposes (nil or empty), which means that the
// scope will only end up with a root key (and one rk version) with no DEKs.
//
// CreateKeys also supports the WithTx(...) and WithReaderWriter(...) options
// which allows the caller to pass an inflight transaction to be used for all
// database operations.  If WithTx(...) or WithReaderWriter(...) are used, then
// the caller is responsible for managing the transaction.  The purpose of the
// WithTx(...) and WithReaderWriter(...) options are to allow the caller to
// create the scope and all of its keys in the same transaction.
//
// The WithRandomReader(...) option is supported as well.  If no optional
// random reader is provided, then the reader from crypto/rand will be used as
// a default.
func (k *Kms) CreateKeys(ctx context.Context, scopeId string, purposes []KeyPurpose, opt ...Option) error {
	const op = "kms.(Kms).CreateKeys"
	if scopeId == "" {
		return fmt.Errorf("%s: missing scope id: %w", op, ErrInvalidParameter)
	}
	for _, p := range purposes {
		if !purposeListContains(k.purposes, p) {
			return fmt.Errorf("%s: not a supported key purpose %q: %w", op, p, ErrInvalidParameter)
		}
	}

	rootWrapper, err := k.GetExternalRootWrapper()
	if err != nil {
		return fmt.Errorf("%s: %w", op, err)
	}

	r, w, localTx, err := k.txFromOpts(ctx, opt...)
	if err != nil {
		return fmt.Errorf("%s: %w", op, err)
	}

	if err := updateKeyCollectionVersion(ctx, w, k.tableNamePrefix); err != nil {
		return fmt.Errorf("%s: %w", op, err)
	}

	opts := getOpts(opt...)
	if _, err := createKeysTx(ctx, r, w, rootWrapper, opts.withRandomReader, k.tableNamePrefix, scopeId, purposes...); err != nil {
		if localTx != nil {
			if rollBackErr := localTx.Rollback(ctx); rollBackErr != nil {
				err = multierror.Append(err, rollBackErr)
			}
		}
		return fmt.Errorf("%s: %w", op, err)
	}
	if localTx != nil {
		if err := localTx.Commit(ctx); err != nil {
			return fmt.Errorf("%s: unable to commit transaction: %w", op, err)
		}
	}

	return nil
}

// RevokeKey will revoke (remove) a key version.
// Deprecated: use RevokeKeyVersion instead.
func (k *Kms) RevokeKey(ctx context.Context, keyVersionId string) error {
	return k.RevokeKeyVersion(ctx, keyVersionId)
}

// RevokeKeyVersion will revoke (remove) a key version.  Be sure to rotate and rewrap KEK
// versions before revoking them.  If it's a DEK, then you need to re-encrypt all
// data that was encrypted with the key version before revoking it.  You must have
// foreign key restrictions between DEK key version IDs
// (kms_data_key_version.private_id) and columns in your tables which store the
// wrapper key ID used for encrypt/decrypt operations, otherwise you could lose
// access to your encrypted data when you revoke a DEK version that's still being used.
func (k *Kms) RevokeKeyVersion(ctx context.Context, keyVersionId string) error {
	const op = "kms.(Kms).RevokeKeyVersion"
	switch {
	case keyVersionId == "":
		return fmt.Errorf("%s: missing key version id: %w", op, ErrInvalidParameter)
	case strings.HasPrefix(keyVersionId, rootKeyVersionPrefix):
		if err := k.revokeRootKeyVersion(ctx, keyVersionId); err != nil {
			return fmt.Errorf("%s: %w", op, err)
		}
		return nil
	case strings.HasPrefix(keyVersionId, dataKeyVersionPrefix):
		if err := k.revokeDataKeyVersion(ctx, keyVersionId); err != nil {
			return fmt.Errorf("%s: %w", op, err)
		}
		return nil
	default:
		return fmt.Errorf("%s: not a valid key version id: %w", op, ErrInvalidParameter)
	}
}

// revokeRootKeyVersion will revoke (remove) a root key version. Be sure to
// rotate and rewrap the keys before revoking a root key version.
func (k *Kms) revokeRootKeyVersion(ctx context.Context, keyVersionId string) error {
	const op = "kms.(Kms).RevokeRootKeyVersion"
	switch {
	case keyVersionId == "":
		return fmt.Errorf("%s: missing key version id: %w", op, ErrInvalidParameter)
	}
	rowsDeleted, err := k.repo.DeleteRootKeyVersion(ctx, keyVersionId)
	switch {
	case err != nil:
		return fmt.Errorf("%s: unable to revoke root key version: %w", op, err)
	case rowsDeleted == 0:
		return fmt.Errorf("%s: unable to revoke root key version: %w", op, ErrKeyNotFound)
	}
	return nil
}

// revokeDataKeyVersion will revoke (remove) a data key version (DEK).  Be sure
// to rotate the DEKs and re-encrypt all data that uses a data key version (DEK)
// before revoking it.  You must have foreign key restrictions between DEK key
// IDs (kms_data_key_version.private_id) and columns in your tables which store
// the wrapper key ID used for encrypt/decrypt operations.
func (k *Kms) revokeDataKeyVersion(ctx context.Context, keyVersionId string) error {
	const op = "kms.(Kms).RevokeDataKeyVersion"
	switch {
	case keyVersionId == "":
		return fmt.Errorf("%s: missing key version id: %w", op, ErrInvalidParameter)
	}
	rowsDeleted, err := k.repo.DeleteDataKeyVersion(ctx, keyVersionId)
	switch {
	case err != nil:
		return fmt.Errorf("%s: unable to revoke data key version: %w", op, err)
	case rowsDeleted == 0:
		return fmt.Errorf("%s: unable to revoke data key version: %w", op, ErrKeyNotFound)
	}
	return nil
}

// RotateKeys will create new versions for the KEK and all DEKs
// in the scope identified by the current KeyPurpose(s) of the KMS.
//
// If an optional WithRewrap(...) is requested, then all existing KEK versions
// in the scope will be re-encrypted with the external root wrapper and
// all DEK versions in the scope will be re-encrypted with the new KEK version.
//
// WithTx(...) and WithReaderWriter(...) options are supported which allow the
// caller to pass an inflight transaction to be used for all database
// operations.  If WithTx(...) or WithReaderWriter(...) are used, then the
// caller is responsible for managing the transaction.  If neither WithTx or
// WithReaderWriter are specified, then RotateKeys will rotate the scope's keys
// within its own transaction, which will be managed by RotateKeys.
//
// The WithRandomReader(...) option is supported.  If no optional random reader
// is provided, then the reader from crypto/rand will be used as a default.
//
// Options supported: WithRandomReader, WithTx, WithRewrap, WithReaderWriter
func (k *Kms) RotateKeys(ctx context.Context, scopeId string, opt ...Option) error {
	const op = "kms.(Kms).RotateKeys"
	if scopeId == "" {
		return fmt.Errorf("%s: missing scope id: %w", op, ErrInvalidParameter)
	}
	rootWrapper, err := k.GetExternalRootWrapper()
	if err != nil {
		return fmt.Errorf("%s: unable to get an external root wrapper: %w", op, err)
	}

	reader, writer, localTx, err := k.txFromOpts(ctx, opt...)
	if err != nil {
		return fmt.Errorf("%s: %w", op, err)
	}

	if err := updateKeyCollectionVersion(ctx, writer, k.tableNamePrefix); err != nil {
		return fmt.Errorf("%s: %w", op, err)
	}

	// since we could have started a local txn, we'll use an anon function for
	// all the stmts which should be managed within that possible local txn.
	if err := func() error {
		rk, err := k.repo.LookupRootKeyByScope(ctx, scopeId, WithReader(reader))
		if err != nil {
			return fmt.Errorf("%s: unable to load the scope's root key: %w", op, err)
		}

		opts := getOpts(opt...)
		if opts.withRewrap {
			// rewrap the root key versions with the provided rootWrapper (assuming
			// it has a new wrapper)
			if err := rewrapRootKeyVersionsTx(ctx, reader, writer, rootWrapper, rk.PrivateId, WithTableNamePrefix(k.tableNamePrefix)); err != nil {
				return fmt.Errorf("%s: unable to rewrap root key versions: %w", op, err)
			}
		}

		// rotate the root key version (adding a new version)
		rkv, err := rotateRootKeyVersionTx(ctx, writer, rootWrapper, rk.PrivateId, WithRandomReader(opts.withRandomReader), WithTableNamePrefix(k.tableNamePrefix))
		if err != nil {
			return fmt.Errorf("%s: unable to rotate root key version: %w", op, err)
		}

		rkvWrapper, _, err := k.loadRoot(ctx, scopeId, WithReader(reader))
		if err != nil {
			return fmt.Errorf("%s: unable to load the root key version wrapper: %w", op, err)
		}

		// we've got a new rootKeyVersion wrapper, so let's rewrap the existing DEKs.
		if opts.withRewrap {
			if err := rewrapDataKeyVersionsTx(ctx, reader, writer, k.tableNamePrefix, rkvWrapper, rk.PrivateId); err != nil {
				return fmt.Errorf("%s: unable to rewrap data key versions: %w", op, err)
			}
		}

		// finally, let's rotate the scope's DEKs
		for _, purpose := range k.purposes {
			if purpose == KeyPurposeRootKey {
				continue
			}
			if err := rotateDataKeyVersionTx(ctx, reader, writer, k.tableNamePrefix, rkv.PrivateId, rkvWrapper, rk.PrivateId, purpose, WithRandomReader(opts.withRandomReader)); err != nil {
				return fmt.Errorf("%s: unable to rotate data key version: %w", op, err)
			}
		}
		return nil
	}(); err != nil {
		if localTx != nil {
			if rollBackErr := localTx.Rollback(ctx); rollBackErr != nil {
				err = multierror.Append(err, rollBackErr)
			}
		}
		return fmt.Errorf("%s: %w", op, err)
	}
	if localTx != nil {
		if err := localTx.Commit(ctx); err != nil {
			return fmt.Errorf("%s: unable to commit transaction: %w", op, err)
		}
	}
	return nil
}

// RewrapKeys will re-encrypt all versions of a scope's KEK with the external
// root key wrapper and re-encrypt all versions of a scopes DEKs with the latest
// KEK version. If you wish to rewrap and rotate keys, then use the RotateKeys function.
//
// WithTx(...) and WithReaderWriter(...) options are supported which allow the
// caller to pass an inflight transaction to be used for all database
// operations.  If WithTx(...) or WithReaderWriter(...) are used, then the
// caller is responsible for managing the transaction.  If neither WithTx or
// WithReaderWriter are specified, then RotateKeys will rotate the scope's keys
// within its own transaction, which will be managed by RewrapKeys.
//
// The WithRandomReader(...) option is supported.  If no optional random reader
// is provided, then the reader from crypto/rand will be used as a default.
//
// Options supported: WithRandomReader, WithTx, WithReaderWriter
func (k *Kms) RewrapKeys(ctx context.Context, scopeId string, opt ...Option) error {
	const op = "kms.(Kms).RewrapKeys"
	if scopeId == "" {
		return fmt.Errorf("%s: missing scope id: %w", op, ErrInvalidParameter)
	}
	rootWrapper, err := k.GetExternalRootWrapper()
	if err != nil {
		return fmt.Errorf("%s: unable to get an external root wrapper: %w", op, err)
	}

	reader, writer, localTx, err := k.txFromOpts(ctx, opt...)
	if err != nil {
		return fmt.Errorf("%s: %w", op, err)
	}

	if err := updateKeyCollectionVersion(ctx, writer, k.tableNamePrefix); err != nil {
		return fmt.Errorf("%s: %w", op, err)
	}

	// since we could have started a local txn, we'll use an anon function for
	// all the stmts which should be managed within that possible local txn.
	if err := func() error {
		rk, err := k.repo.LookupRootKeyByScope(ctx, scopeId, WithReader(reader))
		if err != nil {
			return fmt.Errorf("%s: unable to load the scope's root key: %w", op, err)
		}

		// rewrap the root key versions with the provided rootWrapper (assuming
		// it has a new wrapper)
		if err := rewrapRootKeyVersionsTx(ctx, reader, writer, rootWrapper, rk.PrivateId, WithTableNamePrefix(k.tableNamePrefix)); err != nil {
			return fmt.Errorf("%s: unable to rewrap root key versions: %w", op, err)
		}

		rkvWrapper, _, err := k.loadRoot(ctx, scopeId, WithReader(reader))
		if err != nil {
			return fmt.Errorf("%s: unable to load the root key version wrapper: %w", op, err)
		}

		// we've got a new rootKeyVersion wrapper, so let's rewrap the existing DEKs.
		if err := rewrapDataKeyVersionsTx(ctx, reader, writer, k.tableNamePrefix, rkvWrapper, rk.PrivateId); err != nil {
			return fmt.Errorf("%s: unable to rewrap data key versions: %w", op, err)
		}

		return nil
	}(); err != nil {
		if localTx != nil {
			if rollBackErr := localTx.Rollback(ctx); rollBackErr != nil {
				err = multierror.Append(err, rollBackErr)
			}
		}
		return fmt.Errorf("%s: %w", op, err)
	}
	if localTx != nil {
		if err := localTx.Commit(ctx); err != nil {
			return fmt.Errorf("%s: unable to commit transaction: %w", op, err)
		}
	}
	return nil
}

// txFromOpts will determine the correct transaction strategy given the provided
// options. Options supported: WithReaderWriter, WithTx
func (k *Kms) txFromOpts(ctx context.Context, opt ...Option) (dbw.Reader, dbw.Writer, *dbw.RW, error) {
	const op = "kms.(Kms).getTxFromOpt"
	var localTx *dbw.RW
	var r dbw.Reader
	var w dbw.Writer
	opts := getOpts(opt...)
	switch {
	case opts.withTx != nil:
		if opts.withReader != nil || opts.withWriter != nil {
			return nil, nil, nil, fmt.Errorf("%s: WithTx(...) and WithReaderWriter(...) options cannot be used at the same time: %w", op, ErrInvalidParameter)
		}
		if ok := opts.withTx.IsTx(); !ok {
			return nil, nil, nil, fmt.Errorf("%s: provided transaction has no inflight transaction: %w", op, ErrInvalidParameter)
		}
		r = opts.withTx
		w = opts.withTx
	case opts.withReader != nil, opts.withWriter != nil:
		if opts.withTx != nil {
			return nil, nil, nil, fmt.Errorf("%s: WithTx(...) and WithReaderWriter(...) options cannot be used at the same time: %w", op, ErrInvalidParameter)
		}
		if opts.withReader == nil {
			return nil, nil, nil, fmt.Errorf("%s: WithReaderWriter(...) option is missing the reader: %w", op, ErrInvalidParameter)
		}
		if opts.withWriter == nil {
			return nil, nil, nil, fmt.Errorf("%s: WithReaderWriter(...) option is missing the writer: %w", op, ErrInvalidParameter)
		}
		r = opts.withReader
		w = opts.withWriter
	default:
		var err error
		localTx, err = k.repo.writer.Begin(ctx)
		if err != nil {
			return nil, nil, nil, fmt.Errorf("%s: unable to begin transaction: %w", op, err)
		}
		r = localTx
		w = localTx
	}
	return r, w, localTx, nil
}

// ValidateSchema will validate the database schema against the module's
// required migrations.Version
func (k *Kms) ValidateSchema(ctx context.Context) (string, error) {
	const op = "kms.(Kms).ValidateVersion"
	return k.repo.ValidateSchema(ctx)
}

// ReconcileKeys will reconcile the keys in the kms against known possible
// issues.  This function reconciles the global scope unless the
// WithScopeIds(...) option is provided
//
// The WithRandomReader(...) option is supported as well.  If an optional
// random reader is not provided (is nill), then the reader from crypto/rand
// will be used as a default.
func (k *Kms) ReconcileKeys(ctx context.Context, scopeIds []string, purposes []KeyPurpose, opt ...Option) error {
	const op = "kms.(Kms).ReconcileKeys"
	if len(scopeIds) == 0 {
		return fmt.Errorf("%s: missing scope ids: %w", op, ErrInvalidParameter)
	}
	for _, p := range purposes {
		if !purposeListContains(k.purposes, p) {
			return fmt.Errorf("%s: not a supported key purpose %q: %w", op, p, ErrInvalidParameter)
		}
	}

	opts := getOpts(opt...)
	for _, id := range scopeIds {
		var scopeRootWrapper *multi.PooledWrapper

		for _, purpose := range purposes {
			if _, err := k.GetWrapper(ctx, id, purpose); err != nil {
				switch {
				case errors.Is(err, ErrKeyNotFound):
					if scopeRootWrapper == nil {
						if scopeRootWrapper, _, err = k.loadRoot(ctx, id); err != nil {
							return fmt.Errorf("%s: %w", op, err)
						}
					}
					key, err := generateKey(ctx, opts.withRandomReader)
					if err != nil {
						return fmt.Errorf("%s: error generating random bytes for %q key in scope %q: %w", op, purpose, id, err)
					}

					if _, _, err := k.repo.CreateDataKey(ctx, scopeRootWrapper, purpose, key); err != nil {
						return fmt.Errorf("%s: error creating %q key in scope %s: %w", op, purpose, id, err)
					}
				default:
					return fmt.Errorf("%s: %w", op, err)
				}
			}
		}
	}
	return nil
}

// ListDataKeyVersionReferencers will lists the names of all tables
// referencing the private_id column of the data key version table.
// This can be useful when re-encrypting data that references a specific
// data key version by private_id.
// Supported options:
//   - WithTx
//   - WithReaderWriter
func (k *Kms) ListDataKeyVersionReferencers(ctx context.Context, opt ...Option) ([]string, error) {
	return k.repo.ListDataKeyVersionReferencers(ctx, opt...)
}

func (k *Kms) loadRoot(ctx context.Context, scopeId string, opt ...Option) (_ *multi.PooledWrapper, rootKeyId string, _ error) {
	const op = "kms.(Kms).loadRoot"
	if scopeId == "" {
		return nil, "", fmt.Errorf("%s: missing scope id: %w", op, ErrInvalidParameter)
	}
	rk, err := k.repo.LookupRootKeyByScope(ctx, scopeId, opt...)
	if err != nil {
		if errors.Is(err, dbw.ErrRecordNotFound) {
			return nil, "", fmt.Errorf("%s: missing root key for scope %q: %w", op, scopeId, ErrKeyNotFound)
		}
		return nil, "", fmt.Errorf("%s: unable to find root key for scope %q: %w", op, scopeId, err)
	}
	rootKeyId = rk.PrivateId
	// Now: find the external KMS that can be used to decrypt the root values
	// from the DB.
	externalRootWrapper, err := k.GetExternalRootWrapper()
	if err != nil {
		return nil, "", fmt.Errorf("%s: missing root key wrapper for scope %q: %w", op, scopeId, ErrKeyNotFound)
	}
	opts := getOpts(opt...)
	rootKeyVersions, err := k.repo.ListRootKeyVersions(ctx, externalRootWrapper, rootKeyId, withOrderByVersion(descendingOrderBy), WithReader(opts.withReader))
	if err != nil {
		return nil, "", fmt.Errorf("%s: error looking up root key versions for scope %q: %w", op, scopeId, err)
	}
	if len(rootKeyVersions) == 0 {
		return nil, "", fmt.Errorf("%s: no root key versions found for scope %q: %w", op, scopeId, ErrKeyNotFound)
	}

	var pooled *multi.PooledWrapper
	for i, keyVersion := range rootKeyVersions {
		var err error
		wrapper := aead.NewWrapper()
		if _, err = wrapper.SetConfig(ctx, wrapping.WithKeyId(keyVersion.GetPrivateId())); err != nil {
			return nil, "", fmt.Errorf("%s: error setting config on aead root wrapper in scope %q: %w", op, scopeId, err)
		}
		if err = wrapper.SetAesGcmKeyBytes(keyVersion.Key); err != nil {
			return nil, "", fmt.Errorf("%s: error setting key bytes on aead root wrapper in scope %q: %w", op, scopeId, err)
		}
		if i == 0 {
			pooled, err = multi.NewPooledWrapper(ctx, wrapper)
			if err != nil {
				return nil, "", fmt.Errorf("%s: error getting root pooled wrapper for key version 0 in scope %q: %w", op, scopeId, err)
			}
		} else {
			_, err = pooled.AddWrapper(ctx, wrapper)
			if err != nil {
				return nil, "", fmt.Errorf("%s: error adding pooled wrapper for key version %d in scope %q: %w", op, i, scopeId, err)
			}
		}
	}

	return pooled, rootKeyId, nil
}

func (k *Kms) loadDek(ctx context.Context, scopeId string, purpose KeyPurpose, rootWrapper wrapping.Wrapper, rootKeyId string, opt ...Option) (*multi.PooledWrapper, error) {
	const op = "kms.(Kms).loadDek"
	if scopeId == "" {
		return nil, fmt.Errorf("%s: missing scope id: %w", op, ErrInvalidParameter)
	}
	if rootWrapper == nil {
		return nil, fmt.Errorf("%s: nil root wrapper for scope %q: %w", op, scopeId, ErrInvalidParameter)
	}
	if rootKeyId == "" {
		return nil, fmt.Errorf("%s: missing root key ID for scope %q: %w", op, scopeId, ErrInvalidParameter)
	}
	if !purposeListContains(k.purposes, purpose) {
		return nil, fmt.Errorf("%s: not a supported key purpose %q: %w", op, purpose, ErrInvalidParameter)
	}

	opts := getOpts(opt...)

	keys, err := k.repo.ListDataKeys(ctx, withPurpose(purpose), withRootKeyId(rootKeyId), WithReader(opts.withReader))
	if err != nil {
		return nil, fmt.Errorf("%s: error listing keys for purpose %q: %w", op, purpose, err)
	}
	var keyId string
	switch {
	case len(keys) == 0:
		return nil, fmt.Errorf("%s: error finding %q key for scope %q: %w", op, purpose, scopeId, ErrKeyNotFound)
	case len(keys) > 1:
		return nil, fmt.Errorf("%s: found %q data keys for %q purpose: %w", op, len(keys), purpose, ErrInternal)
	default:
		keyId = keys[0].GetPrivateId()
	}
	keyVersions, err := k.repo.ListDataKeyVersions(ctx, rootWrapper, keyId, withOrderByVersion(descendingOrderBy), WithReader(opts.withReader))
	if err != nil {
		return nil, fmt.Errorf("%s: error looking up %q key versions for scope %q: %w", op, purpose, scopeId, err)
	}
	if len(keyVersions) == 0 {
		return nil, fmt.Errorf("%s: no %q key versions found for scope %q: %w", op, purpose, scopeId, ErrKeyNotFound)
	}

	var pooled *multi.PooledWrapper
	for i, keyVersion := range keyVersions {
		var err error
		wrapper := aead.NewWrapper()
		if _, err = wrapper.SetConfig(ctx, wrapping.WithKeyId(keyVersion.GetPrivateId())); err != nil {
			return nil, fmt.Errorf("%s: error setting config on aead %q wrapper in scope %q: %w", op, purpose, scopeId, err)
		}
		if err = wrapper.SetAesGcmKeyBytes(keyVersion.GetKey()); err != nil {
			return nil, fmt.Errorf("%s: error setting key bytes on aead %q wrapper in scope %q: %w", op, purpose, scopeId, err)
		}
		if i == 0 {
			pooled, err = multi.NewPooledWrapper(ctx, wrapper)
			if err != nil {
				return nil, fmt.Errorf("%s: error getting %q pooled wrapper for key version 0 in scope %q: %w", op, purpose, scopeId, err)
			}
		} else {
			_, err = pooled.AddWrapper(ctx, wrapper)
			if err != nil {
				return nil, fmt.Errorf("%s: error getting %q pooled wrapper for key version %q in scope %q: %w", op, purpose, i, scopeId, err)
			}
		}
	}

	return pooled, nil
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

func scopedPurpose(scopeId string, purpose KeyPurpose) string {
	return scopeId + string(purpose)
}
