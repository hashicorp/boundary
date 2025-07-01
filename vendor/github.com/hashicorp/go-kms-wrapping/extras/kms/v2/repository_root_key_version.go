// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package kms

import (
	"context"
	"errors"
	"fmt"

	"github.com/hashicorp/go-dbw"
	wrapping "github.com/hashicorp/go-kms-wrapping/v2"
)

// LookupRootKeyVersion will look up a root key version in the repository. If
// the key version is not found then an ErrRecordNotFound will be returned.
func (r *repository) LookupRootKeyVersion(ctx context.Context, keyWrapper wrapping.Wrapper, rootKeyVersionId string, _ ...Option) (*rootKeyVersion, error) {
	const op = "kms.(repository).LookupRootKeyVersion"
	if rootKeyVersionId == "" {
		return nil, fmt.Errorf("%s: missing private id: %w", op, ErrInvalidParameter)
	}
	if keyWrapper == nil {
		return nil, fmt.Errorf("%s: missing key wrapper: %w", op, ErrInvalidParameter)
	}
	k := rootKeyVersion{
		tableNamePrefix: r.tableNamePrefix,
	}
	k.PrivateId = rootKeyVersionId
	if err := r.reader.LookupBy(ctx, &k, dbw.WithTable(k.TableName())); err != nil {
		if errors.Is(err, dbw.ErrRecordNotFound) {
			return nil, fmt.Errorf("%s: failed for %q: %w", op, rootKeyVersionId, ErrRecordNotFound)
		}
		return nil, fmt.Errorf("%s: failed for %q: %w", op, rootKeyVersionId, err)
	}
	if err := k.Decrypt(ctx, keyWrapper); err != nil {
		return nil, fmt.Errorf("%s: %w", op, err)
	}
	return &k, nil
}

// CreateRootKeyVersion inserts into the repository and returns the new root key
// version with its PrivateId. Supported options: WithRetryCnt,
// WithRetryErrorsMatching
func (r *repository) CreateRootKeyVersion(ctx context.Context, keyWrapper wrapping.Wrapper, rootKeyId string, key []byte, opt ...Option) (*rootKeyVersion, error) {
	const op = "kms.(repository).CreateRootKeyVersion"
	if rootKeyId == "" {
		return nil, fmt.Errorf("%s: missing root key id: %w", op, ErrInvalidParameter)
	}
	if keyWrapper == nil {
		return nil, fmt.Errorf("%s: missing key wrapper: %w", op, ErrInvalidParameter)
	}
	if len(key) == 0 {
		return nil, fmt.Errorf("%s: missing key: %w", op, ErrInvalidParameter)
	}
	kv := rootKeyVersion{
		tableNamePrefix: r.tableNamePrefix,
	}
	id, err := newRootKeyVersionId()
	if err != nil {
		return nil, fmt.Errorf("%s: %w", op, err)
	}
	kv.PrivateId = id
	kv.RootKeyId = rootKeyId
	kv.Key = key
	if err := kv.Encrypt(ctx, keyWrapper); err != nil {
		return nil, fmt.Errorf("%s: %w", op, err)
	}

	opts := getOpts(opt...)

	var returnedKey interface{}
	_, err = r.writer.DoTx(
		ctx,
		opts.withErrorsMatching,
		opts.withRetryCnt,
		dbw.ExpBackoff{},
		func(_ dbw.Reader, w dbw.Writer) error {
			if err := updateKeyCollectionVersion(ctx, w, r.tableNamePrefix); err != nil {
				return err
			}
			returnedKey = kv.Clone()
			if err := create(ctx, w, returnedKey, dbw.WithTable(kv.TableName())); err != nil {
				return fmt.Errorf("%s: %w", op, err)
			}
			return nil
		},
	)
	if err != nil {
		return nil, fmt.Errorf("%s: failed for %q root key id: %w", op, kv.RootKeyId, err)
	}
	k, ok := returnedKey.(*rootKeyVersion)
	if !ok {
		return nil, fmt.Errorf("%s: not a RootKeyVersion: %w", op, ErrInternal)
	}
	return k, nil
}

// DeleteRootKeyVersion deletes the root key version for the provided id from the
// repository returning a count of the number of records deleted. Supported
// options: WithRetryCnt, WithRetryErrorsMatching
func (r *repository) DeleteRootKeyVersion(ctx context.Context, rootKeyVersionId string, opt ...Option) (int, error) {
	const op = "kms.(repository).DeleteRootKeyVersion"
	if rootKeyVersionId == "" {
		return noRowsAffected, fmt.Errorf("%s: missing private id: %w", op, ErrInvalidParameter)
	}
	k := rootKeyVersion{
		tableNamePrefix: r.tableNamePrefix,
	}
	k.PrivateId = rootKeyVersionId
	if err := r.reader.LookupBy(ctx, &k, dbw.WithTable(k.TableName())); err != nil {
		if errors.Is(err, dbw.ErrRecordNotFound) {
			return noRowsAffected, fmt.Errorf("%s: failed for %q: %w", op, rootKeyVersionId, ErrRecordNotFound)
		}
		return noRowsAffected, fmt.Errorf("%s: failed for %q: %w", op, rootKeyVersionId, err)
	}

	opts := getOpts(opt...)

	var rowsDeleted int
	_, err := r.writer.DoTx(
		ctx,
		opts.withErrorsMatching,
		opts.withRetryCnt,
		dbw.ExpBackoff{},
		func(_ dbw.Reader, w dbw.Writer) (err error) {
			if err := updateKeyCollectionVersion(ctx, w, r.tableNamePrefix); err != nil {
				return err
			}
			dk := k.Clone()
			// no oplog entries for root key version
			rowsDeleted, err = w.Delete(ctx, dk, dbw.WithTable(dk.TableName()))
			if err != nil {
				return fmt.Errorf("%s: %w", op, err)
			}
			if rowsDeleted > 1 {
				return fmt.Errorf("%s: more than 1 resource would have been deleted: %w", op, ErrMultipleRecords)
			}
			return nil
		},
	)
	if err != nil {
		return noRowsAffected, fmt.Errorf("%s: failed for %q: %w", op, rootKeyVersionId, err)
	}
	return rowsDeleted, nil
}

// LatestRootKeyVersion searches for the root key version with the highest
// version number. When no results are found, it returns nil with an
// ErrRecordNotFound error.
func (r *repository) LatestRootKeyVersion(ctx context.Context, keyWrapper wrapping.Wrapper, rootKeyId string, _ ...Option) (*rootKeyVersion, error) {
	const op = "kms.(repository).LatestRootKeyVersion"
	if rootKeyId == "" {
		return nil, fmt.Errorf("%s: missing root key id: %w", op, ErrInvalidParameter)
	}
	if keyWrapper == nil {
		return nil, fmt.Errorf("%s: missing key wrapper: %w", op, ErrInvalidParameter)
	}
	rkv := rootKeyVersion{
		tableNamePrefix: r.tableNamePrefix,
	}
	var foundKeys []*rootKeyVersion
	if err := r.reader.SearchWhere(ctx, &foundKeys, "root_key_id = ?", []interface{}{rootKeyId}, dbw.WithLimit(1), dbw.WithOrder("version desc"), dbw.WithTable(rkv.TableName())); err != nil {
		return nil, fmt.Errorf("%s: failed for %q: %w", op, rootKeyId, err)
	}
	if len(foundKeys) == 0 {
		return nil, fmt.Errorf("%s: %w", op, ErrRecordNotFound)
	}
	if err := foundKeys[0].Decrypt(ctx, keyWrapper); err != nil {
		return nil, fmt.Errorf("%s: %w", op, err)
	}
	return foundKeys[0], nil
}

// ListRootKeyVersions in versions of a root key. Supported options: WithLimit,
// WithOrderByVersion, WithReader
func (r *repository) ListRootKeyVersions(ctx context.Context, keyWrapper wrapping.Wrapper, rootKeyId string, opt ...Option) ([]*rootKeyVersion, error) {
	const op = "kms.(repository).ListRootKeyVersions"
	if rootKeyId == "" {
		return nil, fmt.Errorf("%s: missing root key id: %w", op, ErrInvalidParameter)
	}
	if keyWrapper == nil {
		return nil, fmt.Errorf("%s: missing key wrapper: %w", op, ErrInvalidParameter)
	}
	{
		rkv := rootKeyVersion{
			tableNamePrefix: r.tableNamePrefix,
		}
		opt = append(opt, withTableName(rkv.TableName()))
	}
	var versions []*rootKeyVersion
	err := r.list(ctx, &versions, "root_key_id = ?", []interface{}{rootKeyId}, opt...)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", op, err)
	}
	for i, k := range versions {
		if err := k.Decrypt(ctx, keyWrapper); err != nil {
			return nil, fmt.Errorf("%s: error decrypting key num %d: %w", op, i, err)
		}
	}
	return versions, nil
}

// rewrapRootKeyVersionsTx will rewrap (re-encrypt) the root key versions for a
// given rootKeyId with the latest wrapper.
// This function encapsulates all the work required within a dbw.TxHandler and
// allows this capability to be shared with other repositories or just called
// within a transaction.  To be clear, this repository function doesn't include
// its own transaction and is intended to be used within a transaction provided
// by the caller.  Supported options: WithTableNamePrefix
func rewrapRootKeyVersionsTx(ctx context.Context, reader dbw.Reader, writer dbw.Writer, rootWrapper wrapping.Wrapper, rootKeyId string, opt ...Option) error {
	const (
		op           = "kms.rewrapRootKeyVersionsTx"
		keyFieldName = "CtKey"
	)
	if isNil(reader) {
		return fmt.Errorf("%s: missing reader: %w", op, ErrInvalidParameter)
	}
	if isNil(writer) {
		return fmt.Errorf("%s: missing writer: %w", op, ErrInvalidParameter)
	}
	if isNil(rootWrapper) {
		return fmt.Errorf("%s: missing root wrapper: %w", op, ErrInvalidParameter)
	}
	if rootKeyId == "" {
		return fmt.Errorf("%s: missing root key id: %w", op, ErrInvalidParameter)
	}
	r, err := newRepository(reader, writer, opt...)
	if err != nil {
		return fmt.Errorf("%s: unable to create repo: %w", op, err)
	}
	// rewrap the rootKey versions using the scope's root key to find them
	rkvs, err := r.ListRootKeyVersions(ctx, rootWrapper, rootKeyId, WithReader(reader))
	if err != nil {
		return fmt.Errorf("%s: unable to list root key versions: %w", op, err)
	}
	opts := getOpts(opt...)
	for _, kv := range rkvs {
		if err := kv.Encrypt(ctx, rootWrapper); err != nil {
			return fmt.Errorf("%s: failed to rewrap root key version: %w", op, err)
		}
		kv.tableNamePrefix = opts.withTableNamePrefix
		rowsAffected, err := writer.Update(ctx, kv, []string{keyFieldName}, nil, dbw.WithVersion(&kv.Version), dbw.WithTable(kv.TableName()))
		if err != nil {
			return fmt.Errorf("%s: failed to update root key version: %w", op, err)
		}
		if rowsAffected != 1 {
			return fmt.Errorf("%s: expected to update 1 root key version and updated %d", op, rowsAffected)
		}
	}
	return nil
}

// rotateRootKeyVersionTx will rotate the key version for the given rootKeyId.
// This function encapsulates all the work required within a dbw.TxHandler and
// allows this capability to be shared with other repositories or just called
// within a transaction.  To be clear, this repository function doesn't include
// its own transaction and is intended to be used within a transaction provided
// by the caller.
// Supported options: withRandomReader
func rotateRootKeyVersionTx(ctx context.Context, writer dbw.Writer, rootWrapper wrapping.Wrapper, rootKeyId string, opt ...Option) (*rootKeyVersion, error) {
	const op = "kms.rotateRootKeyVersionTx"
	if isNil(rootWrapper) {
		return nil, fmt.Errorf("%s: missing root wrapper: %w", op, ErrInvalidParameter)
	}
	if rootKeyId == "" {
		return nil, fmt.Errorf("%s: missing root key id: %w", op, ErrInvalidParameter)
	}

	if isNil(writer) {
		return nil, fmt.Errorf("%s: missing writer: %w", op, ErrInvalidParameter)
	}
	opts := getOpts(opt...)
	rootKeyBytes, err := generateKey(ctx, opts.withRandomReader)
	if err != nil {
		return nil, fmt.Errorf("%s: unable to generate key: %w", op, err)
	}
	rkv := rootKeyVersion{
		tableNamePrefix: opts.withTableNamePrefix,
	}
	id, err := newRootKeyVersionId()
	if err != nil {
		return nil, fmt.Errorf("%s: %w", op, err)
	}
	rkv.PrivateId = id
	rkv.RootKeyId = rootKeyId
	rkv.Key = rootKeyBytes
	if err := rkv.Encrypt(ctx, rootWrapper); err != nil {
		return nil, fmt.Errorf("%s: unable to encrypt new root key version: %w", op, err)
	}
	if err := create(ctx, writer, &rkv, dbw.WithTable(rkv.TableName())); err != nil {
		return nil, fmt.Errorf("%s: unable to create root key version: %w", op, err)
	}
	return &rkv, nil
}
