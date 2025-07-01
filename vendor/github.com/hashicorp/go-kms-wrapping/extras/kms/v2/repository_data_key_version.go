// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package kms

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/hashicorp/go-dbw"
	wrapping "github.com/hashicorp/go-kms-wrapping/v2"
)

// CreateDataKeyVersion inserts into the repository and returns the new key
// version with its PrivateId. Supported options: WithRetryCnt,
// WithRetryErrorsMatching
func (r *repository) CreateDataKeyVersion(ctx context.Context, rkvWrapper wrapping.Wrapper, dataKeyId string, key []byte, opt ...Option) (*dataKeyVersion, error) {
	const op = "kms.(repository).CreateDataKeyVersion"
	if rkvWrapper == nil {
		return nil, fmt.Errorf("%s: missing root key version wrapper: %w", op, ErrInvalidParameter)
	}
	if dataKeyId == "" {
		return nil, fmt.Errorf("%s: missing data key id: %w", op, ErrInvalidParameter)
	}
	if len(key) == 0 {
		return nil, fmt.Errorf("%s: missing key: %w", op, ErrInvalidParameter)
	}
	rootKeyVersionId, err := rkvWrapper.KeyId(ctx)
	if err != nil {
		return nil, fmt.Errorf("%s: unable to get key id: %w", op, err)
	}
	switch {
	case rootKeyVersionId == "":
		return nil, fmt.Errorf("%s: missing root key version id: %w", op, ErrInvalidParameter)
	case !strings.HasPrefix(rootKeyVersionId, rootKeyVersionPrefix):
		return nil, fmt.Errorf("%s: root key version id %q doesn't start with prefix %q: %w", op, rootKeyVersionId, rootKeyVersionPrefix, ErrInvalidParameter)
	}
	kv := dataKeyVersion{
		tableNamePrefix: r.tableNamePrefix,
	}
	id, err := newDataKeyVersionId()
	if err != nil {
		return nil, fmt.Errorf("%s: %w", op, err)
	}
	kv.PrivateId = id
	kv.RootKeyVersionId = rootKeyVersionId
	kv.Key = key
	kv.DataKeyId = dataKeyId
	if err := kv.Encrypt(ctx, rkvWrapper); err != nil {
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
			// no oplog entries for root key version
			if err := create(ctx, w, returnedKey, dbw.WithTable(kv.TableName())); err != nil {
				return fmt.Errorf("%s: %w", op, err)
			}
			return nil
		},
	)
	if err != nil {
		return nil, fmt.Errorf("%s: failed for %q data key id: %w", op, kv.DataKeyId, err)
	}
	k, ok := returnedKey.(*dataKeyVersion)
	if !ok {
		return nil, fmt.Errorf("%s: not a DataKeyVersion: %w", op, ErrInternal)
	}
	return k, nil
}

// LookupDataKeyVersion will look up a key version in the repository. If
// the key version is not found then an ErrRecordNotFound will be returned.
func (r *repository) LookupDataKeyVersion(ctx context.Context, keyWrapper wrapping.Wrapper, dataKeyVersionId string, _ ...Option) (*dataKeyVersion, error) {
	const op = "kms.(repository).LookupDatabaseKeyVersion"
	if dataKeyVersionId == "" {
		return nil, fmt.Errorf("%s: missing private id: %w", op, ErrInvalidParameter)
	}
	if keyWrapper == nil {
		return nil, fmt.Errorf("%s: missing key wrapper: %w", op, ErrInvalidParameter)
	}
	k := dataKeyVersion{
		tableNamePrefix: r.tableNamePrefix,
	}
	k.PrivateId = dataKeyVersionId
	if err := r.reader.LookupBy(ctx, &k, dbw.WithTable(k.TableName())); err != nil {
		if errors.Is(err, dbw.ErrRecordNotFound) {
			return nil, fmt.Errorf("%s: failed for %q: %w", op, dataKeyVersionId, ErrRecordNotFound)
		}
		return nil, fmt.Errorf("%s: failed for %q: %w", op, dataKeyVersionId, err)
	}
	if err := k.Decrypt(ctx, keyWrapper); err != nil {
		return nil, fmt.Errorf("%s: %w", op, err)
	}
	return &k, nil
}

// DeleteDataKeyVersion deletes the key version for the provided id from the
// repository returning a count of the number of records deleted. Supported
// options: WithRetryCnt, WithRetryErrorsMatching
func (r *repository) DeleteDataKeyVersion(ctx context.Context, dataKeyVersionId string, opt ...Option) (int, error) {
	const op = "kms.(repository).DeleteDataKeyVersion"
	if dataKeyVersionId == "" {
		return noRowsAffected, fmt.Errorf("%s: missing private id: %w", op, ErrInvalidParameter)
	}
	k := dataKeyVersion{
		tableNamePrefix: r.tableNamePrefix,
	}
	k.PrivateId = dataKeyVersionId
	if err := r.reader.LookupBy(ctx, &k, dbw.WithTable(k.TableName())); err != nil {
		if errors.Is(err, dbw.ErrRecordNotFound) {
			return noRowsAffected, fmt.Errorf("%s: failed for %q: %w", op, dataKeyVersionId, ErrRecordNotFound)
		}
		return noRowsAffected, fmt.Errorf("%s: failed for %q: %w", op, dataKeyVersionId, err)
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
			// no oplog entries for the key version
			rowsDeleted, err = w.Delete(ctx, dk, dbw.WithTable(k.TableName()))
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
		return noRowsAffected, fmt.Errorf("%s: failed for %q: %w", op, dataKeyVersionId, err)
	}
	return rowsDeleted, nil
}

// LatestDataKeyVersion searches for the key version with the highest
// version number. When no results are found, it returns nil with an
// ErrRecordNotFound error.
func (r *repository) LatestDataKeyVersion(ctx context.Context, rkvWrapper wrapping.Wrapper, dataKeyId string, _ ...Option) (*dataKeyVersion, error) {
	const op = "kms.(repository).LatestDataKeyVersion"
	if dataKeyId == "" {
		return nil, fmt.Errorf("%s: missing data key id: %w", op, ErrInvalidParameter)
	}
	if rkvWrapper == nil {
		return nil, fmt.Errorf("%s: missing root key version wrapper: %w", op, ErrInvalidParameter)
	}
	dkv := dataKeyVersion{
		tableNamePrefix: r.tableNamePrefix,
	}
	var foundKeys []*dataKeyVersion
	if err := r.reader.SearchWhere(ctx, &foundKeys, "data_key_id = ?", []interface{}{dataKeyId}, dbw.WithLimit(1), dbw.WithOrder("version desc"), dbw.WithTable(dkv.TableName())); err != nil {
		return nil, fmt.Errorf("%s: failed for %q: %w", op, dataKeyId, err)
	}
	if len(foundKeys) == 0 {
		return nil, fmt.Errorf("%s: %w", op, ErrRecordNotFound)
	}
	if err := foundKeys[0].Decrypt(ctx, rkvWrapper); err != nil {
		return nil, fmt.Errorf("%s: %w", op, err)
	}
	return foundKeys[0], nil
}

// ListDataKeyVersions will lists versions of a key. Supported options:
// WithLimit, WithOrderByVersion, WithReader
func (r *repository) ListDataKeyVersions(ctx context.Context, rkvWrapper wrapping.Wrapper, databaseKeyId string, opt ...Option) ([]*dataKeyVersion, error) {
	const op = "kms.(repository).ListDataKeyVersions"
	if databaseKeyId == "" {
		return nil, fmt.Errorf("%s: missing data key id: %w", op, ErrInvalidParameter)
	}
	if rkvWrapper == nil {
		return nil, fmt.Errorf("%s: missing root key version wrapper: %w", op, ErrInvalidParameter)
	}
	{
		dkv := dataKeyVersion{
			tableNamePrefix: r.tableNamePrefix,
		}
		opt = append(opt, withTableName(dkv.TableName()))
	}
	var versions []*dataKeyVersion
	err := r.list(ctx, &versions, "data_key_id = ?", []interface{}{databaseKeyId}, opt...)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", op, err)
	}
	for i, k := range versions {
		if err := k.Decrypt(ctx, rkvWrapper); err != nil {
			return nil, fmt.Errorf("%s: error decrypting key num %q: %w", op, i, err)
		}
	}
	return versions, nil
}

// ListDataKeyVersionReferencers will lists the names of all tables
// referencing the private_id column of the data key version table.
// Supported options:
//   - WithTx
//   - WithReaderWriter
func (r *repository) ListDataKeyVersionReferencers(ctx context.Context, opt ...Option) ([]string, error) {
	const op = "kms.(repository).ListDataKeyVersionReferencers"
	typ, _, err := r.reader.Dialect()
	if err != nil {
		return nil, fmt.Errorf("%s: failed to get db dialect: %w", op, err)
	}
	var query string
	switch typ {
	case dbw.Postgres:
		query = postgresForeignReferencersQuery
	case dbw.Sqlite:
		query = sqliteForeignReferencersQuery
	default:
		return nil, fmt.Errorf("unsupported DB dialect: %q", typ)
	}
	queryFn := r.reader.Query
	opts := getOpts(opt...)
	if opts.withTx != nil {
		if opts.withReader != nil || opts.withWriter != nil {
			return nil, fmt.Errorf("%s: WithTx(...) and WithReaderWriter(...) options cannot be used at the same time: %w", op, ErrInvalidParameter)
		}
		queryFn = opts.withTx.Query
	} else if opts.withReader != nil {
		queryFn = opts.withReader.Query
	}
	rows, err := queryFn(ctx, query, nil)
	if err != nil {
		return nil, fmt.Errorf("%s: failed to list foreign referencers: %w", op, err)
	}
	defer rows.Close()
	var tableNames []string
	for rows.Next() {
		var tableName string
		err := rows.Scan(&tableName)
		if err != nil {
			return nil, fmt.Errorf("%s: failed to scan table name into string: %w", op, err)
		}
		tableNames = append(tableNames, tableName)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("%s: failed to iterate rows: %w", op, err)
	}
	return tableNames, nil
}

// rewrapDataKeyVersionsTx will rewrap (re-encrypt) the data key versions for a
// given rootKeyId with the latest root key version wrapper.
// This function encapsulates all the work required within a dbw.TxHandler and
// allows this capability to be shared with other repositories or just called
// within a transaction.  To be clear, this repository function doesn't include
// its own transaction and is intended to be used within a transaction provided
// by the caller.
func rewrapDataKeyVersionsTx(ctx context.Context, reader dbw.Reader, writer dbw.Writer, tableNamePrefix string, rkvWrapper wrapping.Wrapper, rootKeyId string, _ ...Option) error {
	const (
		op                        = "kms.rewrapDataKeyVersionsTx"
		keyFieldName              = "CtKey"
		rootKeyVersionIdFieldName = "RootKeyVersionId"
	)
	if isNil(reader) {
		return fmt.Errorf("%s: missing reader: %w", op, ErrInvalidParameter)
	}
	if isNil(writer) {
		return fmt.Errorf("%s: missing writer: %w", op, ErrInvalidParameter)
	}
	if isNil(rkvWrapper) {
		return fmt.Errorf("%s: missing root key version wrapper: %w", op, ErrInvalidParameter)
	}
	if rootKeyId == "" {
		return fmt.Errorf("%s: missing root key id: %w", op, ErrInvalidParameter)
	}
	if tableNamePrefix == "" {
		return fmt.Errorf("%s: missing table name prefix: %w", op, ErrInvalidParameter)
	}

	currentKeyVersionId, err := rkvWrapper.KeyId(ctx)
	if err != nil {
		return fmt.Errorf("%s: unable to get current key version ID: %w", op, err)
	}
	r, err := newRepository(reader, writer, WithTableNamePrefix(tableNamePrefix))
	if err != nil {
		return fmt.Errorf("%s: unable to create repo: %w", op, err)
	}
	dks, err := r.ListDataKeys(ctx, withRootKeyId(rootKeyId), WithReader(reader))
	if err != nil {
		return fmt.Errorf("%s: unable to list the current data keys: %w", op, err)
	}
	dkv := dataKeyVersion{
		tableNamePrefix: tableNamePrefix,
	}
	for _, dk := range dks {
		var versions []*dataKeyVersion
		if err := r.list(ctx, &versions, "data_key_id = ?", []interface{}{dk.PrivateId}, WithReader(reader), withTableName(dkv.TableName())); err != nil {
			return fmt.Errorf("%s: unable to list the current data key versions: %w", op, err)
		}
		for _, v := range versions {
			if err := v.Decrypt(ctx, rkvWrapper); err != nil {
				return fmt.Errorf("%s: failed to decrypt data key version: %w", op, err)
			}
			if err := v.Encrypt(ctx, rkvWrapper); err != nil {
				return fmt.Errorf("%s: failed to rewrap data key version: %w", op, err)
			}
			v.RootKeyVersionId = currentKeyVersionId
			rowsAffected, err := writer.Update(ctx, v, []string{keyFieldName, rootKeyVersionIdFieldName}, nil, dbw.WithVersion(&v.Version), dbw.WithTable(dkv.TableName()))
			if err != nil {
				return fmt.Errorf("%s: failed to update data key version: %w", op, err)
			}
			if rowsAffected != 1 {
				return fmt.Errorf("%s: expected to update 1 data key version and updated %d", op, rowsAffected)
			}
		}
	}
	return nil
}

// rotateDataKeyVersionTx will rotate the key version for the given rootKeyId.
// This function encapsulates all the work required within a dbw.TxHandler and
// allows this capability to be shared with other repositories or just called
// within a transaction.  To be clear, this repository function doesn't include
// its own transaction and is intended to be used within a transaction provided
// by the caller.
// Supported options: withRandomReader
func rotateDataKeyVersionTx(ctx context.Context, reader dbw.Reader, writer dbw.Writer, tableNamePrefix string, rootKeyVersionId string, rkvWrapper wrapping.Wrapper, rootKeyId string, purpose KeyPurpose, opt ...Option) error {
	const op = "kms.rotateDataKeyVersionTx"
	if isNil(reader) {
		return fmt.Errorf("%s: missing reader: %w", op, ErrInvalidParameter)
	}
	if isNil(writer) {
		return fmt.Errorf("%s: missing writer: %w", op, ErrInvalidParameter)
	}
	if rootKeyVersionId == "" {
		return fmt.Errorf("%s: missing root key version id: %w", op, ErrInvalidParameter)
	}
	if isNil(rkvWrapper) {
		return fmt.Errorf("%s: missing root key version wrapper: %w", op, ErrInvalidParameter)
	}
	if rootKeyId == "" {
		return fmt.Errorf("%s: missing root key id: %w", op, ErrInvalidParameter)
	}
	if purpose == KeyPurposeUnknown {
		return fmt.Errorf("%s: missing key purpose: %w", op, ErrInvalidParameter)
	}
	if tableNamePrefix == "" {
		return fmt.Errorf("%s: missing table name prefix: %w", op, ErrInvalidParameter)
	}

	r, err := newRepository(reader, writer, WithTableNamePrefix(tableNamePrefix))
	if err != nil {
		return fmt.Errorf("%s: unable to create repo: %w", op, err)
	}
	dataKeys, err := r.ListDataKeys(ctx, withPurpose(purpose), withRootKeyId(rootKeyId), WithReader(reader))
	switch {
	case err != nil:
		return fmt.Errorf("%s: unable to lookup data key for %q: %w", op, purpose, err)
	case len(dataKeys) == 0:
		// this is NOT an error, there's just not data key to rotate for this purpose.
		return nil
	case len(dataKeys) > 1:
		return fmt.Errorf("%s: too many data key (%d) for %q found: %w", op, len(dataKeys), purpose, ErrInternal)
	}
	opts := getOpts(opt...)
	dekKeyBytes, err := generateKey(ctx, opts.withRandomReader)
	if err != nil {
		return fmt.Errorf("%s: unable to generate %s data key version: %w", op, purpose, err)
	}
	dv := dataKeyVersion{
		tableNamePrefix: tableNamePrefix,
	}
	id, err := newDataKeyVersionId()
	if err != nil {
		return fmt.Errorf("%s: %w", op, err)
	}
	dv.PrivateId = id
	dv.DataKeyId = dataKeys[0].PrivateId
	dv.RootKeyVersionId = rootKeyVersionId
	dv.Key = dekKeyBytes
	if err := dv.Encrypt(ctx, rkvWrapper); err != nil {
		return fmt.Errorf("%s: unable to encrypt new data key version: %w", op, err)
	}
	if err := create(ctx, writer, &dv, dbw.WithTable(dv.TableName())); err != nil {
		return fmt.Errorf("%s: unable to create data key version: %w", op, err)
	}
	return nil
}
