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

// CreateDataKey inserts into the repository and returns the new data key and
// data key version. Supported options: WithRetryCnt, WithRetryErrorsMatching
func (r *repository) CreateDataKey(ctx context.Context, rkvWrapper wrapping.Wrapper, purpose KeyPurpose, key []byte, opt ...Option) (*dataKey, *dataKeyVersion, error) {
	const op = "kms.(Repository).CreateDataKey"
	opts := getOpts(opt...)
	var returnedDk *dataKey
	var returnedDv *dataKeyVersion
	_, err := r.writer.DoTx(
		ctx,
		opts.withErrorsMatching,
		opts.withRetryCnt,
		dbw.ExpBackoff{},
		func(reader dbw.Reader, w dbw.Writer) error {
			if err := updateKeyCollectionVersion(ctx, w, r.tableNamePrefix); err != nil {
				return err
			}
			var err error
			if returnedDk, returnedDv, err = createDataKeyTx(ctx, reader, w, rkvWrapper, r.tableNamePrefix, purpose, key); err != nil {
				return fmt.Errorf("%s: %w", op, err)
			}
			return nil
		},
	)
	if err != nil {
		return nil, nil, fmt.Errorf("%s: unable to create data key for purpose %q: %w", op, purpose, err)
	}
	return returnedDk, returnedDv, nil
}

// createDataKeyTx inserts into the db (via dbw.Writer) and returns the new data key
// and data key version. This function encapsulates all the work required within
// a dbw.TxHandler and allows this capability to be shared within this repository
func createDataKeyTx(ctx context.Context, r dbw.Reader, w dbw.Writer, rkvWrapper wrapping.Wrapper, tableNamePrefix string, purpose KeyPurpose, key []byte) (*dataKey, *dataKeyVersion, error) {
	const op = "kms.createDataKeyTx"
	if rkvWrapper == nil {
		return nil, nil, fmt.Errorf("%s: missing key wrapper: %w", op, ErrInvalidParameter)
	}
	if purpose == KeyPurposeUnknown {
		return nil, nil, fmt.Errorf("%s: missing purpose: %w", op, ErrInvalidParameter)
	}
	if len(key) == 0 {
		return nil, nil, fmt.Errorf("%s: missing key: %w", op, ErrInvalidParameter)
	}
	if tableNamePrefix == "" {
		return nil, nil, fmt.Errorf("%s: missing table name prefix: %w", op, ErrInvalidParameter)
	}
	rootKeyVersionId, err := rkvWrapper.KeyId(ctx)
	if err != nil {
		return nil, nil, fmt.Errorf("%s: unable to lookup root key id: %w", op, err)
	}
	switch {
	case rootKeyVersionId == "":
		return nil, nil, fmt.Errorf("%s: missing root key version id: %w", op, ErrInvalidParameter)
	case !strings.HasPrefix(rootKeyVersionId, rootKeyVersionPrefix):
		return nil, nil, fmt.Errorf("%s: root key version id %q doesn't start with prefix %q: %w", op, rootKeyVersionId, rootKeyVersionPrefix, ErrInvalidParameter)
	}
	rv := rootKeyVersion{tableNamePrefix: tableNamePrefix}
	rv.PrivateId = rootKeyVersionId
	err = r.LookupBy(ctx, &rv, dbw.WithTable(rv.TableName()))
	if err != nil {
		return nil, nil, fmt.Errorf("%s: unable to lookup root key version %q: %w", op, rootKeyVersionId, err)
	}

	dk := dataKey{
		Purpose:         purpose,
		tableNamePrefix: tableNamePrefix,
	}
	dv := dataKeyVersion{
		tableNamePrefix: tableNamePrefix,
	}
	id, err := newDataKeyId()
	if err != nil {
		return nil, nil, fmt.Errorf("%s: %w", op, err)
	}
	dk.PrivateId = id
	dk.RootKeyId = rv.RootKeyId

	id, err = newDataKeyVersionId()
	if err != nil {
		return nil, nil, fmt.Errorf("%s: %w", op, err)
	}
	dv.PrivateId = id
	dv.DataKeyId = dk.PrivateId
	dv.RootKeyVersionId = rootKeyVersionId
	dv.Key = key
	if err := dv.Encrypt(ctx, rkvWrapper); err != nil {
		return nil, nil, fmt.Errorf("%s: %w", op, err)
	}

	// no oplog entries for keys
	if err := create(ctx, w, &dk, dbw.WithTable(dk.TableName())); err != nil {
		return nil, nil, fmt.Errorf("%s: keys create: %w", op, err)
	}
	// no oplog entries for key versions
	if err := create(ctx, w, &dv, dbw.WithTable(dv.TableName())); err != nil {
		return nil, nil, fmt.Errorf("%s: key versions create: %w", op, err)
	}

	return &dk, &dv, nil
}

// LookupDataKey will look up a key in the repository.  If the key is not
// found then an ErrRecordNotFound will be returned.
func (r *repository) LookupDataKey(ctx context.Context, privateId string, _ ...Option) (*dataKey, error) {
	const op = "kms.(Repository).LookupDataKey"
	if privateId == "" {
		return nil, fmt.Errorf("%s: missing private id: %w", op, ErrInvalidParameter)
	}
	k := dataKey{
		tableNamePrefix: r.tableNamePrefix,
	}
	k.PrivateId = privateId
	if err := r.reader.LookupBy(ctx, &k, dbw.WithTable(k.TableName())); err != nil {
		if errors.Is(err, dbw.ErrRecordNotFound) {
			return nil, fmt.Errorf("%s: failed for %q: %w", op, privateId, ErrRecordNotFound)
		}
		return nil, fmt.Errorf("%s: failed for %q: %w", op, privateId, err)
	}
	return &k, nil
}

// DeleteDataKey deletes the key for the provided id from the
// repository returning a count of the number of records deleted. Supported
// options: WithRetryCnt, WithRetryErrorsMatching
func (r *repository) DeleteDataKey(ctx context.Context, privateId string, opt ...Option) (int, error) {
	const op = "kms.(Repository).DeleteDataKey"
	if privateId == "" {
		return noRowsAffected, fmt.Errorf("%s: missing private id: %w", op, ErrInvalidParameter)
	}
	k := dataKey{
		tableNamePrefix: r.tableNamePrefix,
	}
	k.PrivateId = privateId
	if err := r.reader.LookupBy(ctx, &k, dbw.WithTable(k.TableName())); err != nil {
		if errors.Is(err, dbw.ErrRecordNotFound) {
			return noRowsAffected, fmt.Errorf("%s: failed for %q: %w", op, privateId, ErrRecordNotFound)
		}
		return noRowsAffected, fmt.Errorf("%s: failed for %q: %w", op, privateId, err)
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
			// no oplog entries for root keys
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
		return noRowsAffected, fmt.Errorf("%s: failed for %q: %w", op, privateId, err)
	}
	return rowsDeleted, nil
}

// ListDataKeys will list the keys.  Supports options: WithPurpose, WithLimit,
// WithOrderByVersion, WithReader, WithRootKeyId
func (r *repository) ListDataKeys(ctx context.Context, opt ...Option) ([]*dataKey, error) {
	const op = "kms.(Repository).ListDataKeys"
	opts := getOpts(opt...)

	var keys []*dataKey
	var where string
	var whereArgs []interface{}
	switch {
	case opts.withRootKeyId != "":
		where = "root_key_id = ?"
		whereArgs = append(whereArgs, opts.withRootKeyId)
	default:
		where = "1=1"
	}
	if opts.withPurpose != KeyPurposeUnknown {
		where += " and purpose = ?"
		whereArgs = append(whereArgs, opts.withPurpose)
	}
	{
		dk := dataKey{
			tableNamePrefix: r.tableNamePrefix,
		}
		opt = append(opt, withTableName(dk.TableName()))
	}
	err := r.list(ctx, &keys, where, whereArgs, opt...)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", op, err)
	}
	return keys, nil
}
