// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package kms

import (
	"context"
	"fmt"
	"io"

	"github.com/hashicorp/go-dbw"
	"github.com/hashicorp/go-kms-wrapping/extras/kms/v2/migrations"
	wrapping "github.com/hashicorp/go-kms-wrapping/v2"
	"github.com/hashicorp/go-kms-wrapping/v2/aead"
	"github.com/hashicorp/go-secure-stdlib/strutil"
	"github.com/hashicorp/go-uuid"
)

const (
	// defaultLimit is the default for results: -1 signals no limit
	defaultLimit = -1

	// testDefaultWrapperSecret defines a default secret for testing
	testDefaultWrapperSecret = "secret1234567890"

	// stdRetryCnt defines a standard retry count for transactions.
	stdRetryCnt = 20

	// noRowsAffected defines the returned value for no rows affected
	noRowsAffected = 0
)

// orderBy defines an enum type for declaring a column's order by criteria.
type orderBy int

const (
	// unknownOrderBy would designate an unknown ordering of the column, which
	// is the standard ordering for any select without an order by clause.
	unknownOrderBy = iota

	// ascendingOrderBy would designate ordering the column in ascending order.
	ascendingOrderBy

	// descendingOrderBy would designate ordering the column in decending order.
	descendingOrderBy
)

// repository is the iam database repository
type repository struct {
	reader dbw.Reader
	writer dbw.Writer
	// defaultLimit provides a default for limiting the number of results returned from the repo
	defaultLimit int

	// tableNamePrefix defines the prefix to use before the table name and
	// allows us to support custom prefixes as well as multi KMSs within a
	// single schema.
	tableNamePrefix string
}

// newRepository creates a new kms Repository. Supports the options: WithLimit
// which sets a default limit on results returned by repo operations.
func newRepository(r dbw.Reader, w dbw.Writer, opt ...Option) (*repository, error) {
	const op = "kms.newRepository"
	if r == nil {
		return nil, fmt.Errorf("%s: nil reader: %w", op, ErrInvalidParameter)
	}
	if w == nil {
		return nil, fmt.Errorf("%s: nil writer: %w", op, ErrInvalidParameter)
	}
	opts := getOpts(opt...)
	if opts.withLimit == 0 {
		// zero signals the defaults should be used.
		opts.withLimit = defaultLimit
	}
	if _, err := validateSchema(context.Background(), r, opts.withTableNamePrefix); err != nil {
		return nil, fmt.Errorf("%s: %w", op, err)
	}
	return &repository{
		reader:          r,
		writer:          w,
		defaultLimit:    opts.withLimit,
		tableNamePrefix: opts.withTableNamePrefix,
	}, nil
}

// ValidateSchema will validate the database schema against the module's
// required migrations.Version
func (r *repository) ValidateSchema(ctx context.Context) (string, error) {
	const op = "kms.(repository).validateVersion"
	return validateSchema(ctx, r.reader, r.tableNamePrefix)
}

func validateSchema(ctx context.Context, r dbw.Reader, tableNamePrefix string) (string, error) {
	const op = "kms.validateSchema"
	s := schema{
		tableNamePrefix: tableNamePrefix,
	}
	if err := r.LookupWhere(ctx, &s, "1=1", nil, dbw.WithTable(s.TableName())); err != nil {
		return "", fmt.Errorf("%s: unable to get version: %w", op, err)
	}
	if s.Version != migrations.Version {
		return s.Version, fmt.Errorf("%s: invalid schema version, expected version %q and got %q: %w", op, migrations.Version, s.Version, ErrInvalidVersion)
	}
	return s.Version, nil
}

// DefaultLimit returns the default limit for listing as set on the repo
func (r *repository) DefaultLimit() int {
	return r.defaultLimit
}

// list will return a listing of resources and honor the WithLimit option or the
// repo defaultLimit.  WithOrderByVersion is supported for types that have a
// version column.  WithReader option is supported.  Non-exported withTableName
// is supported
func (r *repository) list(ctx context.Context, resources interface{}, where string, args []interface{}, opt ...Option) error {
	opts := getOpts(opt...)
	limit := r.defaultLimit
	var dbOpts []dbw.Option
	if opts.withTableName != "" {
		dbOpts = append(dbOpts, dbw.WithTable(opts.withTableName))
	}
	if opts.withLimit != 0 {
		// non-zero signals an override of the default limit for the repo.
		limit = opts.withLimit
	}
	dbOpts = append(dbOpts, dbw.WithLimit(limit))
	switch resources.(type) {
	case *[]*rootKeyVersion, *[]*dataKeyVersion, []*rootKeyVersion, []*dataKeyVersion:
		switch opts.withOrderByVersion {
		case ascendingOrderBy:
			dbOpts = append(dbOpts, dbw.WithOrder("version asc"))
		case descendingOrderBy:
			dbOpts = append(dbOpts, dbw.WithOrder("version desc"))
		}
	}
	if opts.withReader == nil {
		opts.withReader = r.reader
	}
	return opts.withReader.SearchWhere(ctx, resources, where, args, dbOpts...)
}

type vetForWriter interface {
	vetForWrite(ctx context.Context, opType dbw.OpType) error
}

func updateKeyCollectionVersion(ctx context.Context, w dbw.Writer, tableNamePrefix string) error {
	const (
		op            = "kms.updateKeyCollectionVersion"
		baseTableName = "collection_version"
		sql           = "update %s_%s set version = version + 1"
	)
	if isNil(w) {
		return fmt.Errorf("%s: missing writer: %w", op, ErrInvalidParameter)
	}

	rowsUpdated, err := w.Exec(ctx, fmt.Sprintf(sql, tableNamePrefix, baseTableName), nil)
	if err != nil {
		return fmt.Errorf("%s: %w", op, err)
	}
	if rowsUpdated != 1 {
		return fmt.Errorf("%s: update %q rows and expected 1: %w", op, rowsUpdated, ErrInternal)
	}
	return nil
}

func currentCollectionVersion(ctx context.Context, r dbw.Reader, tableNamePrefix string) (uint64, error) {
	const (
		op            = "kms.currentCollectionVersion"
		baseTableName = "collection_version"
		sql           = "select version from %s_%s"
	)
	if isNil(r) {
		return 0, fmt.Errorf("%s: missing reader: %w", op, ErrInvalidParameter)
	}

	rows, err := r.Query(ctx, fmt.Sprintf(sql, tableNamePrefix, baseTableName), nil)
	if err != nil {
		return 0, fmt.Errorf("%s: %w", op, err)
	}
	v := struct {
		Version uint64
	}{}
	for rows.Next() {
		if err := r.ScanRows(rows, &v); err != nil {
			return 0, fmt.Errorf("%s: %w", op, err)
		}
	}
	return v.Version, nil
}

func create(ctx context.Context, writer dbw.Writer, i interface{}, opt ...dbw.Option) error {
	const op = "kms.create"
	before := func(interface{}) error { return nil }
	if vetter, ok := i.(vetForWriter); ok {
		before = func(i interface{}) error {
			if err := vetter.vetForWrite(ctx, dbw.CreateOp); err != nil {
				return err
			}
			return nil
		}
	}
	if before != nil {
		opt = append(opt, dbw.WithBeforeWrite(before))
	}
	opt = append(opt, dbw.WithLookup(true))
	if err := writer.Create(ctx, i, opt...); err != nil {
		return fmt.Errorf("%s: %w", op, err)
	}
	return nil
}

// keyIder defines a common interface for all keys contained within a
// KeyWithVersion
type keyIder interface {
	GetPrivateId() string
}

// keyWithVersion encapsulates a key with its key version
type keyWithVersion struct {
	Key        keyIder
	KeyVersion keyIder
}

// keys defines a return type for createKeysTx so the returned keys can be
// easily accessed via their KeyPurpose
type keys map[KeyPurpose]keyWithVersion

// createKeysTx creates the root key and DEKs and returns a map of the new keys.
// This function encapsulates all the work required within a dbw.TxHandler and
// allows this capability to be shared with other repositories or just called
// within a transaction.  To be clear, this repository function doesn't include
// its own transaction and is intended to be used within a transaction provided
// by the caller.
func createKeysTx(ctx context.Context, r dbw.Reader, w dbw.Writer, rootWrapper wrapping.Wrapper, randomReader io.Reader, tableNamePrefix string, scopeId string, purpose ...KeyPurpose) (keys, error) {
	const op = "kms.createKeysTx"
	if rootWrapper == nil {
		return nil, fmt.Errorf("%s: missing root wrapper: %w", op, ErrInvalidParameter)
	}
	if randomReader == nil {
		return nil, fmt.Errorf("%s: missing random reader: %w", op, ErrInvalidParameter)
	}
	if scopeId == "" {
		return nil, fmt.Errorf("%s: missing scope id: %w", op, ErrInvalidParameter)
	}
	if tableNamePrefix == "" {
		return nil, fmt.Errorf("%s: missing table name prefix: %w", op, ErrInvalidParameter)
	}
	reserved := reservedKeyPurpose()
	dups := map[KeyPurpose]struct{}{}
	for _, p := range purpose {
		if strutil.StrListContains(reserved, string(p)) {
			return nil, fmt.Errorf("%s: reserved key purpose %q: %w", op, p, ErrInvalidParameter)
		}
		if _, ok := dups[p]; ok {
			return nil, fmt.Errorf("%s: duplicate key purpose %q: %w", op, p, ErrInvalidParameter)
		}
		dups[p] = struct{}{}
	}
	k, err := generateKey(ctx, randomReader)
	if err != nil {
		return nil, fmt.Errorf("%s: error generating random bytes for root key in scope %q: %w", op, scopeId, err)
	}
	rootKey, rootKeyVersion, err := createRootKeyTx(ctx, w, rootWrapper, scopeId, k, tableNamePrefix)
	if err != nil {
		return nil, fmt.Errorf("%s: unable to create root key in scope %q: %w", op, scopeId, err)
	}
	keys := keys{
		KeyPurposeRootKey: keyWithVersion{
			rootKey,
			rootKeyVersion,
		},
	}

	rkvWrapper := aead.NewWrapper()
	if _, err := rkvWrapper.SetConfig(ctx, wrapping.WithKeyId(rootKeyVersion.PrivateId)); err != nil {
		return nil, fmt.Errorf("%s: error setting config on aead root wrapper in scope %q: %w", op, scopeId, err)
	}
	if err := rkvWrapper.SetAesGcmKeyBytes(rootKeyVersion.Key); err != nil {
		return nil, fmt.Errorf("%s: error setting key bytes on aead root wrapper in scope %q: %w", op, scopeId, err)
	}

	for _, p := range purpose {
		k, err = generateKey(ctx, randomReader)
		if err != nil {
			return nil, fmt.Errorf("%s: error generating random bytes for data key of purpose %q in scope %q: %w", op, p, scopeId, err)
		}
		dataKey, dataKeyVersion, err := createDataKeyTx(ctx, r, w, rkvWrapper, tableNamePrefix, p, k)
		if err != nil {
			return nil, fmt.Errorf("%s: unable to create data key of purpose %q in scope %q: %w", op, p, scopeId, err)
		}
		keys[p] = keyWithVersion{
			Key:        dataKey,
			KeyVersion: dataKeyVersion,
		}
	}
	return keys, nil
}

func generateKey(ctx context.Context, randomReader io.Reader) ([]byte, error) {
	const op = "kms.generateKey"
	k, err := uuid.GenerateRandomBytesWithReader(32, randomReader)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", op, err)
	}
	return k, nil
}
