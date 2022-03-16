package kms

import (
	"context"
	"fmt"
	"io"

	"github.com/hashicorp/boundary/internal/db"
	"github.com/hashicorp/boundary/internal/errors"
	"github.com/hashicorp/boundary/internal/types/scope"
	wrapping "github.com/hashicorp/go-kms-wrapping/v2"
	aead "github.com/hashicorp/go-kms-wrapping/v2/aead"
	"github.com/hashicorp/go-uuid"
)

// Repository is the iam database repository
type Repository struct {
	reader db.Reader
	writer db.Writer
	// defaultLimit provides a default for limiting the number of results returned from the repo
	defaultLimit int
}

// NewRepository creates a new kms Repository. Supports the options: WithLimit
// which sets a default limit on results returned by repo operations.
func NewRepository(r db.Reader, w db.Writer, opt ...Option) (*Repository, error) {
	const op = "kms.NewRepository"
	if r == nil {
		return nil, errors.NewDeprecated(errors.InvalidParameter, op, "nil reader")
	}
	if w == nil {
		return nil, errors.NewDeprecated(errors.InvalidParameter, op, "nil writer")
	}
	opts := getOpts(opt...)
	if opts.withLimit == 0 {
		// zero signals the boundary defaults should be used.
		opts.withLimit = db.DefaultLimit
	}
	return &Repository{
		reader:       r,
		writer:       w,
		defaultLimit: opts.withLimit,
	}, nil
}

// list will return a listing of resources and honor the WithLimit option or the
// repo defaultLimit
func (r *Repository) list(ctx context.Context, resources interface{}, where string, args []interface{}, opt ...Option) error {
	opts := getOpts(opt...)
	limit := r.defaultLimit
	var dbOpts []db.Option
	if opts.withLimit != 0 {
		// non-zero signals an override of the default limit for the repo.
		limit = opts.withLimit
	}
	dbOpts = append(dbOpts, db.WithLimit(limit))
	switch opts.withOrderByVersion {
	case db.AscendingOrderBy:
		dbOpts = append(dbOpts, db.WithOrder("version asc"))
	case db.DescendingOrderBy:
		dbOpts = append(dbOpts, db.WithOrder("version desc"))
	}

	return r.reader.SearchWhere(ctx, resources, where, args, dbOpts...)
}

// DefaultLimit returns the default limit for listing as set on the repo
func (r *Repository) DefaultLimit() int {
	return r.defaultLimit
}

// KeyIder defines a common interface for all keys returned from CreateKeysTx in
// a Keys map
type KeyIder interface {
	GetPrivateId() string
}

// Keys defines a return type for CreateKeysTx so the returned keys can be
// easily accessed via their KeyType
type Keys map[KeyType]KeyIder

// CreateKeysTx creates the root key and DEKs returns a map of the new keys.
// This function encapsulates all the work required within a db.TxHandler and
// allows this capability to be shared with the iam repo.
func CreateKeysTx(ctx context.Context, dbReader db.Reader, dbWriter db.Writer, rootWrapper wrapping.Wrapper, randomReader io.Reader, scopeId string) (Keys, error) {
	const op = "kms.CreateKeysTx"
	if dbReader == nil {
		return nil, errors.New(ctx, errors.InvalidParameter, op, "missing db reader")
	}
	if dbWriter == nil {
		return nil, errors.New(ctx, errors.InvalidParameter, op, "missing db writer")
	}
	if rootWrapper == nil {
		return nil, errors.New(ctx, errors.InvalidParameter, op, "missing root wrapper")
	}
	if randomReader == nil {
		return nil, errors.New(ctx, errors.InvalidParameter, op, "missing random reader")
	}
	if scopeId == "" {
		return nil, errors.New(ctx, errors.InvalidParameter, op, "missing scope id")
	}
	k, err := generateKey(ctx, randomReader)
	if err != nil {
		return nil, errors.Wrap(ctx, err, op, errors.WithMsg(fmt.Sprintf("error generating random bytes for root key in scope %s", scopeId)))
	}
	rootKey, rootKeyVersion, err := createRootKeyTx(ctx, dbWriter, rootWrapper, scopeId, k)
	if err != nil {
		return nil, errors.Wrap(ctx, err, op, errors.WithMsg(fmt.Sprintf("unable to create root key in scope %s", scopeId)))
	}

	rkvWrapper := aead.NewWrapper()
	if _, err := rkvWrapper.SetConfig(ctx, wrapping.WithKeyId(rootKeyVersion.GetPrivateId())); err != nil {
		return nil, errors.Wrap(ctx, err, op, errors.WithMsg(fmt.Sprintf("error setting config on aead root wrapper in scope %s", scopeId)))
	}
	if err := rkvWrapper.SetAesGcmKeyBytes(rootKeyVersion.GetKey()); err != nil {
		return nil, errors.Wrap(ctx, err, op, errors.WithMsg(fmt.Sprintf("error setting key bytes on aead root wrapper in scope %s", scopeId)))
	}

	k, err = generateKey(ctx, randomReader)
	if err != nil {
		return nil, errors.Wrap(ctx, err, op, errors.WithMsg(fmt.Sprintf("error generating random bytes for database key in scope %s", scopeId)))
	}
	dbKey, dbKeyVersion, err := createDatabaseKeyTx(ctx, dbReader, dbWriter, rkvWrapper, k)
	if err != nil {
		return nil, errors.Wrap(ctx, err, op, errors.WithMsg(fmt.Sprintf("unable to create database key in scope %s", scopeId)))
	}

	k, err = generateKey(ctx, randomReader)
	if err != nil {
		return nil, errors.Wrap(ctx, err, op, errors.WithMsg(fmt.Sprintf("error generating random bytes for oplog key in scope %s", scopeId)))
	}
	oplogKey, oplogKeyVersion, err := createOplogKeyTx(ctx, dbReader, dbWriter, rkvWrapper, k)
	if err != nil {
		return nil, errors.Wrap(ctx, err, op, errors.WithMsg(fmt.Sprintf("unable to create oplog key in scope %s", scopeId)))
	}

	k, err = generateKey(ctx, randomReader)
	if err != nil {
		return nil, errors.Wrap(ctx, err, op, errors.WithMsg(fmt.Sprintf("error generating random bytes for session key in scope %s", scopeId)))
	}
	sessionKey, sessionKeyVersion, err := createSessionKeyTx(ctx, dbReader, dbWriter, rkvWrapper, k)
	if err != nil {
		return nil, errors.Wrap(ctx, err, op, errors.WithMsg(fmt.Sprintf("unable to create session key in scope %s", scopeId)))
	}

	k, err = generateKey(ctx, randomReader)
	if err != nil {
		return nil, errors.Wrap(ctx, err, op, errors.WithMsg(fmt.Sprintf("error generating random bytes for token key in scope %s", scopeId)))
	}
	tokenKey, tokenKeyVersion, err := createTokenKeyTx(ctx, dbReader, dbWriter, rkvWrapper, k)
	if err != nil {
		return nil, errors.Wrap(ctx, err, op, errors.WithMsg(fmt.Sprintf("unable to create token key in scope %s", scopeId)))
	}

	k, err = generateKey(ctx, randomReader)
	if err != nil {
		return nil, errors.Wrap(ctx, err, op, errors.WithMsg(fmt.Sprintf("error generating random bytes for oidc key in scope %s", scopeId)))
	}
	oidcKey, oidcKeyVersion, err := createOidcKeyTx(ctx, dbReader, dbWriter, rkvWrapper, k)
	if err != nil {
		return nil, errors.Wrap(ctx, err, op, errors.WithMsg(fmt.Sprintf("unable to create oidc key in scope %s", scopeId)))
	}
	keys := Keys{
		KeyTypeRootKey:            rootKey,
		KeyTypeRootKeyVersion:     rootKeyVersion,
		KeyTypeDatabaseKey:        dbKey,
		KeyTypeDatabaseKeyVersion: dbKeyVersion,
		KeyTypeOplogKey:           oplogKey,
		KeyTypeOplogKeyVersion:    oplogKeyVersion,
		KeyTypeSessionKey:         sessionKey,
		KeyTypeSessionKeyVersion:  sessionKeyVersion,
		KeyTypeTokenKey:           tokenKey,
		KeyTypeTokenKeyVersion:    tokenKeyVersion,
		KeyTypeOidcKey:            oidcKey,
		KeyTypeOidcKeyVersion:     oidcKeyVersion,
	}
	if scopeId == scope.Global.String() {
		k, err = generateKey(ctx, randomReader)
		if err != nil {
			return nil, errors.Wrap(ctx, err, op, errors.WithMsg(fmt.Sprintf("error generating random bytes for oidc key in scope %s", scopeId)))
		}
		auditKey, auditKeyVersion, err := createAuditKeyTx(ctx, dbReader, dbWriter, rkvWrapper, k)
		if err != nil {
			return nil, errors.Wrap(ctx, err, op, errors.WithMsg(fmt.Sprintf("unable to create audit key in scope %s", scopeId)))
		}
		keys[KeyTypeAuditKey] = auditKey
		keys[KeyTypeAuditKeyVersion] = auditKeyVersion
	}

	return keys, nil
}

func generateKey(ctx context.Context, randomReader io.Reader) ([]byte, error) {
	const op = "kms.generateKey"
	k, err := uuid.GenerateRandomBytesWithReader(32, randomReader)
	if err != nil {
		return nil, errors.Wrap(ctx, err, op)
	}
	return k, nil
}
