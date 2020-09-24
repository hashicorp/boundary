package kms

import (
	"context"
	"errors"
	"fmt"
	"io"

	"github.com/hashicorp/boundary/internal/db"
	wrapping "github.com/hashicorp/go-kms-wrapping"
	"github.com/hashicorp/go-kms-wrapping/wrappers/aead"
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
	if r == nil {
		return nil, errors.New("error creating db repository with nil reader")
	}
	if w == nil {
		return nil, errors.New("error creating db repository with nil writer")
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
	if opts.withOrder != "" {
		dbOpts = append(dbOpts, db.WithOrder(opts.withOrder))
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
	if dbReader == nil {
		return nil, fmt.Errorf("create keys: missing db reader: %w", db.ErrInvalidParameter)
	}
	if dbWriter == nil {
		return nil, fmt.Errorf("create keys: missing db writer: %w", db.ErrInvalidParameter)
	}
	if rootWrapper == nil {
		return nil, fmt.Errorf("create keys: missing root wrapper: %w", db.ErrInvalidParameter)
	}
	if randomReader == nil {
		return nil, fmt.Errorf("create keys: missing random reader: %w", db.ErrInvalidParameter)
	}
	if scopeId == "" {
		return nil, fmt.Errorf("create keys: missing scope id: %w", db.ErrInvalidParameter)
	}
	k, err := generateKey(randomReader)
	if err != nil {
		return nil, fmt.Errorf("create keys: error generating random bytes for root key in scope %s: %w", scopeId, err)
	}
	rootKey, rootKeyVersion, err := createRootKeyTx(ctx, dbWriter, rootWrapper, scopeId, k)
	if err != nil {
		return nil, fmt.Errorf("create keys: unable to create root key in scope %s: %w", scopeId, err)
	}

	rkvWrapper := aead.NewWrapper(nil)
	if _, err := rkvWrapper.SetConfig(map[string]string{
		"key_id": rootKeyVersion.GetPrivateId(),
	}); err != nil {
		return nil, fmt.Errorf("create keys: error setting config on aead root wrapper in scope %s: %w", scopeId, err)
	}
	if err := rkvWrapper.SetAESGCMKeyBytes(rootKeyVersion.GetKey()); err != nil {
		return nil, fmt.Errorf("create keys: error setting key bytes on aead root wrapper in scope %s: %w", scopeId, err)
	}

	k, err = generateKey(randomReader)
	if err != nil {
		return nil, fmt.Errorf("create keys: error generating random bytes for database key in scope %s: %w", scopeId, err)
	}
	dbKey, dbKeyVersion, err := createDatabaseKeyTx(ctx, dbReader, dbWriter, rkvWrapper, k)
	if err != nil {
		return nil, fmt.Errorf("create keys: unable to create database key in scope %s: %w", scopeId, err)
	}

	k, err = generateKey(randomReader)
	if err != nil {
		return nil, fmt.Errorf("create keys: error generating random bytes for oplog key in scope %s: %w", scopeId, err)
	}
	oplogKey, oplogKeyVersion, err := createOplogKeyTx(ctx, dbReader, dbWriter, rkvWrapper, k)
	if err != nil {
		return nil, fmt.Errorf("create keys: unable to create oplog key in scope %s: %w", scopeId, err)
	}

	k, err = generateKey(randomReader)
	if err != nil {
		return nil, fmt.Errorf("create keys: error generating random bytes for session key in scope %s: %w", scopeId, err)
	}
	sessionKey, sessionKeyVersion, err := createSessionKeyTx(ctx, dbReader, dbWriter, rkvWrapper, k)
	if err != nil {
		return nil, fmt.Errorf("create keys: unable to create session key in scope %s: %w", scopeId, err)
	}

	k, err = generateKey(randomReader)
	if err != nil {
		return nil, fmt.Errorf("create keys: error generating random bytes for token key in scope %s: %w", scopeId, err)
	}
	tokenKey, tokenKeyVersion, err := createTokenKeyTx(ctx, dbReader, dbWriter, rkvWrapper, k)
	if err != nil {
		return nil, fmt.Errorf("create keys: unable to create token key in scope %s: %w", scopeId, err)
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
	}
	return keys, nil
}

func generateKey(randomReader io.Reader) ([]byte, error) {
	k, err := uuid.GenerateRandomBytesWithReader(32, randomReader)
	if err != nil {
		return nil, fmt.Errorf("error generating random bytes for key: %w", err)
	}
	return k, nil
}
