package kms

import (
	"context"
	"fmt"
	"io"
	"reflect"
	"sync"

	"github.com/hashicorp/boundary/internal/db"
	"github.com/hashicorp/boundary/internal/errors"
	"github.com/hashicorp/boundary/internal/types/scope"
	wrapping "github.com/hashicorp/go-kms-wrapping/v2"
	"github.com/hashicorp/go-kms-wrapping/v2/multi"
	aead "github.com/hashicorp/go-kms-wrapping/wrappers/aead/v2"
)

// ExternalWrappers holds wrappers defined outside of Boundary, e.g. in its
// configuration file.
type ExternalWrappers struct {
	m          sync.RWMutex
	root       wrapping.Wrapper
	workerAuth wrapping.Wrapper
	recovery   wrapping.Wrapper
}

// Root returns the wrapper for root keys
func (e *ExternalWrappers) Root() wrapping.Wrapper {
	e.m.RLock()
	defer e.m.RUnlock()
	return e.root
}

// WorkerAuth returns the wrapper for worker authentication
func (e *ExternalWrappers) WorkerAuth() wrapping.Wrapper {
	e.m.RLock()
	defer e.m.RUnlock()
	return e.workerAuth
}

// Recovery returns the wrapper for recovery operations
func (e *ExternalWrappers) Recovery() wrapping.Wrapper {
	e.m.RLock()
	defer e.m.RUnlock()
	return e.recovery
}

// Kms is a way to access wrappers for a given scope and purpose. Since keys can
// never change, only be added or (eventually) removed, it opportunistically
// caches, going to the database as needed.
type Kms struct {
	// scopePurposeCache holds a per-scope-purpose multiwrapper containing the
	// current encrypting key and all previous key versions, for decryption
	scopePurposeCache sync.Map

	externalScopeCache      map[string]*ExternalWrappers
	externalScopeCacheMutex sync.RWMutex

	derivedPurposeCache sync.Map

	repo *Repository
}

// NewKms takes in a repo and returns a Kms.
func NewKms(repo *Repository, opt ...Option) (*Kms, error) {
	const op = "kms.NewKms"
	if repo == nil {
		return nil, errors.NewDeprecated(errors.InvalidParameter, op, "missing underlying repo")
	}

	return &Kms{
		externalScopeCache: make(map[string]*ExternalWrappers),
		repo:               repo,
	}, nil
}

// GetScopePurposeCache is used in test functions for validation. Since the
// tests need to be in a different package to avoid circular dependencies, this
// is exported.
func (k *Kms) GetScopePurposeCache() *sync.Map {
	return &k.scopePurposeCache
}

func (k *Kms) GetDerivedPurposeCache() *sync.Map {
	return &k.derivedPurposeCache
}

// AddExternalWrappers allows setting the external keys.
//
// TODO: If we support more than one, e.g. for encrypting against many in case
// of a key loss, there will need to be some refactoring here to have the values
// being stored in the struct be a multiwrapper, but that's for a later project.
func (k *Kms) AddExternalWrappers(ctx context.Context, opt ...Option) error {
	const op = "kms.AddExternalWrappers"
	k.externalScopeCacheMutex.Lock()
	defer k.externalScopeCacheMutex.Unlock()

	ext := k.externalScopeCache[scope.Global.String()]
	if ext == nil {
		ext = &ExternalWrappers{}
	}
	ext.m.Lock()
	defer ext.m.Unlock()

	opts := getOpts(opt...)
	if opts.withRootWrapper != nil {
		ext.root = opts.withRootWrapper
		keyId, err := ext.root.KeyId(ctx)
		if err != nil {
			return errors.Wrap(ctx, err, op, errors.WithMsg("error reading root wrapper key ID"))
		}
		if keyId == "" {
			return errors.New(ctx, errors.InvalidParameter, op, "root wrapper has no key ID")
		}
	}
	if opts.withWorkerAuthWrapper != nil {
		ext.workerAuth = opts.withWorkerAuthWrapper
		keyId, err := ext.workerAuth.KeyId(ctx)
		if err != nil {
			return errors.Wrap(ctx, err, op, errors.WithMsg("error reading worker auth wrapper key ID"))
		}
		if keyId == "" {
			return errors.New(ctx, errors.InvalidParameter, op, "worker auth wrapper has no key ID")
		}
	}
	if opts.withRecoveryWrapper != nil {
		ext.recovery = opts.withRecoveryWrapper
		keyId, err := ext.root.KeyId(ctx)
		if err != nil {
			return errors.Wrap(ctx, err, op, errors.WithMsg("error reading recovery wrapper key ID"))
		}
		if keyId == "" {
			return errors.New(ctx, errors.InvalidParameter, op, "recovery wrapper has no key ID")
		}
	}

	k.externalScopeCache[scope.Global.String()] = ext
	return nil
}

func (k *Kms) GetExternalWrappers() *ExternalWrappers {
	k.externalScopeCacheMutex.RLock()
	defer k.externalScopeCacheMutex.RUnlock()

	ext := k.externalScopeCache[scope.Global.String()]
	ext.m.RLock()
	defer ext.m.RUnlock()

	ret := &ExternalWrappers{
		root:       ext.root,
		workerAuth: ext.workerAuth,
		recovery:   ext.recovery,
	}
	return ret
}

// GetWrapper returns a wrapper for the given scope and purpose. When a keyId is
// passed, it will ensure that the returning wrapper has that key ID in the
// multiwrapper. This is not necesary for encryption but should be supplied for
// decryption.
func (k *Kms) GetWrapper(ctx context.Context, scopeId string, purpose KeyPurpose, opt ...Option) (wrapping.Wrapper, error) {
	const op = "kms.GetWrapper"
	if scopeId == "" {
		return nil, errors.New(ctx, errors.InvalidParameter, op, "missing scope id")
	}

	switch purpose {
	case KeyPurposeOplog, KeyPurposeDatabase, KeyPurposeTokens, KeyPurposeSessions, KeyPurposeOidc, KeyPurposeAudit:
	case KeyPurposeUnknown:
		return nil, errors.New(ctx, errors.InvalidParameter, op, "missing key purpose")
	default:
		return nil, errors.New(ctx, errors.InvalidParameter, op, fmt.Sprintf("unsupported purpose %q", purpose))
	}

	opts := getOpts(opt...)
	// Fast-path: we have a valid key at the scope/purpose. Verify the key with
	// that ID is in the multiwrapper; if not, fall through to reload from the
	// DB.
	val, ok := k.scopePurposeCache.Load(scopeId + purpose.String())
	if ok {
		wrapper := val.(*multi.PooledWrapper)
		if opts.withKeyId == "" {
			return wrapper, nil
		}
		if keyIdWrapper := wrapper.WrapperForKeyId(opts.withKeyId); keyIdWrapper != nil {
			return keyIdWrapper, nil
		}
		// Fall through to refresh our multiwrapper for this scope/purpose from the DB
	}

	// We don't have it cached, so we'll need to read from the database. Get the
	// root for the scope as we'll need it to decrypt the value coming from the
	// DB. We don't cache the roots as we expect that after a few calls the
	// scope-purpose cache will catch everything in steady-state.
	rootWrapper, rootKeyId, err := k.loadRoot(ctx, scopeId, opt...)
	if err != nil {
		return nil, errors.Wrap(ctx, err, op, errors.WithMsg(fmt.Sprintf("error loading root key for scope %s", scopeId)))
	}
	if rootWrapper == nil {
		return nil, errors.New(ctx, errors.InvalidParameter, op, fmt.Sprintf("got nil root wrapper for scope %s", scopeId))
	}

	wrapper, err := k.loadDek(ctx, scopeId, purpose, rootWrapper, rootKeyId, opt...)
	if err != nil {
		return nil, errors.Wrap(ctx, err, op, errors.WithMsg(fmt.Sprintf("error loading %s for scope %s", purpose.String(), scopeId)))
	}
	k.scopePurposeCache.Store(scopeId+purpose.String(), wrapper)

	if opts.withKeyId != "" {
		if keyIdWrapper := wrapper.WrapperForKeyId(opts.withKeyId); keyIdWrapper != nil {
			return keyIdWrapper, nil
		}
		return nil, errors.New(ctx, errors.KeyNotFound, op, "unable to find specified key ID")
	}

	return wrapper, nil
}

func (k *Kms) loadRoot(ctx context.Context, scopeId string, opt ...Option) (*multi.PooledWrapper, string, error) {
	const op = "kms.loadRoot"
	opts := getOpts(opt...)
	repo := opts.withRepository
	if repo == nil {
		repo = k.repo
	}
	rootKeys, err := repo.ListRootKeys(ctx)
	if err != nil {
		return nil, "", errors.Wrap(ctx, err, op)
	}
	var rootKeyId string
	for _, k := range rootKeys {
		if k.GetScopeId() == scopeId {
			rootKeyId = k.GetPrivateId()
			break
		}
	}
	if rootKeyId == "" {
		return nil, "", errors.New(ctx, errors.KeyNotFound, op, fmt.Sprintf("missing root key for scope %s", scopeId))
	}

	// Now: find the external KMS that can be used to decrypt the root values
	// from the DB.
	k.externalScopeCacheMutex.Lock()
	externalWrappers := k.externalScopeCache[scope.Global.String()]
	k.externalScopeCacheMutex.Unlock()
	if externalWrappers == nil {
		return nil, "", errors.New(ctx, errors.KeyNotFound, op, "could not find kms information at either the needed scope or global fallback")
	}

	externalWrappers.m.RLock()
	defer externalWrappers.m.RUnlock()

	if externalWrappers.root == nil {
		return nil, "", errors.New(ctx, errors.InvalidParameter, op, fmt.Sprintf("root key wrapper for scope %s is nil", scopeId))
	}
	rootKeyVersions, err := repo.ListRootKeyVersions(ctx, externalWrappers.root, rootKeyId, WithOrderByVersion(db.DescendingOrderBy))
	if err != nil {
		return nil, "", errors.Wrap(ctx, err, op, errors.WithMsg(fmt.Sprintf("error looking up root key versions for scope %s", scopeId)))
	}
	if len(rootKeyVersions) == 0 {
		return nil, "", errors.New(ctx, errors.KeyNotFound, op, fmt.Sprintf("no root key versions found for scope %s", scopeId))
	}

	var pooled *multi.PooledWrapper
	for i, key := range rootKeyVersions {
		var err error
		wrapper := aead.NewWrapper()
		if _, err = wrapper.SetConfig(ctx, wrapping.WithKeyId(key.GetPrivateId())); err != nil {
			return nil, "", errors.Wrap(ctx, err, op, errors.WithMsg(fmt.Sprintf("error setting config on aead root wrapper in scope %s", scopeId)))
		}
		if err = wrapper.SetAesGcmKeyBytes(key.GetKey()); err != nil {
			return nil, "", errors.Wrap(ctx, err, op, errors.WithMsg(fmt.Sprintf("error setting key bytes on aead root wrapper in scope %s", scopeId)))
		}
		if i == 0 {
			pooled, err = multi.NewPooledWrapper(ctx, wrapper)
			if err != nil {
				return nil, "", errors.Wrap(ctx, err, op, errors.WithMsg(fmt.Sprintf("error getting root pooled wrapper for key version 0 in scope %s", scopeId)))
			}
		} else {
			_, err = pooled.AddWrapper(ctx, wrapper)
			if err != nil {
				return nil, "", errors.Wrap(ctx, err, op, errors.WithMsg(fmt.Sprintf("error adding pooled wrapper for key version %d in scope %s", i, scopeId)))
			}
		}
	}

	return pooled, rootKeyId, nil
}

// ReconcileKeys will reconcile the keys in the kms against known possible issues.
func (k *Kms) ReconcileKeys(ctx context.Context, randomReader io.Reader) error {
	const op = "kms.ReconcileKeys"
	if isNil(randomReader) {
		return errors.New(ctx, errors.InvalidParameter, op, "missing rand reader")
	}

	// it's possible that the global audit key was created after this instance's
	// database was initialized... so check if the audit wrapper is available
	// for the global scope and if not, then add one to the global scope
	if _, err := k.GetWrapper(ctx, scope.Global.String(), KeyPurposeAudit); err != nil {
		switch {
		case errors.Match(errors.T(errors.KeyNotFound), err):
			globalRootWrapper, _, err := k.loadRoot(ctx, scope.Global.String())
			if err != nil {
				return errors.Wrap(ctx, err, op)
			}
			key, err := generateKey(ctx, randomReader)
			if err != nil {
				return errors.Wrap(ctx, err, op, errors.WithMsg(fmt.Sprintf("error generating random bytes for database key in scope %s", scope.Global.String())))
			}
			if _, _, err := k.repo.CreateAuditKey(ctx, globalRootWrapper, key); err != nil {
				return errors.Wrap(ctx, err, op, errors.WithMsg(fmt.Sprintf("error creating audit key in scope %s", scope.Global.String())))
			}
		default:
			errors.Wrap(ctx, err, op)
		}
	}
	return nil
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

// Dek is an interface wrapping dek types to allow a lot less switching in loadDek
type Dek interface {
	GetRootKeyId() string
	GetPrivateId() string
}

// DekVersion is an interface wrapping versioned dek types to allow a lot less switching in loadDek
type DekVersion interface {
	GetPrivateId() string
	GetKey() []byte
}

func (k *Kms) loadDek(ctx context.Context, scopeId string, purpose KeyPurpose, rootWrapper wrapping.Wrapper, rootKeyId string, opt ...Option) (*multi.PooledWrapper, error) {
	const op = "kms.loadDek"
	if rootWrapper == nil {
		return nil, errors.New(ctx, errors.InvalidParameter, op, fmt.Sprintf("nil root wrapper for scope %s", scopeId))
	}
	if rootKeyId == "" {
		return nil, errors.New(ctx, errors.InvalidParameter, op, fmt.Sprintf("missing root key ID for scope %s", scopeId))
	}

	opts := getOpts(opt...)
	repo := opts.withRepository
	if repo == nil {
		repo = k.repo
	}

	var keys []Dek
	var err error
	switch purpose {
	case KeyPurposeDatabase:
		keys, err = repo.ListDatabaseKeys(ctx)
	case KeyPurposeOplog:
		keys, err = repo.ListOplogKeys(ctx)
	case KeyPurposeTokens:
		keys, err = repo.ListTokenKeys(ctx)
	case KeyPurposeSessions:
		keys, err = repo.ListSessionKeys(ctx)
	case KeyPurposeOidc:
		keys, err = repo.ListOidcKeys(ctx)
	case KeyPurposeAudit:
		keys, err = repo.ListAuditKeys(ctx)
	default:
		return nil, errors.New(ctx, errors.InvalidParameter, op, "unknown or invalid DEK purpose specified")
	}
	if err != nil {
		return nil, errors.Wrap(ctx, err, op, errors.WithMsg("error listing root keys"))
	}
	var keyId string
	for _, k := range keys {
		if k.GetRootKeyId() == rootKeyId {
			keyId = k.GetPrivateId()
			break
		}
	}
	if keyId == "" {
		return nil, errors.New(ctx, errors.KeyNotFound, op, fmt.Sprintf("error finding %s key for scope %s", purpose.String(), scopeId))
	}

	var keyVersions []DekVersion
	switch purpose {
	case KeyPurposeDatabase:
		keyVersions, err = repo.ListDatabaseKeyVersions(ctx, rootWrapper, keyId, WithOrderByVersion(db.DescendingOrderBy))
	case KeyPurposeOplog:
		keyVersions, err = repo.ListOplogKeyVersions(ctx, rootWrapper, keyId, WithOrderByVersion(db.DescendingOrderBy))
	case KeyPurposeTokens:
		keyVersions, err = repo.ListTokenKeyVersions(ctx, rootWrapper, keyId, WithOrderByVersion(db.DescendingOrderBy))
	case KeyPurposeSessions:
		keyVersions, err = repo.ListSessionKeyVersions(ctx, rootWrapper, keyId, WithOrderByVersion(db.DescendingOrderBy))
	case KeyPurposeOidc:
		keyVersions, err = repo.ListOidcKeyVersions(ctx, rootWrapper, keyId, WithOrderByVersion(db.DescendingOrderBy))
	case KeyPurposeAudit:
		keyVersions, err = repo.ListAuditKeyVersions(ctx, rootWrapper, keyId, WithOrderByVersion(db.DescendingOrderBy))
	default:
		return nil, errors.New(ctx, errors.InvalidParameter, op, "unknown or invalid DEK purpose specified")
	}
	if err != nil {
		return nil, errors.Wrap(ctx, err, op, errors.WithMsg(fmt.Sprintf("error looking up %s key versions for scope %s", purpose.String(), scopeId)))
	}
	if len(keyVersions) == 0 {
		return nil, errors.New(ctx, errors.KeyNotFound, op, fmt.Sprintf("no %s key versions found for scope %s", purpose.String(), scopeId))
	}

	var pooled *multi.PooledWrapper
	for i, keyVersion := range keyVersions {
		var err error
		wrapper := aead.NewWrapper()
		if _, err = wrapper.SetConfig(ctx, wrapping.WithKeyId(keyVersion.GetPrivateId())); err != nil {
			return nil, errors.Wrap(ctx, err, op, errors.WithMsg(fmt.Sprintf("error setting config on aead %s wrapper in scope %s", purpose.String(), scopeId)))
		}
		if err = wrapper.SetAesGcmKeyBytes(keyVersion.GetKey()); err != nil {
			return nil, errors.Wrap(ctx, err, op, errors.WithMsg(fmt.Sprintf("error setting key bytes on aead %s wrapper in scope %s", purpose.String(), scopeId)))
		}
		if i == 0 {
			pooled, err = multi.NewPooledWrapper(ctx, wrapper)
			if err != nil {
				return nil, errors.Wrap(ctx, err, op, errors.WithMsg(fmt.Sprintf("error getting %s pooled wrapper for key version 0 in scope %s", purpose.String(), scopeId)))
			}
		} else {
			_, err = pooled.AddWrapper(ctx, wrapper)
			if err != nil {
				return nil, errors.Wrap(ctx, err, op, errors.WithMsg(fmt.Sprintf("error getting %s pooled wrapper for key version %d in scope %s", purpose.String(), i, scopeId)))
			}
		}
	}

	return pooled, nil
}
