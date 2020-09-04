package kms

import (
	"context"
	"errors"
	"fmt"
	"sync"

	"github.com/hashicorp/boundary/internal/types/scope"
	"github.com/hashicorp/go-hclog"
	wrapping "github.com/hashicorp/go-kms-wrapping"
	"github.com/hashicorp/go-kms-wrapping/wrappers/aead"
	"github.com/hashicorp/go-kms-wrapping/wrappers/multiwrapper"
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
	logger hclog.Logger

	// scopePurposeCache holds a per-scope-purpose multiwrapper containing the
	// current encrypting key and all previous key versions, for decryption
	scopePurposeCache sync.Map

	externalScopeCache      map[string]*ExternalWrappers
	externalScopeCacheMutex sync.RWMutex

	repo *Repository
}

// NewKms takes in a repo and returns a Kms. Supported options: WithLogger.
func NewKms(repo *Repository, opt ...Option) (*Kms, error) {
	if repo == nil {
		return nil, errors.New("new kms created without an underlying repo")
	}

	opts := getOpts(opt...)

	return &Kms{
		logger:             opts.withLogger,
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

// AddExternalWrappers allows setting the external keys.
//
// TODO: If we support more than one, e.g. for encrypting against many in case
// of a key loss, there will need to be some refactoring here to have the values
// being stored in the struct be a multiwrapper, but that's for a later project.
func (k *Kms) AddExternalWrappers(opt ...Option) error {
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
		if ext.root.KeyID() == "" {
			return fmt.Errorf("root wrapper has no key ID")
		}
	}
	if opts.withWorkerAuthWrapper != nil {
		ext.workerAuth = opts.withWorkerAuthWrapper
		if ext.workerAuth.KeyID() == "" {
			return fmt.Errorf("worker auth wrapper has no key ID")
		}
	}
	if opts.withRecoveryWrapper != nil {
		ext.recovery = opts.withRecoveryWrapper
		if ext.recovery.KeyID() == "" {
			return fmt.Errorf("recovery wrapper has no key ID")
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

func generateKeyId(scopeId string, purpose KeyPurpose, version uint32) string {
	return fmt.Sprintf("%s_%s_%d", scopeId, purpose, version)
}

// GetWrapper returns a wrapper for the given scope and purpose. When a keyId is
// passed, it will ensure that the returning wrapper has that key ID in the
// multiwrapper. This is not necesary for encryption but should be supplied for
// decryption.
func (k *Kms) GetWrapper(ctx context.Context, scopeId string, purpose KeyPurpose, opt ...Option) (wrapping.Wrapper, error) {
	if scopeId == "" {
		return nil, errors.New("no scope ID provided")
	}

	switch purpose {
	case KeyPurposeOplog, KeyPurposeDatabase, KeyPurposeTokens, KeyPurposeSessions:
	case KeyPurposeUnknown:
		return nil, errors.New("key purpose not specified")
	default:
		return nil, fmt.Errorf("unsupported purpose %q", purpose)
	}

	opts := getOpts(opt...)
	// Fast-path: we have a valid key at the scope/purpose. Verify the key with
	// that ID is in the multiwrapper; if not, fall through to reload from the
	// DB.
	val, ok := k.scopePurposeCache.Load(scopeId + purpose.String())
	if ok {
		wrapper := val.(*multiwrapper.MultiWrapper)
		if opts.withKeyId == "" || wrapper.WrapperForKeyID(opts.withKeyId) != nil {
			return wrapper, nil
		}
		// Fall through to refresh our multiwrapper for this scope/purpose from the DB
	}

	// We don't have it cached, so we'll need to read from the database. Get the
	// root for the scope as we'll need it to decrypt the value coming from the
	// DB. We don't cache the roots as we expect that after a few calls the
	// scope-purpose cache will catch everything in steady-state.
	rootWrapper, rootKeyId, err := k.loadRoot(ctx, scopeId, opt...)
	if err != nil {
		return nil, fmt.Errorf("error loading root key for scope %s: %w", scopeId, err)
	}
	if rootWrapper == nil {
		return nil, fmt.Errorf("got nil root wrapper for scope %s", scopeId)
	}

	wrapper, err := k.loadDek(ctx, scopeId, purpose, rootWrapper, rootKeyId, opt...)
	if err != nil {
		return nil, fmt.Errorf("error loading %s for scope %s: %w", purpose.String(), scopeId, err)
	}
	k.scopePurposeCache.Store(scopeId+purpose.String(), wrapper)

	return wrapper, nil
}

func (k *Kms) loadRoot(ctx context.Context, scopeId string, opt ...Option) (*multiwrapper.MultiWrapper, string, error) {
	opts := getOpts(opt...)
	repo := opts.withRepository
	if repo == nil {
		repo = k.repo
	}
	rootKeys, err := repo.ListRootKeys(ctx)
	if err != nil {
		return nil, "", fmt.Errorf("error listing root keys: %w", err)
	}
	var rootKeyId string
	for _, k := range rootKeys {
		if k.GetScopeId() == scopeId {
			rootKeyId = k.GetPrivateId()
			break
		}
	}
	if rootKeyId == "" {
		return nil, "", fmt.Errorf("error finding root key for scope %s", scopeId)
	}

	// Now: find the external KMS that can be used to decrypt the root values
	// from the DB.
	k.externalScopeCacheMutex.Lock()
	externalWrappers := k.externalScopeCache[scope.Global.String()]
	k.externalScopeCacheMutex.Unlock()
	if externalWrappers == nil {
		return nil, "", errors.New("could not find kms information at either the needed scope or global fallback")
	}

	externalWrappers.m.RLock()
	defer externalWrappers.m.RUnlock()

	if externalWrappers.root == nil {
		return nil, "", fmt.Errorf("root key wrapper for scope %s is nil", scopeId)
	}
	rootKeyVersions, err := repo.ListRootKeyVersions(ctx, externalWrappers.root, rootKeyId, WithOrder("version desc"))
	if err != nil {
		return nil, "", fmt.Errorf("error looking up root key versions for scope %s with key ID %s: %w", scopeId, externalWrappers.root.KeyID(), err)
	}
	if len(rootKeyVersions) == 0 {
		return nil, "", fmt.Errorf("no root key versions found for scope %s", scopeId)
	}

	var multi *multiwrapper.MultiWrapper
	for i, key := range rootKeyVersions {
		wrapper := aead.NewWrapper(nil)
		if _, err := wrapper.SetConfig(map[string]string{
			"key_id": key.GetPrivateId(),
		}); err != nil {
			return nil, "", fmt.Errorf("error setting config on aead root wrapper in scope %s: %w", scopeId, err)
		}
		if err := wrapper.SetAESGCMKeyBytes(key.GetKey()); err != nil {
			return nil, "", fmt.Errorf("error setting key bytes on aead root wrapper in scope %s: %w", scopeId, err)
		}
		if i == 0 {
			multi = multiwrapper.NewMultiWrapper(wrapper)
		} else {
			multi.AddWrapper(wrapper)
		}
	}

	return multi, rootKeyId, err
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

func (k *Kms) loadDek(ctx context.Context, scopeId string, purpose KeyPurpose, rootWrapper wrapping.Wrapper, rootKeyId string, opt ...Option) (*multiwrapper.MultiWrapper, error) {
	if rootWrapper == nil {
		return nil, fmt.Errorf("got nil root wrapper in loadDek for scope %s", scopeId)
	}
	if rootKeyId == "" {
		return nil, fmt.Errorf("no root key ID provided for scope %s", scopeId)
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
	}
	if err != nil {
		return nil, fmt.Errorf("error listing root keys: %w", err)
	}
	var keyId string
	for _, k := range keys {
		if k.GetRootKeyId() == rootKeyId {
			keyId = k.GetPrivateId()
			break
		}
	}
	if keyId == "" {
		return nil, fmt.Errorf("error finding %s key for scope %s", purpose.String(), scopeId)
	}

	var keyVersions []DekVersion
	switch purpose {
	case KeyPurposeDatabase:
		keyVersions, err = repo.ListDatabaseKeyVersions(ctx, rootWrapper, keyId, WithOrder("version desc"))
	case KeyPurposeOplog:
		keyVersions, err = repo.ListOplogKeyVersions(ctx, rootWrapper, keyId, WithOrder("version desc"))
	case KeyPurposeTokens:
		keyVersions, err = repo.ListTokenKeyVersions(ctx, rootWrapper, keyId, WithOrder("version desc"))
	case KeyPurposeSessions:
		keyVersions, err = repo.ListSessionKeyVersions(ctx, rootWrapper, keyId, WithOrder("version desc"))
	}
	if err != nil {
		return nil, fmt.Errorf("error looking up %s key versions for scope %s with key ID %s: %w", purpose.String(), scopeId, rootWrapper.KeyID(), err)
	}
	if len(keyVersions) == 0 {
		return nil, fmt.Errorf("no %s key versions found for scope %s", purpose.String(), scopeId)
	}

	var multi *multiwrapper.MultiWrapper
	for i, keyVersion := range keyVersions {
		wrapper := aead.NewWrapper(nil)
		if _, err := wrapper.SetConfig(map[string]string{
			"key_id": keyVersion.GetPrivateId(),
		}); err != nil {
			return nil, fmt.Errorf("error setting config on aead %s wrapper in scope %s: %w", purpose.String(), scopeId, err)
		}
		if err := wrapper.SetAESGCMKeyBytes(keyVersion.GetKey()); err != nil {
			return nil, fmt.Errorf("error setting key bytes on aead %s wrapper in scope %s: %w", purpose.String(), scopeId, err)
		}
		if i == 0 {
			multi = multiwrapper.NewMultiWrapper(wrapper)
		} else {
			multi.AddWrapper(wrapper)
		}
	}

	return multi, err
}
