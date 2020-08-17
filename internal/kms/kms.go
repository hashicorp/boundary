package kms

import (
	"context"
	"errors"
	"fmt"
	"hash"
	"sync"

	"github.com/hashicorp/boundary/internal/types/scope"
	"github.com/hashicorp/go-hclog"
	wrapping "github.com/hashicorp/go-kms-wrapping"
	"github.com/hashicorp/go-kms-wrapping/wrappers/aead"
	"github.com/hashicorp/go-kms-wrapping/wrappers/multiwrapper"
	"golang.org/x/crypto/blake2b"
)

type ExternalWrappers struct {
	m          sync.RWMutex
	root       wrapping.Wrapper
	workerAuth wrapping.Wrapper
}

func (e *ExternalWrappers) Root() wrapping.Wrapper {
	e.m.RLock()
	defer e.m.RUnlock()
	return e.root
}

func (e *ExternalWrappers) WorkerAuth() wrapping.Wrapper {
	e.m.RLock()
	defer e.m.RUnlock()
	return e.workerAuth
}

type Kms struct {
	logger hclog.Logger

	// scopePurposeCache holds a per-scope-purpose multiwrapper containing the
	// current encrypting key and all previous key versions, for decryption
	scopePurposeCache sync.Map

	externalScopeCache      map[string]*ExternalWrappers
	externalScopeCacheMutex sync.RWMutex

	repo *Repository
}

func NewKms(opt ...Option) (*Kms, error) {
	opts := getOpts(opt...)
	ret := &Kms{
		logger:             opts.withLogger,
		externalScopeCache: make(map[string]*ExternalWrappers, 3),
		repo:               opts.withRepository,
	}
	if ret.repo == nil {
		return nil, errors.New("new kms created without an underlying repo")
	}
	return ret, nil
}

// AddExternalWrappers allows setting the external keys for a scope.
//
// TODO: If we support more than one, e.g. for encrypting against many in case
// of a key loss, there will need to be some refactoring here to have the values
// being stored in the struct be a multiwrapper, but that's for a later project.
func (k *Kms) AddExternalWrappers(scopeId string, opt ...Option) error {
	k.externalScopeCacheMutex.Lock()
	defer k.externalScopeCacheMutex.Unlock()

	ext := k.externalScopeCache[scopeId]
	if ext == nil {
		ext = &ExternalWrappers{}
	}
	ext.m.Lock()
	defer ext.m.Unlock()

	opts := getOpts(opt...)
	if opts.withRootWrapper != nil {
		ext.root = opts.withRootWrapper
		if ext.root.KeyID() == "" {
			return fmt.Errorf("root wrapper passed in for scope %s has no key ID", scopeId)
		}
	}
	if opts.withWorkerAuthWrapper != nil {
		ext.workerAuth = opts.withWorkerAuthWrapper
		if ext.workerAuth.KeyID() == "" {
			return fmt.Errorf("worker auth wrapper passed in for scope %s has no key ID", scopeId)
		}
	}

	k.externalScopeCache[scopeId] = ext
	return nil
}

func (k *Kms) GetExternalWrappers(scopeId string) *ExternalWrappers {
	k.externalScopeCacheMutex.RLock()
	defer k.externalScopeCacheMutex.RUnlock()

	return k.externalScopeCache[scopeId]
}

func generateKeyId(scopeId, purpose string, version uint32) string {
	return fmt.Sprintf("%s_%s_%d", scopeId, purpose, version)
}

func (k *Kms) GetWrapper(ctx context.Context, scopeId, purpose, keyId string) (wrapping.Wrapper, error) {
	switch purpose {
	case "oplog", "database":
	default:
		return nil, fmt.Errorf("unsupported purpose %q", purpose)
	}
	// Fast-path: we have a valid key at the scope/purpose. Verify the key with
	// that ID is in the multiwrapper; if not, fall through to reload from the
	// DB.
	val, ok := k.scopePurposeCache.Load(scopeId + purpose)
	if ok {
		wrapper := val.(*multiwrapper.MultiWrapper)
		if wrapper.WrapperForKeyID(keyId) != nil {
			return wrapper, nil
		}
		// Fall through to refresh our multiwrapper for this scope/purpose from the DB
	}

	// We don't have it cached, so we'll need to read from the database. Get the
	// root for the scope as we'll need it to decrypt the value coming from the
	// DB. We don't cache the roots as we expect that after a few calls the
	// scope-purpose cache will catch everything in steady-state.
	rootWrapper, err := k.loadRoot(ctx, scopeId)
	if err != nil {
		return nil, fmt.Errorf("error loading root key for scope %s: %w", scopeId, err)
	}

	// TODO: Look up dek in the db, then decrypt with the root wrapper. For now
	// since we don't have DEKs, derive a key.
	baseWrapper := rootWrapper.WrapperForKeyID("__base__").(*aead.Wrapper)
	derived, err := baseWrapper.NewDerivedWrapper(&aead.DerivedWrapperOptions{
		KeyID: generateKeyId(scopeId, purpose, 1),
		Hash:  func() hash.Hash { b, _ := blake2b.New256(nil); return b },
		Salt:  []byte(scopeId),
		Info:  []byte(purpose),
	})
	if err != nil {
		return nil, fmt.Errorf("error creating derived wrapper: %w", err)
	}

	// Store the looked-up value into the scope cache.
	k.scopePurposeCache.Store(scopeId+purpose, multiwrapper.NewMultiWrapper(derived))

	return derived, nil
}

func (k *Kms) loadRoot(ctx context.Context, scopeId string) (*multiwrapper.MultiWrapper, error) {
	rootKeys, err := k.repo.ListRootKeys(ctx)
	if err != nil {
		return nil, fmt.Errorf("error listing root keys: %w", err)
	}
	var rootKeyId string
	for _, k := range rootKeys {
		if k.GetScopeId() == scopeId {
			rootKeyId = k.GetPrivateId()
			break
		}
	}
	if rootKeyId == "" {
		return nil, fmt.Errorf("error finding root key for scope %s", scopeId)
	}

	// Now: find the external KMS that can be used to decrypt the root values
	// from the DB.
	k.externalScopeCacheMutex.Lock()
	externalWrappers := k.externalScopeCache[scopeId]
	if externalWrappers == nil {
		// Note that if we ever allow per-project-scope external wrappers this will
		// become quite a bit more complicated to go up the chain of external KMSes, but
		// that's not in the plans currently so for now ignore that possibility.
		externalWrappers = k.externalScopeCache[scope.Global.String()]
		if externalWrappers == nil {
			k.externalScopeCacheMutex.Unlock()
			return nil, errors.New("could not find kms information at either the needed scope or global fallback")
		}
	}
	k.externalScopeCacheMutex.Unlock()

	externalWrappers.m.RLock()
	defer externalWrappers.m.RUnlock()

	if externalWrappers.root == nil {
		return nil, fmt.Errorf("root key wrapper for scope %s is nil", scopeId)
	}
	rootKeyVersions, err := k.repo.ListRootKeyVersions(ctx, externalWrappers.root, rootKeyId, WithOrder("version desc"))
	if err != nil {
		return nil, fmt.Errorf("error looking up root key versions for scope %s: %w", scopeId, err)
	}
	if len(rootKeyVersions) == 0 {
		return nil, fmt.Errorf("no root key versions found for scope %s", scopeId)
	}

	var multi *multiwrapper.MultiWrapper
	for i, key := range rootKeyVersions {
		wrapper := aead.NewWrapper(nil)
		if _, err := wrapper.SetConfig(map[string]string{
			"key_id": key.GetPrivateId(),
		}); err != nil {
			return nil, fmt.Errorf("error setting config on aead root wrapper in scope %s: %w", scopeId, err)
		}
		if err := wrapper.SetAESGCMKeyBytes(key.GetKey()); err != nil {
			return nil, fmt.Errorf("error setting key bytes on aead root wrapper in scope %s: %w", scopeId, err)
		}
		if i == 0 {
			multi = multiwrapper.NewMultiWrapper(wrapper)
		} else {
			multi.AddWrapper(wrapper)
		}
	}

	return multi, err
}
