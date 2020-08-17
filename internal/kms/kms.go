package kms

import (
	"fmt"
	"hash"
	"sync"

	"github.com/hashicorp/go-hclog"
	wrapping "github.com/hashicorp/go-kms-wrapping"
	"github.com/hashicorp/go-kms-wrapping/wrappers/aead"
	"github.com/hashicorp/go-kms-wrapping/wrappers/multiwrapper"
	"golang.org/x/crypto/blake2b"
)

type externalWrappers struct {
	Root       wrapping.Wrapper
	WorkerAuth wrapping.Wrapper
}

type Kms struct {
	logger hclog.Logger

	// scopePurposeCache holds a per-scope-purpose multiwrapper containing the
	// current encrypting key and all previous key versions, for decryption
	scopePurposeCache sync.Map

	externalScopeCache sync.Map
}

func NewKms(opt ...Option) *Kms {
	opts := getOpts(opt...)
	return &Kms{
		logger: opts.withLogger,
	}
}

// AddExternalWrappers allows setting the external keys for a scope.
//
// TODO: If we support more than one, e.g. for encrypting against many in case
// of a key loss, there will need to be some refactoring here to have the values
// being stored in the struct be a multiwrapper, but that's for a later project.
func (k *Kms) AddExternalWrappers(scopeId string, opt ...Option) error {
	opts := getOpts(opt...)
	if opts.withRootWrapper == nil {
		return fmt.Errorf("nil root wrapper passed in for scope %s", scopeId)
	}
	if opts.withWorkerAuthWrapper == nil {
		return fmt.Errorf("nil worker auth wrapper passed in for scope %s", scopeId)
	}
	ext := &externalWrappers{
		Root:       opts.withRootWrapper,
		WorkerAuth: opts.withWorkerAuthWrapper,
	}
	if ext.Root.KeyID() == "" {
		return fmt.Errorf("root wrapper passed in for scope %s has no key ID", scopeId)
	}
	if ext.WorkerAuth.KeyID() == "" {
		return fmt.Errorf("worker auth wrapper passed in for scope %s has no key ID", scopeId)
	}
	k.externalScopeCache.Store(scopeId, ext)
	return nil
}

func generateKeyId(scopeId, purpose string, version uint32) string {
	return fmt.Sprintf("%s_%s_%d", scopeId, purpose, version)
}

func (k *Kms) GetWrapper(scopeId, purpose, keyId string) (wrapping.Wrapper, error) {
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
	rootWrapper, err := k.loadRoot(scopeId)
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

func (k *Kms) loadRoot(scopeId string) (*multiwrapper.MultiWrapper, error) {
	// TODO: look up all root versions in DB and decrypt with appropriate external wrapper

	return nil, nil
}
