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
	Root wrapping.Wrapper
}

type versionedKeys struct {
	versionsCache sync.Map
}

type scopeKms struct {
	purposeCache sync.Map
}

type Kms struct {
	logger            hclog.Logger
	scopePurposeCache sync.Map

	externalByScopeCache sync.Map
	externalByKeyIdCache sync.Map
}

func NewKms(opt ...Option) *Kms {
	opts := getOpts(opt...)
	return &Kms{
		logger: opts.withLogger,
	}
}

func (k *Kms) AddExternalWrappers(scopeId string, opt ...Option) error {
	opts := getOpts(opt...)
	if opts.withRootWrapper == nil {
		return fmt.Errorf("nil root wrapper passed in for scope %s", scopeId)
	}
	ext := &externalWrappers{
		Root: opts.withRootWrapper,
	}
	if ext.Root.KeyID() == "" {
		return fmt.Errorf("root wrapper passed in for scope %s has no key ID", scopeId)
	}
	if _, loaded := k.externalByKeyIdCache.LoadOrStore(ext.Root.KeyID(), ext); loaded {
		return fmt.Errorf("key ID for given root wrapper collides with an existing key")
	}
	k.externalByScopeCache.Store(scopeId, ext)
	return nil
}

func keyId(scopeId, purpose string, version uint32) string {
	return fmt.Sprintf("%s_%s_%d", scopeId, purpose, version)
}

func (k *Kms) GetWrapper(scopeId, purpose string) (wrapping.Wrapper, error) {
	// Fast-path: we have a valid key at the scope/purpose
	val, ok := k.scopePurposeCache.Load(scopeId + purpose)
	if ok {
		return val.(wrapping.Wrapper), nil
	}

	// We don't have it cached, so we'll need to read from the database. Get the
	// root for the scope. This may have been the purpose to begin with, but
	// that's okay.
	rootWrapper, err := k.loadRoot(scopeId)
	if err != nil {
		return nil, fmt.Errorf("error loading root key for scope %s: %w", scopeId, err)
	}

	// TODO: Look up dek in the db, then decrypt with the root wrapper. For now
	// since we don't have DEKs, derive a key.
	// TODO: Once we have rotation, switch all of this to multiwrapper
	derived, err := rootWrapper.NewDerivedWrapper(&aead.DerivedWrapperOptions{
		KeyID: keyId(scopeId, purpose, 1),
		Hash:  func() hash.Hash { b, _ := blake2b.New256(nil); return b },
		Salt:  []byte(scopeId),
		Info:  []byte(purpose),
	})
	if origVal, loaded := k.scopePurposeCache.LoadOrStore(scopeId+purpose, derived); loaded {
		// This was created async by some other thread, so return the already-existing value
		return origVal.(wrapping.Wrapper), nil
	}

	return derived, nil
}

func (k *Kms) loadRoot(scopeId string) (*multiwrapper.MultiWrapper, error) {
	val, ok := k.scopePurposeCache.Load(scopeId + "root")
	if ok {
		return val.(*multiwrapper.MultiWrapper), nil
	}
	// TODO: look up all root versions in DB and decrypt with appropriate external wrapper
}
