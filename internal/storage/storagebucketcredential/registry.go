// Copyright IBM Corp. 2020, 2025
// SPDX-License-Identifier: BUSL-1.1

package storagebucketcredential

import (
	"context"
	"fmt"
	"sync"

	"github.com/hashicorp/boundary/internal/errors"
)

const Domain = "storage-bucket-credential"

// NewFunc is a function that creates a storage bucket credential with the provided storage bucket Id,
// and options.
type NewFunc func(ctx context.Context, storageBucketId string, opt ...Option) (StorageBucketCredential, error)

// AllocFunc is a function that creates an in-memory storage bucket credential.
type AllocFunc func() StorageBucketCredential

// VetFunc is a function that checks the given storage bucket credential to ensure it can
// be used by the Repository.
type VetFunc func(context.Context, StorageBucketCredential) error

// VetForUpdateFunc is a function that checks the given StorageBucketCredential and field mask
// paths are valid and be used to update a storage bucket credential in the Repository.
type VetForUpdateFunc func(context.Context, StorageBucketCredential, []string) error

// sbcHooks defines the interface containing all the hooks needed for
// managing storage bucket credential suptypes.
type sbcHooks interface {
	// NewStorageBucketCredential creates a new in memory storage bucket credential.
	NewStorageBucketCredential(ctx context.Context, storageBucketId string, opt ...Option) (StorageBucketCredential, error)
	// AllocStorageBucketCredential will allocate an empty storage bucket credential.
	AllocStorageBucketCredential() StorageBucketCredential
	// Vet validates that the given StorageBucketCredential has the proper fields and values
	// for creation in the database for this type of storage bucket credential.
	Vet(ctx context.Context, t StorageBucketCredential) error
}

type registryEntry struct {
	sbcHooks sbcHooks
}

type Registry struct {
	m map[Subtype]*registryEntry
	sync.RWMutex
}

func (r *Registry) set(s Subtype, entry *registryEntry) {
	r.Lock()
	defer r.Unlock()

	_, previouslySet := r.m[s]
	if previouslySet {
		panic(fmt.Sprintf("storage bucket credential subtype %s already registered", s))
	}

	r.m[s] = entry
}

func (r *Registry) get(s Subtype) (*registryEntry, bool) {
	r.RLock()
	defer r.RUnlock()

	entry, ok := r.m[s]
	if ok {
		return entry, ok
	}
	return nil, ok
}

func (r *Registry) NewFunc(s Subtype) (NewFunc, bool) {
	entry, ok := r.get(s)
	if !ok {
		return nil, ok
	}
	return entry.sbcHooks.NewStorageBucketCredential, ok
}

func (r *Registry) AllocFunc(s Subtype) (AllocFunc, bool) {
	entry, ok := r.get(s)
	if !ok {
		return nil, ok
	}
	return entry.sbcHooks.AllocStorageBucketCredential, ok
}

func (r *Registry) VetFunc(s Subtype) (VetFunc, bool) {
	entry, ok := r.get(s)
	if !ok {
		return nil, ok
	}
	return entry.sbcHooks.Vet, ok
}

var SubtypeRegistry = Registry{
	m: make(map[Subtype]*registryEntry),
}

// SubtypeFromType returns the Subtype from the provided string or if
// no Subtype was registered with that string Unknown is returned.
func SubtypeFromType(t string) Subtype {
	return Subtype(t)
}

// New creates a StorageBucketCredential of the given subtype and storageBucketId.
func New(ctx context.Context, subtype Subtype, storageBucketId string, opt ...Option) (StorageBucketCredential, error) {
	const op = "storagebucketcredential.New"
	nf, ok := SubtypeRegistry.NewFunc(subtype)
	if !ok {
		return nil, errors.New(ctx, errors.InvalidParameter, op, "unsupported subtype")
	}
	return nf(ctx, storageBucketId, opt...)
}

// Register registers repository hooks for a provided Subtype. Register
// panics if the subtype has already been registered or if any of the
// prefixes are associated with another subtype.
func Register(s Subtype, sh sbcHooks) {
	SubtypeRegistry.set(s, &registryEntry{
		sbcHooks: sh,
	})
}
