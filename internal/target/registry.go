// Copyright IBM Corp. 2020, 2025
// SPDX-License-Identifier: BUSL-1.1

package target

import (
	"context"
	"fmt"
	"sync"

	"github.com/hashicorp/boundary/globals"
	"github.com/hashicorp/boundary/internal/errors"
	"github.com/hashicorp/boundary/internal/types/resource"
)

const Domain = "target"

// NewFunc is a function that creates a Target with the provided project and options.
type NewFunc func(ctx context.Context, projectId string, opt ...Option) (Target, error)

// AllocFunc is a function that creates an in-memory Target.
type AllocFunc func() Target

// VetFunc is a function that checks the given Target to ensure it can
// be used by the Repository.
type VetFunc func(context.Context, Target) error

// VetForUpdateFunc is a function that checks the given Target and field mask
// paths are valid and be used to update a target in the Repository.
type VetForUpdateFunc func(context.Context, Target, []string) error

// VetCredentialSourcesFunc is a function that checks the given CredentialLibraries
// and StaticCredentials to ensure that they are valid for a Target subtype.
type VetCredentialSourcesFunc func(context.Context, []*CredentialLibrary, []*StaticCredential) error

// targetHooks defines the interface containing all the hooks needed for
// managing target suptypes.
type targetHooks interface {
	// NewTarget creates a new in memory target.
	NewTarget(ctx context.Context, projectId string, opt ...Option) (Target, error)
	// AllocTarget will allocate an empty target.
	AllocTarget() Target
	// Vet validates that the given Target has the proper fields and values
	// for creation in the database for this type of target.
	Vet(ctx context.Context, t Target) error
	// VetForUpdate validates that the given Target has the proper fields
	// and values for updating the database for this type of target given the
	// field mask paths.
	VetForUpdate(ctx context.Context, t Target, paths []string) error
	// VetCredentialSources checks that the provided credential libriaries and
	// static credentials are properly built for association with a target of this type.
	VetCredentialSources(ctx context.Context, cls []*CredentialLibrary, creds []*StaticCredential) error
}

type registryEntry struct {
	targetHooks targetHooks
	prefix      string
}

type registry struct {
	m map[globals.Subtype]*registryEntry

	sync.RWMutex
}

func (r *registry) set(s globals.Subtype, entry *registryEntry) {
	r.Lock()
	defer r.Unlock()

	_, previouslySet := r.m[s]
	if previouslySet {
		panic(fmt.Sprintf("target subtype %s already registered", s))
	}

	globals.RegisterPrefixToResourceInfo(entry.prefix, resource.Target, Domain, s)

	r.m[s] = entry
}

func (r *registry) get(s globals.Subtype) (*registryEntry, bool) {
	r.RLock()
	defer r.RUnlock()

	entry, ok := r.m[s]
	if ok {
		return entry, ok
	}
	return nil, ok
}

func (r *registry) newFunc(s globals.Subtype) (NewFunc, bool) {
	entry, ok := r.get(s)
	if !ok {
		return nil, ok
	}
	return entry.targetHooks.NewTarget, ok
}

func (r *registry) allocFunc(s globals.Subtype) (AllocFunc, bool) {
	entry, ok := r.get(s)
	if !ok {
		return nil, ok
	}
	return entry.targetHooks.AllocTarget, ok
}

func (r *registry) vetFunc(s globals.Subtype) (VetFunc, bool) {
	entry, ok := r.get(s)
	if !ok {
		return nil, ok
	}
	return entry.targetHooks.Vet, ok
}

func (r *registry) vetForUpdateFunc(s globals.Subtype) (VetForUpdateFunc, bool) {
	entry, ok := r.get(s)
	if !ok {
		return nil, ok
	}
	return entry.targetHooks.VetForUpdate, ok
}

func (r *registry) vetCredentialSourcesFunc(s globals.Subtype) (VetCredentialSourcesFunc, bool) {
	entry, ok := r.get(s)
	if !ok {
		return nil, ok
	}

	return entry.targetHooks.VetCredentialSources, ok
}

func (r *registry) idPrefix(s globals.Subtype) (string, bool) {
	entry, ok := r.get(s)
	if !ok {
		return "", ok
	}
	return entry.prefix, ok
}

var subtypeRegistry = registry{
	m: make(map[globals.Subtype]*registryEntry),
}

// SubtypeFromType returns the Subtype from the provided string or if
// no Subtype was registered with that string Unknown is returned.
func SubtypeFromType(t string) globals.Subtype {
	return globals.Subtype(t)
}

// SubtypeFromId returns the Subtype from the provided id if the id's prefix
// was registered with a Subtype. Otherwise Unknown is returned.
func SubtypeFromId(id string) globals.Subtype {
	return globals.ResourceInfoFromPrefix(id).Subtype
}

// Prefixes returns the list of all known target Prefixes.
func Prefixes() []string {
	return globals.PrefixesFromDomain(Domain)
}

// New creates a Target of the given subtype and projectId.
func New(ctx context.Context, subtype globals.Subtype, projectId string, opt ...Option) (Target, error) {
	const op = "target.New"
	nf, ok := subtypeRegistry.newFunc(subtype)
	if !ok {
		return nil, errors.New(ctx, errors.InvalidParameter, op, "unsupported subtype")
	}
	return nf(ctx, projectId, opt...)
}

// Register registers repository hooks and the prefixes for a provided Subtype. Register
// panics if the subtype has already been registered or if any of the
// prefixes are associated with another subtype.
func Register(s globals.Subtype, th targetHooks, prefix string) {
	subtypeRegistry.set(s, &registryEntry{
		targetHooks: th,
		prefix:      prefix,
	})
}
