package target

import (
	"context"
	"fmt"
	"sync"

	"github.com/hashicorp/boundary/internal/types/subtypes"
)

// AllocFunc is a function that creates an in-memory Target.
type AllocFunc func() Target

// VetFunc is a function that checks the given Target to ensure it can
// be used by the Repository.
type VetFunc func(context.Context, Target) error

type registryEntry struct {
	alloc  AllocFunc
	vet    VetFunc
	prefix string
}

type registry struct {
	m        map[subtypes.Subtype]*registryEntry
	subtypes *subtypes.Registry

	sync.RWMutex
}

func (r *registry) set(s subtypes.Subtype, entry *registryEntry) {
	r.Lock()
	defer r.Unlock()

	_, previouslySet := r.m[s]
	if previouslySet {
		panic(fmt.Sprintf("target subtype %s already registered", s))
	}

	if err := r.subtypes.Register(s, entry.prefix); err != nil {
		panic(err)
	}

	r.m[s] = entry
}

func (r *registry) get(s subtypes.Subtype) (*registryEntry, bool) {
	r.RLock()
	defer r.RUnlock()

	entry, ok := r.m[s]
	if ok {
		return entry, ok
	}
	return nil, ok
}

func (r *registry) allocFunc(s subtypes.Subtype) (AllocFunc, bool) {
	entry, ok := r.get(s)
	if !ok {
		return nil, ok
	}
	return entry.alloc, ok
}

func (r *registry) vetFunc(s subtypes.Subtype) (VetFunc, bool) {
	entry, ok := r.get(s)
	if !ok {
		return nil, ok
	}
	return entry.vet, ok
}

func (r *registry) idPrefix(s subtypes.Subtype) (string, bool) {
	entry, ok := r.get(s)
	if !ok {
		return "", ok
	}
	return entry.prefix, ok
}

var subtypeRegistry = registry{
	m:        make(map[subtypes.Subtype]*registryEntry),
	subtypes: subtypes.NewRegistry(),
}

// SubtypeFromType returns the Subtype from the provided string or if
// no Subtype was registered with that string Unknown is returned.
func SubtypeFromType(t string) subtypes.Subtype {
	subtypeRegistry.RLock()
	defer subtypeRegistry.RUnlock()
	return subtypeRegistry.subtypes.SubtypeFromType(t)
}

// SubtypeFromId returns the Subtype from the provided id if the id's prefix
// was registered with a Subtype. Otherwise Unknown is returned.
func SubtypeFromId(id string) subtypes.Subtype {
	subtypeRegistry.RLock()
	defer subtypeRegistry.RUnlock()
	return subtypeRegistry.subtypes.SubtypeFromId(id)
}

// Register registers repository hooks and the prefixes for a provided Subtype. Register
// panics if the subtype has already been registered or if any of the
// prefixes are associated with another subtype.
func Register(s subtypes.Subtype, af AllocFunc, vf VetFunc, prefix string) {
	subtypeRegistry.set(s, &registryEntry{
		alloc:  af,
		vet:    vf,
		prefix: prefix,
	})
}
