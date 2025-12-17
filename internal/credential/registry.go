// Copyright IBM Corp. 2020, 2025
// SPDX-License-Identifier: BUSL-1.1

package credential

import (
	"context"
	"fmt"
	"sync"

	"github.com/hashicorp/boundary/globals"
)

// newStoreFunc is a function that creates a Store from the provided result.
type newStoreFunc func(context.Context, *StoreListQueryResult) (Store, error)

// StoreSubtypeHooks defines the interface expected to be implemented
// by credential store subtype hooks.
type StoreSubtypeHooks interface {
	NewStore(context.Context, *StoreListQueryResult) (Store, error)
}

type registry struct {
	m map[globals.Subtype]StoreSubtypeHooks

	sync.RWMutex
}

func (r *registry) set(s globals.Subtype, subtype StoreSubtypeHooks) {
	r.Lock()
	defer r.Unlock()

	_, previouslySet := r.m[s]
	if previouslySet {
		panic(fmt.Sprintf("credential store subtype %s already registered", s))
	}

	r.m[s] = subtype
}

func (r *registry) get(s globals.Subtype) (StoreSubtypeHooks, bool) {
	r.RLock()
	defer r.RUnlock()

	subtype, ok := r.m[s]
	if ok {
		return subtype, ok
	}
	return nil, ok
}

func (r *registry) newFunc(s globals.Subtype) (newStoreFunc, bool) {
	subtype, ok := r.get(s)
	if !ok {
		return nil, ok
	}
	return subtype.NewStore, ok
}

var subtypeRegistry = registry{
	m: make(map[globals.Subtype]StoreSubtypeHooks),
}

// RegisterStoreSubtype registers repository hooks for a provided store sub type.
// RegisterStoreSubtype panics if the subtype has already been registered.
func RegisterStoreSubtype(s globals.Subtype, hooks StoreSubtypeHooks) {
	subtypeRegistry.set(s, hooks)
}
