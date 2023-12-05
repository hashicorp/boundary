// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: BUSL-1.1

package credential

import (
	"context"
	"fmt"
	"sync"

	"github.com/hashicorp/boundary/globals"
)

// NewFunc is a function that creates a Store from the provided store union.
type NewFunc func(ctx context.Context, storeUnion *StoreUnion) (Store, error)

// StoreSubtype defines the interface expected to be implemented
// by credential store subtypes.
type StoreSubtype interface {
	NewStore(ctx context.Context, storeUnion *StoreUnion) (Store, error)
}

type registry struct {
	m map[globals.Subtype]StoreSubtype

	sync.RWMutex
}

func (r *registry) set(s globals.Subtype, subtype StoreSubtype) {
	r.Lock()
	defer r.Unlock()

	_, previouslySet := r.m[s]
	if previouslySet {
		panic(fmt.Sprintf("target subtype %s already registered", s))
	}

	r.m[s] = subtype
}

func (r *registry) get(s globals.Subtype) (StoreSubtype, bool) {
	r.RLock()
	defer r.RUnlock()

	subtype, ok := r.m[s]
	if ok {
		return subtype, ok
	}
	return nil, ok
}

func (r *registry) newFunc(s globals.Subtype) (NewFunc, bool) {
	subtype, ok := r.get(s)
	if !ok {
		return nil, ok
	}
	return subtype.NewStore, ok
}

var subtypeRegistry = registry{
	m: make(map[globals.Subtype]StoreSubtype),
}

// RegisterStoreSubtype registers repository hooks for a provided store sub type.
// RegisterStoreSubtype panics if the subtype has already been registered.
func RegisterStoreSubtype(s globals.Subtype, subtype StoreSubtype) {
	subtypeRegistry.set(s, subtype)
}
