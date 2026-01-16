// Copyright IBM Corp. 2020, 2025
// SPDX-License-Identifier: BUSL-1.1

package host

import (
	"context"
	"fmt"
	"sync"

	"github.com/hashicorp/boundary/globals"
)

// newCatalogFunc is a function that creates a Catalog from the provided result.
type newCatalogFunc func(context.Context, *CatalogListQueryResult) (Catalog, error)

// CatalogSubtypeHooks defines the interface expected to be implemented
// by credential store subtype hooks.
type CatalogSubtypeHooks interface {
	NewCatalog(context.Context, *CatalogListQueryResult) (Catalog, error)
}

type registry struct {
	m map[globals.Subtype]CatalogSubtypeHooks

	sync.RWMutex
}

func (r *registry) set(s globals.Subtype, subtype CatalogSubtypeHooks) {
	r.Lock()
	defer r.Unlock()

	_, previouslySet := r.m[s]
	if previouslySet {
		panic(fmt.Sprintf("host catalog subtype %s already registered", s))
	}

	r.m[s] = subtype
}

func (r *registry) get(s globals.Subtype) (CatalogSubtypeHooks, bool) {
	r.RLock()
	defer r.RUnlock()

	subtype, ok := r.m[s]
	if ok {
		return subtype, ok
	}
	return nil, ok
}

func (r *registry) newFunc(s globals.Subtype) (newCatalogFunc, bool) {
	subtype, ok := r.get(s)
	if !ok {
		return nil, ok
	}
	return subtype.NewCatalog, ok
}

var subtypeRegistry = registry{
	m: make(map[globals.Subtype]CatalogSubtypeHooks),
}

// RegisterCatalogSubtype registers repository hooks for a provided catalog sub type.
// RegisterCatalogSubtype panics if the subtype has already been registered.
func RegisterCatalogSubtype(s globals.Subtype, hooks CatalogSubtypeHooks) {
	subtypeRegistry.set(s, hooks)
}
