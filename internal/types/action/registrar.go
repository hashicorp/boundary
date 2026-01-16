// Copyright IBM Corp. 2020, 2025
// SPDX-License-Identifier: BUSL-1.1

package action

import (
	"fmt"
	"sync"

	"github.com/hashicorp/boundary/internal/types/resource"
)

type resourceActionSets struct {
	individual ActionSet
	collection ActionSet
	valid      ActionSet
}

type byResource struct {
	mu sync.RWMutex
	m  map[resource.Type]*resourceActionSets
}

func (b *byResource) add(r resource.Type, individual ActionSet, collection ActionSet) error {
	b.mu.Lock()
	defer b.mu.Unlock()

	if b.m == nil {
		b.m = make(map[resource.Type]*resourceActionSets)
	}

	_, ok := b.m[r]
	if ok {
		return fmt.Errorf("%s already registered", r)
	}
	b.m[r] = &resourceActionSets{
		individual: individual,
		collection: collection,
		valid:      Union(individual, collection),
	}

	return nil
}

func (b *byResource) get(r resource.Type) (*resourceActionSets, error) {
	b.mu.RLock()
	defer b.mu.RUnlock()
	a, ok := b.m[r]
	if !ok {
		return nil, fmt.Errorf("resource not found: %s", r)
	}
	return a, nil
}

var byResourceRegistrar = &byResource{}

// RegisterResource registers ActionSets for r. If RegisterResource is called
// twice with the same resource, it panics.
func RegisterResource(r resource.Type, individual ActionSet, collection ActionSet) {
	if err := byResourceRegistrar.add(r, individual, collection); err != nil {
		panic(err)
	}
}

// ActionSetForResource returns the ActionSet registered for r
// or an error if r has not been registered.
func ActionSetForResource(r resource.Type) (ActionSet, error) {
	a, err := byResourceRegistrar.get(r)
	if err != nil {
		return nil, err
	}
	return a.valid, nil
}

// CollectionActionSetForResource returns the collection ActionSet registered
// for r or an error if r has not been registered.
func CollectionActionSetForResource(r resource.Type) (ActionSet, error) {
	a, err := byResourceRegistrar.get(r)
	if err != nil {
		return nil, err
	}
	return a.collection, nil
}

// IdActionSetForResource returns the individual ActionSet registered
// for r or an error if r has not been registered.
func IdActionSetForResource(r resource.Type) (ActionSet, error) {
	a, err := byResourceRegistrar.get(r)
	if err != nil {
		return nil, err
	}
	return a.individual, nil
}
