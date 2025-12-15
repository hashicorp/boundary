// Copyright IBM Corp. 2020, 2025
// SPDX-License-Identifier: BUSL-1.1

package auth

import (
	"context"
	"fmt"
	"sync"

	"github.com/hashicorp/boundary/globals"
)

// newAuthMethodFunc is a function that creates an AuthMethod from the provided result.
type newAuthMethodFunc func(context.Context, *AuthMethodListQueryResult) (AuthMethod, error)

// AuthMethodSubtypeHooks defines the interface expected to be implemented
// by auth method subtype hooks.
type AuthMethodSubtypeHooks interface {
	NewAuthMethod(context.Context, *AuthMethodListQueryResult) (AuthMethod, error)
}

type registry struct {
	m map[globals.Subtype]AuthMethodSubtypeHooks

	sync.RWMutex
}

func (r *registry) set(s globals.Subtype, subtype AuthMethodSubtypeHooks) {
	r.Lock()
	defer r.Unlock()

	_, previouslySet := r.m[s]
	if previouslySet {
		panic(fmt.Sprintf("auth method subtype %s already registered", s))
	}

	r.m[s] = subtype
}

func (r *registry) get(s globals.Subtype) (AuthMethodSubtypeHooks, bool) {
	r.RLock()
	defer r.RUnlock()

	subtype, ok := r.m[s]
	if ok {
		return subtype, ok
	}
	return nil, ok
}

func (r *registry) newFunc(s globals.Subtype) (newAuthMethodFunc, bool) {
	subtype, ok := r.get(s)
	if !ok {
		return nil, ok
	}
	return subtype.NewAuthMethod, ok
}

var subtypeRegistry = registry{
	m: make(map[globals.Subtype]AuthMethodSubtypeHooks),
}

// RegisterAuthMethodSubtype registers repository hooks for a provided auth method sub type.
// RegisterAuthMethodSubtype panics if the subtype has already been registered.
func RegisterAuthMethodSubtype(s globals.Subtype, hooks AuthMethodSubtypeHooks) {
	subtypeRegistry.set(s, hooks)
}
