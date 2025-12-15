// Copyright IBM Corp. 2020, 2025
// SPDX-License-Identifier: BUSL-1.1

// Package subtypes provides helpers to work with boundary resource subtypes.
package subtypes

import (
	"context"
	"fmt"
	"strings"
	"sync"

	"github.com/hashicorp/boundary/globals"
	"github.com/hashicorp/boundary/internal/errors"
)

// Registry stores a collection of boundary resource subtypes along with their
// prefixes and allows for translating prefixes back to registered subtypes.
type Registry struct {
	subtypesPrefixes map[string]globals.Subtype
	knownSubtypes    map[globals.Subtype]any

	sync.RWMutex
}

// NewRegistry creates a new boundary resource subtype registry.
func NewRegistry() *Registry {
	return &Registry{
		subtypesPrefixes: make(map[string]globals.Subtype),
		knownSubtypes:    make(map[globals.Subtype]any),
	}
}

// SubtypeFromType returns the Subtype from the provided string or if
// no Subtype was registered with that string Unknown is returned.
func (r *Registry) SubtypeFromType(t string) globals.Subtype {
	r.RLock()
	defer r.RUnlock()

	st := globals.Subtype(t)
	if _, ok := r.knownSubtypes[st]; !ok {
		return globals.UnknownSubtype
	}
	return st
}

// SubtypeFromId returns the Subtype from the provided id if the id's prefix
// was registered with a Subtype. Otherwise Unknown is returned.
func (r *Registry) SubtypeFromId(id string) globals.Subtype {
	r.RLock()
	defer r.RUnlock()

	i := strings.Index(id, "_")
	if i == -1 {
		return globals.UnknownSubtype
	}
	prefix := id[:i]

	subtype, ok := r.subtypesPrefixes[prefix]
	if !ok {
		return globals.UnknownSubtype
	}
	return subtype
}

// Prefixes returns the list of all known Prefixes.
func (r *Registry) Prefixes() []string {
	r.RLock()
	defer r.RUnlock()

	ret := make([]string, 0, len(r.subtypesPrefixes))
	for p := range r.subtypesPrefixes {
		ret = append(ret, p)
	}
	return ret
}

// Register registers all the prefixes for a provided Subtype. Register returns
// an error if the subtype has already been registered or if any of the
// prefixes are associated with another subtype.
func (r *Registry) Register(ctx context.Context, subtype globals.Subtype, prefixes ...string) error {
	r.Lock()
	defer r.Unlock()

	const op = "subtypes.(Registry).Register"
	if _, present := r.knownSubtypes[subtype]; present {
		return errors.New(ctx, errors.SubtypeAlreadyRegistered, op, fmt.Sprintf("subtype %q already registered", subtype))
	}
	r.knownSubtypes[subtype] = nil

	for _, prefix := range prefixes {
		prefix = strings.TrimSpace(prefix)
		if st, ok := r.subtypesPrefixes[prefix]; ok {
			return errors.New(ctx, errors.SubtypeAlreadyRegistered, op, fmt.Sprintf("prefix %q is already registered to subtype %q", prefix, st))
		}
		r.subtypesPrefixes[prefix] = subtype
	}
	return nil
}
