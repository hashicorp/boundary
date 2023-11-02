// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: BUSL-1.1

package subtypes

import (
	"context"
	"fmt"
	"strings"
	"sync"

	"github.com/hashicorp/boundary/globals"
	"github.com/hashicorp/boundary/internal/errors"
)

var globalRegistry = newRegistry()

// newGlobalRegistry creates a new boundary resource subtype registry.
func newRegistry() *registry {
	return &registry{
		subtypesPrefixes: make(map[string]map[string]globals.Subtype),
		knownSubtypes:    make(map[string]map[globals.Subtype]any),
	}
}

// registry stores a collection of boundary resource subtypes along with their
// prefixes and allows for translating prefixes back to registered subtypes.
type registry struct {
	subtypesPrefixes map[string]map[string]globals.Subtype
	knownSubtypes    map[string]map[globals.Subtype]any

	sync.RWMutex
}

// SubtypeFromType returns the Subtype from the provided string or if
// no Subtype was registered with that string Unknown is returned.
func (r *registry) subtypeFromType(domain, t string) globals.Subtype {
	r.RLock()
	defer r.RUnlock()

	knownSubtypes, ok := r.knownSubtypes[domain]
	if !ok {
		return globals.UnknownSubtype
	}

	st := globals.Subtype(t)
	if _, ok := knownSubtypes[st]; !ok {
		return globals.UnknownSubtype
	}
	return st
}

// SubtypeFromId returns the Subtype from the provided id if the id's prefix
// was registered with a Subtype. Otherwise Unknown is returned.
func (r *registry) subtypeFromId(domain, id string) globals.Subtype {
	r.RLock()
	defer r.RUnlock()

	i := strings.Index(id, "_")
	if i == -1 {
		return globals.UnknownSubtype
	}
	prefix := id[:i]

	subtypePrefixes, ok := r.subtypesPrefixes[domain]
	if !ok {
		return globals.UnknownSubtype
	}

	subtype, ok := subtypePrefixes[prefix]
	if !ok {
		return globals.UnknownSubtype
	}
	return subtype
}

func (r *registry) prefixes(domain string) []string {
	r.RLock()
	defer r.RUnlock()

	subtypePrefixes, ok := r.subtypesPrefixes[domain]
	if !ok {
		return nil
	}

	ret := make([]string, 0, len(subtypePrefixes))
	for p := range subtypePrefixes {
		ret = append(ret, p)
	}
	return ret
}

// Register registers all the prefixes for a provided Subtype. Register returns
// an error if the subtype has already been registered or if any of the
// prefixes are associated with another subtype.
func (r *registry) register(ctx context.Context, domain string, subtype globals.Subtype, prefixes ...string) error {
	r.Lock()
	defer r.Unlock()

	const op = "subtypes.(registry).register"

	knownSubtypes, present := r.knownSubtypes[domain]
	if !present {
		knownSubtypes = make(map[globals.Subtype]any)
		r.knownSubtypes[domain] = knownSubtypes
		r.subtypesPrefixes[domain] = make(map[string]globals.Subtype)
	}

	if _, present := knownSubtypes[subtype]; present {
		return errors.New(
			ctx,
			errors.SubtypeAlreadyRegistered,
			op,
			fmt.Sprintf("subtype %q already registered in domain %s", subtype, domain),
		)
	}
	knownSubtypes[subtype] = nil

	for _, prefix := range prefixes {
		prefix = strings.TrimSpace(prefix)
		if st, ok := r.subtypesPrefixes[domain][prefix]; ok {
			return errors.New(
				ctx,
				errors.SubtypeAlreadyRegistered,
				op,
				fmt.Sprintf("prefix %q is already registered to subtype %q in domain %s", prefix, st, domain),
			)
		}
		r.subtypesPrefixes[domain][prefix] = subtype
	}
	return nil
}

// SubtypeFromType returns the Subtype from the provided string or if
// no Subtype was registered with that string Unknown is returned.
func SubtypeFromType(domain, t string) globals.Subtype {
	return globalRegistry.subtypeFromType(domain, t)
}

// SubtypeFromId returns the Subtype from the provided id if the id's prefix
// was registered with a Subtype. Otherwise Unknown is returned.
func SubtypeFromId(domain, id string) globals.Subtype {
	return globalRegistry.subtypeFromId(domain, id)
}

// Prefixes returns the list of all known Prefixes for a domain.
func Prefixes(domain string) []string {
	return globalRegistry.prefixes(domain)
}

// Register registers all the prefixes for a provided Subtype.  Register returns
// an error if the subtype has already been registered or if any of the
// prefixes are associated with another subtype.
func Register(domain string, subtype globals.Subtype, prefixes ...string) error {
	ctx := context.TODO()
	return globalRegistry.register(ctx, domain, subtype, prefixes...)
}
