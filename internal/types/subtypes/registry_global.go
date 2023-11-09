// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: BUSL-1.1

package subtypes

import (
	"strings"
	"sync"

	"github.com/hashicorp/boundary/globals"
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

// SubtypeFromId returns the Subtype from the provided id if the id's prefix
// was registered with a Subtype. Otherwise Unknown is returned.
func SubtypeFromId(domain, id string) globals.Subtype {
	return globals.ResourceInfoFromPrefix(id).Subtype
}
