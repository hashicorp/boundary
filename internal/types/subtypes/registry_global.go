// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: BUSL-1.1

package subtypes

import (
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
