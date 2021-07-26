// Package subtypes provides helpers to work with boundary resource subtypes.
package subtypes

import (
	"fmt"
	"strings"

	"github.com/hashicorp/boundary/internal/errors"
)

// Subtype variables identify a boundary resource subtype.
type Subtype string

const (
	UnknownSubtype Subtype = "unknown"
)

// String returns the string representation of a Subtype
func (t Subtype) String() string {
	return string(t)
}

// Registry stores a collection of boundary resource subtypes along with their
// prefixes and allows for translating prefixes back to registered subtypes.
// Registry is not thread safe.
type Registry struct {
	subtypesPrefixes map[string]Subtype
	knownSubtypes map[Subtype]interface{}
}

// New Registry creates a new boundary resource subtype registry.
func NewRegistry() *Registry {
	return &Registry{
		subtypesPrefixes: make(map[string]Subtype),
		knownSubtypes:    make(map[Subtype]interface{}),
	}
}

// SubtypeFromType returns the Subtype from the provided string or if
// no Subtype was registered with that string Unknown is returned.
func (r *Registry) SubtypeFromType(t string) Subtype {
	st := Subtype(t)
	if _, ok := r.knownSubtypes[st]; !ok {
		return UnknownSubtype
	}
	return st
}

// SubtypeFromId returns the Subtype from the provided id if the id's prefix
// was registered with a Subtype. Otherwise Unknown is returned.
func (r *Registry) SubtypeFromId(id string) Subtype {
	i := strings.Index(id, "_")
	if i == -1 {
		return UnknownSubtype
	}
	prefix := id[:i]

	subtype, ok := r.subtypesPrefixes[prefix]
	if !ok {
		return UnknownSubtype
	}
	return subtype
}

// Register registers all the prefixes for a provided Subtype. Register returns
// an error if the subtype has already been registered or if any of the
// prefixes are associated with another subtype.
func (r *Registry) Register(subtype Subtype, prefixes ...string) error {
	const op = "subtypes.(Registry).Register"
	if _, present := r.knownSubtypes[subtype]; present {
		return errors.New(errors.SubtypeAlreadyRegistered, op, fmt.Sprintf("subtype %q already registered", subtype))
	}
	r.knownSubtypes[subtype] = nil

	for _, prefix := range prefixes {
		prefix = strings.TrimSpace(prefix)
		if st, ok := r.subtypesPrefixes[prefix]; ok {
			return errors.New(errors.SubtypeAlreadyRegistered, op, fmt.Sprintf("prefix %q is already registered to subtype %q", prefix, st))
		}
		r.subtypesPrefixes[prefix] = subtype
	}
	return nil
}
