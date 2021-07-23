package subtypes

import (
	"fmt"
	"strings"
	"sync"
)

type Subtype string

const (
	UnknownSubtype Subtype = "unknown"
)

func (t Subtype) String() string {
	return string(t)
}

// Registry stores a collection of subtypes along with their prefixes and
// allows for translating prefixes back to registered subtypes.
type Registry struct {
	subtypeMu        sync.RWMutex
	subtypesPrefixes map[string]Subtype
	knownSubtypes map[Subtype]interface{}
}

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

	r.subtypeMu.RLock()
	subtype, ok := r.subtypesPrefixes[prefix]
	r.subtypeMu.RUnlock()
	if !ok {
		return UnknownSubtype
	}
	return subtype
}

// Register registers all the prefixes for a provided Subtype. Register panics if the
// subtype has already been registered or if any of the prefixes are associated with
// another subtype.
func (r *Registry) Register(subtype Subtype, prefixes ...string) {
	r.subtypeMu.Lock()
	defer r.subtypeMu.Unlock()

	if _, present := r.knownSubtypes[subtype]; present {
		panic("subtype.(Registry).Register: subtype is already registered")
	}
	r.knownSubtypes[subtype] = nil

	for _, prefix := range prefixes {
		prefix = strings.TrimSpace(prefix)
		if st, ok := r.subtypesPrefixes[prefix]; ok {
			panic(fmt.Sprintf("subtype.(Registry).Register: prefix is already registered to subtype %q", st))
		}
		r.subtypesPrefixes[prefix] = subtype
	}
}
