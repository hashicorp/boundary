package credential

import (
	"strings"
	"sync"
)

type Subtype int

const (
	UnknownSubtype Subtype = iota
	VaultSubtype
)

func (t Subtype) String() string {
	switch t {
	case VaultSubtype:
		return "vault"
	}
	return "unknown"
}

// Subtype uses the provided subtype
func SubtypeFromType(t string) Subtype {
	switch {
	case strings.EqualFold(strings.TrimSpace(t), VaultSubtype.String()):
		return VaultSubtype
	}
	return UnknownSubtype
}

func SubtypeFromId(id string) Subtype {
	prefix := id[:strings.Index(id, "_")]

	subtypeMu.RLock()
	subtype, ok := subtypes[prefix]
	subtypeMu.RUnlock()
	if !ok {
		return UnknownSubtype
	}
	return subtype
}

var (
	subtypeMu sync.RWMutex
	subtypes  = make(map[string]Subtype)
)

// Register registers the prefixes for a Subtype. Register panics if the
// subtype is unknown.
func Register(subtype Subtype, prefixes ...string) {
	subtypeMu.Lock()
	defer subtypeMu.Unlock()

	switch subtype {
	case VaultSubtype:
	default:
		panic("credential.Register: subtype is unknown ")
	}

	for _, prefix := range prefixes {
		prefix = strings.TrimSpace(prefix)
		subtypes[prefix] = subtype
	}
}
