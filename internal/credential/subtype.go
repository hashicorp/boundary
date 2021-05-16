package credential

import (
	"strings"
	"sync"
)

type SubType int

const (
	UnknownSubtype SubType = iota
	VaultSubtype
)

func (t SubType) String() string {
	switch t {
	case VaultSubtype:
		return "vault"
	}
	return "unknown"
}

// Subtype uses the provided subtype
func SubtypeFromType(t string) SubType {
	switch {
	case strings.EqualFold(strings.TrimSpace(t), VaultSubtype.String()):
		return VaultSubtype
	}
	return UnknownSubtype
}

func SubtypeFromId(id string) SubType {
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
	subtypes  = make(map[string]SubType)
)

// Register registers the prefixes for a Subtype. Register panics if the
// subtype is unknown.
func Register(subtype SubType, prefixes ...string) {
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
