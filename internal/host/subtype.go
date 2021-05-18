package host

import (
	"strings"

	"github.com/hashicorp/boundary/internal/host/static"
)

type Subtype int

const (
	UnknownSubtype Subtype = iota
	StaticSubtype
)

func (t Subtype) String() string {
	switch t {
	case StaticSubtype:
		return "static"
	}
	return "unknown"
}

// Subtype uses the provided subtype
func SubtypeFromType(t string) Subtype {
	switch {
	case strings.EqualFold(strings.TrimSpace(t), StaticSubtype.String()):
		return StaticSubtype
	}
	return UnknownSubtype
}

func SubtypeFromId(id string) Subtype {
	switch {
	case strings.HasPrefix(strings.TrimSpace(id), static.HostPrefix),
		strings.HasPrefix(strings.TrimSpace(id), static.HostSetPrefix),
		strings.HasPrefix(strings.TrimSpace(id), static.HostCatalogPrefix):
		return StaticSubtype
	}
	return UnknownSubtype
}
