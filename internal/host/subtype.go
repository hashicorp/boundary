package host

import (
	"strings"

	"github.com/hashicorp/boundary/internal/host/static"
)

type SubType int

const (
	UnknownSubtype SubType = iota
	StaticSubtype
)

func (t SubType) String() string {
	switch t {
	case StaticSubtype:
		return "static"
	}
	return "unknown"
}

// Subtype uses the provided subtype
func SubtypeFromType(t string) SubType {
	switch {
	case strings.EqualFold(strings.TrimSpace(t), StaticSubtype.String()):
		return StaticSubtype
	}
	return UnknownSubtype
}

func SubtypeFromId(id string) SubType {
	switch {
	case strings.HasPrefix(strings.TrimSpace(id), static.HostPrefix),
		strings.HasPrefix(strings.TrimSpace(id), static.HostSetPrefix),
		strings.HasPrefix(strings.TrimSpace(id), static.HostCatalogPrefix):
		return StaticSubtype
	}
	return UnknownSubtype
}
