package credential

import (
	"github.com/hashicorp/boundary/internal/types/subtypes"
)

var registry = subtypes.NewRegistry()

// Subtype uses the provided subtype
func SubtypeFromType(t string) subtypes.Subtype {
	return registry.SubtypeFromType(t)
}

func SubtypeFromId(id string) subtypes.Subtype {
	return registry.SubtypeFromId(id)
}

// Register registers all the prefixes for a provided Subtype. Register panics if the
// subtype has already been registered.
func Register(subtype subtypes.Subtype, prefixes ...string) {
	registry.Register(subtype, prefixes...)
}
