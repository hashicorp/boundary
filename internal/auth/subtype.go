package auth

import (
	"github.com/hashicorp/boundary/internal/db/timestamp"
	"github.com/hashicorp/boundary/internal/types/subtypes"
)

var registry = subtypes.NewRegistry()

// SubtypeFromType returns the Subtype from the provided string or if
// no Subtype was registered with that string Unknown is returned.
func SubtypeFromType(t string) subtypes.Subtype {
	return registry.SubtypeFromType(t)
}

// SubtypeFromId returns the Subtype from the provided id if the id's prefix
// was registered with a Subtype. Otherwise Unknown is returned.
func SubtypeFromId(id string) subtypes.Subtype {
	return registry.SubtypeFromId(id)
}

// Register registers all the prefixes for a provided Subtype. Register returns
// an error if the subtype has already been registered or if any of the
// prefixes are associated with another subtype.
func Register(subtype subtypes.Subtype, prefixes ...string) error {
	return registry.Register(subtype, prefixes...)
}

// AuthMethod contains the common methods across all the different types of auth methods.
type AuthMethod interface {
	GetPublicId() string
	GetCreateTime() *timestamp.Timestamp
	GetUpdateTime() *timestamp.Timestamp
	GetName() string
	GetDescription() string
	GetScopeId() string
	GetVersion() uint32
	GetIsPrimaryAuthMethod() bool
}

type Account interface {
	GetPublicId() string
	GetCreateTime() *timestamp.Timestamp
	GetUpdateTime() *timestamp.Timestamp
	GetName() string
	GetDescription() string
	GetAuthMethodId() string
	GetVersion() uint32
}

type ManagedGroup interface {
	GetPublicId() string
	GetCreateTime() *timestamp.Timestamp
	GetUpdateTime() *timestamp.Timestamp
	GetName() string
	GetDescription() string
	GetAuthMethodId() string
	GetVersion() uint32
}
