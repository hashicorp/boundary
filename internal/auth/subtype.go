package auth

import (
	"github.com/hashicorp/boundary/internal/db/timestamp"
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

