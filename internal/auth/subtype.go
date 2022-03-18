package auth

import (
	"github.com/hashicorp/boundary/internal/boundary"
)

// AuthMethod contains the common methods across all the different types of auth methods.
type AuthMethod interface {
	boundary.Resource
	GetScopeId() string
	GetIsPrimaryAuthMethod() bool
}

type Account interface {
	boundary.Resource
	GetAuthMethodId() string
}

type ManagedGroup interface {
	boundary.Resource
	GetAuthMethodId() string
}
