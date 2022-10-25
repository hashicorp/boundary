package auth

import (
	"github.com/hashicorp/boundary/internal/boundary"
)

// Domain defines the domain for the auth package.
const Domain = "auth"

// AuthMethod contains the common methods across all the different types of auth methods.
type AuthMethod interface {
	boundary.Resource
	GetScopeId() string
	GetIsPrimaryAuthMethod() bool
}

type Account interface {
	boundary.Resource
	GetAuthMethodId() string
	GetLoginName() string
	GetEmail() string
	GetSubject() string
}

type ManagedGroup interface {
	boundary.Resource
	GetAuthMethodId() string
}
