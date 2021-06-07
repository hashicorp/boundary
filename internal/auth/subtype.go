package auth

import (
	"strings"

	"github.com/hashicorp/boundary/internal/auth/oidc"
	"github.com/hashicorp/boundary/internal/auth/password"
	"github.com/hashicorp/boundary/internal/db/timestamp"
	"github.com/hashicorp/boundary/internal/intglobals"
)

type Subtype int

const (
	UnknownSubtype Subtype = iota
	PasswordSubtype
	OidcSubtype
)

func (t Subtype) String() string {
	switch t {
	case PasswordSubtype:
		return "password"
	case OidcSubtype:
		return "oidc"
	}
	return "unknown"
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

var (
	_ AuthMethod = (*oidc.AuthMethod)(nil)
	_ AuthMethod = (*password.AuthMethod)(nil)
)

type Account interface {
	GetPublicId() string
	GetCreateTime() *timestamp.Timestamp
	GetUpdateTime() *timestamp.Timestamp
	GetName() string
	GetDescription() string
	GetAuthMethodId() string
	GetVersion() uint32
}

var (
	_ Account = (*oidc.Account)(nil)
	_ Account = (*password.Account)(nil)
)

type ManagedGroup interface {
	GetPublicId() string
	GetCreateTime() *timestamp.Timestamp
	GetUpdateTime() *timestamp.Timestamp
	GetName() string
	GetDescription() string
	GetAuthMethodId() string
	GetVersion() uint32
}

var _ ManagedGroup = (*oidc.ManagedGroup)(nil)

// SubtypeFromType converts a string to a Subtype.
// returns UnknownSubtype if no Subtype with that name is found.
func SubtypeFromType(t string) Subtype {
	switch {
	case strings.EqualFold(strings.TrimSpace(t), PasswordSubtype.String()):
		return PasswordSubtype
	case strings.EqualFold(strings.TrimSpace(t), OidcSubtype.String()):
		return OidcSubtype
	}
	return UnknownSubtype
}

// SubtypeFromId takes any public id in the auth subsystem and uses the prefix to determine
// what subtype the id is for.
// Returns UnknownSubtype if no Subtype with this id's prefix is found.
func SubtypeFromId(id string) Subtype {
	switch {
	case strings.HasPrefix(strings.TrimSpace(id), password.AuthMethodPrefix),
		strings.HasPrefix(strings.TrimSpace(id), password.OldAccountPrefix),
		strings.HasPrefix(strings.TrimSpace(id), password.NewAccountPrefix):
		return PasswordSubtype
	case strings.HasPrefix(strings.TrimSpace(id), oidc.AuthMethodPrefix),
		strings.HasPrefix(strings.TrimSpace(id), oidc.AccountPrefix),
		strings.HasPrefix(strings.TrimSpace(id), intglobals.OidcManagedGroupPrefix):
		return OidcSubtype
	}
	return UnknownSubtype
}
