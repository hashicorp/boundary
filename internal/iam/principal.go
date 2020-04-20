package iam

import (
	"context"

	"github.com/hashicorp/watchtower/internal/db"
)

// MemberType defines the possible types for members
type PrincipalType uint32

const (
	UnknownPrincipal   PrincipalType = 0
	UserPrincipal      PrincipalType = 1
	UserAliasPrincipal PrincipalType = 2
	GroupPrincipal     PrincipalType = 3
)

type Principal interface {
	// Principals are resources...
	Resource

	// Roles assigned to this principal (User, UserAlias, Group)
	// Friendly names are the keys to the map of Roles returned
	// Options specify any filters to apply.
	// For example: WithAll(bool) returns all principal's roles
	// including those inherited from Groups, and Users when
	// the principal is an Alias
	Roles(context.Context, db.Reader, ...Option) (map[string]Role, error)

	// Allowed returns if the principal (user, alias, group)
	// is allowed to do an action using a resource
	Allowed(context.Context, Action, Resource, db.Reader, ...Option) (bool, error)
}
