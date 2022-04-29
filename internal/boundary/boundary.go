// Package boundary contains global interfaces and other definitions that
// define the Boundary domain.
package boundary

import (
	"context"

	"github.com/hashicorp/boundary/internal/db/timestamp"
)

// An Entity is an object distinguished by its identity, rather than its
// attributes. It can contain value objects and other entities.
type Entity interface {
	GetPublicId() string
}

// An Aggregate is an entity that is the root of a transactional
// consistency boundary.
type Aggregate interface {
	Entity
	GetVersion() uint32
	GetCreateTime() *timestamp.Timestamp
	GetUpdateTime() *timestamp.Timestamp
}

// A Resource is an aggregate with a name and description.
type Resource interface {
	Aggregate
	GetName() string
	GetDescription() string
}

// AuthzProtectedEntity is used by some functions (primarily
// AuthzProtectedEntityProvider-conforming implementations) to deliver some
// common information necessary for calculating authz.
type AuthzProtectedEntity interface {
	Entity
	GetScopeId() string
	GetUserId() string
}

type AuthzProtectedEntityProvider interface {
	// Fetches basic resource info for the given scopes. Note that this is a
	// "where clause" style of argument: if the set of scopes is populated these
	// are the scopes to limit to (e.g. to put in a where clause). An empty set
	// of scopes means to look in *all* scopes, not none!
	FetchAuthzProtectedEntityInfo(context.Context, []string) (map[string][]AuthzProtectedEntity, error)
}
