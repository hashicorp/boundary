package perms

/*
A really useful page to be aware of when looking at ACLs is
https://hashicorp.atlassian.net/wiki/spaces/ICU/pages/866976600/API+Actions+and+Permissions
speaking of which: TODO: put that chart in public docs.

Anyways, from that page you can see that there are really only a few patterns of
ACLs that are ever allowed; see the Allowed function for a description along
with the code.

This makes it actually quite simple to perform the ACL checking. Much of ACL
construction is thus synthesizing something reasonable from a set of Grants.
*/

import (
	"github.com/hashicorp/boundary/internal/types/action"
	"github.com/hashicorp/boundary/internal/types/resource"
)

// ACL provides an entry point into the permissions engine for determining if an
// action is allowed on a resource based on a principal's (user or group) grants.
type ACL struct {
	scopeMap map[string][]Grant
}

// ACLResults provides a type for the permission's engine results so that we can
// pass more detailed information along in the future if we want. It was useful
// in Vault, may be useful here.
type ACLResults struct {
	Allowed bool

	// This is included but unexported for testing/debugging
	scopeMap map[string][]Grant
}

// Resource defines something within boundary that requires authorization
// capabilities.  Resources must have a ScopeId.
type Resource struct {
	// ScopeId is the scope that contains the Resource.
	ScopeId string

	// Id is the public id of the resource.
	Id string

	// Type of resource.
	Type resource.Type

	// Pin if defined would constrain the resource within the collection of the
	// pin id.
	Pin string
}

// NewACL creates an ACL from the grants provided.
func NewACL(grants ...Grant) ACL {
	ret := ACL{
		scopeMap: make(map[string][]Grant, len(grants)),
	}

	for _, grant := range grants {
		ret.scopeMap[grant.scope.Id] = append(ret.scopeMap[grant.scope.Id], grant)
	}

	return ret
}

// Allowed determines if the grants for an ACL allow an action for a resource.
func (a ACL) Allowed(r Resource, aType action.Type) (results ACLResults) {
	// First, get the grants within the specified scope
	grants := a.scopeMap[r.ScopeId]
	results.scopeMap = a.scopeMap

	// Now, go through and check the cases indicated above
	for _, grant := range grants {
		if !(grant.actions[aType] || grant.actions[action.All]) {
			continue
		}
		switch {
		// id=<resource.id>;actions=<action> where ID cannot be a wildcard
		case grant.id == r.Id &&
			grant.id != "" &&
			grant.id != "*" &&
			grant.typ == resource.Unknown:

			results.Allowed = true
			return

		// type=<resource.type>;actions=<action> when action is list or create.
		// Must be a top level collection, otherwise must be one of the two
		// formats specified below.
		case grant.id == "" &&
			r.Id == "" &&
			grant.typ == r.Type &&
			grant.typ != resource.Unknown &&
			topLevelType(r.Type) &&
			(aType == action.List || aType == action.Create):

			results.Allowed = true
			return

		// id=*;type=<resource.type>;actions=<action> where type cannot be
		// unknown but can be a wildcard to allow any resource at all
		case grant.id == "*" &&
			grant.typ != resource.Unknown &&
			(grant.typ == r.Type ||
				grant.typ == resource.All):

			results.Allowed = true
			return

		// id=<pin>;type=<resource.type>;actions=<action> where type can be a
		// wildcard and this this is operating on a non-top-level type
		case grant.id != "" &&
			grant.id == r.Pin &&
			grant.typ != resource.Unknown &&
			(grant.typ == r.Type || grant.typ == resource.All) &&
			!topLevelType(r.Type):

			results.Allowed = true
			return
		}
	}
	return
}

func topLevelType(typ resource.Type) bool {
	switch typ {
	case resource.AuthMethod,
		resource.AuthToken,
		resource.Group,
		resource.HostCatalog,
		resource.Role,
		resource.Scope,
		resource.Session,
		resource.Target,
		resource.User:
		return true
	}
	return false
}
