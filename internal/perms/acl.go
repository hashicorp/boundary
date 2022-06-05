package perms

import (
	"strings"

	"github.com/hashicorp/boundary/internal/types/action"
	"github.com/hashicorp/boundary/internal/types/resource"
)

const AnonymousUserId = "u_anon"

// ACL provides an entry point into the permissions engine for determining if an
// action is allowed on a resource based on a principal's (user or group) grants.
type ACL struct {
	scopeMap map[string][]Grant
}

// ACLResults provides a type for the permission's engine results so that we can
// pass more detailed information along in the future if we want. It was useful
// in Vault, may be useful here.
type ACLResults struct {
	AuthenticationFinished bool
	Authorized             bool
	OutputFields           OutputFieldsMap

	// This is included but unexported for testing/debugging
	scopeMap map[string][]Grant
}

// Resource defines something within boundary that requires authorization
// capabilities.  Resources must have a ScopeId.
type Resource struct {
	// ScopeId is the scope that contains the Resource.
	ScopeId string `json:"scope_id,omitempty"`

	// Id is the public id of the resource.
	Id string `json:"id,omitempty"`

	// Type of resource.
	Type resource.Type `json:"type,omitempty"`

	// Pin if defined would constrain the resource within the collection of the
	// pin id.
	Pin string `json:"pin,omitempty"`
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

	var parentAction action.Type
	split := strings.Split(aType.String(), ":")
	if len(split) == 2 {
		parentAction = action.Map[split[0]]
	}
	// Now, go through and check the cases indicated above
	for _, grant := range grants {
		var outputFieldsOnly bool
		switch {
		case len(grant.actions) == 0:
			// Continue with the next grant, unless we have output fields
			// specified in which case we continue to be able to apply the
			// output fields depending on ID and type.
			if len(grant.OutputFields) > 0 {
				outputFieldsOnly = true
			} else {
				continue
			}
		case grant.actions[aType]:
			// We have this action
		case grant.actions[parentAction]:
			// We don't have this action, but it's a subaction and we have the
			// parent action. As an example, if we are looking for "read:self"
			// and have "read", this is sufficient.
		case grant.actions[action.All]:
			// All actions are allowed
		default:
			// No actions in the grant match what we're looking for, so continue
			// with the next grant
			continue
		}

		// We step through all grants, to fetch the full list of output fields.
		// However, we shortcut if we find *.
		//
		// If the action was not found above but we did find output fields in
		// patterns that match, we do not authorize the request, but we do build
		// up the output fields patterns.
		//
		// Note that when using IsActionOrParent it is merely to test whether it
		// is an allowed format since some formats operate ony on collections
		// (or don't operate at all on collections) and we want to ensure that
		// it is/isn't a create or list command or subcommand to know whether
		// that form is valid. The actual checking of whether the given action
		// is granted to the user already happened above.
		var found bool
		switch {
		// id=<resource.id>;actions=<action> where ID cannot be a wildcard; or
		// id=<resource.id>;output_fields=<fields> where fields cannot be a
		// wildcard.
		case grant.id == r.Id &&
			grant.id != "" &&
			grant.id != "*" &&
			grant.typ == resource.Unknown &&
			!action.List.IsActionOrParent(aType) &&
			!action.Create.IsActionOrParent(aType):

			found = true

		// type=<resource.type>;actions=<action> when action is list or create.
		// Must be a top level collection, otherwise must be one of the two
		// formats specified below. Or,
		// type=resource.type;output_fields=<fields> and no action.
		case grant.id == "" &&
			r.Id == "" &&
			grant.typ == r.Type &&
			grant.typ != resource.Unknown &&
			topLevelType(r.Type) &&
			(action.List.IsActionOrParent(aType) ||
				action.Create.IsActionOrParent(aType)):

			found = true

		// id=*;type=<resource.type>;actions=<action> where type cannot be
		// unknown but can be a wildcard to allow any resource at all; or
		// id=*;type=<resource.type>;output_fields=<fields> with no action.
		case grant.id == "*" &&
			grant.typ != resource.Unknown &&
			(grant.typ == r.Type ||
				grant.typ == resource.All):

			found = true

		// id=<pin>;type=<resource.type>;actions=<action> where type can be a
		// wildcard and this this is operating on a non-top-level type. Same for
		// output fields only.
		case grant.id != "" &&
			grant.id == r.Pin &&
			grant.typ != resource.Unknown &&
			(grant.typ == r.Type || grant.typ == resource.All) &&
			!topLevelType(r.Type):

			found = true
		}

		if found {
			if !outputFieldsOnly {
				results.Authorized = true
			}
			if results.OutputFields = results.OutputFields.AddFields(grant.OutputFields.Fields()); results.OutputFields.HasAll() && results.Authorized {
				return
			}
		}
	}
	return
}

func topLevelType(typ resource.Type) bool {
	switch typ {
	case resource.AuthMethod,
		resource.AuthToken,
		resource.CredentialStore,
		resource.Group,
		resource.HostCatalog,
		resource.Role,
		resource.Scope,
		resource.Session,
		resource.Target,
		resource.User,
		resource.Worker:
		return true
	}
	return false
}
