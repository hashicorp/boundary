// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: BUSL-1.1


package perms

import (
	"strings"

	"github.com/hashicorp/boundary/globals"
	"github.com/hashicorp/boundary/internal/types/action"
	"github.com/hashicorp/boundary/internal/types/resource"
	"github.com/hashicorp/boundary/sdk/pbs/controller/api/resources/scopes"
)

// AclGrant is used to decouple API-based grants from those we utilize for ACLs.
// Notably it uses a single ID per grant instead of multiple IDs.
type AclGrant struct {
	// The scope ID, which will be a project ID or an org ID
	scope Scope

	// The ID to use
	id string

	// The type, if provided
	typ resource.Type

	// The set of actions being granted
	actions actionSet

	// The set of output fields granted
	OutputFields *OutputFields
}

// Actions returns the actions as a slice from the internal map, along with the
// string representations of those actions.
func (a AclGrant) Actions() ([]action.Type, []string) {
	return a.actions.Actions()
}

// ACL provides an entry point into the permissions engine for determining if an
// action is allowed on a resource based on a principal's (user or group) grants.
type ACL struct {
	scopeMap map[string][]AclGrant
}

// ACLResults provides a type for the permission's engine results so that we can
// pass more detailed information along in the future if we want. It was useful
// in Vault, may be useful here.
type ACLResults struct {
	AuthenticationFinished bool
	Authorized             bool
	OutputFields           *OutputFields

	// This is included but unexported for testing/debugging
	scopeMap map[string][]AclGrant
}

// Permission provides information about the specific
// resources that a user has been granted access to for a given scope, resource, and action.
type Permission struct {
	ScopeId  string // The scope id for which the permission applies.
	Resource resource.Type
	Action   action.Type

	ResourceIds []string // Any specific resource ids that have been referred in the grant's `id` field, if applicable.
	OnlySelf    bool     // The grant only allows actions against the user's own resources.
	All         bool     // We got a wildcard in the grant string's `id` field.
}

// UserPermissions is a set of Permissions for a User.
type UserPermissions struct {
	UserId      string
	Permissions []Permission
}

// Resource defines something within boundary that requires authorization
// capabilities. Resources must have a ScopeId.
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

// NewACL creates an ACL from the grants provided. Note that this converts the
// API-based Grants to AclGrants.
func NewACL(grants ...Grant) ACL {
	ret := ACL{
		scopeMap: make(map[string][]AclGrant, len(grants)),
	}

	for _, grant := range grants {
		switch {
		case len(grant.ids) > 0:
			for _, id := range grant.ids {
				ret.scopeMap[grant.scope.Id] = append(ret.scopeMap[grant.scope.Id], aclGrantFromGrant(grant, id))
			}
		default:
			// This handles the no-ID case as well as the deprecated single-ID case
			ret.scopeMap[grant.scope.Id] = append(ret.scopeMap[grant.scope.Id], aclGrantFromGrant(grant, grant.id))
		}
	}

	return ret
}

func aclGrantFromGrant(grant Grant, id string) AclGrant {
	return AclGrant{
		scope:        grant.scope,
		id:           id,
		typ:          grant.typ,
		actions:      grant.actions,
		OutputFields: grant.OutputFields,
	}
}

// Allowed determines if the grants for an ACL allow an action for a resource.
func (a ACL) Allowed(r Resource, aType action.Type, userId string, opt ...Option) (results ACLResults) {
	opts := getOpts(opt...)

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
			if _, hasSetFields := grant.OutputFields.Fields(); hasSetFields {
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
		// Case 1: We only allow specific actions on specific types for the
		// anonymous user. ID being supplied or not doesn't matter in this case,
		// it must be an explicit type and action(s); adding this as an explicit
		// case here prevents duplicating logic in two of the other more
		// general-purpose cases below (3 and 4). See notes there about ID being
		// present or not.
		case !opts.withSkipAnonymousUserRestrictions &&
			(userId == globals.AnonymousUserId || userId == ""):
			switch {
			// Allow discovery of scopes, so that auth methods within can be
			// discovered
			case grant.typ == r.Type &&
				grant.typ == resource.Scope &&
				(aType == action.List || aType == action.NoOp):
				found = true

			// Allow discovery of and authenticating to auth methods
			case grant.typ == r.Type &&
				grant.typ == resource.AuthMethod &&
				(aType == action.List || aType == action.NoOp || aType == action.Authenticate):
				found = true
			}

		// Case 2:
		// id=<resource.id>;actions=<action> where ID cannot be a wildcard; or
		// id=<resource.id>;output_fields=<fields> where fields cannot be a
		// wildcard.
		case grant.id == r.Id &&
			grant.id != "" &&
			grant.id != "*" &&
			(grant.typ == resource.Unknown || grant.typ == globals.ResourceTypeFromPrefix(grant.id)) &&
			!action.List.IsActionOrParent(aType) &&
			!action.Create.IsActionOrParent(aType):

			found = true

		// Case 3: type=<resource.type>;actions=<action> when action is list or
		// create (cannot be a wildcard). Must be a top level collection,
		// otherwise must be one of the two formats specified in cases 4 or 5.
		// Or, type=resource.type;output_fields=<fields> and no action. This is
		// more of a semantic difference compared to 4 more than a security
		// difference; this type is for clarity as it ties more closely to the
		// concept of create and list as actions on a collection, operating on a
		// collection directly. The format in case 4 will still work for
		// create/list on collections but that's more of a shortcut to allow
		// things like id=*;type=*;actions=* for admin flows so that you don't
		// need to separate out explicit collection actions into separate typed
		// grants for each collection within a role. This does mean there are
		// "two ways of doing things" but it's a reasonable UX tradeoff given
		// that "all IDs" can reasonably be construed to include "and the one
		// I'm making" and "all of them for listing".
		case grant.id == "" &&
			r.Id == "" &&
			grant.typ == r.Type &&
			grant.typ != resource.Unknown &&
			resource.TopLevelType(r.Type) &&
			(action.List.IsActionOrParent(aType) ||
				action.Create.IsActionOrParent(aType)):

			found = true

		// Case 4:
		// id=*;type=<resource.type>;actions=<action> where type cannot be
		// unknown but can be a wildcard to allow any resource at all; or
		// id=*;type=<resource.type>;output_fields=<fields> with no action.
		case grant.id == "*" &&
			grant.typ != resource.Unknown &&
			(grant.typ == r.Type ||
				grant.typ == resource.All):

			found = true

		// Case 5:
		// id=<pin>;type=<resource.type>;actions=<action> where type can be a
		// wildcard and this this is operating on a non-top-level type. Same for
		// output fields only.
		case grant.id != "" &&
			grant.id == r.Pin &&
			grant.typ != resource.Unknown &&
			(grant.typ == r.Type || grant.typ == resource.All) &&
			!resource.TopLevelType(r.Type):

			found = true
		}

		if found {
			if !outputFieldsOnly {
				results.Authorized = true
			}
			fields, _ := grant.OutputFields.Fields()
			results.OutputFields = results.OutputFields.AddFields(fields)
			if results.OutputFields.Has("*") && results.Authorized {
				return
			}
		}
	}
	return
}

// ListPermissions builds a set of Permissions based on the grants in the ACL.
// Permissions are determined for the given resource for each of the provided scopes.
// There must be a grant for a given resource for one of the provided "id actions"
// or for action.All in order for a Permission to be created for the scope.
// The set of "id actions" is resource dependant, but will generally include all
// actions that can be taken on an individual resource.
func (a ACL) ListPermissions(requestedScopes map[string]*scopes.ScopeInfo,
	requestedType resource.Type,
	idActions action.ActionSet,
	userId string,
) []Permission {
	perms := make([]Permission, 0, len(requestedScopes))
	for scopeId := range requestedScopes {
		p := Permission{
			ScopeId:  scopeId,
			Resource: requestedType,
			Action:   action.List,
			OnlySelf: true, // default to only self to be restrictive
		}
		if userId == globals.RecoveryUserId {
			p.All = true
			p.OnlySelf = false
			perms = append(perms, p)
			continue
		}

		// Get grants for a specific scope id from the source of truth.
		grants := a.scopeMap[scopeId]
		for _, grant := range grants {
			// This grant doesn't match what we're looking for, ignore.
			if grant.typ != requestedType && grant.typ != resource.All && globals.ResourceTypeFromPrefix(grant.id) != requestedType {
				continue
			}

			// We found a grant that matches the requested resource type:
			// Search to see if one or all actions in the action set have been granted.
			found := false
			if ok := grant.actions[action.All]; ok {
				found = true
			} else {
				for _, a := range idActions {
					if ok := grant.actions[a]; ok {
						found = true
						break
					}
				}
			}
			if !found { // In this case, none of the requested actions were granted for the given scope id.
				continue
			}

			actions, _ := grant.Actions()
			excludeList := make(action.ActionSet, 0, len(actions))
			for _, aa := range actions {
				if aa != action.List {
					excludeList = append(excludeList, aa)
				}
			}
			p.OnlySelf = p.OnlySelf && excludeList.OnlySelf()

			switch grant.id {
			case "*":
				p.All = true
			case "":
				continue
			default:
				p.ResourceIds = append(p.ResourceIds, grant.id)
			}
		}

		if p.All || len(p.ResourceIds) > 0 {
			perms = append(perms, p)
		}
	}

	return perms
}
