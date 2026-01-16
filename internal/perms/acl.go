// Copyright IBM Corp. 2020, 2025
// SPDX-License-Identifier: BUSL-1.1

package perms

import (
	"strings"

	"github.com/hashicorp/boundary/globals"
	"github.com/hashicorp/boundary/internal/types/action"
	"github.com/hashicorp/boundary/internal/types/resource"
	"github.com/hashicorp/boundary/internal/types/scope"
	"github.com/hashicorp/boundary/sdk/pbs/controller/api/resources/scopes"
)

// AclGrant is used to decouple API-based grants from those we utilize for ACLs.
// Notably it uses a single ID per grant instead of multiple IDs.
type AclGrant struct {
	// The scope ID of the role that sourced this grant
	RoleScopeId string

	// The parent scope ID of the role that sourced this grant
	RoleParentScopeId string

	// The grant's applied scope ID
	GrantScopeId string

	// The ID to use
	Id string

	// The type, if provided
	Type resource.Type

	// The set of actions being granted
	ActionSet ActionSet

	// The set of output fields granted
	OutputFields *OutputFields
}

// Actions returns the actions as a slice from the internal map, along with the
// string representations of those actions.
func (ag AclGrant) Actions() ([]action.Type, []string) {
	return ag.ActionSet.Actions()
}

func (ag AclGrant) Clone() AclGrant {
	ret := AclGrant{
		RoleScopeId:       ag.RoleScopeId,
		RoleParentScopeId: ag.RoleParentScopeId,
		GrantScopeId:      ag.GrantScopeId,
		Id:                ag.Id,
		Type:              ag.Type,
	}
	if ag.ActionSet != nil {
		ret.ActionSet = make(map[action.Type]bool, len(ag.ActionSet))
		for k, v := range ag.ActionSet {
			ret.ActionSet[k] = v
		}
	}
	if ag.OutputFields != nil {
		ret.OutputFields = new(OutputFields)
		ret.OutputFields.fields = make(map[string]bool, len(ag.OutputFields.fields))
		for k, v := range ag.OutputFields.fields {
			ret.OutputFields.fields[k] = v
		}
	}
	return ret
}

// ACL provides an entry point into the permissions engine for determining if an
// action is allowed on a resource based on a principal's (user or group)
// grants.
type ACL struct {
	// directScopeMap is a map of scope IDs to grants valid for that scope ID
	// where the grant scope ID was specified directly
	directScopeMap map[string][]AclGrant
	// childrenScopeMap is a map of _parent_ scope IDs to grants, so that when
	// we are checking a resource we can see if there were any "children" grant
	// scope IDs that match
	childrenScopeMap map[string][]AclGrant
	// descendantsGrants is a list of grants that apply to all descendants of
	// global
	descendantsGrants []AclGrant
}

// ACLResults provides a type for the permission's engine results so that we can
// pass more detailed information along in the future if we want. It was useful
// in Vault, may be useful here.
type ACLResults struct {
	AuthenticationFinished bool
	Authorized             bool
	OutputFields           *OutputFields

	// This is included but unexported for testing/debugging
	directScopeMap    map[string][]AclGrant
	childrenScopeMap  map[string][]AclGrant
	descendantsGrants []AclGrant
}

// Permission provides information about the specific
// resources that a user has been granted access to for a given scope, resource, and action.
type Permission struct {
	RoleScopeId       string // The scope id of the granting role
	RoleParentScopeId string // The parent scope id of the granting role
	GrantScopeId      string // Same as the scope ID unless "children" or "descendants" was used.
	Resource          resource.Type
	Action            action.Type

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

	// ParentScopeId is the parent scope of the resource.
	ParentScopeId string `json:"-"`
}

// NewACL creates an ACL from the grants provided. Note that this converts the
// API-based Grants to AclGrants.
func NewACL(grants ...Grant) ACL {
	ret := ACL{
		directScopeMap:    make(map[string][]AclGrant, len(grants)),
		childrenScopeMap:  make(map[string][]AclGrant, len(grants)),
		descendantsGrants: make([]AclGrant, 0, len(grants)),
	}

	for _, grant := range grants {
		ids := grant.ids
		if len(ids) == 0 {
			// This handles the no-ID case as well as the deprecated single-ID case
			ids = []string{grant.id}
		}
		for _, id := range ids {
			switch grant.grantScopeId {
			case globals.GrantScopeDescendants:
				ret.descendantsGrants = append(ret.descendantsGrants, aclGrantFromGrant(grant, id))
			case globals.GrantScopeChildren:
				// We use the role's scope here because we're evaluating the
				// grants themselves, not the resource, so we want to know the
				// scope of the role that said "children"
				ret.childrenScopeMap[grant.roleScopeId] = append(ret.childrenScopeMap[grant.roleScopeId], aclGrantFromGrant(grant, id))
			default:
				ret.directScopeMap[grant.grantScopeId] = append(ret.directScopeMap[grant.grantScopeId], aclGrantFromGrant(grant, id))
			}
		}
	}

	return ret
}

func (a ACL) DirectScopeGrantMap() map[string][]AclGrant {
	ret := make(map[string][]AclGrant, len(a.directScopeMap))
	for k, v := range a.directScopeMap {
		newSlice := make([]AclGrant, len(v))
		for i, g := range v {
			newSlice[i] = g.Clone()
		}
		ret[k] = newSlice
	}
	return ret
}

func (a ACL) ChildrenScopeGrantMap() map[string][]AclGrant {
	ret := make(map[string][]AclGrant, len(a.childrenScopeMap))
	for k, v := range a.childrenScopeMap {
		newSlice := make([]AclGrant, len(v))
		for i, g := range v {
			newSlice[i] = g.Clone()
		}
		ret[k] = newSlice
	}
	return ret
}

func (a ACL) DescendantsGrants() []AclGrant {
	ret := make([]AclGrant, len(a.descendantsGrants))
	for i, v := range a.descendantsGrants {
		ret[i] = v.Clone()
	}
	return ret
}

func aclGrantFromGrant(grant Grant, id string) AclGrant {
	return AclGrant{
		RoleScopeId:       grant.roleScopeId,
		RoleParentScopeId: grant.roleParentScopeId,
		GrantScopeId:      grant.grantScopeId,
		Id:                id,
		Type:              grant.typ,
		ActionSet:         grant.actions,
		OutputFields:      grant.OutputFields,
	}
}

// Allowed determines if the grants for an ACL allow an action for a resource.
func (a ACL) Allowed(r Resource, aType action.Type, userId string, opt ...Option) (results ACLResults) {
	opts := getOpts(opt...)

	// First, get the grants within the specified scopes
	grants := a.directScopeMap[r.ScopeId]
	grants = append(grants, a.childrenScopeMap[r.ParentScopeId]...)
	if r.ScopeId != scope.Global.String() {
		// Descendants grants do not apply to global!
		grants = append(grants, a.descendantsGrants...)
	}
	results.directScopeMap = a.directScopeMap
	results.childrenScopeMap = a.childrenScopeMap
	results.descendantsGrants = a.descendantsGrants

	var parentAction action.Type
	split := strings.Split(aType.String(), ":")
	if len(split) == 2 {
		parentAction = action.Map[split[0]]
	}
	// Now, go through and check whether grants match
	for _, grant := range grants {
		var outputFieldsOnly bool
		switch {
		case len(grant.ActionSet) == 0:
			// Continue with the next grant, unless we have output fields
			// specified in which case we continue to be able to apply the
			// output fields depending on ID and type.
			if _, hasSetFields := grant.OutputFields.Fields(); hasSetFields {
				outputFieldsOnly = true
			} else {
				continue
			}
		case grant.ActionSet[aType]:
			// We have this action
		case grant.ActionSet[parentAction]:
			// We don't have this action, but it's a subaction and we have the
			// parent action. As an example, if we are looking for "read:self"
			// and have "read", this is sufficient.
		case grant.ActionSet[action.All]:
			// All actions are allowed
		default:
			// No actions in the grant match what we're looking for, so continue
			// with the next grant
			continue
		}

		// We step through all grants in order to fetch the full list of output
		// fields, even if we find a match. However, we shortcut if we find *
		// for output fields, which is the default.
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
			case grant.Type == r.Type &&
				grant.Type == resource.Scope &&
				(aType == action.List || aType == action.NoOp):
				found = true

			// Allow discovery of and authenticating to auth methods
			case grant.Type == r.Type &&
				grant.Type == resource.AuthMethod &&
				(aType == action.List || aType == action.NoOp || aType == action.Authenticate):
				found = true
			}

		// Case 2: id=<resource.Id>;actions=<action> where ID cannot be a
		// wildcard. Type is optional but if present must match the resource.
		// This will also allow matching an id with specific output fields
		// (handled later). Cannot be a list or create action as those do not
		// operate on specific IDs, only types.
		case grant.Id == r.Id &&
			grant.Id != "" &&
			grant.Id != "*" &&
			(grant.Type == resource.Unknown || grant.Type == globals.ResourceInfoFromPrefix(grant.Id).Type) &&
			!action.List.IsActionOrParent(aType) &&
			!action.Create.IsActionOrParent(aType):

			found = true

		// Case 3: type=<resource.Type>;actions=<action> when action is list or
		// create (cannot be a wildcard). Must be a top level collection; if not
		// it's handled in cases 4 or 5. This is more of a semantic difference
		// compared to case 4 more than a security difference; this type is for
		// clarity as it ties more closely to the concept of create and list as
		// actions on a collection, operating on a collection directly. The
		// format in case 4 will still work for create/list on collections but
		// that's more of a shortcut to allow things like id=*;type=*;actions=*
		// for admin flows so that you don't need to separate out explicit
		// collection actions into separate typed grants for each collection
		// within a role. This does mean there are "two ways of doing things"
		// but it's a reasonable UX tradeoff given that "all IDs" can reasonably
		// be construed to include "and the one I'm making" and "all of them for
		// listing".
		case grant.Id == "" &&
			r.Id == "" &&
			grant.Type == r.Type &&
			grant.Type != resource.Unknown &&
			r.Type.TopLevelType() &&
			(action.List.IsActionOrParent(aType) ||
				action.Create.IsActionOrParent(aType)):

			found = true

		// Case 4:
		// id=*;type=<resource.Type>;actions=<action> where type cannot be
		// unknown but can be a wildcard to allow any resource at all; or
		// id=*;type=<resource.Type>;output_fields=<fields> with no action.
		case grant.Id == "*" &&
			grant.Type != resource.Unknown &&
			(grant.Type == r.Type ||
				grant.Type == resource.All):

			found = true

		// Case 5:
		// id=<pin>;type=<resource.Type>;actions=<action> where type can be a
		// wildcard and this this is operating on a non-top-level type.
		case grant.Id != "" &&
			grant.Id == r.Pin &&
			grant.Type != resource.Unknown &&
			(grant.Type == r.Type || grant.Type == resource.All) &&
			!r.Type.TopLevelType():

			found = true
		}

		if found {
			if !outputFieldsOnly {
				results.Authorized = true
			}
			fields, _ := grant.OutputFields.Fields()
			results.OutputFields = results.OutputFields.AddFields(fields)
			if results.OutputFields.Has("*") && results.Authorized {
				return results
			}
		}
	}
	return results
}

// ListResolvableAliasesPermissions builds a set of Permissions based on the
// grants in the ACL. The permissions will only be created if there is at least
// one grant of the provided resource type that includes at least one of the
// provided actions in the action set. Note that unlike the ListPermissions
// method, this method does not attempt to generate permissions for the
// u_recovery user. To get the resolvable aliases for u_recovery, the user could
// simply query all aliases with a destination id.
func (a ACL) ListResolvableAliasesPermissions(requestedType resource.Type, actions action.ActionSet) []Permission {
	perms := make([]Permission, 0, len(a.directScopeMap)+len(a.childrenScopeMap)+len(a.descendantsGrants))

	childScopeMap := a.childrenScopeMap
	scopeMap := a.directScopeMap

	// Unilaterally add the descendants grants, if any. Not specifying an Id or
	// ParentScopeId in ScopeInfo means that the only grants that might match
	// are descendants, and we tell buildPermission to include descendants.
	p := Permission{
		RoleScopeId:  scope.Global.String(),
		GrantScopeId: globals.GrantScopeDescendants,
		Resource:     requestedType,
		Action:       action.ListResolvableAliases,
		OnlySelf:     true, // default to only self to be restrictive
	}
	if a.buildPermission(&scopes.ScopeInfo{}, requestedType, actions, true, &p) {
		perms = append(perms, p)
		// Shortcut here because this is all we need -- this will turn into all
		// scopes. We only need to check for "global" in the direct map.
		if _, ok := a.directScopeMap[scope.Global.String()]; !ok {
			return perms
		}
		childScopeMap = nil
		scopeMap = map[string][]AclGrant{scope.Global.String(): a.directScopeMap[scope.Global.String()]}
	}

	// Next look at children grants; provide only the parent scope ID and tell
	// buildPermission to ignore descendants so that we know that the
	// permissions being looked at come from a child relationship. Cache the
	// scope IDs so we can ignore direct grants.
	childrenScopes := map[string]struct{}{}
	for scopeId := range childScopeMap {
		p := Permission{
			RoleScopeId:  scopeId,
			GrantScopeId: globals.GrantScopeChildren,
			Resource:     requestedType,
			Action:       action.ListResolvableAliases,
			OnlySelf:     true, // default to only self to be restrictive
		}
		if scopeId != scope.Global.String() { // Must be an org then so global is parent
			p.RoleParentScopeId = scope.Global.String()
		}
		if a.buildPermission(&scopes.ScopeInfo{ParentScopeId: scopeId}, requestedType, actions, false, &p) {
			if p.All {
				// only cache to childrenScopes when all IDs are granted because if the role with 'children' grant specifies
				// resource IDs, the IDs may not overlap with the children scope roles which means we cannot skip
				// parsing permissions on the children roles
				childrenScopes[scopeId] = struct{}{}
			}
			perms = append(perms, p)
		}
	}

	// Now look at direct grants; provide only Id so that we know the
	// permissions being looked at will include those specific scopes.
	for grantScopeId, grants := range scopeMap {
		p := Permission{
			GrantScopeId: grantScopeId,
			Resource:     requestedType,
			Action:       action.ListResolvableAliases,
			OnlySelf:     true, // default to only self to be restrictive
		}

		if len(grants) > 0 {
			// Since scopeIds will be the same for all of these grants, and it's
			// not children or descendants, we can get it from any of the grants
			p.RoleParentScopeId = grants[0].RoleParentScopeId
			p.RoleScopeId = grants[0].RoleScopeId
		}

		switch {
		case grantScopeId == p.RoleScopeId:
			// If the role and grant scope IDs are the same, they share a
			// parent, so we can look at the role's parent scope ID in the
			// children scopes map
			if _, ok := childrenScopes[p.RoleParentScopeId]; ok {
				// We already looked at this scope in the children grants, so skip it
				continue
			}
		case strings.HasPrefix(p.RoleScopeId, scope.Org.Prefix()):
			// Since direct grants must be in the same scope or downstream, if
			// the role scope ID is an org and the role and grant scopes are
			// different, the grant is on a project, so look for children from
			// the org
			if _, ok := childrenScopes[p.RoleScopeId]; ok {
				// We already found grants at this scope in the children grants,
				// so skip it
				continue
			}
		case p.RoleScopeId == scope.Global.String() && strings.HasPrefix(grantScopeId, scope.Org.Prefix()):
			// Handle the case where the parent scope is global, and the grant is at the org level.
			// Direct grants must either match the parent scope or be downstream. This condition
			// accounts for a scenario where a child grant exists at the org level while the parent
			// is global. If the grant were for projects, it would require a descendants grant instead.
			// Skip processing if the current scope is already accounted for in the childrenScopes map.
			if _, ok := childrenScopes[p.RoleScopeId]; ok {
				continue
			}
		}
		if a.buildPermission(&scopes.ScopeInfo{Id: grantScopeId}, requestedType, actions, false, &p) {
			perms = append(perms, p)
		}
	}

	return perms
}

// ListPermissions builds a set of Permissions based on the grants in the ACL.
// Permissions are determined for the given resource for each of the provided scopes.
// There must be a grant for a given resource for one of the provided "id actions"
// or for action.All in order for a Permission to be created for the scope.
// The set of "id actions" is resource dependant, but will generally include all
// actions that can be taken on an individual resource.
func (a ACL) ListPermissions(
	requestedScopes map[string]*scopes.ScopeInfo,
	requestedType resource.Type,
	idActions action.ActionSet,
	userId string,
) []Permission {
	perms := make([]Permission, 0, len(requestedScopes))
	for scopeId, scopeInfo := range requestedScopes {
		if scopeInfo == nil {
			continue
		}
		// Note: this function is called either with the scope resulting from
		// authentication (which would have the scope info for the specific
		// resource) or recursive scopes, which are fully resolved. The scopes
		// included have already been run through acl.Allowed() to see if the
		// user has access to the resource, so the grant scope ID can correctly
		// be set here to be the same as the role scope ID even if it's
		// technically coming from children/descendants grants.
		p := Permission{
			RoleScopeId:       scopeId,
			RoleParentScopeId: scopeInfo.ParentScopeId,
			GrantScopeId:      scopeId,
			Resource:          requestedType,
			Action:            action.List,
			OnlySelf:          true, // default to only self to be restrictive
		}
		if userId == globals.RecoveryUserId {
			p.All = true
			p.OnlySelf = false
			perms = append(perms, p)
			continue
		}
		if a.buildPermission(scopeInfo, requestedType, idActions, false, &p) {
			perms = append(perms, p)
		}
	}
	return perms
}

// buildPermission populates the provided permission with either the resource ids
// or marking All to true if there are grants that have an action that match
// one of the provided idActions for the provided type
func (a ACL) buildPermission(
	scopeInfo *scopes.ScopeInfo,
	requestedType resource.Type,
	idActions action.ActionSet,
	includeDescendants bool,
	p *Permission,
) bool {
	// Get grants for a specific scope id from the source of truth.
	if scopeInfo == nil {
		return false
	}
	var grants []AclGrant
	if scopeInfo.Id != "" {
		grants = a.directScopeMap[scopeInfo.Id]
	}
	if scopeInfo.ParentScopeId != "" {
		grants = append(grants, a.childrenScopeMap[scopeInfo.ParentScopeId]...)
	}
	// If the scope is global it needs to be a direct grant; descendants doesn't
	// include global
	if includeDescendants || (scopeInfo.Id != "" && scopeInfo.Id != scope.Global.String()) {
		grants = append(grants, a.descendantsGrants...)
	}
	for _, grant := range grants {
		// This grant doesn't match what we're looking for, ignore.
		if grant.Type != requestedType && grant.Type != resource.All && globals.ResourceInfoFromPrefix(grant.Id).Type != requestedType {
			continue
		}

		// We found a grant that matches the requested resource type:
		// Search to see if one or all actions in the action set have been granted.
		found := false
		if ok := grant.ActionSet[action.All]; ok {
			found = true
		} else {
			for idA := range idActions {
				if ok := grant.ActionSet[idA]; ok {
					found = true
					break
				}
			}
		}
		if !found { // In this case, none of the requested actions were granted for the given scope id.
			continue
		}

		actions, _ := grant.Actions()
		excludeList := make(action.ActionSet, len(actions))
		for _, aa := range actions {
			if aa != action.List {
				excludeList.Add(aa)
			}
		}
		p.OnlySelf = p.OnlySelf && excludeList.OnlySelf()

		switch grant.Id {
		case "*":
			p.All = true
		case "":
			continue
		default:
			p.ResourceIds = append(p.ResourceIds, grant.Id)
		}
	}

	return p.All || len(p.ResourceIds) > 0
}
