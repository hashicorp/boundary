// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package perms

import (
	"context"
	"encoding/json"
	"fmt"
	"sort"
	"strings"
	"unicode"

	"github.com/hashicorp/boundary/globals"
	"github.com/hashicorp/boundary/internal/errors"
	"github.com/hashicorp/boundary/internal/types/action"
	"github.com/hashicorp/boundary/internal/types/resource"
	"github.com/hashicorp/boundary/internal/types/scope"
	"golang.org/x/exp/slices"
)

type actionSet map[action.Type]bool

// Actions is a helper that goes through the map and returns both the actual
// types of actions as a slice and the equivalent strings
func (a actionSet) Actions() (typs []action.Type, strs []string) {
	typs = make([]action.Type, 0, len(a))
	strs = make([]string, 0, len(a))
	for k, v := range a {
		// Nothing should be in there if not true, but doesn't hurt to validate
		if !v {
			continue
		}
		typs = append(typs, k)
		strs = append(strs, k.String())
	}
	return
}

// GrantTuple is simply a struct that can be reference from other code to return
// a set of scopes and grants to parse
type GrantTuple struct {
	RoleId  string
	ScopeId string
	Grant   string
}

// Scope provides an in-memory representation of iam.Scope without the
// underlying storage references or capabilities.
type Scope struct {
	// Id is the public id of the iam.Scope
	Id string

	// Type is the scope's type (org or project)
	Type scope.Type
}

// Grant is a Go representation of a parsed grant
type Grant struct {
	// The scope, containing the ID and type
	scope Scope

	// The ID of the grant, if provided. Deprecated in favor of ids.
	id string

	// The IDs in the grant, if provided
	ids []string

	// The type, if provided
	typ resource.Type

	// The set of actions being granted
	actions actionSet

	// The set of output fields granted
	OutputFields *OutputFields

	// This is used as a temporary staging area before validating permissions to
	// allow the same validation code across grant string formats
	actionsBeingParsed []string
}

// Id returns the ID the grant refers to, if any
func (g Grant) Id() string {
	return g.id
}

// Ids returns the IDs the grant refers to, if any
func (g Grant) Ids() []string {
	return g.ids
}

// Type returns the type the grant refers to, or Unknown
func (g Grant) Type() resource.Type {
	return g.typ
}

// Actions returns the actions as a slice from the internal map, along with the
// string representations of those actions.
func (g Grant) Actions() ([]action.Type, []string) {
	return g.actions.Actions()
}

// hasActionOrSubaction checks whether a grant's action set contains the given
// action or contains an action that is a subaction of the passed-in parameter.
// This is used for validation checking of parsed grants. N.B.: this is the
// opposite check of action.Type.IsActionOrParent, which is why the ordering is
// reversed going into that call.
func (g Grant) hasActionOrSubaction(act action.Type) bool {
	for k := range g.actions {
		if act.IsActionOrParent(k) {
			return true
		}
	}
	return false
}

func (g Grant) clone() *Grant {
	ret := &Grant{
		scope: g.scope,
		id:    g.id,
		ids:   g.ids,
		typ:   g.typ,
	}
	if g.ids != nil {
		ret.ids = make([]string, len(g.ids))
		copy(ret.ids, g.ids)
	}
	if g.actionsBeingParsed != nil {
		ret.actionsBeingParsed = append(ret.actionsBeingParsed, g.actionsBeingParsed...)
	}
	if g.actions != nil {
		ret.actions = make(map[action.Type]bool, len(g.actions))
		for action := range g.actions {
			ret.actions[action] = true
		}
	}
	if outFields, hasSetFields := g.OutputFields.Fields(); hasSetFields {
		fieldsToAdd := make([]string, 0, len(outFields))
		for _, v := range outFields {
			fieldsToAdd = append(fieldsToAdd, v)
		}
		ret.OutputFields = ret.OutputFields.AddFields(fieldsToAdd)
	}
	return ret
}

// CanonicalString returns the canonical representation of the grant
func (g Grant) CanonicalString() string {
	var builder []string

	if g.id != "" {
		builder = append(builder, fmt.Sprintf("id=%s", g.id))
	}

	if len(g.ids) > 0 {
		builder = append(builder, fmt.Sprintf("ids=%s", strings.Join(g.ids, ",")))
	}

	if g.typ != resource.Unknown {
		builder = append(builder, fmt.Sprintf("type=%s", g.typ.String()))
	}

	if len(g.actions) > 0 {
		actions := make([]string, 0, len(g.actions))
		for action := range g.actions {
			actions = append(actions, action.String())
		}
		sort.Strings(actions)
		builder = append(builder, fmt.Sprintf("actions=%s", strings.Join(actions, ",")))
	}

	if outFields, hasSetFields := g.OutputFields.Fields(); hasSetFields {
		builder = append(builder, fmt.Sprintf("output_fields=%s", strings.Join(outFields, ",")))
	}

	return strings.Join(builder, ";")
}

// MarshalJSON provides a custom marshaller for grants
func (g Grant) MarshalJSON(ctx context.Context) ([]byte, error) {
	const op = "perms.(Grant).MarshalJSON"
	res := make(map[string]any, 4)
	if g.id != "" {
		res["id"] = g.id
	}
	if len(g.ids) > 0 {
		res["ids"] = g.ids
	}
	if g.typ != resource.Unknown {
		res["type"] = g.typ.String()
	}
	if len(g.actions) > 0 {
		actions := make([]string, 0, len(g.actions))
		for action := range g.actions {
			actions = append(actions, action.String())
		}
		sort.Strings(actions)
		res["actions"] = actions
	}
	if outFields, hasSetFields := g.OutputFields.Fields(); hasSetFields {
		res["output_fields"] = outFields
	}
	b, err := json.Marshal(res)
	if err != nil {
		return nil, errors.Wrap(ctx, err, op, errors.WithCode(errors.Encode))
	}
	return b, nil
}

// This is purposefully unexported since the values being set here are not being
// checked for validity. This should only be called by the main parsing function
// when JSON is detected.
func (g *Grant) unmarshalJSON(ctx context.Context, data []byte) error {
	const op = "perms.(Grant).unmarshalJSON"
	raw := make(map[string]any, 4)
	if err := json.Unmarshal(data, &raw); err != nil {
		return errors.Wrap(ctx, err, op, errors.WithCode(errors.Decode))
	}
	if rawId, ok := raw["id"]; ok {
		id, ok := rawId.(string)
		if !ok {
			return errors.New(ctx, errors.InvalidParameter, op, fmt.Sprintf("unable to interpret %q as string", "id"))
		}
		g.id = id
	}
	if rawIds, ok := raw["ids"]; ok {
		ids, ok := rawIds.([]any)
		if !ok {
			return errors.New(ctx, errors.InvalidParameter, op, fmt.Sprintf("unable to interpret %q as array", "ids"))
		}
		g.ids = make([]string, len(ids))
		for i, id := range ids {
			idStr, ok := id.(string)
			if !ok {
				return errors.New(ctx, errors.InvalidParameter, op, fmt.Sprintf("unable to interpret %q element %q as string", "ids", id))
			}
			g.ids[i] = idStr
		}
	}
	if rawType, ok := raw["type"]; ok {
		typ, ok := rawType.(string)
		if !ok {
			return errors.New(ctx, errors.InvalidParameter, op, fmt.Sprintf("unable to interpret %q as string", "type"))
		}
		g.typ = resource.Map[typ]
		if g.typ == resource.Unknown {
			return errors.New(ctx, errors.InvalidParameter, op, fmt.Sprintf("unknown type specifier %q", typ))
		}
	}
	if rawActions, ok := raw["actions"]; ok {
		interfaceActions, ok := rawActions.([]any)
		if !ok {
			return errors.New(ctx, errors.InvalidParameter, op, fmt.Sprintf("unable to interpret %q as array", "actions"))
		}
		if len(interfaceActions) > 0 {
			g.actionsBeingParsed = make([]string, 0, len(interfaceActions))
			for _, v := range interfaceActions {
				actionStr, ok := v.(string)
				switch {
				case !ok:
					return errors.New(ctx, errors.InvalidParameter, op, fmt.Sprintf("unable to interpret %v in actions array as string", v))
				case actionStr == "":
					return errors.New(ctx, errors.InvalidParameter, op, "empty action found")
				default:
					g.actionsBeingParsed = append(g.actionsBeingParsed, strings.ToLower(actionStr))
				}
			}
		}
	}
	if rawOutputFields, ok := raw["output_fields"]; ok {
		interfaceOutputFields, ok := rawOutputFields.([]any)
		if !ok {
			return errors.New(ctx, errors.InvalidParameter, op, fmt.Sprintf("unable to interpret %q as array", "output_fields"))
		}
		// We do the make here because we detect later if the field was set but
		// no values given
		switch len(interfaceOutputFields) {
		case 0:
			// JSON was set but no fields defined, add an empty array
			g.OutputFields = g.OutputFields.AddFields([]string{})
		default:
			fields := make([]string, 0, len(interfaceOutputFields))
			for _, v := range interfaceOutputFields {
				field, ok := v.(string)
				switch {
				case !ok:
					return errors.New(ctx, errors.InvalidParameter, op, fmt.Sprintf("unable to interpret %v in output_fields array as string", v))
				default:
					fields = append(fields, field)
				}
			}
			g.OutputFields = g.OutputFields.AddFields(fields)
		}
	}
	return nil
}

func (g *Grant) unmarshalText(ctx context.Context, grantString string) error {
	const op = "perms.(Grant).unmarshalText"
	segments := strings.Split(grantString, ";")
	for _, segment := range segments {
		kv := strings.Split(segment, "=")

		// Ensure we don't accept "foo=bar=baz", "=foo", or "foo="
		switch {
		case len(kv) != 2:
			return errors.New(ctx, errors.InvalidParameter, op, fmt.Sprintf("segment %q not formatted correctly, wrong number of equal signs", segment))
		case len(kv[0]) == 0:
			return errors.New(ctx, errors.InvalidParameter, op, fmt.Sprintf("segment %q not formatted correctly, missing key", segment))
		case len(kv[1]) == 0 && kv[0] != "output_fields":
			return errors.New(ctx, errors.InvalidParameter, op, fmt.Sprintf("segment %q not formatted correctly, missing value", segment))
		}

		switch kv[0] {
		case "id":
			g.id = kv[1]

		case "ids":
			g.ids = strings.Split(kv[1], ",")

		case "type":
			typeString := strings.ToLower(kv[1])
			g.typ = resource.Map[typeString]
			if g.typ == resource.Unknown {
				return errors.New(ctx, errors.InvalidParameter, op, fmt.Sprintf("unknown type specifier %q", typeString))
			}

		case "actions":
			actions := strings.Split(kv[1], ",")
			if len(actions) > 0 {
				g.actionsBeingParsed = make([]string, 0, len(actions))
				for _, action := range actions {
					if action == "" {
						return errors.New(ctx, errors.InvalidParameter, op, "empty action found")
					}
					g.actionsBeingParsed = append(g.actionsBeingParsed, strings.ToLower(action))
				}
			}

		case "output_fields":
			switch len(kv[1]) {
			case 0:
				g.OutputFields = g.OutputFields.AddFields([]string{})
			default:
				g.OutputFields = g.OutputFields.AddFields(strings.Split(kv[1], ","))
			}
		}
	}

	return nil
}

// Parse parses a grant string. Note that this does not do checking
// of the validity of IDs and such; that's left for other parts of the system.
// We may not check at all (e.g. let it be an authz-time failure) or could check
// after submission to catch errors.
//
// The scope must be the org and project where this grant originated, not the
// request.
func Parse(ctx context.Context, scopeId, grantString string, opt ...Option) (Grant, error) {
	const op = "perms.Parse"
	if len(grantString) == 0 {
		return Grant{}, errors.New(ctx, errors.InvalidParameter, op, "missing grant string")
	}
	if scopeId == "" {
		return Grant{}, errors.New(ctx, errors.InvalidParameter, op, "missing scope id")
	}
	grantString = strings.ToValidUTF8(grantString, string(unicode.ReplacementChar))

	grant := Grant{
		scope: Scope{Id: strings.ToValidUTF8(scopeId, string(unicode.ReplacementChar))},
	}
	switch {
	case scopeId == scope.Global.String():
		grant.scope.Type = scope.Global
	case strings.HasPrefix(scopeId, scope.Org.Prefix()):
		grant.scope.Type = scope.Org
	case strings.HasPrefix(scopeId, scope.Project.Prefix()):
		grant.scope.Type = scope.Project
	default:
		return Grant{}, errors.New(ctx, errors.InvalidParameter, op, "invalid scope type")
	}

	switch {
	case grantString[0] == '{':
		if err := grant.unmarshalJSON(ctx, []byte(grantString)); err != nil {
			return Grant{}, errors.Wrap(ctx, err, op, errors.WithMsg("unable to parse JSON grant string"))
		}

	default:
		if err := grant.unmarshalText(ctx, grantString); err != nil {
			return Grant{}, errors.Wrap(ctx, err, op, errors.WithMsg("unable to parse grant string"))
		}
	}

	if grant.id != "" && len(grant.ids) > 0 {
		return Grant{}, errors.New(ctx, errors.InvalidParameter, op, fmt.Sprintf("input grant string %q contains both %q and %q fields", grantString, "id", "ids"))
	}
	if len(grant.ids) > 1 && slices.Contains(grant.ids, "*") {
		return Grant{}, errors.New(ctx, errors.InvalidParameter, op, fmt.Sprintf("input grant string %q contains both wildcard and non-wildcard values in %q field", grantString, "ids"))
	}

	opts := getOpts(opt...)

	var grantIds []string
	var deprecatedId bool
	switch {
	case grant.id != "":
		grantIds = []string{grant.id}
		deprecatedId = true
	case len(grant.ids) > 0:
		grantIds = grant.ids
		// Ensure we aren't seeing mixed types. We will have already filtered
		// out the wildcard case above.
		if len(grant.ids) > 1 {
			var seenType resource.Type
			for i, id := range grantIds {
				if i == 0 {
					seenType = globals.ResourceTypeFromPrefix(id)
					continue
				}
				if seenType != globals.ResourceTypeFromPrefix(id) {
					return Grant{}, errors.New(ctx, errors.InvalidParameter, op, fmt.Sprintf("input grant string %q contains ids of differently-typed resources", grantString))
				}
			}
		}
	}
	// It's possible that there is no id in a grant. In that case we still need
	// to validate it and build up the parsed Grant. We insert an empty ID value
	// in this case; the code below will check that it's non-empty before
	// running any ID-specific logic on it.
	if len(grantIds) == 0 {
		grantIds = []string{""}
	}
	for i, currId := range grantIds {
		// Check for templated values ID, and substitute in with the authenticated
		// values if so. If we are using a dummy user or account ID, store the
		// original ID and return it at the end; this is usually the case when
		// validating grant formats.
		var origId string
		if currId != "" {
			if strings.HasPrefix(currId, "{{") {
				id := strings.TrimSuffix(strings.TrimPrefix(currId, "{{"), "}}")
				id = strings.TrimSpace(id)
				switch id {
				case "user.id", ".User.Id":
					if opts.withUserId != "" {
						grantIds[i] = strings.ToValidUTF8(opts.withUserId, string(unicode.ReplacementChar))
					} else {
						// Otherwise, substitute in a dummy value
						origId = currId
						grantIds[i] = "u_dummy"
					}
				case "account.id", ".Account.Id":
					if opts.withAccountId != "" {
						grantIds[i] = strings.ToValidUTF8(opts.withAccountId, string(unicode.ReplacementChar))
					} else {
						origId = currId
						grantIds[i] = "acctoidc_dummy"
					}
				default:
					fieldName := "ids"
					if deprecatedId {
						fieldName = "id"
					}
					return Grant{}, errors.New(ctx, errors.InvalidParameter, op, fmt.Sprintf("unknown template %q in grant %q value", currId, fieldName))
				}
			}
		}

		// We don't need to do these twice as they don't depend on IDs; they
		// also clear state such as actionsBeingParsed
		if i == 0 {
			if err := grant.validateType(ctx); err != nil {
				return Grant{}, errors.Wrap(ctx, err, op)
			}
			if err := grant.parseAndValidateActions(ctx); err != nil {
				return Grant{}, errors.Wrap(ctx, err, op)
			}
		}

		if !opts.withSkipFinalValidation {
			switch {
			case grantIds[i] == "*":
				// Matches
				//   id=*;type=sometype;actions=foo,bar
				// or
				//   id=*;type=*;actions=foo,bar
				// This can be a non-unknown type or wildcard
				if grant.typ == resource.Unknown {
					return Grant{}, errors.New(ctx, errors.InvalidParameter, op, fmt.Sprintf("parsed grant string %q contains wildcard id and no specified type", grant.CanonicalString()))
				}
			case grantIds[i] != "":
				// Non-wildcard but specified ID. This can match
				//   id=foo_bar;actions=foo,bar
				// or
				//   id=foo_bar;type=sometype;actions=foo,bar
				// or
				//   id=foo_bar;type=*;actions=foo,bar
				// but notably the specified types have to actually make sense: in
				// the second example the type corresponding to the ID must have the
				// specified type as a child type; in the third the ID must be a
				// type that has child types.
				idType := globals.ResourceTypeFromPrefix(grantIds[i])
				if idType == resource.Unknown {
					return Grant{}, errors.New(ctx, errors.InvalidParameter, op, fmt.Sprintf("parsed grant string %q contains an id %q of an unknown resource type", grant.CanonicalString(), grantIds[i]))
				}
				switch grant.typ {
				case resource.Unknown:
					// This is fine as-is but we do not support collection actions
					// without a type (either directly specified or wildcard) so
					// check that
					if grant.actions[action.Create] ||
						grant.actions[action.List] {
						return Grant{}, errors.New(ctx, errors.InvalidParameter, op, fmt.Sprintf("parsed grant string %q contains create or list action in a format that does not allow these", grant.CanonicalString()))
					}
				case resource.All:
					// Verify that the ID is a type that has child types
					if !resource.HasChildTypes(idType) {
						return Grant{}, errors.New(ctx, errors.InvalidParameter, op, fmt.Sprintf("parsed grant string %q contains an id that does not support child types", grant.CanonicalString()))
					}
				default:
					// Specified resource type, verify it's a child
					if resource.Parent(grant.typ) != idType {
						return Grant{}, errors.New(ctx, errors.InvalidParameter, op, fmt.Sprintf("parsed grant string %q contains type %s that is not a child type of the type (%s) of the specified id", grant.CanonicalString(), grant.typ.String(), idType.String()))
					}
				}
			default: // no specified id
				switch grant.typ {
				case resource.Unknown:
					// Error -- no ID or type isn't valid (although we should never
					// get to this point because original parsing should error)
					return Grant{}, errors.New(ctx, errors.InvalidParameter, op, fmt.Sprintf("parsed grant string %q contains no id or type", grant.CanonicalString()))
				case resource.All:
					// "type=*;actions=..." is not supported -- we require you to
					// explicitly set a pin or set the ID to *
					return Grant{}, errors.New(ctx, errors.InvalidParameter, op, fmt.Sprintf("parsed grant string %q contains wildcard type with no id value", grant.CanonicalString()))
				default:
					// Here we have type=something,actions=<something else>. This
					// means we're operating on collections and support only create
					// or list. Note that wildcard actions are not okay here; that
					// uses the format id=*;type=<something>;actions=*
					switch len(grant.actions) {
					case 0:
						// It's okay to have no actions if only output fields are being defined
						if _, hasSetFields := grant.OutputFields.Fields(); !hasSetFields {
							return Grant{}, errors.New(ctx, errors.InvalidParameter, op, fmt.Sprintf("parsed grant string %q contains no actions or output fields", grant.CanonicalString()))
						}
					case 1:
						if !grant.hasActionOrSubaction(action.Create) &&
							!grant.hasActionOrSubaction(action.List) {
							return Grant{}, errors.New(ctx, errors.InvalidParameter, op, fmt.Sprintf("parsed grant string %q contains non-create or non-list action in a format that only allows these", grant.CanonicalString()))
						}
					case 2:
						if !grant.hasActionOrSubaction(action.Create) || !grant.hasActionOrSubaction(action.List) {
							return Grant{}, errors.New(ctx, errors.InvalidParameter, op, fmt.Sprintf("parsed grant string %q contains non-create or non-list action in a format that only allows these", grant.CanonicalString()))
						}
					default:
						return Grant{}, errors.New(ctx, errors.InvalidParameter, op, fmt.Sprintf("parsed grant string %q contains non-create or non-list action in a format that only allows these", grant.CanonicalString()))
					}
				}
			}
			// This might be zero if output fields is populated
			if len(grant.actions) > 0 {
				// Create a dummy resource and pass it through Allowed and
				// ensure that we get allowed. We need to use the templated
				// grant, if any, so we send in a clone with an updated ID.
				grantForValidation := grant.clone()
				grantForValidation.id = grantIds[i]
				acl := NewACL(*grantForValidation)
				r := Resource{
					ScopeId: scopeId,
					Id:      grantIds[i],
					Type:    grant.typ,
				}
				if !resource.TopLevelType(grant.typ) {
					r.Pin = grantIds[i]
				}
				var allowed bool
				for k := range grant.actions {
					results := acl.Allowed(r, k, globals.AnonymousUserId, WithSkipAnonymousUserRestrictions(true))
					if results.Authorized {
						allowed = true
						break
					}
				}
				if !allowed {
					return Grant{}, errors.New(ctx, errors.InvalidParameter, op, fmt.Sprintf("parsed grant string %q would not result in any action being authorized", grant.CanonicalString()))
				}
			}
		}

		// If we substituted in a dummy value, replace with the original now
		if origId != "" {
			grantIds[i] = origId
		}
	}

	// See if we need to move grantIds back for the deprecated case. grantIds
	// will always be at least size 1 since we add the empty string if no IDs
	// were provided, so we can check to see if that was the case first.
	switch {
	case grantIds[0] == "":
		// Nothing to do
	case deprecatedId:
		grant.id = grantIds[0]
	default:
		grant.ids = grantIds
	}

	return grant, nil
}

// validateType ensures that we are not allowing access to disallowed resource
// types. It does not explicitly check the resource string itself; that's the
// job of the parsing functions to look up the string from the Map and ensure
// it's not unknown.
func (g Grant) validateType(ctx context.Context) error {
	const op = "perms.(Grant).validateType"
	switch g.typ {
	case resource.Controller:
		return errors.New(ctx, errors.InvalidParameter, op, fmt.Sprintf("unknown type specifier %q", g.typ))
	}
	return nil
}

func (g *Grant) parseAndValidateActions(ctx context.Context) error {
	const op = "perms.(Grant).parseAndValidateActions"
	if len(g.actionsBeingParsed) == 0 {
		g.actionsBeingParsed = nil
		// If there are no actions it's fine if the grant is just used to
		// specify output fields
		if _, hasSetFields := g.OutputFields.Fields(); hasSetFields {
			return nil
		}
		return errors.New(ctx, errors.InvalidParameter, op, "missing actions")
	}

	for _, a := range g.actionsBeingParsed {
		if a == "" {
			return errors.New(ctx, errors.InvalidParameter, op, "empty action found")
		}
		if g.actions == nil {
			g.actions = make(map[action.Type]bool, len(g.actionsBeingParsed))
		}
		if am := action.Map[a]; am == action.Unknown {
			return errors.New(ctx, errors.InvalidParameter, op, fmt.Sprintf("unknown action %q", a))
		} else {
			g.actions[am] = true
		}
	}

	if len(g.actions) > 1 && g.actions[action.All] {
		return errors.New(ctx, errors.InvalidParameter, op, fmt.Sprintf("%q cannot be specified with other actions", action.All.String()))
	}

	g.actionsBeingParsed = nil

	return nil
}
