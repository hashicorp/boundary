package perms

import (
	"encoding/json"
	"fmt"
	"sort"
	"strings"

	"github.com/hashicorp/boundary/internal/errors"
	"github.com/hashicorp/boundary/internal/types/action"
	"github.com/hashicorp/boundary/internal/types/resource"
	"github.com/hashicorp/boundary/internal/types/scope"
)

// GrantPair is simply a struct that can be reference from other code to return
// a set of scopes and grants to parse
type GrantPair struct {
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
	// The scope ID, which will be a project ID or an org ID
	scope Scope

	// The ID in the grant, if provided.
	id string

	// The type, if provided
	typ resource.Type

	// The set of actions being granted
	actions map[action.Type]bool

	// This is used as a temporary staging area before validating permissions to
	// allow the same validation code across grant string formats
	actionsBeingParsed []string
}

func (g Grant) Id() string {
	return g.id
}

func (g Grant) Type() resource.Type {
	return g.typ
}

func (g Grant) Actions() (typs []action.Type, strs []string) {
	typs = make([]action.Type, 0, len(g.actions))
	strs = make([]string, 0, len(g.actions))
	for k, v := range g.actions {
		// Nothing should be in there if not true, but doesn't hurt to validate
		if !v {
			continue
		}
		typs = append(typs, k)
		strs = append(strs, k.String())
	}
	return
}

func (g Grant) clone() *Grant {
	ret := &Grant{
		scope: g.scope,
		id:    g.id,
		typ:   g.typ,
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
	return ret
}

// CanonicalString returns the canonical representation of the grant
func (g Grant) CanonicalString() string {
	var builder []string

	if g.id != "" {
		builder = append(builder, fmt.Sprintf("id=%s", g.id))
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

	return strings.Join(builder, ";")
}

// MarshalJSON provides a custom marshaller for grants
func (g Grant) MarshalJSON() ([]byte, error) {
	const op = "perms.(Grant).MarshalJSON"
	res := make(map[string]interface{}, 4)
	if g.id != "" {
		res["id"] = g.id
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
	b, err := json.Marshal(res)
	if err != nil {
		return nil, errors.Wrap(err, op, errors.WithCode(errors.Encode))
	}
	return b, nil
}

// This is purposefully unexported since the values being set here are not being
// checked for validity. This should only be called by the main parsing function
// when JSON is detected.
func (g *Grant) unmarshalJSON(data []byte) error {
	const op = "perms.(Grant).unmarshalJSON"
	raw := make(map[string]interface{}, 4)
	if err := json.Unmarshal(data, &raw); err != nil {
		return errors.Wrap(err, op, errors.WithCode(errors.Decode))
	}
	if rawId, ok := raw["id"]; ok {
		id, ok := rawId.(string)
		if !ok {
			return errors.New(errors.InvalidParameter, op, fmt.Sprintf("unable to interpret %q as string", "id"))
		}
		g.id = id
	}
	if rawType, ok := raw["type"]; ok {
		typ, ok := rawType.(string)
		if !ok {
			return errors.New(errors.InvalidParameter, op, fmt.Sprintf("unable to interpret %q as string", "type"))
		}
		g.typ = resource.Map[typ]
		if g.typ == resource.Unknown {
			return errors.New(errors.InvalidParameter, op, fmt.Sprintf("unknown type specifier %q", typ))
		}
	}
	if rawActions, ok := raw["actions"]; ok {
		interfaceActions, ok := rawActions.([]interface{})
		if !ok {
			return errors.New(errors.InvalidParameter, op, fmt.Sprintf("unable to interpret %q as array", "actions"))
		}
		if len(interfaceActions) > 0 {
			g.actionsBeingParsed = make([]string, 0, len(interfaceActions))
			for _, v := range interfaceActions {
				actionStr, ok := v.(string)
				switch {
				case !ok:
					return errors.New(errors.InvalidParameter, op, fmt.Sprintf("unable to interpret %v in actions array as string", v))
				case actionStr == "":
					return errors.New(errors.InvalidParameter, op, "empty action found")
				default:
					g.actionsBeingParsed = append(g.actionsBeingParsed, strings.ToLower(actionStr))
				}
			}
		}
	}
	return nil
}

func (g *Grant) unmarshalText(grantString string) error {
	const op = "perms.(Grant).unmarshalText"
	segments := strings.Split(grantString, ";")
	for _, segment := range segments {
		kv := strings.Split(segment, "=")

		// Ensure we don't accept "foo=bar=baz", "=foo", or "foo="
		switch {
		case len(kv) != 2:
			return errors.New(errors.InvalidParameter, op, fmt.Sprintf("segment %q not formatted correctly, wrong number of equal signs", segment))
		case len(kv[0]) == 0:
			return errors.New(errors.InvalidParameter, op, fmt.Sprintf("segment %q not formatted correctly, missing key", segment))
		case len(kv[1]) == 0:
			return errors.New(errors.InvalidParameter, op, fmt.Sprintf("segment %q not formatted correctly, missing value", segment))
		}

		switch kv[0] {
		case "id":
			g.id = kv[1]

		case "type":
			typeString := strings.ToLower(kv[1])
			g.typ = resource.Map[typeString]
			if g.typ == resource.Unknown {
				return errors.New(errors.InvalidParameter, op, fmt.Sprintf("unknown type specifier %q", typeString))
			}

		case "actions":
			actions := strings.Split(kv[1], ",")
			if len(actions) > 0 {
				g.actionsBeingParsed = make([]string, 0, len(actions))
				for _, action := range actions {
					if action == "" {
						return errors.New(errors.InvalidParameter, op, "empty action found")
					}
					g.actionsBeingParsed = append(g.actionsBeingParsed, strings.ToLower(action))
				}
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
func Parse(scopeId, grantString string, opt ...Option) (Grant, error) {
	const op = "perms.Parse"
	if len(grantString) == 0 {
		return Grant{}, errors.New(errors.InvalidParameter, op, "missing grant string")
	}
	if scopeId == "" {
		return Grant{}, errors.New(errors.InvalidParameter, op, "missing scope id")
	}

	grant := Grant{
		scope: Scope{Id: scopeId},
	}
	switch {
	case scopeId == "global":
		grant.scope.Type = scope.Global
	case strings.HasPrefix(scopeId, scope.Org.Prefix()):
		grant.scope.Type = scope.Org
	case strings.HasPrefix(scopeId, scope.Project.Prefix()):
		grant.scope.Type = scope.Project
	default:
		return Grant{}, errors.New(errors.InvalidParameter, op, "invalid scope type")
	}

	switch {
	case grantString[0] == '{':
		if err := grant.unmarshalJSON([]byte(grantString)); err != nil {
			return Grant{}, errors.Wrap(err, op, errors.WithMsg("unable to parse JSON grant string"))
		}

	default:
		if err := grant.unmarshalText(grantString); err != nil {
			return Grant{}, errors.Wrap(err, op, errors.WithMsg("unable to parse grant string"))
		}
	}

	opts := getOpts(opt...)

	// Check for templated values ID, and substitute in with the authenticated values
	// if so
	if grant.id != "" && strings.HasPrefix(grant.id, "{{") {
		id := strings.TrimSuffix(strings.TrimPrefix(grant.id, "{{"), "}}")
		id = strings.TrimSpace(id)
		switch id {
		case "user.id":
			if opts.withUserId != "" {
				grant.id = opts.withUserId
			}
		case "account.id":
			if opts.withAccountId != "" {
				grant.id = opts.withAccountId
			}
		default:
			return Grant{}, errors.New(errors.InvalidParameter, op, fmt.Sprintf("unknown template %q in grant %q value", grant.id, "id"))
		}
	}

	if err := grant.validateType(); err != nil {
		return Grant{}, errors.Wrap(err, op)
	}

	if err := grant.parseAndValidateActions(); err != nil {
		return Grant{}, errors.Wrap(err, op)
	}

	if !opts.withSkipFinalValidation {
		// Filter out some forms that don't make sense

		// First up, an ID is given, no type, and actions contains "create" or
		// "list". Note wildcard for actions is still okay.
		if grant.id != "" && grant.typ == resource.Unknown {
			if grant.actions[action.Create] ||
				grant.actions[action.List] {
				return Grant{}, errors.New(errors.InvalidParameter, op, "parsed grant string contains create or list action in a format that does not allow these")
			}
		}
		// If no ID is given...
		if grant.id == "" {
			// Check the type
			switch grant.typ {
			case resource.Unknown:
				// Error -- no ID or type isn't valid (although we should never
				// get to this point because original parsing should error)
				return Grant{}, errors.New(errors.InvalidParameter, op, "parsed grant string contains no id or type")
			case resource.All:
				// "type=*;actions=..." is not supported -- we reqiure you to
				// explicitly set a pin or set the ID to *
				return Grant{}, errors.New(errors.InvalidParameter, op, "parsed grant string contains wildcard type with no id value")
			default:
				// Here we have type=something,actions=<something else>. This
				// means we're operating on collections. Note that wildcard
				// actions are not okay here; that uses the format
				// id=*;type=<something>;actions=*
				switch len(grant.actions) {
				case 0:
					// A total lack of actions is already caught elsewhere but
					// this is here for completeness
					return Grant{}, errors.New(errors.InvalidParameter, op, "parsed grant string contains no actions")
				case 1:
					if !grant.actions[action.Create] &&
						!grant.actions[action.List] {
						return Grant{}, errors.New(errors.InvalidParameter, op, "parsed grant string contains non-create or non-list action in a format that only allows these")
					}
				case 2:
					if !grant.actions[action.Create] || !grant.actions[action.List] {
						return Grant{}, errors.New(errors.InvalidParameter, op, "parsed grant string contains non-create or non-list action in a format that only allows these")
					}
				default:
					return Grant{}, errors.New(errors.InvalidParameter, op, "parsed grant string contains non-create or non-list action in a format that only allows these")
				}
			}
		}
		// Create a dummy resource and pass it through Allowed and ensure that
		// we get allowed.
		acl := NewACL(grant)
		r := Resource{
			ScopeId: scopeId,
			Id:      grant.id,
			Type:    grant.typ,
		}
		if !topLevelType(grant.typ) {
			r.Pin = grant.id
		}
		var allowed bool
		for k := range grant.actions {
			results := acl.Allowed(r, k)
			if results.Allowed {
				allowed = true
			}
		}
		if !allowed {
			return Grant{}, errors.New(errors.InvalidParameter, op, "parsed grant string would not result in any action being authorized")
		}
	}

	return grant, nil
}

func (g Grant) validateType() error {
	const op = "perms.(Grant).validateType"
	switch g.typ {
	case resource.Unknown,
		resource.All,
		resource.Scope,
		resource.User,
		resource.Group,
		resource.Role,
		resource.AuthMethod,
		resource.Account,
		resource.HostCatalog,
		resource.HostSet,
		resource.Host,
		resource.Target,
		resource.Session:
		return nil
	}
	return errors.New(errors.InvalidParameter, op, fmt.Sprintf("unknown type specifier %q", g.typ))
}

func (g *Grant) parseAndValidateActions() error {
	const op = "perms.(Grant).parseAndValidateActions"
	if len(g.actionsBeingParsed) == 0 {
		return errors.New(errors.InvalidParameter, op, "missing actions")
	}

	for _, a := range g.actionsBeingParsed {
		if a == "" {
			return errors.New(errors.InvalidParameter, op, "empty action found")
		}
		if g.actions == nil {
			g.actions = make(map[action.Type]bool, len(g.actionsBeingParsed))
		}
		if am := action.Map[a]; am == action.Unknown {
			return errors.New(errors.InvalidParameter, op, fmt.Sprintf("unknown action %q", a))
		} else {
			g.actions[am] = true
		}
	}

	if len(g.actions) > 1 && g.actions[action.All] {
		return errors.New(errors.InvalidParameter, op, fmt.Sprintf("%q cannot be specified with other actions", action.All.String()))
	}

	g.actionsBeingParsed = nil

	return nil
}
