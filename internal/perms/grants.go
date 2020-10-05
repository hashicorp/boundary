package perms

import (
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strings"

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
	return json.Marshal(res)
}

// This is purposefully unexported since the values being set here are not being
// checked for validity. This should only be called by the main parsing function
// when JSON is detected.
func (g *Grant) unmarshalJSON(data []byte) error {
	raw := make(map[string]interface{}, 4)
	if err := json.Unmarshal(data, &raw); err != nil {
		return err
	}
	if rawId, ok := raw["id"]; ok {
		id, ok := rawId.(string)
		if !ok {
			return fmt.Errorf("unable to interpret %q as string", "id")
		}
		g.id = strings.ToLower(id)
	}
	if rawType, ok := raw["type"]; ok {
		typ, ok := rawType.(string)
		if !ok {
			return fmt.Errorf("unable to interpret %q as string", "type")
		}
		g.typ = resource.Map[typ]
		if g.typ == resource.Unknown {
			return fmt.Errorf("unknown type specifier %q", typ)
		}
	}
	if rawActions, ok := raw["actions"]; ok {
		interfaceActions, ok := rawActions.([]interface{})
		if !ok {
			return fmt.Errorf("unable to interpret %q as array", "actions")
		}
		if len(interfaceActions) > 0 {
			g.actionsBeingParsed = make([]string, 0, len(interfaceActions))
			for _, v := range interfaceActions {
				actionStr, ok := v.(string)
				switch {
				case !ok:
					return fmt.Errorf("unable to interpret %v in actions array as string", v)
				case actionStr == "":
					return errors.New("empty action found")
				default:
					g.actionsBeingParsed = append(g.actionsBeingParsed, strings.ToLower(actionStr))
				}
			}
		}
	}
	return nil
}

func (g *Grant) unmarshalText(grantString string) error {
	segments := strings.Split(grantString, ";")
	for _, segment := range segments {
		kv := strings.Split(segment, "=")

		// Ensure we don't accept "foo=bar=baz", "=foo", or "foo="
		switch {
		case len(kv) != 2:
			return fmt.Errorf("segment %q not formatted correctly, wrong number of equal signs", segment)
		case len(kv[0]) == 0:
			return fmt.Errorf("segment %q not formatted correctly, missing key", segment)
		case len(kv[1]) == 0:
			return fmt.Errorf("segment %q not formatted correctly, missing value", segment)
		}

		switch kv[0] {
		case "id":
			g.id = strings.ToLower(kv[1])

		case "type":
			typeString := strings.ToLower(kv[1])
			g.typ = resource.Map[typeString]
			if g.typ == resource.Unknown {
				return fmt.Errorf("unknown type specifier %q", typeString)
			}

		case "actions":
			actions := strings.Split(kv[1], ",")
			if len(actions) > 0 {
				g.actionsBeingParsed = make([]string, 0, len(actions))
				for _, action := range actions {
					if action == "" {
						return errors.New("empty action found")
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
	if len(grantString) == 0 {
		return Grant{}, errors.New("grant string is empty")
	}

	if scopeId == "" {
		return Grant{}, errors.New("no scope ID provided")
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
		return Grant{}, errors.New("invalid scope type")
	}

	switch {
	case grantString[0] == '{':
		if err := grant.unmarshalJSON([]byte(grantString)); err != nil {
			return Grant{}, fmt.Errorf("unable to parse JSON grant string: %w", err)
		}

	default:
		if err := grant.unmarshalText(grantString); err != nil {
			return Grant{}, fmt.Errorf("unable to parse grant string: %w", err)
		}
	}

	opts := getOpts(opt...)

	// Check for templated values ID, and substitute in with the authenticated values
	// if so
	if grant.id != "" && strings.HasPrefix(grant.id, "{{") {
		id := strings.TrimSuffix(strings.TrimPrefix(grant.id, "{{"), "}}")
		id = strings.ToLower(strings.TrimSpace(id))
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
			return Grant{}, fmt.Errorf("unknown template %q in grant %q value", grant.id, "id")
		}
	}

	if err := grant.validateType(); err != nil {
		return Grant{}, err
	}

	if err := grant.parseAndValidateActions(); err != nil {
		return Grant{}, err
	}

	if !opts.withSkipFinalValidation {
		// Validate the grant. Create a dummy resource and pass it through
		// Allowed and ensure that we get allowed.
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
			return Grant{}, errors.New("parsed grant string would not result in any action being authorized")
		}
	}

	return grant, nil
}

func (g Grant) validateType() error {
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
	return fmt.Errorf("unknown type specifier %q", g.typ)
}

func (g *Grant) parseAndValidateActions() error {
	if len(g.actionsBeingParsed) == 0 {
		return errors.New("no actions specified")
	}

	for _, a := range g.actionsBeingParsed {
		if a == "" {
			return errors.New("empty action found")
		}
		if g.actions == nil {
			g.actions = make(map[action.Type]bool, len(g.actionsBeingParsed))
		}
		if am := action.Map[a]; am == action.Unknown {
			return fmt.Errorf("unknown action %q", a)
		} else {
			g.actions[am] = true
		}
	}

	if len(g.actions) > 1 && g.actions[action.All] {
		return fmt.Errorf("%q cannot be specified with other actions", action.All.String())
	}

	g.actionsBeingParsed = nil

	return nil
}
