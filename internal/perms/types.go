package perms

import (
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strings"

	"github.com/hashicorp/watchtower/internal/iam"
)

const (
	TypeNone        = ""
	TypeAll         = "*"
	TypeRole        = "role"
	TypeGroup       = "group"
	TypeUser        = "user"
	TypeAuthMethod  = "auth-method"
	TypeHostCatalog = "host-catalog"
	TypeHostSet     = "host-set"
	TypeHost        = "host"
	TypeTarget      = "target"
)

type Scope struct {
	Id   string
	Type iam.ScopeType
}

// Grant is a Go representation of a parsed grant
type Grant struct {
	// The scope ID, which will be a project ID or an org ID
	Scope Scope

	// Project, if defined
	Project string

	// The ID in the grant, if provided.
	Id string

	// The type, if provided
	Type string

	// The set of actions being granted
	Actions map[iam.Action]bool

	// This is used as a temporary staging area before validating permissions to
	// allow the same validation code across grant string formats
	actionsBeingParsed []string
}

func (g Grant) clone() *Grant {
	ret := &Grant{
		Scope:   g.Scope,
		Project: g.Project,
		Id:      g.Id,
		Type:    g.Type,
	}
	if g.actionsBeingParsed != nil {
		ret.actionsBeingParsed = append(ret.actionsBeingParsed, g.actionsBeingParsed...)
	}
	if g.Actions != nil {
		ret.Actions = make(map[iam.Action]bool, len(g.Actions))
		for action := range g.Actions {
			ret.Actions[action] = true
		}
	}
	return ret
}

func (g Grant) CanonicalString() string {
	var builder []string
	if g.Project != "" {
		builder = append(builder, fmt.Sprintf("project=%s", g.Project))
	}

	if g.Id != "" {
		builder = append(builder, fmt.Sprintf("id=%s", g.Id))
	}

	if g.Type != TypeNone {
		builder = append(builder, fmt.Sprintf("type=%s", g.Type))
	}

	if len(g.Actions) > 0 {
		actions := make([]string, 0, len(g.Actions))
		for action := range g.Actions {
			actions = append(actions, action.String())
		}
		sort.Strings(actions)
		builder = append(builder, fmt.Sprintf("actions=%s", strings.Join(actions, ",")))
	}

	return strings.Join(builder, ";")
}

func (g Grant) MarshalJSON() ([]byte, error) {
	res := make(map[string]interface{}, 4)
	if g.Project != "" {
		res["project"] = g.Project
	}
	if g.Id != "" {
		res["id"] = g.Id
	}
	if g.Type != "" {
		res["type"] = g.Type
	}
	if len(g.Actions) > 0 {
		actions := make([]string, 0, len(g.Actions))
		for action := range g.Actions {
			actions = append(actions, action.String())
		}
		sort.Strings(actions)
		res["actions"] = actions
	}
	return json.Marshal(res)
}

// This is purposfully unexported since the values being set here are not being
// checked for validity. This should only be called by the main parsing function
// when JSON is detected.
func (g *Grant) unmarshalJSON(data []byte) error {
	raw := make(map[string]interface{}, 4)
	if err := json.Unmarshal(data, &raw); err != nil {
		return err
	}
	if rawProj, ok := raw["project"]; ok {
		project, ok := rawProj.(string)
		if !ok {
			return fmt.Errorf("unable to interpret %q as string", "project")
		}
		g.Project = strings.ToLower(project)
	}
	if rawId, ok := raw["id"]; ok {
		id, ok := rawId.(string)
		if !ok {
			return fmt.Errorf("unable to interpret %q as string", "id")
		}
		g.Id = strings.ToLower(id)
	}
	if rawType, ok := raw["type"]; ok {
		typ, ok := rawType.(string)
		if !ok {
			return fmt.Errorf("unable to interpret %q as string", "type")
		}
		g.Type = strings.ToLower(typ)
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
				if !ok {
					return fmt.Errorf("unable to interpret %v in actions array as string", v)
				}
				if actionStr == "" {
					return errors.New("empty action found")
				}
				g.actionsBeingParsed = append(g.actionsBeingParsed, strings.ToLower(actionStr))
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
		case "project":
			g.Project = strings.ToLower(kv[1])

		case "id":
			g.Id = strings.ToLower(kv[1])

		case "type":
			g.Type = strings.ToLower(kv[1])

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

// ParseGrantString parses a grant string. Note that this does not do checking
// of the validity of IDs and such; that's left for other parts of the system.
// We may not check at all (e.g. let it be an authz-time failure) or could check
// after submission to catch errors.
//
// The scope must be the org and project where this grant originated, not the
// request.
//
// WARNING: It is the responsibility of the caller to validate that a returned
// Grant matches the incoming scope and if not that the relationship is valid.
// Specifically, if a project is specified as part of a grant, the grant's
// returned scope will be a project scope with the associated project ID. The
// caller must validate that the project ID is valid and that its enclosing
// organization is the original organization scope. Likely this can be done in a
// centralized helper context; however it's not done here to avoid reaching into
// the database from within this package.
func ParseGrantString(scope Scope, grantString string) (Grant, error) {
	if len(grantString) == 0 {
		return Grant{}, errors.New("grant string is empty")
	}

	switch scope.Type {
	case iam.ProjectScope, iam.OrganizationScope:
	default:
		return Grant{}, errors.New("invalid scope type")
	}

	if scope.Id == "" {
		return Grant{}, errors.New("no scope ID provided")
	}

	grant := Grant{
		Scope: scope,
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

	if err := grant.validateAndModifyProject(); err != nil {
		return Grant{}, err
	}

	if err := grant.validateType(); err != nil {
		return Grant{}, err
	}

	if err := grant.parseAndValidateActions(); err != nil {
		return Grant{}, err
	}

	return grant, nil
}

func (g *Grant) validateAndModifyProject() error {
	if g.Project == "" {
		return nil
	}
	if g.Scope.Type != iam.OrganizationScope {
		return errors.New("cannot specify a project in the grant when the scope is not an organization")
	}
	g.Scope.Type = iam.ProjectScope
	g.Scope.Id = g.Project
	return nil
}

func (g Grant) validateType() error {
	switch g.Type {
	case TypeNone,
		TypeAll,
		TypeRole,
		TypeGroup,
		TypeUser,
		TypeAuthMethod,
		TypeHostCatalog,
		TypeHostSet,
		TypeHost,
		TypeTarget:
		return nil
	}
	return fmt.Errorf("unknown type specifier %q", g.Type)
}

func (g *Grant) parseAndValidateActions() error {
	if len(g.actionsBeingParsed) == 0 {
		return errors.New("no actions specified")
	}

	for _, action := range g.actionsBeingParsed {
		if action == "" {
			return errors.New("empty action found")
		}
		if g.Actions == nil {
			g.Actions = make(map[iam.Action]bool, len(g.actionsBeingParsed))
		}
		if a := iam.ActionMap[action]; a == iam.ActionUnknown {
			return fmt.Errorf("unknown action %q", action)
		} else {
			g.Actions[a] = true
		}
	}

	if len(g.Actions) > 1 && g.Actions[iam.ActionAll] {
		return fmt.Errorf("%q cannot be specified with other actions", iam.ActionAll.String())
	}

	g.actionsBeingParsed = nil

	return nil
}
