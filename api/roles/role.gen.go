// Code generated by "make api"; DO NOT EDIT.
package roles

import (
	"encoding/json"
	"time"

	"github.com/fatih/structs"

	"github.com/hashicorp/watchtower/api"
	"github.com/hashicorp/watchtower/api/internal/strutil"
)

type Role struct {
	Client *api.Client `json:"-"`

	defaultFields []string

	// The ID of the Role
	// Output only.
	Id string `json:"id,omitempty"`
	// Optional name for identification purposes
	Name *string `json:"name,omitempty"`
	// Optional user-set description for identification purposes
	Description *string `json:"description,omitempty"`
	// The time this resource was created
	// Output only.
	CreatedTime time.Time `json:"created_time,omitempty"`
	// The time this resource was last updated.
	// Output only.
	UpdatedTime time.Time `json:"updated_time,omitempty"`
	// Whether the resource is disabled
	Disabled *bool `json:"disabled,omitempty"`
	// The scope the grants will apply to. If the role is at the global scope,
	// this can be an organization or project. If the role is at an organization
	// scope, this can be a project within the organization. It is invalid for
	// this to be anything other than the role's scope when the role's scope is
	// a project.
	GrantScopeId *string `json:"grant_scope_id,omitempty"`
	// The version can be used in subsiquent write requests to ensure this resource
	// has not changed and to fail the write if it has.
	// Output only.
	Version *uint32 `json:"version,omitempty"`
	// The principals that are assigned this role.
	// Output only.
	UserIds []string `json:"user_ids,omitempty"`
	// Output only.
	GroupIds []string `json:"group_ids,omitempty"`
	// The grants that this role provides for it's principals.
	// Output only.
	Grants []string `json:"grants,omitempty"`
	// The canonical version of the grants in the grants field with the same index.
	// Output only.
	GrantsCanonical []string `json:"grants_canonical,omitempty"`
	// The JSON version of the grants in the grants field with the same index.
	// Output only.
	GrantsJson []string `json:"grants_json,omitempty"`
}

func (s *Role) SetDefault(key string) {
	s.defaultFields = strutil.AppendIfMissing(s.defaultFields, key)
}

func (s *Role) UnsetDefault(key string) {
	s.defaultFields = strutil.StrListDelete(s.defaultFields, key)
}

func (s Role) MarshalJSON() ([]byte, error) {
	m := structs.Map(s)
	if m == nil {
		m = make(map[string]interface{})
	}
	for _, k := range s.defaultFields {
		m[k] = nil
	}
	return json.Marshal(m)
}
