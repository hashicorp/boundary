// Code generated by "make api"; DO NOT EDIT.
package roles

import (
	"encoding/json"
	"strings"
	"time"

	"github.com/fatih/structs"

	"github.com/hashicorp/watchtower/api"
	"github.com/hashicorp/watchtower/api/info"
	"github.com/hashicorp/watchtower/api/internal/strutil"
)

type Role struct {
	Client *api.Client `json:"-"`

	defaultFields []string

	// The ID of the Role
	// Output only.
	Id string `json:"id,omitempty"`
	// Scope information for this resource
	// Output only.
	Scope info.Scope `json:"scope,omitempty"`
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
	// this can be an org or project. If the role is at an org
	// scope, this can be a project within the org. It is invalid for
	// this to be anything other than the role's scope when the role's scope is
	// a project.
	GrantScopeId *string `json:"grant_scope_id,omitempty"`
	// The version can be used in subsiquent write requests to ensure this resource
	// has not changed and to fail the write if it has.
	// Output only.
	Version uint32 `json:"version,omitempty"`
	// The IDs (only) of principals that are assigned to this role.
	// Output only.
	PrincipalIds []string `json:"principal_ids,omitempty"`
	// The principals that are assigned to this role.
	// Output only.
	Principals []*Principal `json:"principals,omitempty"`
	// The grants that this role provides for its principals.
	// Output only.
	GrantStrings []string `json:"grant_strings,omitempty"`
	// The parsed grant information.
	// Output only.
	Grants []*Grant `json:"grants,omitempty"`
}

func (s *Role) SetDefault(key string) {
	lowerKey := strings.ToLower(key)
	validMap := map[string]string{"createdtime": "created_time", "description": "description", "disabled": "disabled", "grants": "grants", "grantscopeid": "grant_scope_id", "grantstrings": "grant_strings", "id": "id", "name": "name", "principalids": "principal_ids", "principals": "principals", "scope": "scope", "updatedtime": "updated_time", "version": "version"}
	for k, v := range validMap {
		if k == lowerKey || v == lowerKey {
			s.defaultFields = strutil.AppendIfMissing(s.defaultFields, v)
			return
		}
	}
}

func (s *Role) UnsetDefault(key string) {
	lowerKey := strings.ToLower(key)
	validMap := map[string]string{"createdtime": "created_time", "description": "description", "disabled": "disabled", "grants": "grants", "grantscopeid": "grant_scope_id", "grantstrings": "grant_strings", "id": "id", "name": "name", "principalids": "principal_ids", "principals": "principals", "scope": "scope", "updatedtime": "updated_time", "version": "version"}
	for k, v := range validMap {
		if k == lowerKey || v == lowerKey {
			s.defaultFields = strutil.StrListDelete(s.defaultFields, v)
			return
		}
	}
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
