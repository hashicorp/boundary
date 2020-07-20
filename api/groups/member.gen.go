// Code generated by "make api"; DO NOT EDIT.
package groups

import (
	"github.com/hashicorp/watchtower/api"
)

type Member struct {
	Client *api.Client `json:"-"`

	// The ID of the member.
	// Output only.
	Id string `json:"id,omitempty"`
	// The type of the member.
	// Output only.
	Type string `json:"type,omitempty"`
	// The scope ID of the member.
	// Output only.
	ScopeId string `json:"scope_id,omitempty"`
}
