package event

import (
	"google.golang.org/protobuf/proto"
)

type (
	Id string
	Op string
)

// RequestInfo defines the fields captured about a Boundary request.
type RequestInfo struct {
	EventId  string `json:"-"`
	Id       string `json:"id,omitempty" class:"public"`
	Method   string `json:"method,omitempty" class:"public"`
	Path     string `json:"path,omitempty" class:"public"`
	PublicId string `json:"public_id,omitempty" class:"public"`
}

// UserInfo defines the fields captured about a user for a Boundary request.
type UserInfo struct {
	UserId        string `json:"id,omitempty"`
	AuthAccountId string `json:"auth_account_id,omitempty"`
}

type GrantsInfo struct {
	Grants []GrantsPair `json:"grants_pair,omitempty"`
}

type GrantsPair struct {
	Grant   string `json:"grant,omitempty"`
	ScopeId string `json:"scope_id,omitempty"`
}

type Auth struct {
	// AccessorId is a std audit field == auth_token public_id
	AccessorId string      `json:"accessor_id"`
	UserInfo   *UserInfo   `json:"user_info,omitempty"` // boundary field
	GrantsInfo *GrantsInfo `json:"grants_info,omitempty"`
	UserEmail  string      `json:"email,omitempty"`
	UserName   string      `json:"name,omitempty"`
}

type Request struct {
	Operation string        `json:"operation,omitempty" class:"public"` // std audit field
	Endpoint  string        `json:"endpoint,omitempty" class:"public"`  // std audit field
	Details   proto.Message `json:"details,omitempty"`                  // boundary field
}

type Response struct {
	StatusCode int           `json:"status_code,omitempty"` // std audit
	Details    proto.Message `json:"details,omitempty"`     // boundary field
}
