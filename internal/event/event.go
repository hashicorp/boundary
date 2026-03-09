// Copyright IBM Corp. 2020, 2025
// SPDX-License-Identifier: BUSL-1.1

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
	ClientIp string `json:"client_ip,omitempty" class:"public"`
}

// UserInfo defines the fields captured about a user for a Boundary request.
type UserInfo struct {
	UserId        string `json:"id,omitempty" class:"public"`
	AuthAccountId string `json:"auth_account_id,omitempty" class:"public"`
}

type GrantsInfo struct {
	Grants []Grant `json:"grants,omitempty"`
}

type Grant struct {
	Grant   string `json:"grant,omitempty" class:"public"`
	ScopeId string `json:"scope_id,omitempty" class:"public"`
	RoleId  string `json:"role_id,omitempty" class:"public"`
}

type Auth struct {
	DisabledAuthEntirely *bool       `json:"disabled_auth_entirely,omitempty" class:"public"`
	AuthTokenId          string      `json:"auth_token_id" class:"public"`
	UserInfo             *UserInfo   `json:"user_info,omitempty"` // boundary field
	GrantsInfo           *GrantsInfo `json:"grants_info,omitempty"`
	UserEmail            string      `json:"email,omitempty" class:"sensitive"`
	UserName             string      `json:"name,omitempty" class:"sensitive"`
}

type Request struct {
	Operation              string           `json:"operation,omitempty" class:"public"` // std audit field
	Endpoint               string           `json:"endpoint,omitempty" class:"public"`  // std audit field
	Details                proto.Message    `json:"details,omitempty"`                  // boundary field
	DetailsUpstreamMessage *UpstreamMessage `json:"details_upstream_message,omitempty"` // boundary field
	UserAgents             []*UserAgent     `json:"user_agents,omitempty"`              // boundary field
}

type Response struct {
	StatusCode             int              `json:"status_code,omitempty"`              // std audit
	Details                proto.Message    `json:"details,omitempty"`                  // boundary field
	DetailsUpstreamMessage *UpstreamMessage `json:"details_upstream_message,omitempty"` // boundary field
}

type UpstreamMessage struct {
	Type    string        `json:"type,omitempty" class:"public"` // boundary field
	Message proto.Message `json:"message,omitempty"`             // boundary field
}

// UserAgent defines the fields parsed from a request's User-Agent header.
type UserAgent struct {
	Product        string   `json:"product,omitempty"`         // product identifier
	ProductVersion string   `json:"product_version,omitempty"` // version number of the product
	Comments       []string `json:"comments,omitempty"`        // comments about the product
}
