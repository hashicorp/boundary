package event

type Type string

const (
	EveryType       Type = "*"
	ObservationType Type = "observation"
	AuditType       Type = "audit"
	ErrorType       Type = "error"
)

type Id string
type Op string

// RequestInfo defines the fields captured about a Boundary request.  This type
// is duplicated in the internal/auth package, but there are circular dependency
// issues.  TBD how to resolve this, but for now, we've dupped it here.
//
// fields are intentionally alphabetically ordered so they will match output
// from marshaling event json
type RequestInfo struct {
	Id       string    `json:"id,omitempty"`
	Method   string    `json:"method,omitempty"`
	Path     string    `json:"path,omitempty"`
	PublicId string    `json:"public_id,omitempty"`
	UserInfo *UserInfo `json:"user_info,omitempty"`
}

// UserInfo defines the fields captured about a user for a Boundary request.
// This type is duplicated in the internal/auth package, but there are circular
// dependency issues.  TBD how to resolve this, but for now, we've dupped it
// here.
//
// fields are intentionally alphabetically ordered so they will match output
// from marshaling event json
type UserInfo struct {
	Grants []GrantsPair `json:"grants_pair,omitempty"`
	Id     string       `json:"id,omitempty"`
}

// UserInfo defines the fields captured about a user for a Boundary request.
// This type is duplicated in the internal/perms package, but there are circular
// dependency issues.  TBD how to resolve this, but for now, we've dupped it
// here.
//
// fields are intentionally alphabetically ordered so they will match output
// from marshaling event json
type GrantsPair struct {
	Grant   string `json:"grant,omitempty"`
	ScopeId string `json:"scope_id,omitempty"`
}
