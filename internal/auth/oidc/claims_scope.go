package oidc

import (
	"github.com/hashicorp/boundary/internal/auth/oidc/store"
	"github.com/hashicorp/boundary/internal/errors"
	"google.golang.org/protobuf/proto"
)

// defaultClaimsScopeTableName defines the default table name for an ClaimsScope
const defaultClaimsScopeTableName = "auth_oidc_scope"

// ClaimsScope defines optional OIDC scope values that are used to request
// claims, in addition to the default scope of "openid".
//
// see: https://openid.net/specs/openid-connect-core-1_0.html#ScopeClaims
type ClaimsScope struct {
	*store.ClaimsScope
	tableName string
}

func NewClaimsScope(authMethodId, claimsScope string) (*ClaimsScope, error) {
	const op = "oidc.NewClaimsScope"
	cs := &ClaimsScope{
		ClaimsScope: &store.ClaimsScope{
			OidcMethodId: authMethodId,
			Scope:        claimsScope,
		},
	}
	if err := cs.validate(op); err != nil {
		return nil, err
	}
	return cs, nil
}

// validate the ClaimsScope.  On success, it will return nil.
func (cs *ClaimsScope) validate(caller errors.Op) error {
	if cs.OidcMethodId == "" {
		return errors.New(errors.InvalidParameter, caller, "missing oidc auth method id")
	}
	if cs.Scope == "" {
		return errors.New(errors.InvalidParameter, caller, "missing claims scope")
	}
	return nil
}

// AllocClaimsScope makes an empty one in memory
func AllocClaimsScope() ClaimsScope {
	return ClaimsScope{
		ClaimsScope: &store.ClaimsScope{},
	}
}

// Clone a ClaimsScope
func (cs *ClaimsScope) Clone() *ClaimsScope {
	cp := proto.Clone(cs.ClaimsScope)
	return &ClaimsScope{
		ClaimsScope: cp.(*store.ClaimsScope),
	}
}

// TableName returns the table name.
func (s *ClaimsScope) TableName() string {
	if s.tableName != "" {
		return s.tableName
	}
	return defaultClaimsScopeTableName
}

// SetTableName sets the table name.
func (s *ClaimsScope) SetTableName(n string) {
	s.tableName = n
}
