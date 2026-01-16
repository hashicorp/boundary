// Copyright IBM Corp. 2020, 2025
// SPDX-License-Identifier: BUSL-1.1

package oidc

import (
	"context"

	"github.com/hashicorp/boundary/internal/auth/oidc/store"
	"github.com/hashicorp/boundary/internal/errors"
	"google.golang.org/protobuf/proto"
)

const (
	// defaultClaimsScopeTableName defines the default table name for an ClaimsScope
	defaultClaimsScopeTableName = "auth_oidc_scope"

	DefaultClaimsScope = "openid"
)

// ClaimsScope defines optional OIDC scope values that are used to request
// claims, in addition to the default scope of "openid" (see: DefaultClaimsScope).
//
// see: https://openid.net/specs/openid-connect-core-1_0.html#ScopeClaims
type ClaimsScope struct {
	*store.ClaimsScope
	tableName string
}

func NewClaimsScope(ctx context.Context, authMethodId, claimsScope string) (*ClaimsScope, error) {
	const op = "oidc.NewClaimsScope"
	cs := &ClaimsScope{
		ClaimsScope: &store.ClaimsScope{
			OidcMethodId: authMethodId,
			Scope:        claimsScope,
		},
	}
	if err := cs.validate(ctx, op); err != nil {
		return nil, err
	}
	return cs, nil
}

// validate the ClaimsScope.  On success, it will return nil.
func (s *ClaimsScope) validate(ctx context.Context, caller errors.Op) error {
	if s.OidcMethodId == "" {
		return errors.New(ctx, errors.InvalidParameter, caller, "missing oidc auth method id")
	}
	if s.Scope == "" {
		return errors.New(ctx, errors.InvalidParameter, caller, "missing claims scope")
	}
	if s.Scope == DefaultClaimsScope {
		return errors.New(ctx, errors.InvalidParameter, caller, "openid is the default scope and cannot be added as optional")
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
func (s *ClaimsScope) Clone() *ClaimsScope {
	cp := proto.Clone(s.ClaimsScope)
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
