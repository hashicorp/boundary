// Copyright IBM Corp. 2020, 2025
// SPDX-License-Identifier: BUSL-1.1

package oidc

import (
	"context"

	"github.com/hashicorp/boundary/internal/auth/oidc/store"
	"github.com/hashicorp/boundary/internal/errors"
	"google.golang.org/protobuf/proto"
)

// defaultAudClaimTableName defines the default table name for an AudClaim
const defaultAudClaimTableName = "auth_oidc_aud_claim"

// AudClaim defines an audience claim for an OIDC auth method.  It is assigned
// to an OIDC AuthMethod and updates/deletes to that AuthMethod are cascaded to
// its AudClaims.  AudClaims are value objects of an AuthMethod, therefore
// there's no need for oplog metadata, since only the AuthMethod will have
// metadata because it's the root aggregate.
//
// see aud claim in the oidc spec:
// https://openid.net/specs/openid-connect-core-1_0.html#AuthRequest
type AudClaim struct {
	*store.AudClaim
	tableName string
}

// NewAudClaim creates a new in memory audience claim assigned to an OIDC
// AuthMethod. It supports no options.  If an AuthMethod as assigned AudClaims,
// then ID tokens issued from the provider must contain one of the assigned
// audiences to be valid.
//
// For more info on oidc aud claims, see the oidc spec:
// https://openid.net/specs/openid-connect-core-1_0.html#AuthRequest
func NewAudClaim(ctx context.Context, authMethodId string, audClaim string) (*AudClaim, error) {
	const op = "oidc.NewAudClaim"

	c := &AudClaim{
		AudClaim: &store.AudClaim{
			OidcMethodId: authMethodId,
			Aud:          audClaim,
		},
	}
	if err := c.validate(ctx, op); err != nil {
		return nil, err // intentionally not wrapped
	}
	return c, nil
}

// validate the AudClaim.  On success, it will return nil.
func (c *AudClaim) validate(ctx context.Context, caller errors.Op) error {
	if c.OidcMethodId == "" {
		return errors.New(ctx, errors.InvalidParameter, caller, "missing oidc auth method id")
	}
	if c.Aud == "" {
		return errors.New(ctx, errors.InvalidParameter, caller, "missing aud claim")
	}
	return nil
}

// AllocAudClaim make an empty one in memory.
func AllocAudClaim() AudClaim {
	return AudClaim{
		AudClaim: &store.AudClaim{},
	}
}

// Clone an AudClaim
func (c *AudClaim) Clone() *AudClaim {
	cp := proto.Clone(c.AudClaim)
	return &AudClaim{
		AudClaim: cp.(*store.AudClaim),
	}
}

// TableName returns the table name.
func (c *AudClaim) TableName() string {
	if c.tableName != "" {
		return c.tableName
	}
	return defaultAudClaimTableName
}

// SetTableName sets the table name.
func (c *AudClaim) SetTableName(n string) {
	c.tableName = n
}
