package oidc

import (
	"github.com/hashicorp/boundary/internal/auth/oidc/store"
	"github.com/hashicorp/boundary/internal/errors"
	"github.com/hashicorp/boundary/internal/oplog"
	"google.golang.org/protobuf/proto"
)

// DefaultAudClaimTableName defines the default table name for an AudClaim
const DefaultAudClaimTableName = "auth_oidc_aud_claim"

// AudClaim defines an audience claim for an OIDC auth method.  It is assigned
// to an OIDC AuthMethod and updates/deletes to that AuthMethod are cascaded to
// its AudClaims.
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
func NewAudClaim(authMethodId string, audClaim string) (*AudClaim, error) {
	const op = "oidc.NewCallbackUrl"

	c := &AudClaim{
		AudClaim: &store.AudClaim{
			OidcMethodId: authMethodId,
			Aud:          audClaim,
		},
	}
	if err := c.validate(op); err != nil {
		return nil, err // intentionally not wrapped
	}
	return c, nil
}

// validate the AudClaim.  On success, it will return nil.
func (a *AudClaim) validate(caller errors.Op) error {
	if a.OidcMethodId == "" {
		return errors.New(errors.InvalidParameter, caller, "missing oidc auth method id")
	}
	if a.Aud == "" {
		return errors.New(errors.InvalidParameter, caller, "empty aud claim")
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
	return DefaultAudClaimTableName
}

// SetTableName sets the table name.
func (c *AudClaim) SetTableName(n string) {
	c.tableName = n
}

// oplog will create oplog metadata for the AudClaim.
func (c *AudClaim) oplog(op oplog.OpType, authMethodScopeId string) oplog.Metadata {
	metadata := oplog.Metadata{
		"resource-public-id": []string{c.OidcMethodId}, // the auth method is the root aggregate
		"resource-type":      []string{"oidc auth aud claim"},
		"op-type":            []string{op.String()},
	}
	if authMethodScopeId != "" {
		metadata["scope-id"] = []string{authMethodScopeId}
	}
	return metadata
}
