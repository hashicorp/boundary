package oidc

import (
	"github.com/hashicorp/boundary/internal/auth/oidc/store"
	"github.com/hashicorp/boundary/internal/errors"
	"github.com/hashicorp/boundary/internal/oplog"
	"google.golang.org/protobuf/proto"
)

type AudClaim struct {
	*store.AudClaim
	tableName string
}

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

func (a *AudClaim) validate(caller errors.Op) error {
	if a.Aud == "" {
		return errors.New(errors.InvalidParameter, caller, "empty aud claim")
	}
	return nil
}

func allocAudClaim() AudClaim {
	return AudClaim{
		AudClaim: &store.AudClaim{},
	}
}

func (c *AudClaim) clone() *AudClaim {
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
	return "auth_oidc_aud_claim"
}

// SetTableName sets the table name.
func (c *AudClaim) SetTableName(n string) {
	c.tableName = n
}

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
