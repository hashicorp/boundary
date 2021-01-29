package oidc

import (
	"github.com/hashicorp/boundary/internal/auth/oidc/store"
	"github.com/hashicorp/boundary/internal/errors"
	"github.com/hashicorp/boundary/internal/oplog"
	"google.golang.org/protobuf/proto"
)

type Certificate struct {
	*store.Certificate
	tableName string
}

func NewCertificate(authMethodId string, cert string) (*Certificate, error) {
	const op = "oidc.NewCallbackUrl"

	c := &Certificate{
		Certificate: &store.Certificate{
			OidcMethodId: authMethodId,
			Cert:         cert,
		},
	}
	if err := c.validate(op); err != nil {
		return nil, err // intentionally not wrapped
	}
	return c, nil
}

func (a *Certificate) validate(caller errors.Op) error {
	if a.Cert == "" {
		return errors.New(errors.InvalidParameter, caller, "empty cert")
	}
	return nil
}

func allocCertificate() Certificate {
	return Certificate{
		Certificate: &store.Certificate{},
	}
}

func (c *Certificate) clone() *Certificate {
	cp := proto.Clone(c.Certificate)
	return &Certificate{
		Certificate: cp.(*store.Certificate),
	}
}

// TableName returns the table name.
func (c *Certificate) TableName() string {
	if c.tableName != "" {
		return c.tableName
	}
	return "auth_oidc_certificate"
}

// SetTableName sets the table name.
func (c *Certificate) SetTableName(n string) {
	c.tableName = n
}

func (c *Certificate) oplog(op oplog.OpType, authMethodScopeId string) oplog.Metadata {
	metadata := oplog.Metadata{
		"resource-public-id": []string{c.OidcMethodId}, // the auth method is the root aggregate
		"resource-type":      []string{"oidc auth certificate"},
		"op-type":            []string{op.String()},
	}
	if authMethodScopeId != "" {
		metadata["scope-id"] = []string{authMethodScopeId}
	}
	return metadata
}
