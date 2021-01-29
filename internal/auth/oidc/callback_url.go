package oidc

import (
	"net/url"

	"github.com/hashicorp/boundary/internal/auth/oidc/store"
	"github.com/hashicorp/boundary/internal/errors"
	"github.com/hashicorp/boundary/internal/oplog"
	"google.golang.org/protobuf/proto"
)

type CallbackUrl struct {
	*store.CallbackUrl
	tableName string
}

func NewCallbackUrl(authMethodId string, callback *url.URL) (*CallbackUrl, error) {
	const op = "oidc.NewCallbackUrl"

	c := &CallbackUrl{
		CallbackUrl: &store.CallbackUrl{
			OidcMethodId: authMethodId,
			Url:          callback.String(),
		},
	}
	if err := c.validate(op); err != nil {
		return nil, err // intentionally not wrapped
	}
	return c, nil
}

func (a *CallbackUrl) validate(caller errors.Op) error {
	if a.Url == "" {
		return errors.New(errors.InvalidParameter, caller, "empty callback URL")
	}
	return nil
}

func allocCallbackUrl() CallbackUrl {
	return CallbackUrl{
		CallbackUrl: &store.CallbackUrl{},
	}
}

func (c *CallbackUrl) clone() *CallbackUrl {
	cp := proto.Clone(c.CallbackUrl)
	return &CallbackUrl{
		CallbackUrl: cp.(*store.CallbackUrl),
	}
}

// TableName returns the table name.
func (c *CallbackUrl) TableName() string {
	if c.tableName != "" {
		return c.tableName
	}
	return "auth_oidc_callback_url"
}

// SetTableName sets the table name.
func (c *CallbackUrl) SetTableName(n string) {
	c.tableName = n
}

func (c *CallbackUrl) oplog(op oplog.OpType, authMethodScopeId string) oplog.Metadata {
	metadata := oplog.Metadata{
		"resource-public-id": []string{c.OidcMethodId}, // the auth method is the root aggregate
		"resource-type":      []string{"oidc auth callback url"},
		"op-type":            []string{op.String()},
	}
	if authMethodScopeId != "" {
		metadata["scope-id"] = []string{authMethodScopeId}
	}
	return metadata
}
