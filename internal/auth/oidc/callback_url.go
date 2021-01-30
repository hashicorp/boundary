package oidc

import (
	"net/url"

	"github.com/hashicorp/boundary/internal/auth/oidc/store"
	"github.com/hashicorp/boundary/internal/errors"
	"github.com/hashicorp/boundary/internal/oplog"
	"google.golang.org/protobuf/proto"
)

// DefaultAuthMethodTableName defines the default table name for a CallbackUrl
const DefaultCallbackUrlTableName = "auth_oidc_callback_url"

// CallbackUrl defines an callback URL for an OIDC auth method.  Callbacks are
// "owned" by their coresponding OIDC auth method.
//
// see redirect_uri in the oidc spec:
// https://openid.net/specs/openid-connect-core-1_0.html#AuthRequest
type CallbackUrl struct {
	*store.CallbackUrl
	tableName string
}

// NewCallbackUrl creates a new in memory callback for an OIDC AuthMethod.  It
// supports no options.
//
// For more info on oidc callbacks, see redirect_uri in the oidc spec:
// https://openid.net/specs/openid-connect-core-1_0.html#AuthRequest
func NewCallbackUrl(authMethodId string, callback *url.URL) (*CallbackUrl, error) {
	const op = "oidc.NewCallbackUrl"
	if callback == nil {
		return nil, errors.New(errors.InvalidParameter, op, "nil callback url")
	}
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

// validate the CallbackUrl.  On success, it will return nil.
func (c *CallbackUrl) validate(caller errors.Op) error {
	if c.OidcMethodId == "" {
		return errors.New(errors.InvalidParameter, caller, "missing oidc auth method id")
	}
	if _, err := url.Parse(c.Url); err != nil {
		return errors.New(errors.InvalidParameter, caller, "not a valid callback URL", errors.WithWrap(err))
	}
	return nil
}

// AllocCallbackUrl makes an empty one in memory
func AllocCallbackUrl() CallbackUrl {
	return CallbackUrl{
		CallbackUrl: &store.CallbackUrl{},
	}
}

// Clone a CallbackUrl
func (c *CallbackUrl) Clone() *CallbackUrl {
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
	return DefaultCallbackUrlTableName
}

// SetTableName sets the table name.
func (c *CallbackUrl) SetTableName(n string) {
	c.tableName = n
}

// oplog will create oplog metadata for the CallbackUrl.
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
