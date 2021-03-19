package oidc

import (
	"net/url"

	"github.com/hashicorp/boundary/internal/auth/oidc/store"
	"github.com/hashicorp/boundary/internal/errors"
	"google.golang.org/protobuf/proto"
)

// defaultCallbackUrlTableName defines the default table name for a CallbackUrl
const defaultCallbackUrlTableName = "auth_oidc_callback_url"

// CallbackUrl defines an callback URL for an OIDC auth method. It is assigned
// to an OIDC AuthMethod and updates/deletes to that AuthMethod are cascaded to
// its CallbackUrls.  CallbackUrls are value objects of an AuthMethod, therefore
// there's no need for oplog metadata, since only the AuthMethod will have
// metadata because it's the root aggregate.
//
// see redirect_uri in the oidc spec:
// https://openid.net/specs/openid-connect-core-1_0.html#AuthRequest
type CallbackUrl struct {
	*store.CallbackUrl
	tableName string
}

// NewCallbackUrl creates a new in memory callback assigned to an OIDC
// AuthMethod.  It supports no options.
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
	return defaultCallbackUrlTableName
}

// SetTableName sets the table name.
func (c *CallbackUrl) SetTableName(n string) {
	c.tableName = n
}
