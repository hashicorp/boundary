// Copyright IBM Corp. 2020, 2025
// SPDX-License-Identifier: BUSL-1.1

package ldap

import (
	"context"
	"fmt"
	"net/url"

	"github.com/hashicorp/boundary/internal/auth/ldap/store"
	"github.com/hashicorp/boundary/internal/errors"
	"github.com/hashicorp/go-secure-stdlib/strutil"
	"google.golang.org/protobuf/proto"
)

const urlTableName = "auth_ldap_url"

// Url represents a required one to many auth method urls.  It is assigned to an
// LDAP AuthMethod and updates/deletes to that AuthMethod are cascaded to its
// Urls.  Urls are value objects of an AuthMethod, therefore there's no need for
// oplog metadata, since only the AuthMethod will have metadata because it's the
// root aggregate.
type Url struct {
	*store.Url
	tableName string
}

// NewUrl creates a new in memory Url.  connectionPriority cannot be less than
// one. No options are currently supported.
func NewUrl(ctx context.Context, authMethodId string, connectionPriority int, url *url.URL, _ ...Option) (*Url, error) {
	const op = "ldap.NewUrl"
	switch {
	case authMethodId == "":
		return nil, errors.New(ctx, errors.InvalidParameter, op, "missing auth method id")
	case connectionPriority < 1:
		return nil, errors.New(ctx, errors.InvalidParameter, op, "connection priority cannot be less than one")
	case url == nil:
		return nil, errors.New(ctx, errors.InvalidParameter, op, "missing url")
	case !strutil.StrListContainsCaseInsensitive([]string{"ldap", "ldaps"}, url.Scheme):
		return nil, errors.New(ctx, errors.InvalidParameter, op, fmt.Sprintf("scheme %q is not ldap or ldaps", url.Scheme))
	}
	return &Url{
		Url: &store.Url{
			LdapMethodId:       authMethodId,
			ServerUrl:          url.String(),
			ConnectionPriority: uint32(connectionPriority),
		},
	}, nil
}

// allocUrl makes an empty one in memory
func allocUrl() *Url {
	return &Url{
		Url: &store.Url{},
	}
}

// clone a Url
func (u *Url) clone() *Url {
	cp := proto.Clone(u.Url)
	return &Url{
		Url: cp.(*store.Url),
	}
}

// TableName returns the table name
func (u *Url) TableName() string {
	if u.tableName != "" {
		return u.tableName
	}
	return urlTableName
}

// SetTableName sets the table name.
func (u *Url) SetTableName(n string) {
	u.tableName = n
}
