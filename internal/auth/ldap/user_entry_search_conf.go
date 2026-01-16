// Copyright IBM Corp. 2020, 2025
// SPDX-License-Identifier: BUSL-1.1

package ldap

import (
	"context"

	"github.com/hashicorp/boundary/internal/auth/ldap/store"
	"github.com/hashicorp/boundary/internal/errors"
	"google.golang.org/protobuf/proto"
)

const userEntrySearchConfTableName = "auth_ldap_user_entry_search"

// UserEntrySearchConf represent a set of optional configuration fields used to
// search for user entries.  It is assigned to an LDAP AuthMethod and
// updates/deletes to that AuthMethod are cascaded to its UserEntrySearchConf.
// UserEntrySearchConf are value objects of an AuthMethod, therefore there's no
// need for oplog metadata, since only the AuthMethod will have metadata because
// it's the root aggregate.
type UserEntrySearchConf struct {
	*store.UserEntrySearchConf
	tableName string
}

// NewUserEntrySearchConf creates a new in memory NewUserEntrySearchConf.
// Supported options are: WithUserDn, WithUserAttr, WithUserFilter and all other
// options are ignored.
func NewUserEntrySearchConf(ctx context.Context, authMethodId string, opt ...Option) (*UserEntrySearchConf, error) {
	const op = "ldap.NewUserEntrySearchConf"
	opts, err := getOpts(opt...)
	if err != nil {
		return nil, errors.Wrap(ctx, err, op)
	}
	switch {
	case authMethodId == "":
		return nil, errors.New(ctx, errors.InvalidParameter, op, "missing auth method id")
	case opts.withUserDn == "" && opts.withUserAttr == "" && opts.withUserFilter == "":
		return nil, errors.New(ctx, errors.InvalidParameter, op, "you must supply either dn, attr, or filter")
	}
	return &UserEntrySearchConf{
		UserEntrySearchConf: &store.UserEntrySearchConf{
			LdapMethodId: authMethodId,
			UserDn:       opts.withUserDn,
			UserAttr:     opts.withUserAttr,
			UserFilter:   opts.withUserFilter,
		},
	}, nil
}

// allocUserEntrySearchConf makes an empty one in memory
func allocUserEntrySearchConf() *UserEntrySearchConf {
	return &UserEntrySearchConf{
		UserEntrySearchConf: &store.UserEntrySearchConf{},
	}
}

// clone a UserEntrySearchConf
func (uc *UserEntrySearchConf) clone() *UserEntrySearchConf {
	cp := proto.Clone(uc.UserEntrySearchConf)
	return &UserEntrySearchConf{
		UserEntrySearchConf: cp.(*store.UserEntrySearchConf),
	}
}

// TableName returns the table name
func (uc *UserEntrySearchConf) TableName() string {
	if uc.tableName != "" {
		return uc.tableName
	}
	return userEntrySearchConfTableName
}

// SetTableName sets the table name.
func (uc *UserEntrySearchConf) SetTableName(n string) {
	uc.tableName = n
}
