// Copyright IBM Corp. 2020, 2025
// SPDX-License-Identifier: BUSL-1.1

package ldap

import (
	"context"

	"github.com/hashicorp/boundary/internal/auth/ldap/store"
	"github.com/hashicorp/boundary/internal/errors"
	"google.golang.org/protobuf/proto"
)

const groupEntrySearchConfTableName = "auth_ldap_group_entry_search"

// GroupEntrySearchConf represent a set of optional configuration fields used to
// search for group entries.  It is assigned to an LDAP AuthMethod and
// updates/deletes to that AuthMethod are cascaded to its GroupEntrySearchConf.
// GroupEntrySearchConf are value objects of an AuthMethod, therefore there's no
// need for oplog metadata, since only the AuthMethod will have metadata because
// it's the root aggregate.
type GroupEntrySearchConf struct {
	*store.GroupEntrySearchConf
	tableName string
}

// NewGroupEntrySearchConf creates a new in memory NewGroupEntrySearchConf.
// Supported options are: WithGroupDn, WithGroupAttr, WithGroupFilter and all
// other options are ignored.
func NewGroupEntrySearchConf(ctx context.Context, authMethodId string, opt ...Option) (*GroupEntrySearchConf, error) {
	const op = "ldap.NewGroupEntrySearchConf"
	opts, err := getOpts(opt...)
	if err != nil {
		return nil, errors.Wrap(ctx, err, op)
	}
	switch {
	case authMethodId == "":
		return nil, errors.New(ctx, errors.InvalidParameter, op, "missing auth method id")
	case opts.withGroupDn == "" && opts.withGroupAttr == "" && opts.withGroupFilter == "":
		return nil, errors.New(ctx, errors.InvalidParameter, op, "you must supply either dn, attr, or filter")
	}
	return &GroupEntrySearchConf{
		GroupEntrySearchConf: &store.GroupEntrySearchConf{
			LdapMethodId: authMethodId,
			GroupDn:      opts.withGroupDn,
			GroupAttr:    opts.withGroupAttr,
			GroupFilter:  opts.withGroupFilter,
		},
	}, nil
}

// allocGroupEntrySearchConf makes an empty one in memory
func allocGroupEntrySearchConf() *GroupEntrySearchConf {
	return &GroupEntrySearchConf{
		GroupEntrySearchConf: &store.GroupEntrySearchConf{},
	}
}

// clone a GroupEntrySearchConf
func (gc *GroupEntrySearchConf) clone() *GroupEntrySearchConf {
	cp := proto.Clone(gc.GroupEntrySearchConf)
	return &GroupEntrySearchConf{
		GroupEntrySearchConf: cp.(*store.GroupEntrySearchConf),
	}
}

// TableName returns the table name
func (gc *GroupEntrySearchConf) TableName() string {
	if gc.tableName != "" {
		return gc.tableName
	}
	return groupEntrySearchConfTableName
}

// SetTableName sets the table name.
func (gc *GroupEntrySearchConf) SetTableName(n string) {
	gc.tableName = n
}
