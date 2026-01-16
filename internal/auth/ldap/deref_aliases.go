// Copyright IBM Corp. 2020, 2025
// SPDX-License-Identifier: BUSL-1.1

package ldap

import (
	"context"

	"github.com/hashicorp/boundary/internal/auth/ldap/store"
	"github.com/hashicorp/boundary/internal/errors"
	"google.golang.org/protobuf/proto"
)

const derefAliasesTableName = "auth_ldap_deref_aliases"

// DerefAliases represent optional config parameters which allow Boundary to
// properly dereference aliases when ldap searching
type DerefAliases struct {
	*store.DerefAliases
	tableName string
}

// NewDerefAliases creates a new in memory NewDerefAliases. No options are currently supported.
func NewDerefAliases(ctx context.Context, authMethodId string, derefType DerefAliasType) (*DerefAliases, error) {
	const op = "ldap.NewDerefAliases"
	switch {
	case authMethodId == "":
		return nil, errors.New(ctx, errors.InvalidParameter, op, "missing auth method id")
	case derefType == "":
		return nil, errors.New(ctx, errors.InvalidParameter, op, "missing dereference alias type")
	default:
		if err := derefType.IsValid(ctx); err != nil {
			return nil, errors.Wrap(ctx, err, op)
		}
	}
	return &DerefAliases{
		DerefAliases: &store.DerefAliases{
			LdapMethodId:       authMethodId,
			DereferenceAliases: string(derefType),
		},
	}, nil
}

// allocDerefAliases makes an empty one in memory
func allocDerefAliases() *DerefAliases {
	return &DerefAliases{
		DerefAliases: &store.DerefAliases{},
	}
}

// clone a deref aliases
func (da *DerefAliases) clone() *DerefAliases {
	cp := proto.Clone(da.DerefAliases)
	return &DerefAliases{
		DerefAliases: cp.(*store.DerefAliases),
	}
}

// TableName returns the table name
func (da *DerefAliases) TableName() string {
	if da.tableName != "" {
		return da.tableName
	}
	return derefAliasesTableName
}

// SetTableName sets the table name.
func (da *DerefAliases) SetTableName(n string) {
	da.tableName = n
}
