// Copyright IBM Corp. 2020, 2025
// SPDX-License-Identifier: BUSL-1.1

package ldap

import (
	"context"
	"fmt"
	"sort"
	"strings"

	"github.com/hashicorp/boundary/internal/auth/ldap/store"
	"github.com/hashicorp/boundary/internal/errors"
	"golang.org/x/exp/slices"
	"google.golang.org/protobuf/proto"
)

const (
	acctAttributeMapTableName = "auth_ldap_account_attribute_map"
)

// AccountToAttribute defines a type for: to account attributes
type AccountToAttribute string

const (
	// ToEmailAttribute defines the valid email attribute name
	ToEmailAttribute AccountToAttribute = "email"
	// ToFullNameAttribute defines the valid full name attribute name
	ToFullNameAttribute AccountToAttribute = "fullName"
)

// ConvertToAccountToAttribute will convert a string to an AccountToAttribute.
// Useful within the ldap package and service packages which wish to
// convert/validate a string into an AccountToAttribute
func ConvertToAccountToAttribute(ctx context.Context, s string) (AccountToAttribute, error) {
	const op = "ldap.ConvertToAccountToAttribute"
	switch {
	case strings.EqualFold(s, string(ToEmailAttribute)):
		return ToEmailAttribute, nil
	case strings.EqualFold(s, string(ToFullNameAttribute)):
		return ToFullNameAttribute, nil
	default:
		return "", errors.New(ctx, errors.InvalidParameter, op, fmt.Sprintf("%q is not a valid ToAccountAttribute value (%q, %q)", s, ToEmailAttribute, ToFullNameAttribute))
	}
}

// AccountAttributeMap defines optional from/to account attribute maps.
type AccountAttributeMap struct {
	*store.AccountAttributeMap
	tableName string
}

// NewAccountAttributeMap creates a new one in memory
func NewAccountAttributeMap(ctx context.Context, authMethodId, fromAttribute string, toAttribute AccountToAttribute) (*AccountAttributeMap, error) {
	const op = "ldap.NewAccountAttributeMap"
	aam := &AccountAttributeMap{
		AccountAttributeMap: &store.AccountAttributeMap{
			LdapMethodId:  authMethodId,
			FromAttribute: fromAttribute,
			ToAttribute:   string(toAttribute),
		},
	}
	if err := aam.validate(ctx, op); err != nil {
		return nil, err
	}
	return aam, nil
}

// validate the AccountClaimMap.  On success, it will return nil.
func (aam *AccountAttributeMap) validate(ctx context.Context, caller errors.Op) error {
	if aam.LdapMethodId == "" {
		return errors.New(ctx, errors.InvalidParameter, caller, "missing ldap auth method id")
	}
	if aam.FromAttribute == "" {
		return errors.New(ctx, errors.InvalidParameter, caller, "missing from attribute")
	}
	if _, err := ConvertToAccountToAttribute(ctx, aam.ToAttribute); err != nil {
		return errors.Wrap(ctx, err, caller)
	}
	return nil
}

// AllocAccountAttributeMap makes an empty one in memory
func AllocAccountAttributeMap() AccountAttributeMap {
	return AccountAttributeMap{
		AccountAttributeMap: &store.AccountAttributeMap{},
	}
}

// clone a AccountAttributeMap
func (aam *AccountAttributeMap) clone() *AccountAttributeMap {
	cp := proto.Clone(aam.AccountAttributeMap)
	return &AccountAttributeMap{
		AccountAttributeMap: cp.(*store.AccountAttributeMap),
	}
}

// TableName returns the table name.
func (aam *AccountAttributeMap) TableName() string {
	if aam.tableName != "" {
		return aam.tableName
	}
	return acctAttributeMapTableName
}

// SetTableName sets the table name.
func (aam *AccountAttributeMap) SetTableName(n string) {
	aam.tableName = n
}

// AttributeMap defines the To and From of an ldap attribute map
type AttributeMap struct {
	To   string
	From string
}

// ParseAccountAttributeMaps will parse the inbound attribute maps
func ParseAccountAttributeMaps(ctx context.Context, m ...string) ([]AttributeMap, error) {
	const op = "ldap.ParseAccountAttributeMaps"

	am := make([]AttributeMap, 0, len(m))
	for _, s := range m {
		// Split into key/value which maps From/To
		parts := strings.SplitN(s, "=", 2)
		if len(parts) != 2 {
			return nil, errors.New(ctx, errors.InvalidParameter, op, fmt.Sprintf("error parsing attribute map %q: format must be key=value", s))
		}
		from, to := parts[0], parts[1]
		toAttr, err := ConvertToAccountToAttribute(ctx, to)
		if err != nil {
			return nil, errors.Wrap(ctx, err, op)
		}
		found := slices.ContainsFunc(am, func(m AttributeMap) bool {
			if m.To == to {
				return true
			}
			return false
		})
		if found {
			return nil, errors.New(ctx, errors.InvalidParameter, op, fmt.Sprintf("duplicate map for %q attribute", toAttr))
		}
		am = append(am, AttributeMap{
			To:   string(to),
			From: from,
		})
	}
	sort.Slice(am, func(i, j int) bool {
		return am[i].From < am[j].From
	})
	return am, nil
}
