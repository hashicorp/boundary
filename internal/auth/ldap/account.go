// Copyright IBM Corp. 2020, 2025
// SPDX-License-Identifier: BUSL-1.1

package ldap

import (
	"context"
	"strings"

	"github.com/hashicorp/boundary/internal/auth"
	"github.com/hashicorp/boundary/internal/auth/ldap/store"
	"github.com/hashicorp/boundary/internal/db/timestamp"
	"github.com/hashicorp/boundary/internal/errors"
	"github.com/hashicorp/boundary/internal/oplog"
	"github.com/hashicorp/boundary/internal/types/resource"
	"google.golang.org/protobuf/proto"
)

// accountTableName defines the default table name for an Account
const accountTableName = "auth_ldap_account"

// Account contains an ldap auth account. It is assigned to an ldap AuthMethod
// and updates/deletes to that AuthMethod are cascaded to its Accounts.
type Account struct {
	*store.Account
	tableName string
}

// make sure ldap.Account implements the auth.Account interface
var _ auth.Account = (*Account)(nil)

// NewAccount creates a new in memory Account assigned to ldap AuthMethod.
// WithFullName, WithEmail, WithDn, WithName and WithDescription are the only
// valid options. All other options are ignored.
func NewAccount(ctx context.Context, scopeId, authMethodId, loginName string, opt ...Option) (*Account, error) {
	const op = "ldap.NewAccount"
	switch {
	case scopeId == "":
		return nil, errors.New(ctx, errors.InvalidParameter, op, "missing scope id")
	case authMethodId == "":
		return nil, errors.New(ctx, errors.InvalidParameter, op, "missing auth method id")
	case loginName == "":
		return nil, errors.New(ctx, errors.InvalidParameter, op, "missing login name")
	}
	opts, err := getOpts(opt...)
	if err != nil {
		return nil, errors.Wrap(ctx, err, op)
	}
	a := &Account{
		Account: &store.Account{
			ScopeId:        scopeId,
			AuthMethodId:   authMethodId,
			LoginName:      loginName,
			Dn:             opts.withDn,
			Name:           opts.withName,
			Description:    opts.withDescription,
			FullName:       opts.withFullName,
			Email:          opts.withEmail,
			MemberOfGroups: opts.withMemberOfGroups,
		},
	}
	if err := a.validate(ctx, op); err != nil {
		return nil, err // intentionally not wrapped.
	}
	return a, nil
}

// validate the Account.  On success, it will return nil.
func (a *Account) validate(ctx context.Context, caller errors.Op) error {
	const op = "ldap.(Account).validate"
	switch {
	case caller == "":
		return errors.New(ctx, errors.InvalidParameter, op, "missing caller")
	case a.ScopeId == "":
		return errors.New(ctx, errors.InvalidParameter, caller, "missing scope id")
	case a.AuthMethodId == "":
		return errors.New(ctx, errors.InvalidParameter, caller, "missing auth method id")
	case a.LoginName == "":
		return errors.New(ctx, errors.InvalidParameter, caller, "missing login name")
	case strings.ToLower(a.LoginName) != a.LoginName:
		return errors.New(ctx, errors.InvalidParameter, op, "login name must be lower case")
	case a.Email != "" && len(a.Email) > 320:
		return errors.New(ctx, errors.InvalidParameter, caller, "email address is too long")
	case a.FullName != "" && len(a.FullName) > 512:
		return errors.New(ctx, errors.InvalidParameter, caller, "full name is too long")
	default:
		return nil
	}
}

// AllocAccount makes an empty one in memory
func AllocAccount() *Account {
	return &Account{
		Account: &store.Account{},
	}
}

// clone an Account.
func (a *Account) clone() *Account {
	cp := proto.Clone(a.Account)
	return &Account{
		Account: cp.(*store.Account),
	}
}

// TableName returns the table name.
func (a *Account) TableName() string {
	if a.tableName != "" {
		return a.tableName
	}
	return accountTableName
}

// SetTableName sets the table name.
func (a *Account) SetTableName(n string) {
	a.tableName = n
}

// GetSubject returns the subject, which will always be empty as this type
// doesn't currently support subject.
func (a *Account) GetSubject() string {
	return ""
}

// GetResourceType returns the resource type of the Account
func (a *Account) GetResourceType() resource.Type {
	return resource.Account
}

// oplog will create oplog metadata for the Account.
func (a *Account) oplog(ctx context.Context, opType oplog.OpType) (oplog.Metadata, error) {
	const op = "ldap.(Account).oplog"
	switch {
	case a == nil:
		return nil, errors.New(ctx, errors.InvalidParameter, op, "missing account")
	case opType == oplog.OpType_OP_TYPE_UNSPECIFIED:
		return nil, errors.New(ctx, errors.InvalidParameter, op, "missing op type")
	case a.PublicId == "":
		return nil, errors.New(ctx, errors.InvalidParameter, op, "missing public id")
	case a.ScopeId == "":
		return nil, errors.New(ctx, errors.InvalidParameter, op, "missing scope id")
	case a.AuthMethodId == "":
		return nil, errors.New(ctx, errors.InvalidParameter, op, "missing auth method id")
	}
	metadata := oplog.Metadata{
		"resource-public-id": []string{a.PublicId},
		"resource-type":      []string{"ldap account"},
		"op-type":            []string{opType.String()},
		"scope-id":           []string{a.ScopeId},
		"auth-method-id":     []string{a.AuthMethodId},
	}
	return metadata, nil
}

type deletedAccount struct {
	PublicId   string `gorm:"primary_key"`
	DeleteTime *timestamp.Timestamp
}

// TableName returns the tablename to override the default gorm table name
func (s *deletedAccount) TableName() string {
	return "auth_ldap_account_deleted"
}
