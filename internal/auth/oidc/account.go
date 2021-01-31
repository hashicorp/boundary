package oidc

import (
	"net/url"

	"github.com/hashicorp/boundary/internal/auth/oidc/store"
	"github.com/hashicorp/boundary/internal/errors"
	"github.com/hashicorp/boundary/internal/oplog"
	"google.golang.org/protobuf/proto"
)

// DefaultAccountTableName defines the default table name for an Account
const DefaultAccountTableName = "auth_oidc_account"

// Account contains an OIDC auth method configuration. It is owned
// by a scope.
type Account struct {
	*store.Account
	tableName string
}

// NewAccount creates a new in memory Account assigned to authMethodId.
// WithFullName, WithEmail, WithName and WithDescription are the only valid
// options. All other options are ignored.
func NewAccount(authMethodId string, issuerId *url.URL, subjectId string, opt ...Option) (*Account, error) {
	const op = "oidc.NewAccount"

	if issuerId == nil {
		return nil, errors.New(errors.InvalidParameter, op, "nil issuer id")
	}

	opts := getOpts(opt...)
	a := &Account{
		Account: &store.Account{
			AuthMethodId: authMethodId,
			IssuerId:     issuerId.String(),
			SubjectId:    subjectId,
			Name:         opts.withName,
			Description:  opts.withDescription,
			FullName:     opts.withFullName,
			Email:        opts.withEmail,
		},
	}
	if err := a.validate(op); err != nil {
		return nil, err // intentionally not wrapped.
	}

	return a, nil
}

// validate the Account.  On success, it will return nil.
func (a *Account) validate(caller errors.Op) error {
	if a.AuthMethodId == "" {
		return errors.New(errors.InvalidParameter, caller, "missing auth method id")
	}
	if a.SubjectId == "" {
		return errors.New(errors.InvalidParameter, caller, "missing subject id")
	}
	if a.IssuerId == "" {
		return errors.New(errors.InvalidParameter, caller, "missing issuer id")
	}
	if _, err := url.Parse(a.IssuerId); err != nil {
		return errors.New(errors.InvalidParameter, caller, "not a valid issuer", errors.WithWrap(err))
	}
	if a.Email != "" && len(a.Email) > 320 {
		return errors.New(errors.InvalidParameter, caller, "email address is too long")
	}
	if a.FullName != "" && len(a.FullName) > 512 {
		return errors.New(errors.InvalidParameter, caller, "full name is too long")
	}
	return nil
}

// AllocAccount makes an empty one in memory
func AllocAccount() Account {
	return Account{
		Account: &store.Account{},
	}
}

// Clone an Account.
func (a *Account) Clone() *Account {
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
	return DefaultAccountTableName
}

// SetTableName sets the table name.
func (a *Account) SetTableName(n string) {
	a.tableName = n
}

// oplog will create oplog metadata for the Account.
func (c *Account) oplog(op oplog.OpType, authMethodScopeId string) oplog.Metadata {
	metadata := oplog.Metadata{
		"resource-public-id": []string{c.AuthMethodId}, // the auth method is the root aggregate
		"resource-type":      []string{"oidc auth aud claim"},
		"op-type":            []string{op.String()},
	}
	if authMethodScopeId != "" {
		metadata["scope-id"] = []string{authMethodScopeId}
	}
	return metadata
}
