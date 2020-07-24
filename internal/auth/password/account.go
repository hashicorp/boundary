package password

import (
	"fmt"

	"github.com/hashicorp/watchtower/internal/auth/password/store"
	"github.com/hashicorp/watchtower/internal/db"
	"github.com/hashicorp/watchtower/internal/oplog"
	"google.golang.org/protobuf/proto"
)

// An Account contains a user name. It is owned by an auth method.
type Account struct {
	*store.Account
	tableName string

	// CredentialID is included when Authenticate or ChangePassword is
	// called. A new CredentialID is generated when a password is changed.
	CredentialID string `gorm:"-"`
}

func allocAccount() Account {
	return Account{
		Account: &store.Account{},
	}
}

// NewAccount creates a new in memory Account with userName assigned to
// authMethodId. Name and description are the only valid options. All other
// options are ignored.
func NewAccount(authMethodId string, userName string, opt ...Option) (*Account, error) {
	// NOTE(mgaffney): The scopeId in the embedded *store.Account is
	// populated by a trigger in the database.
	if authMethodId == "" {
		return nil, fmt.Errorf("new: password account: no auth method id: %w", db.ErrInvalidParameter)
	}
	if userName == "" {
		return nil, fmt.Errorf("new: password account: no user name: %w", db.ErrInvalidParameter)
	}

	opts := getOpts(opt...)
	a := &Account{
		Account: &store.Account{
			AuthMethodId: authMethodId,
			UserName:     userName,
			Name:         opts.withName,
			Description:  opts.withDescription,
		},
	}
	return a, nil
}

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
	return "auth_password_account"
}

// SetTableName sets the table name.
func (a *Account) SetTableName(n string) {
	a.tableName = n
}

func (a *Account) oplog(op oplog.OpType) oplog.Metadata {
	metadata := oplog.Metadata{
		"resource-public-id": []string{a.GetPublicId()},
		"resource-type":      []string{"password account"},
		"op-type":            []string{op.String()},
	}
	if a.AuthMethodId != "" {
		metadata["auth-method-id"] = []string{a.AuthMethodId}
	}
	return metadata
}
