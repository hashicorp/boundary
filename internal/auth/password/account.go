package password

import (
	"fmt"

	"github.com/hashicorp/watchtower/internal/auth/password/store"
	"github.com/hashicorp/watchtower/internal/db"
	"google.golang.org/protobuf/proto"
)

// An Account contains a user name. It is owned by an auth method.
type Account struct {
	*store.Account
	tableName string
}

// NewAccount creates a new in memory Account assigned to authMethodId.
// Name and description are the only valid options. All other options are
// ignored.
func NewAccount(authMethodId string, userName string, opt ...Option) (*Account, error) {
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
	if n != "" {
		a.tableName = n
	}
}
