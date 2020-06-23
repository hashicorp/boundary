package password

import (
	"fmt"

	"github.com/hashicorp/watchtower/internal/auth/password/store"
	"github.com/hashicorp/watchtower/internal/db"
	"google.golang.org/protobuf/proto"
)

// A AuthMethod contains accounts and password configurations. It is owned
// by a scope.
type AuthMethod struct {
	*store.AuthMethod
	tableName string
}

// NewAuthMethod creates a new in memory AuthMethod assigned to scopeId.
// Name and description are the only valid options. All other options are
// ignored.
func NewAuthMethod(scopeId string, opt ...Option) (*AuthMethod, error) {
	if scopeId == "" {
		return nil, fmt.Errorf("new: password auth method: no scope id: %w", db.ErrInvalidParameter)
	}

	opts := getOpts(opt...)
	a := &AuthMethod{
		AuthMethod: &store.AuthMethod{
			ScopeId:     scopeId,
			Name:        opts.withName,
			Description: opts.withDescription,
		},
	}
	return a, nil
}

func (a *AuthMethod) clone() *AuthMethod {
	cp := proto.Clone(a.AuthMethod)
	return &AuthMethod{
		AuthMethod: cp.(*store.AuthMethod),
	}
}

// TableName returns the table name.
func (a *AuthMethod) TableName() string {
	if a.tableName != "" {
		return a.tableName
	}
	return "auth_password_method"
}

// SetTableName sets the table name.
func (a *AuthMethod) SetTableName(n string) {
	if n != "" {
		a.tableName = n
	}
}
