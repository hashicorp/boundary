package password

import (
	"fmt"

	"github.com/hashicorp/watchtower/internal/auth/password/store"
	"github.com/hashicorp/watchtower/internal/db"
	"github.com/hashicorp/watchtower/internal/oplog"
	"google.golang.org/protobuf/proto"
)

// A AuthMethod contains accounts and password configurations. It is owned
// by a scope.
type AuthMethod struct {
	*store.AuthMethod
	tableName string
}

func allocAuthMethod() AuthMethod {
	return AuthMethod{
		AuthMethod: &store.AuthMethod{},
	}
}

// NewAuthMethod creates a new in memory AuthMethod assigned to scopeId.
// Name and description are the only valid options. All other options are
// ignored.  MinUserNameLength and MinPasswordLength are pre-set to the
// default values of 5 and 8 respectively.
func NewAuthMethod(scopeId string, opt ...Option) (*AuthMethod, error) {
	if scopeId == "" {
		return nil, fmt.Errorf("new: password auth method: no scope id: %w", db.ErrInvalidParameter)
	}

	opts := getOpts(opt...)
	a := &AuthMethod{
		AuthMethod: &store.AuthMethod{
			ScopeId:           scopeId,
			Name:              opts.withName,
			Description:       opts.withDescription,
			MinUserNameLength: 3,
			MinPasswordLength: 8,
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
	a.tableName = n
}

func (a *AuthMethod) oplog(op oplog.OpType) oplog.Metadata {
	metadata := oplog.Metadata{
		"resource-public-id": []string{a.GetPublicId()},
		"resource-type":      []string{"password auth method"},
		"op-type":            []string{op.String()},
	}
	if a.ScopeId != "" {
		metadata["scope-id"] = []string{a.ScopeId}
	}
	return metadata
}
