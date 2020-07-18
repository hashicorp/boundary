package password

import (
	"fmt"

	"github.com/hashicorp/watchtower/internal/auth/password/store"
	"github.com/hashicorp/watchtower/internal/db"
	"github.com/hashicorp/watchtower/internal/oplog"
	"google.golang.org/protobuf/proto"
)

// A Configuration is an interface holding one of the configuration types
// for a specific key derivation function. Argon2 is currently the only
// configuration type.
type Configuration interface{}

// A AuthMethod contains accounts and password configurations. It is owned
// by a scope.
type AuthMethod struct {
	*store.AuthMethod
	tableName string

	Config Configuration `gorm:"-"`
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
			ScopeId:           scopeId,
			Name:              opts.withName,
			Description:       opts.withDescription,
			MinUserNameLength: 5,
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
	if n != "" {
		a.tableName = n
	}
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
