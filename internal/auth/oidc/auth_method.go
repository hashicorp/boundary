package oidc

import (
	"context"
	"net/url"

	"github.com/hashicorp/boundary/internal/auth/oidc/store"
	"github.com/hashicorp/boundary/internal/errors"
	"github.com/hashicorp/boundary/internal/oplog"
	wrapping "github.com/hashicorp/go-kms-wrapping"
	"github.com/hashicorp/go-kms-wrapping/structwrapping"
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
func NewAuthMethod(scopeId string, state AuthMethodState, discoveryUrl url.URL, clientId string, clientSecret ClientSecret, maxAge uint32, opt ...Option) (*AuthMethod, error) {
	const op = "oidc.NewAuthMethod"

	opts := getOpts(opt...)
	a := &AuthMethod{
		AuthMethod: &store.AuthMethod{
			ScopeId:      scopeId,
			Name:         opts.withName,
			Description:  opts.withDescription,
			State:        string(state),
			DiscoveryUrl: discoveryUrl.String(),
			ClientId:     clientId,
			ClientSecret: string(clientSecret),
			MaxAge:       maxAge,
		},
	}
	if err := a.validate(op); err != nil {
		return nil, err // intentionally not wrapped.
	}
	if a.ClientSecretHmac != "" {
		return nil, errors.New(errors.InvalidParameter, op, "client secret hmac should be empty")
	}
	return a, nil
}

// validate the AuthMethod.  On success, it will return nil.
func (a *AuthMethod) validate(caller errors.Op) error {
	if a.ScopeId == "" {
		return errors.New(errors.InvalidParameter, caller, "missing scope id")
	}
	if !validState(a.State) {
		return errors.New(errors.InvalidParameter, caller, "missing scope id")
	}
	if _, err := url.Parse(a.DiscoveryUrl); err != nil {
		return errors.New(errors.InvalidParameter, caller, "not a valid discovery URL", errors.WithWrap(err))
	}
	if len(a.ClientId) == 0 {
		return errors.New(errors.InvalidParameter, caller, "client id is empty")
	}
	if len(a.ClientSecret) == 0 {
		return errors.New(errors.InvalidParameter, caller, "client secret is empty")
	}
	return nil
}

func allocAuthMethod() AuthMethod {
	return AuthMethod{
		AuthMethod: &store.AuthMethod{},
	}
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
	return "auth_oidc_method"
}

// SetTableName sets the table name.
func (a *AuthMethod) SetTableName(n string) {
	a.tableName = n
}

func (a *AuthMethod) oplog(op oplog.OpType) oplog.Metadata {
	metadata := oplog.Metadata{
		"resource-public-id": []string{a.GetPublicId()},
		"resource-type":      []string{"oidc auth method"},
		"op-type":            []string{op.String()},
		"scope-id":           []string{a.ScopeId},
	}
	return metadata
}

func (a *AuthMethod) encrypt(ctx context.Context, cipher wrapping.Wrapper) error {
	const op = "oidc.(AuthMethod).encrypt"
	if err := structwrapping.WrapStruct(ctx, cipher, a, nil); err != nil {
		return errors.Wrap(err, op, errors.WithCode(errors.Encrypt))
	}
	a.KeyId = cipher.KeyID()
	return nil
}

func (a *AuthMethod) decrypt(ctx context.Context, cipher wrapping.Wrapper) error {
	const op = "oidc.(AuthMethod).encrypt"
	if err := structwrapping.UnwrapStruct(ctx, cipher, a, nil); err != nil {
		return errors.Wrap(err, op, errors.WithCode(errors.Decrypt))
	}
	return nil
}
