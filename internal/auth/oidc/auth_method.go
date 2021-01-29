package oidc

import (
	"context"
	"crypto/ed25519"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"net/url"

	"github.com/hashicorp/boundary/internal/auth/oidc/store"
	"github.com/hashicorp/boundary/internal/errors"
	"github.com/hashicorp/boundary/internal/kms"
	"github.com/hashicorp/boundary/internal/oplog"
	wrapping "github.com/hashicorp/go-kms-wrapping"
	"github.com/hashicorp/go-kms-wrapping/structwrapping"
	"google.golang.org/protobuf/proto"
)

/// DefaultAuthMethodTableName defines the default table name for an AuthMethod
const DefaultAuthMethodTableName = "auth_oidc_method"

// A AuthMethod contains accounts and password configurations. It is owned
// by a scope.
type AuthMethod struct {
	*store.AuthMethod
	tableName string
}

// NewAuthMethod creates a new in memory AuthMethod assigned to scopeId.
// WithMaxAge, WithName and WithDescription are the only valid options. All
// other options are ignored.  WithMaxAge m
func NewAuthMethod(scopeId string, discoveryUrl *url.URL, clientId string, clientSecret ClientSecret, opt ...Option) (*AuthMethod, error) {
	const op = "oidc.NewAuthMethod"

	if discoveryUrl == nil {
		return nil, errors.New(errors.InvalidParameter, op, "empty discovery URL")
	}

	opts := getOpts(opt...)
	a := &AuthMethod{
		AuthMethod: &store.AuthMethod{
			ScopeId:      scopeId,
			Name:         opts.withName,
			Description:  opts.withDescription,
			State:        string(InactiveState),
			DiscoveryUrl: discoveryUrl.String(),
			ClientId:     clientId,
			ClientSecret: string(clientSecret),
			MaxAge:       int32(opts.withMaxAge),
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
	if a.MaxAge < -1 {
		return errors.New(errors.InvalidParameter, caller, "max age cannot be less than -1")
	}
	return nil
}

// AllocAuthmehtod makes an empty one in memory
func AllocAuthMethod() AuthMethod {
	return AuthMethod{
		AuthMethod: &store.AuthMethod{},
	}
}

// Clone an auth method.
func (a *AuthMethod) Clone() *AuthMethod {
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
	return DefaultAuthMethodTableName
}

// SetTableName sets the table name.
func (a *AuthMethod) SetTableName(n string) {
	a.tableName = n
}

// oplog will create oplog metadata for the auth method.
func (a *AuthMethod) oplog(op oplog.OpType) oplog.Metadata {
	metadata := oplog.Metadata{
		"resource-public-id": []string{a.GetPublicId()},
		"resource-type":      []string{"oidc auth method"},
		"op-type":            []string{op.String()},
		"scope-id":           []string{a.ScopeId},
	}
	return metadata
}

// encrypt the auth method before writing it to the db
func (a *AuthMethod) encrypt(ctx context.Context, cipher wrapping.Wrapper) error {
	const op = "oidc.(AuthMethod).encrypt"
	if err := structwrapping.WrapStruct(ctx, cipher, a.AuthMethod, nil); err != nil {
		return errors.Wrap(err, op, errors.WithCode(errors.Encrypt))
	}
	a.KeyId = cipher.KeyID()
	if err := a.hmacClientSecret(cipher); err != nil {
		return errors.Wrap(err, op)
	}
	return nil
}

// decrypt the auth method after reading it from the db
func (a *AuthMethod) decrypt(ctx context.Context, cipher wrapping.Wrapper) error {
	const op = "oidc.(AuthMethod).encrypt"
	if err := structwrapping.UnwrapStruct(ctx, cipher, a.AuthMethod, nil); err != nil {
		return errors.Wrap(err, op, errors.WithCode(errors.Decrypt))
	}
	return nil
}

// hmacClientSecret before writing it to the db
func (a *AuthMethod) hmacClientSecret(cipher wrapping.Wrapper) error {
	const op = "oidc.(AuthMethod).hmacClientSecret"
	reader, err := kms.NewDerivedReader(cipher, 32, []byte(a.PublicId), nil)
	if err != nil {
		return errors.Wrap(err, op)
	}
	key, _, err := ed25519.GenerateKey(reader)
	if err != nil {
		return errors.New(errors.Encrypt, op, "unable to generate derived key")
	}
	mac := hmac.New(sha256.New, key)
	_, _ = mac.Write([]byte(a.ClientSecret))
	a.ClientSecretHmac = base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
	return nil
}
