// Copyright IBM Corp. 2020, 2025
// SPDX-License-Identifier: BUSL-1.1

package ldap

import (
	"context"

	"github.com/hashicorp/boundary/internal/auth/ldap/store"
	"github.com/hashicorp/boundary/internal/errors"
	wrapping "github.com/hashicorp/go-kms-wrapping/v2"
	"github.com/hashicorp/go-kms-wrapping/v2/extras/structwrapping"
	"google.golang.org/protobuf/proto"
)

const bindCredentialTableName = "auth_ldap_bind_credential"

// BindCredential represent optional parameters which allow Boundary to bind
// (aka authenticate) using the credentials provided when searching for the user
// entry used to authenticate the end user.
type BindCredential struct {
	*store.BindCredential
	tableName string
}

// NewBindCredential creates a new in memory BindCredential. No options are currently supported.
func NewBindCredential(ctx context.Context, authMethodId string, dn string, password []byte, _ ...Option) (*BindCredential, error) {
	const op = "ldap.NewBindCredential"
	switch {
	case authMethodId == "":
		return nil, errors.New(ctx, errors.InvalidParameter, op, "missing auth method id")
	case dn == "":
		return nil, errors.New(ctx, errors.InvalidParameter, op, "missing dn")
	case len(password) == 0:
		return nil, errors.New(ctx, errors.InvalidParameter, op, "missing password")
	}
	return &BindCredential{
		BindCredential: &store.BindCredential{
			LdapMethodId: authMethodId,
			Dn:           dn,
			Password:     password,
		},
	}, nil
}

// allocBindCredential makes an empty one in memory
func allocBindCredential() *BindCredential {
	return &BindCredential{
		BindCredential: &store.BindCredential{},
	}
}

// clone a bind credential
func (bc *BindCredential) clone() *BindCredential {
	cp := proto.Clone(bc.BindCredential)
	return &BindCredential{
		BindCredential: cp.(*store.BindCredential),
	}
}

// TableName returns the table name
func (bc *BindCredential) TableName() string {
	if bc.tableName != "" {
		return bc.tableName
	}
	return bindCredentialTableName
}

// SetTableName sets the table name.
func (bc *BindCredential) SetTableName(n string) {
	bc.tableName = n
}

// encrypt the bind credential before writing it to the database
func (bc *BindCredential) encrypt(ctx context.Context, cipher wrapping.Wrapper) error {
	const op = "ldap.(BindCredential).encrypt"
	if cipher == nil {
		return errors.New(ctx, errors.InvalidParameter, op, "missing cipher")
	}
	if err := structwrapping.WrapStruct(ctx, cipher, bc.BindCredential); err != nil {
		return errors.Wrap(ctx, err, op, errors.WithCode(errors.Encrypt))
	}
	var err error
	if bc.KeyId, err = cipher.KeyId(ctx); err != nil {
		return errors.Wrap(ctx, err, op, errors.WithCode(errors.Encrypt), errors.WithMsg("failed to read cipher key id"))
	}
	if bc.PasswordHmac, err = hmacField(ctx, cipher, bc.Password, bc.LdapMethodId); err != nil {
		return errors.Wrap(ctx, err, op, errors.WithCode(errors.Encrypt), errors.WithMsg("failed to hmac password"))
	}

	return nil
}

// decrypt the bind credential after reading it from the database
func (bc *BindCredential) decrypt(ctx context.Context, cipher wrapping.Wrapper) error {
	const op = "ldap.(BindCredential).decrypt"
	if cipher == nil {
		return errors.New(ctx, errors.InvalidParameter, op, "missing cipher")
	}
	if err := structwrapping.UnwrapStruct(ctx, cipher, bc.BindCredential); err != nil {
		return errors.Wrap(ctx, err, op, errors.WithCode(errors.Decrypt))
	}
	return nil
}
