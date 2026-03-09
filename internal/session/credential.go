// Copyright IBM Corp. 2020, 2025
// SPDX-License-Identifier: BUSL-1.1

package session

import (
	"context"

	"github.com/hashicorp/boundary/internal/errors"
	wrapping "github.com/hashicorp/go-kms-wrapping/v2"
	"github.com/hashicorp/go-kms-wrapping/v2/extras/structwrapping"
)

// Credential represents the credential data which is sent to the worker.
type Credential []byte

type credential struct {
	SessionId        string `gorm:"index:,unique,composite:session_credential_session_id_credential_sha256_uq"`
	KeyId            string
	Credential       []byte `gorm:"-" wrapping:"pt,credential_data"`
	CtCredential     []byte `gorm:"column:credential" wrapping:"ct,credential_data"`
	CredentialSha256 []byte `gorm:"index:,unique,composite:session_credential_session_id_credential_sha256_uq"`
}

// TableName returns the table name.
func (c *credential) TableName() string {
	return "session_credential"
}

func (c *credential) encrypt(ctx context.Context, cipher wrapping.Wrapper) error {
	const op = "session.(credential).encrypt"
	if err := structwrapping.WrapStruct(ctx, cipher, c, nil); err != nil {
		return errors.Wrap(ctx, err, op, errors.WithCode(errors.Encrypt))
	}
	var err error
	c.KeyId, err = cipher.KeyId(ctx)
	if err != nil {
		return errors.Wrap(ctx, err, op, errors.WithMsg("unable to discover wrapper key id"))
	}
	return nil
}

func (c *credential) decrypt(ctx context.Context, cipher wrapping.Wrapper) error {
	const op = "session.(credential).decrypt"
	if err := structwrapping.UnwrapStruct(ctx, cipher, c, nil); err != nil {
		return errors.Wrap(ctx, err, op, errors.WithCode(errors.Decrypt))
	}
	return nil
}
