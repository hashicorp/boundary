package session

import (
	"context"

	"github.com/hashicorp/boundary/internal/errors"
	wrapping "github.com/hashicorp/go-kms-wrapping"
	"github.com/hashicorp/go-kms-wrapping/structwrapping"
)

// Credential represents the credential data which is sent to the worker.
type Credential []byte

type credential struct {
	SessionId    string
	KeyId        string
	Credential   []byte `gorm:"-" wrapping:"pt,credential_data"`
	CtCredential []byte `gorm:"column:credential" wrapping:"ct,credential_data"`
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
	c.KeyId = cipher.KeyID()
	return nil
}

func (c *credential) decrypt(ctx context.Context, cipher wrapping.Wrapper) error {
	const op = "session.(credential).decrypt"
	if err := structwrapping.UnwrapStruct(ctx, cipher, c, nil); err != nil {
		return errors.Wrap(ctx, err, op, errors.WithCode(errors.Decrypt))
	}
	return nil
}
