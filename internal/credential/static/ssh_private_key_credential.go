// Copyright IBM Corp. 2020, 2025
// SPDX-License-Identifier: BUSL-1.1

package static

import (
	"context"

	"github.com/hashicorp/boundary/internal/credential"
	"github.com/hashicorp/boundary/internal/credential/static/store"
	"github.com/hashicorp/boundary/internal/db/timestamp"
	"github.com/hashicorp/boundary/internal/errors"
	"github.com/hashicorp/boundary/internal/libs/crypto"
	"github.com/hashicorp/boundary/internal/oplog"
	"github.com/hashicorp/boundary/internal/types/resource"
	wrapping "github.com/hashicorp/go-kms-wrapping/v2"
	"golang.org/x/crypto/ssh"
	"google.golang.org/protobuf/proto"
)

var _ credential.Static = (*SshPrivateKeyCredential)(nil)

// A SshPrivateKeyCredential contains the credential with a username and private key.
// It is owned by a credential store.
type SshPrivateKeyCredential struct {
	*store.SshPrivateKeyCredential
	tableName          string `gorm:"-"`
	PassphraseUnneeded bool   `gorm:"-"`
}

// NewSshPrivateKeyCredential creates a new in memory static Credential containing a
// username and private key that is assigned to storeId. Name and description are the only
// valid options. All other options are ignored.
func NewSshPrivateKeyCredential(
	ctx context.Context,
	storeId string,
	username string,
	privateKey credential.PrivateKey,
	opt ...Option,
) (*SshPrivateKeyCredential, error) {
	const op = "static.NewSshPrivateKeyCredential"

	opts := getOpts(opt...)
	if len(privateKey) != 0 {
		var err error
		if len(opts.withPrivateKeyPassphrase) == 0 {
			_, err = ssh.ParsePrivateKey(privateKey)
		} else {
			_, err = ssh.ParsePrivateKeyWithPassphrase(privateKey, opts.withPrivateKeyPassphrase)
		}
		switch {
		case err == nil:
		case err.Error() == (&ssh.PassphraseMissingError{}).Error():
			// This is okay, if it's brokered and the client can use it, no worries
		default:
			return nil, errors.Wrap(ctx, err, op, errors.WithCode(errors.InvalidParameter))
		}
	}

	l := &SshPrivateKeyCredential{
		SshPrivateKeyCredential: &store.SshPrivateKeyCredential{
			StoreId:              storeId,
			Name:                 opts.withName,
			Description:          opts.withDescription,
			Username:             username,
			PrivateKey:           privateKey,
			PrivateKeyPassphrase: opts.withPrivateKeyPassphrase,
		},
	}

	// If a private key was given and no passphrase was given and everything is
	// okay, we can nil out any passphrase we have, so set this as a hint
	if len(privateKey) != 0 && len(opts.withPrivateKeyPassphrase) == 0 {
		l.PassphraseUnneeded = true
		// These shouldn't be set, but safety
		l.PrivateKeyPassphrase = nil
		l.PrivateKeyPassphraseEncrypted = nil
		l.PrivateKeyPassphraseHmac = nil
	}

	return l, nil
}

func allocSshPrivateKeyCredential() *SshPrivateKeyCredential {
	return &SshPrivateKeyCredential{
		SshPrivateKeyCredential: &store.SshPrivateKeyCredential{},
	}
}

func (c *SshPrivateKeyCredential) clone() *SshPrivateKeyCredential {
	cp := proto.Clone(c.SshPrivateKeyCredential)
	return &SshPrivateKeyCredential{
		SshPrivateKeyCredential: cp.(*store.SshPrivateKeyCredential),
	}
}

// TableName returns the table name.
func (c *SshPrivateKeyCredential) TableName() string {
	if c.tableName != "" {
		return c.tableName
	}
	return "credential_static_ssh_private_key_credential"
}

// SetTableName sets the table name.
func (c *SshPrivateKeyCredential) SetTableName(n string) {
	c.tableName = n
}

// GetResourceType returns the resource type of the Credential
func (c *SshPrivateKeyCredential) GetResourceType() resource.Type {
	return resource.Credential
}

func (c *SshPrivateKeyCredential) oplog(op oplog.OpType) oplog.Metadata {
	metadata := oplog.Metadata{
		"resource-public-id": []string{c.PublicId},
		"resource-type":      []string{"credential-static-ssh-private-key"},
		"op-type":            []string{op.String()},
	}
	if c.StoreId != "" {
		metadata["store-id"] = []string{c.StoreId}
	}
	return metadata
}

func (c *SshPrivateKeyCredential) encrypt(ctx context.Context, cipher wrapping.Wrapper) error {
	const op = "static.(SshPrivateKeyCredential).encrypt"

	if len(c.PrivateKey) == 0 {
		return errors.New(ctx, errors.InvalidParameter, op, "no private key defined")
	}

	keyId, err := cipher.KeyId(ctx)
	if err != nil {
		return errors.Wrap(ctx, err, op, errors.WithCode(errors.Encrypt), errors.WithMsg("error reading cipher key id"))
	}
	c.KeyId = keyId

	// Encrypt private key
	blobInfo, err := cipher.Encrypt(ctx, c.PrivateKey)
	if err != nil {
		return errors.Wrap(ctx, err, op, errors.WithCode(errors.Encrypt))
	}
	protoBytes, err := proto.Marshal(blobInfo)
	if err != nil {
		return errors.Wrap(ctx, err, op, errors.WithCode(errors.Encode))
	}
	c.PrivateKeyEncrypted = protoBytes
	if err := c.hmacPrivateKey(ctx, cipher); err != nil {
		return errors.Wrap(ctx, err, op)
	}

	if len(c.PrivateKeyPassphrase) > 0 {
		// Encrypt passphrase
		blobInfo, err := cipher.Encrypt(ctx, c.PrivateKeyPassphrase)
		if err != nil {
			return errors.Wrap(ctx, err, op, errors.WithCode(errors.Encrypt))
		}
		protoBytes, err := proto.Marshal(blobInfo)
		if err != nil {
			return errors.Wrap(ctx, err, op, errors.WithCode(errors.Encode))
		}
		c.PrivateKeyPassphraseEncrypted = protoBytes
		if err := c.hmacPrivateKeyPassphrase(ctx, cipher); err != nil {
			return errors.Wrap(ctx, err, op)
		}
	}

	return nil
}

func (c *SshPrivateKeyCredential) decrypt(ctx context.Context, cipher wrapping.Wrapper) error {
	const op = "static.(SshPrivateKeyCredential).decrypt"

	if len(c.PrivateKeyEncrypted) > 0 {
		dec := new(wrapping.BlobInfo)
		if err := proto.Unmarshal(c.PrivateKeyEncrypted, dec); err != nil {
			return errors.Wrap(ctx, err, op, errors.WithCode(errors.Decode))
		}
		pt, err := cipher.Decrypt(ctx, dec)
		if err != nil {
			return errors.Wrap(ctx, err, op, errors.WithCode(errors.Decrypt))
		}
		c.PrivateKey = pt
	}

	if len(c.PrivateKeyPassphraseEncrypted) > 0 {
		dec := new(wrapping.BlobInfo)
		if err := proto.Unmarshal(c.PrivateKeyPassphraseEncrypted, dec); err != nil {
			return errors.Wrap(ctx, err, op, errors.WithCode(errors.Decode))
		}
		pt, err := cipher.Decrypt(ctx, dec)
		if err != nil {
			return errors.Wrap(ctx, err, op, errors.WithCode(errors.Decrypt))
		}
		c.PrivateKeyPassphrase = pt
	}

	return nil
}

func (c *SshPrivateKeyCredential) hmacPrivateKey(ctx context.Context, cipher wrapping.Wrapper) error {
	const op = "static.(SshPrivateKeyCredential).hmacPrivateKey"
	if cipher == nil {
		return errors.New(ctx, errors.InvalidParameter, op, "missing cipher")
	}
	hm, err := crypto.HmacSha256(ctx, c.PrivateKey, cipher, []byte(c.StoreId), nil)
	if err != nil {
		return errors.Wrap(ctx, err, op)
	}
	c.PrivateKeyHmac = []byte(hm)
	return nil
}

func (c *SshPrivateKeyCredential) hmacPrivateKeyPassphrase(ctx context.Context, cipher wrapping.Wrapper) error {
	const op = "static.(SshPrivateKeyCredential).hmacPrivateKeyPassphrase"
	if cipher == nil {
		return errors.New(ctx, errors.InvalidParameter, op, "missing cipher")
	}
	hm, err := crypto.HmacSha256(ctx, c.PrivateKeyPassphrase, cipher, []byte(c.StoreId), nil)
	if err != nil {
		return errors.Wrap(ctx, err, op)
	}
	c.PrivateKeyPassphraseHmac = []byte(hm)
	return nil
}

type deletedSSHPrivateKeyCredential struct {
	PublicId   string `gorm:"primary_key"`
	DeleteTime *timestamp.Timestamp
}

// TableName returns the tablename to override the default gorm table name
func (s *deletedSSHPrivateKeyCredential) TableName() string {
	return "credential_static_ssh_private_key_credential_deleted"
}
