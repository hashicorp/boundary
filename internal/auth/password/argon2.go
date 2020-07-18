package password

import (
	"context"
	"crypto/rand"
	"fmt"

	wrapping "github.com/hashicorp/go-kms-wrapping"
	"github.com/hashicorp/go-kms-wrapping/structwrapping"
	"github.com/hashicorp/watchtower/internal/auth/password/store"
	"github.com/hashicorp/watchtower/internal/db"
	"github.com/hashicorp/watchtower/internal/oplog"
	"golang.org/x/crypto/argon2"
	"google.golang.org/protobuf/proto"
)

// A Argon2Configuration contains configuration parameters for the argon2
// key derivation function. It is owned by an AuthMethod.
type Argon2Configuration struct {
	*store.Argon2Configuration
	tableName string
}

// NewArgon2Configuration creates a new in memory Argon2Configuration assigned to authMethodId.
// Name and description are the only valid options. All other options are
// ignored.
func NewArgon2Configuration(authMethodId string) (*Argon2Configuration, error) {
	if authMethodId == "" {
		return nil, fmt.Errorf("new: password argon2 configuration: no authMethodId: %w", db.ErrInvalidParameter)
	}

	id, err := newArgon2ConfigurationId()
	if err != nil {
		return nil, fmt.Errorf("new: password argon2 configuration: %w", err)
	}

	c := &Argon2Configuration{
		Argon2Configuration: &store.Argon2Configuration{
			PasswordMethodId: authMethodId,
			PublicId:         id,
			Iterations:       3,
			Memory:           64 * 1024,
			Threads:          1,
			SaltLength:       32,
			KeyLength:        32,
		},
	}

	return c, nil
}

func (c *Argon2Configuration) clone() *Argon2Configuration {
	cp := proto.Clone(c.Argon2Configuration)
	return &Argon2Configuration{
		Argon2Configuration: cp.(*store.Argon2Configuration),
	}
}

// TableName returns the table name.
func (c *Argon2Configuration) TableName() string {
	if c.tableName != "" {
		return c.tableName
	}
	return "auth_password_argon2_conf"
}

// SetTableName sets the table name.
func (c *Argon2Configuration) SetTableName(n string) {
	if n != "" {
		c.tableName = n
	}
}

func (c *Argon2Configuration) oplog(op oplog.OpType) oplog.Metadata {
	metadata := oplog.Metadata{
		"resource-public-id": []string{c.GetPublicId()},
		"resource-type":      []string{"password argon2 conf"},
		"op-type":            []string{op.String()},
	}
	if c.PasswordMethodId != "" {
		metadata["password-method-id"] = []string{c.PasswordMethodId}
	}
	return metadata
}

// A Argon2Credential contains a key derived from a password and the salt
// used in the key derivation. It is owned by an Account.
type Argon2Credential struct {
	*store.Argon2Credential
	tableName string
}

func newArgon2Credential(accountId string, password string, conf *Argon2Configuration) (*Argon2Credential, error) {
	if accountId == "" {
		return nil, fmt.Errorf("new: password argon2 credential: no accountId: %w", db.ErrInvalidParameter)
	}
	if password == "" {
		return nil, fmt.Errorf("new: password argon2 credential: no password: %w", db.ErrInvalidParameter)
	}
	if conf == nil {
		return nil, fmt.Errorf("new: password argon2 credential: no argon2 configuration: %w", db.ErrNilParameter)
	}

	id, err := newArgon2CredentialId()
	if err != nil {
		return nil, fmt.Errorf("new: password argon2 credential: %w", err)
	}

	c := &Argon2Credential{
		Argon2Credential: &store.Argon2Credential{
			PublicId:          id,
			PasswordAccountId: accountId,
			PasswordConfId:    conf.PublicId,
		},
	}

	salt := make([]byte, conf.SaltLength)
	if _, err := rand.Read(salt); err != nil {
		return nil, fmt.Errorf("new: password argon2 credential: %w", err)
	}
	c.Salt = salt
	c.DerivedKey = argon2.IDKey([]byte(password), c.Salt, conf.Iterations, conf.Memory, uint8(conf.Threads), conf.KeyLength)
	return c, nil
}

func (c *Argon2Credential) clone() *Argon2Credential {
	cp := proto.Clone(c.Argon2Credential)
	return &Argon2Credential{
		Argon2Credential: cp.(*store.Argon2Credential),
	}
}

// TableName returns the table name.
func (c *Argon2Credential) TableName() string {
	if c.tableName != "" {
		return c.tableName
	}
	return "auth_password_argon2_cred"
}

// SetTableName sets the table name.
func (c *Argon2Credential) SetTableName(n string) {
	if n != "" {
		c.tableName = n
	}
}

func (c *Argon2Credential) encrypt(ctx context.Context, cipher wrapping.Wrapper) error {
	if err := structwrapping.WrapStruct(ctx, cipher, c.Argon2Credential, nil); err != nil {
		return fmt.Errorf("error encrypting argon2 credential: %w", err)
	}
	return nil
}

func (c *Argon2Credential) decrypt(ctx context.Context, cipher wrapping.Wrapper) error {
	if err := structwrapping.UnwrapStruct(ctx, cipher, c.Argon2Credential, nil); err != nil {
		return fmt.Errorf("error decrypting argon2 credential: %w", err)
	}
	return nil
}

func (c *Argon2Credential) oplog(op oplog.OpType) oplog.Metadata {
	metadata := oplog.Metadata{
		"resource-public-id":  []string{c.GetPublicId()},
		"resource-type":       []string{"argon2 credential"},
		"op-type":             []string{op.String()},
		"password-account-id": []string{c.PasswordAccountId},
	}
	if c.PasswordMethodId != "" {
		metadata["password-method-id"] = []string{c.PasswordMethodId}
	}
	return metadata
}
