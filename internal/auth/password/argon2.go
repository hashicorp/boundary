package password

import (
	"fmt"

	"github.com/hashicorp/watchtower/internal/auth/password/store"
	"github.com/hashicorp/watchtower/internal/db"
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
