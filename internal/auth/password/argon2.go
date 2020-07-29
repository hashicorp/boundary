package password

import (
	"strings"

	"github.com/hashicorp/watchtower/internal/auth/password/store"
	"github.com/hashicorp/watchtower/internal/oplog"
	"google.golang.org/protobuf/proto"
)

// Argon2Configuration is a configuration for using the argon2id key
// derivation function. It is owned by an AuthMethod.
//
// Iterations, Memory, and Threads are the cost parameters. The cost
// parameters should be increased as memory latency and CPU parallelism
// increases.
//
// For a detailed specification of Argon2 see:
// https://github.com/P-H-C/phc-winner-argon2/blob/master/argon2-specs.pdf
type Argon2Configuration struct {
	*store.Argon2Configuration
	tableName string
}

// NewArgon2Configuration creates a new in memory Argon2Configuration with
// reasonable default settings.
func NewArgon2Configuration() *Argon2Configuration {
	return &Argon2Configuration{
		Argon2Configuration: &store.Argon2Configuration{
			Iterations: 3,
			Memory:     64 * 1024,
			Threads:    1,
			SaltLength: 32,
			KeyLength:  32,
		},
	}
}

func (c *Argon2Configuration) validate() error {
	switch {
	case c == nil, c.Argon2Configuration == nil:
		return ErrInvalidConfiguration
	case c.Iterations == 0, c.Memory == 0, c.Threads == 0, c.SaltLength == 0, c.KeyLength == 0:
		return ErrInvalidConfiguration
	default:
		return nil
	}
}

// AuthMethodId returns the Id of the AuthMethod which owns c.
func (c *Argon2Configuration) AuthMethodId() string {
	if c != nil && c.Argon2Configuration != nil {
		return c.PasswordMethodId
	}
	return ""
}

func (c *Argon2Configuration) clone() *Argon2Configuration {
	cp := proto.Clone(c.Argon2Configuration)
	return &Argon2Configuration{
		Argon2Configuration: cp.(*store.Argon2Configuration),
	}
}

// TableName returns the table name.
func (c *Argon2Configuration) TableName() string {
	if c != nil && c.tableName != "" {
		return c.tableName
	}
	return "auth_password_argon2_conf"
}

// SetTableName sets the table name.
func (c *Argon2Configuration) SetTableName(n string) {
	c.tableName = n
}

func (c *Argon2Configuration) oplog(op oplog.OpType) oplog.Metadata {
	metadata := oplog.Metadata{
		"resource-public-id": []string{c.PrivateId},
		"resource-type":      []string{"password argon2 conf"},
		"op-type":            []string{op.String()},
	}
	if c.PasswordMethodId != "" {
		metadata["password-method-id"] = []string{c.PasswordMethodId}
	}
	return metadata
}

func (c *Argon2Configuration) whereDup() (string, []interface{}) {
	var where []string
	var args []interface{}

	where, args = append(where, "password_method_id = ?"), append(args, c.PasswordMethodId)
	where, args = append(where, "iterations = ?"), append(args, c.Iterations)
	where, args = append(where, "memory = ?"), append(args, c.Memory)
	where, args = append(where, "threads = ?"), append(args, c.Threads)
	where, args = append(where, "key_length = ?"), append(args, c.KeyLength)
	where, args = append(where, "salt_length = ?"), append(args, c.SaltLength)

	return strings.Join(where, " and "), args
}
