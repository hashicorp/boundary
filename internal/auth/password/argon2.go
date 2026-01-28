// Copyright IBM Corp. 2020, 2025
// SPDX-License-Identifier: BUSL-1.1

package password

import (
	"context"
	"io"
	"strings"

	"github.com/hashicorp/boundary/internal/auth/password/store"
	"github.com/hashicorp/boundary/internal/errors"
	"github.com/hashicorp/boundary/internal/oplog"
	wrapping "github.com/hashicorp/go-kms-wrapping/v2"
	"github.com/hashicorp/go-kms-wrapping/v2/extras/structwrapping"
	"golang.org/x/crypto/argon2"
	"google.golang.org/protobuf/proto"
)

// hashingPermitPool is the global permit pool used to restrict concurrent
// password hashing. It can be resized with SetHashingPermits.
var hashingPermitPool *resizablePermitPool

func init() {
	hashingPermitPool = newResizablePermitPool(1)
}

// SetHashingPermits sets the number of concurrent password hashing operations permitted.
func SetHashingPermits(n int) error {
	const op = "password.SetHashingPermits"
	if n <= 0 {
		return errors.New(context.Background(), errors.InvalidParameter, op, "n must be greater than 0")
	}
	if err := hashingPermitPool.SetPermits(n); err != nil {
		return err
	}
	return nil
}

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

func (c *Argon2Configuration) validate(ctx context.Context) error {
	const op = "password.(Argon2Configuration).validate"
	if c == nil {
		return errors.New(ctx, errors.PasswordInvalidConfiguration, op, "missing config")
	}
	if c.Argon2Configuration == nil {
		return errors.New(ctx, errors.PasswordInvalidConfiguration, op, "missing embedded config")
	}
	if c.Iterations == 0 {
		return errors.New(ctx, errors.PasswordInvalidConfiguration, op, "missing iterations")
	}
	if c.Memory == 0 {
		return errors.New(ctx, errors.PasswordInvalidConfiguration, op, "missing memory")
	}
	if c.Threads == 0 {
		return errors.New(ctx, errors.PasswordInvalidConfiguration, op, "missing threads")
	}
	if c.SaltLength == 0 {
		return errors.New(ctx, errors.PasswordInvalidConfiguration, op, "missing salt length")
	}
	if c.KeyLength == 0 {
		return errors.New(ctx, errors.PasswordInvalidConfiguration, op, "missing key length")
	}
	return nil
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

func (c *Argon2Configuration) whereDup() (string, []any) {
	var where []string
	var args []any

	where, args = append(where, "password_method_id = ?"), append(args, c.PasswordMethodId)
	where, args = append(where, "iterations = ?"), append(args, c.Iterations)
	where, args = append(where, "memory = ?"), append(args, c.Memory)
	where, args = append(where, "threads = ?"), append(args, c.Threads)
	where, args = append(where, "key_length = ?"), append(args, c.KeyLength)
	where, args = append(where, "salt_length = ?"), append(args, c.SaltLength)

	return strings.Join(where, " and "), args
}

// A Argon2Credential contains a key derived from a password and the salt
// used in the key derivation. It is owned by an Account.
type Argon2Credential struct {
	*store.Argon2Credential
	tableName string
}

func newArgon2Credential(ctx context.Context, accountId string, password string, conf *Argon2Configuration, randReader io.Reader) (*Argon2Credential, error) {
	const op = "password.newArgon2Credential"
	if accountId == "" {
		return nil, errors.New(ctx, errors.InvalidParameter, op, "missing accountId")
	}
	if password == "" {
		return nil, errors.New(ctx, errors.InvalidParameter, op, "missing password")
	}
	if conf == nil {
		return nil, errors.New(ctx, errors.InvalidParameter, op, "missing argon2 configuration")
	}

	id, err := newArgon2CredentialId(ctx)
	if err != nil {
		return nil, errors.Wrap(ctx, err, op)
	}

	c := &Argon2Credential{
		Argon2Credential: &store.Argon2Credential{
			PrivateId:         id,
			PasswordAccountId: accountId,
			PasswordConfId:    conf.PrivateId,
			PasswordMethodId:  conf.PasswordMethodId,
		},
	}

	// Generate a random salt
	salt := make([]byte, conf.SaltLength)
	if _, err := io.ReadFull(randReader, salt); err != nil {
		return nil, errors.Wrap(ctx, err, op, errors.WithCode(errors.Io))
	}
	c.Salt = salt

	// Limit the number of concurrent calls to the argon2 hashing function,
	// since each call consumes a significant amount of CPU and memory.
	if err := hashingPermitPool.Do(ctx, func() {
		c.DerivedKey = argon2.IDKey([]byte(password), c.Salt, conf.Iterations, conf.Memory, uint8(conf.Threads), conf.KeyLength)
	}); err != nil {
		// Context was canceled while waiting for a permit
		return nil, errors.Wrap(ctx, err, op, errors.WithMsg("context canceled while waiting for hashing permit"))
	}
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
	if c != nil && c.tableName != "" {
		return c.tableName
	}
	return "auth_password_argon2_cred"
}

// SetTableName sets the table name.
func (c *Argon2Credential) SetTableName(n string) {
	c.tableName = n
}

func (c *Argon2Credential) encrypt(ctx context.Context, cipher wrapping.Wrapper) error {
	const op = "password.(Argon2Credential).encrypt"
	if err := structwrapping.WrapStruct(ctx, cipher, c.Argon2Credential, nil); err != nil {
		return errors.Wrap(ctx, err, op, errors.WithCode(errors.Encrypt))
	}
	keyId, err := cipher.KeyId(ctx)
	if err != nil {
		return errors.Wrap(ctx, err, op, errors.WithCode(errors.Encrypt), errors.WithMsg("error reading cipher key id"))
	}
	c.KeyId = keyId
	return nil
}

func (c *Argon2Credential) decrypt(ctx context.Context, cipher wrapping.Wrapper) error {
	const op = "password.(Argon2Credential).decrypt"
	if err := structwrapping.UnwrapStruct(ctx, cipher, c.Argon2Credential, nil); err != nil {
		return errors.Wrap(ctx, err, op, errors.WithCode(errors.Decrypt))
	}
	return nil
}

func (c *Argon2Credential) oplog(op oplog.OpType) oplog.Metadata {
	metadata := oplog.Metadata{
		"resource-public-id":  []string{c.PrivateId},
		"resource-type":       []string{"argon2 credential"},
		"op-type":             []string{op.String()},
		"password-account-id": []string{c.PasswordAccountId},
	}
	if c.PasswordMethodId != "" {
		metadata["password-method-id"] = []string{c.PasswordMethodId}
	}
	return metadata
}
