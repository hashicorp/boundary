package userpass

import (
	"context"
	"errors"
	"fmt"

	wrapping "github.com/hashicorp/go-kms-wrapping"
	"github.com/hashicorp/watchtower/internal/db"
)

var (
	// ErrTooShort is returned when a new password is to short.
	ErrTooShort = errors.New("password to short")
)

// Option - how Options are passed as arguments.
type Option func(*options)

type options struct {
}

// A Repository stores and retrieves the persistent types in the userpass
// package. It is not safe to use a repository concurrently.
type Repository struct {
	reader  db.Reader
	writer  db.Writer
	wrapper wrapping.Wrapper
}

// NewRepository creates a new Repository. The returned repository should
// only be used for one transaction and it is not safe for concurrent go
// routines to access it.
func NewRepository(r db.Reader, w db.Writer, wrapper wrapping.Wrapper) (*Repository, error) {
	switch {
	case r == nil:
		return nil, fmt.Errorf("db.Reader: %w", db.ErrNilParameter)
	case w == nil:
		return nil, fmt.Errorf("db.Writer: %w", db.ErrNilParameter)
	case wrapper == nil:
		return nil, fmt.Errorf("wrapping.Wrapper: %w", db.ErrNilParameter)
	}

	return &Repository{
		reader:  r,
		writer:  w,
		wrapper: wrapper,
	}, nil
}

// A User represents an IAM User configured for username/password
// authentication.
type User struct {
	// UserID is the iam.UserID of the user.
	UserID string

	// UserName is the username used for username/password authentication.
	// The UserName must be unique within the scope of the UserID.
	UserName string

	// Password is the password used for username/password authentication.
	// If set, the password must contain at least 8 characters.
	//
	// Password is never returned from any method.
	Password string

	// CredentialID is a unique ID representing the user's current
	// password. A new CredentialID is created when a user's password is
	// changed. If the user's password is not set, the CredentialID will be
	// empty.
	CredentialID string
}

// CreateUser inserts u into the repository and returns a new User with an
// empty password. u is not changed. u must contain a valid iam UserID. u
// must contain a UserName unique with the scope of the UserID. opt is
// ignored.
//
// If u.Password is empty, a user will be created but username/password
// authentication will be disabled for the user.
func (r *Repository) CreateUser(ctx context.Context, u *User, opt ...Option) (*User, error) {
	panic("not implemented")
}

// UpdateUser updates the repository entry for u.UserId with the values in
// u for the fields listed in fieldMask. It returns a new User with an
// empty password containing the updated values and a count of the number
// of records updated. u is not changed.
//
// u must contain a valid iam UserID. Only u.UserName and u.Password can be
// updated. If u.UserName is set to a non-empty string, it must be unique
// within the scope of the UserId.
//
// If u.Password is set to the zero value and included in fieldMask, the
// user's password will be deleted and username/password authentication
// will be disabled for the user.
//
// Any other attributes of u set to the zero value and included in the
// fieldMask will result in a db.ErrInvalidFieldMask. Only password can be
// set to NULL in the database.
func (r *Repository) UpdateUser(ctx context.Context, u *User, fieldMask []string, opt ...Option) (*User, int, error) {
	panic("not implemented")
}

// LookupUser returns the User for id. The Password for the returned user
// will be empty. Returns nil, nil if no User is found for id.
func (r *Repository) LookupUser(ctx context.Context, id string, opt ...Option) (*User, error) {
	panic("not implemented")
}

// DeleteUser deletes id from the repository returning a count of the
// number of records deleted.
func (r *Repository) DeleteUser(ctx context.Context, id string, opt ...Option) (int, error) {
	panic("not implemented")
}

// Authenticate returns true and a CredentialID if password matches the
// password for userName in scopeId.
//
// A CredentialID represents a user's current password. A new CredentialID
// is generated when a user's password is changed.
//
// Authenticate will update the stored values for password to the current
// password settings for scopeId if authentication is successful and the
// stored values are not using the current password settings.
func (r *Repository) Authenticate(ctx context.Context, scopeId string, userName string, password string) (bool, string, error) {
	panic("not implemented")
}

// ChangePassword updates the password for userName in scopeId to new if
// old equals the stored password. Returns true and a CredentialID if
// password is successfully changed.
//
// Returns false if old does not match the stored password for userName.
func (r *Repository) ChangePassword(ctx context.Context, scopeId string, userName string, old, new string) (bool, string, error) {
	panic("not implemented")
}

// A Configuration is an interface holding one of the configuration types.
// Argon2 is currently the only configuration type.
type Configuration interface{}

// GetConfiguration returns the current configuration for scopeId.
func (r *Repository) GetConfiguration(ctx context.Context, scopeId string) (Configuration, error) {
	panic("not implemented")
}

// SetConfiguration sets the configuration for scopeId to c.
func (r *Repository) SetConfiguration(ctx context.Context, scopeId string, c Configuration) error {
	panic("not implemented")
}

// Argon2 is a Configuration for using the argon2id key derivation
// function. For a detailed specification of Argon2 see:
// https://github.com/P-H-C/phc-winner-argon2/blob/master/argon2-specs.pdf
//
// Iterations, Memory, and Threads are the cost parameters. The cost
// parameters should be increased as memory latency and CPU parallelism
// increases.
type Argon2 struct {

	// Iterations is the time parameter in the Argon2 specification. It
	// specifies the number of passes over the memory. Must be > 0.
	Iterations uint32

	// Memory is the memory parameter in the Argon2 specification. It
	// specifies the size of the memory in KiB. For example Memory=32*1024
	// sets the memory cost to ~32 MB. Must be > 0.
	Memory uint32

	// Threads is the threads parameter in the Argon2 specification. It
	// can be adjusted to the number of available CPUs. Must be > 0.
	Threads uint8

	// SaltLength is in bytes. Must be >= 16.
	SaltLength uint32

	// KeyLength is in bytes. Must be >= 16.
	KeyLength uint32
}
