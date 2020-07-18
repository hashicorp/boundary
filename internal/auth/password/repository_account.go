package password

import (
	"context"
	"fmt"
	"regexp"

	"github.com/hashicorp/watchtower/internal/auth/password/store"
	"github.com/hashicorp/watchtower/internal/db"
	"github.com/hashicorp/watchtower/internal/oplog"
)

// CreateAccount inserts a into the repository and returns a new
// Account containing the account's PublicId. a is not changed. a must
// contain a valid AuthMethodId. a must not contain a PublicId. The PublicId is
// generated and assigned by this method.
//
// Password is the only valid option. All other options are ignored.
//
// Both a.Name and a.Description are optional. If a.Name is set, it must be
// unique within a.AuthMethodId.
//
// Both a.CreateTime and a.UpdateTime are ignored.
func (r *Repository) CreateAccount(ctx context.Context, a *Account, opt ...Option) (*Account, error) {
	if a == nil {
		return nil, fmt.Errorf("create: password account: %w", db.ErrNilParameter)
	}
	if a.Account == nil {
		return nil, fmt.Errorf("create: password account: embedded Account: %w", db.ErrNilParameter)
	}
	if a.AuthMethodId == "" {
		return nil, fmt.Errorf("create: password account: no auth method id: %w", db.ErrInvalidParameter)
	}
	if a.PublicId != "" {
		return nil, fmt.Errorf("create: password account: public id not empty: %w", db.ErrInvalidParameter)
	}
	if !validUserName(a.UserName) {
		return nil, fmt.Errorf("create: password account: invalid user name: %w", db.ErrInvalidParameter)
	}

	cc, err := r.currentConfig(ctx, a.AuthMethodId)
	if err != nil {
		return nil, fmt.Errorf("create: password account: retrieve current configuration: %w", err)
	}

	if cc.MinUserNameLength > len(a.UserName) {
		return nil, fmt.Errorf("create: password account: user name %q: %w", a.UserName, ErrTooShort)
	}

	a = a.clone()
	id, err := newAccountId()
	if err != nil {
		return nil, fmt.Errorf("create: password account: %w", err)
	}
	a.PublicId = id

	opts := getOpts(opt...)

	var cred *Argon2Credential
	if opts.withPassword {
		if cc.MinPasswordLength > len(opts.password) {
			return nil, fmt.Errorf("create: password account: password: %w", ErrTooShort)
		}
		if cred, err = newArgon2Credential(id, opts.password, cc.argon2()); err != nil {
			return nil, fmt.Errorf("create: password account: %w", err)
		}
	}

	var newCred *Argon2Credential
	var newAccount *Account
	_, err = r.writer.DoTx(ctx, db.StdRetryCnt, db.ExpBackoff{},
		func(_ db.Reader, w db.Writer) error {
			newAccount = a.clone()
			if err := w.Create(ctx, newAccount, db.WithOplog(r.wrapper, a.oplog(oplog.OpType_OP_TYPE_CREATE))); err != nil {
				return err
			}

			if cred != nil {
				newCred = cred.clone()
				if err := newCred.encrypt(ctx, r.wrapper); err != nil {
					return err
				}
				if err := w.Create(ctx, newCred, db.WithOplog(r.wrapper, cred.oplog(oplog.OpType_OP_TYPE_CREATE))); err != nil {
					return err
				}
			}
			return nil
		},
	)

	if err != nil {
		if db.IsUniqueError(err) {
			return nil, fmt.Errorf("create: password account: in auth method: %s: name %s already exists: %w",
				a.AuthMethodId, a.Name, db.ErrNotUnique)
		}
		return nil, fmt.Errorf("create: password account: in auth method: %s: %w", a.AuthMethodId, err)
	}
	return newAccount, nil
}

var reInvalidUserName = regexp.MustCompile("[^a-z0-9.]")

func validUserName(u string) bool {
	if u == "" {
		return false
	}
	return !reInvalidUserName.Match([]byte(u))
}

type currentConfig struct {
	PasswordConfId    string `gorm:"primary_key"`
	PasswordMethodId  string
	ConfType          string
	MinUserNameLength int
	MinPasswordLength int

	Iterations uint32
	Memory     uint32
	Threads    uint32
	SaltLength uint32
	KeyLength  uint32
}

func (c *currentConfig) TableName() string {
	return "auth_password_current_conf"
}

func (r *Repository) currentConfig(ctx context.Context, authMethodId string) (*currentConfig, error) {
	var cc currentConfig
	if err := r.reader.LookupWhere(ctx, &cc, "password_method_id = ?", authMethodId); err != nil {
		return nil, err
	}
	return &cc, nil
}

func (c *currentConfig) argon2() *Argon2Configuration {
	if c.ConfType != "argon2" {
		return nil
	}
	return &Argon2Configuration{
		Argon2Configuration: &store.Argon2Configuration{
			PublicId:         c.PasswordConfId,
			PasswordMethodId: c.PasswordMethodId,
			Iterations:       c.Iterations,
			Memory:           c.Memory,
			Threads:          c.Threads,
			SaltLength:       c.SaltLength,
			KeyLength:        c.KeyLength,
		},
	}
}
