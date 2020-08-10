package password

import (
	"context"
	"fmt"

	"github.com/hashicorp/boundary/internal/auth/password/store"
	"github.com/hashicorp/boundary/internal/db"
	"github.com/hashicorp/boundary/internal/oplog"
)

// A Configuration is an interface holding one of the configuration types
// for a specific key derivation function. Argon2Configuration is currently
// the only configuration type.
type Configuration interface {
	AuthMethodId() string
	validate() error
}

// GetConfiguration returns the current configuration for authMethodId.
func (r *Repository) GetConfiguration(ctx context.Context, authMethodId string) (Configuration, error) {
	if authMethodId == "" {
		return nil, fmt.Errorf("get password configuration: no auth method id: %w", db.ErrInvalidParameter)
	}
	cc, err := r.currentConfig(ctx, authMethodId)
	if err != nil {
		return nil, fmt.Errorf("get password configuration: %w", err)
	}
	return cc.argon2(), nil
}

// SetConfiguration sets the configuration for c.AuthMethodId to c and
// returns a new Configuration. c is not changed. c must contain a valid
// AuthMethodId. c.PrivateId is ignored.
//
// If c contains new settings for c.AuthMethodId, SetConfiguration inserts
// c into the repository and updates AuthMethod to use the new
// configuration. If c contains settings equal to the current configuration
// for c.AuthMethodId, SetConfiguration ignores c. If c contains settings
// equal to a previous configuration for c.AuthMethodId, SetConfiguration
// updates AuthMethod to use the previous configuration.
func (r *Repository) SetConfiguration(ctx context.Context, c Configuration) (Configuration, error) {
	if c == nil {
		return nil, fmt.Errorf("set password configuration: %w", db.ErrNilParameter)
	}
	if c.AuthMethodId() == "" {
		return nil, fmt.Errorf("set password configuration: no auth method id: %w", db.ErrInvalidParameter)
	}
	if err := c.validate(); err != nil {
		return nil, fmt.Errorf("set password configuration: %w", err)
	}

	switch v := c.(type) {
	case *Argon2Configuration:
		out, err := r.setArgon2Conf(ctx, v)
		if err != nil {
			return nil, fmt.Errorf("set password configuration: %w", err)
		}
		return out, nil
	default:
		return nil, fmt.Errorf("set password configuration: %w", ErrUnsupportedConfiguration)
	}
}

func (r *Repository) setArgon2Conf(ctx context.Context, c *Argon2Configuration) (*Argon2Configuration, error) {
	c = c.clone()

	id, err := newArgon2ConfigurationId()
	if err != nil {
		return nil, err
	}
	c.PrivateId = id

	a := &AuthMethod{
		AuthMethod: &store.AuthMethod{
			PublicId: c.PasswordMethodId,
		},
	}

	newArgon2Conf := &Argon2Configuration{Argon2Configuration: &store.Argon2Configuration{}}

	_, err = r.writer.DoTx(ctx, db.StdRetryCnt, db.ExpBackoff{},
		func(rr db.Reader, w db.Writer) error {
			where, args := c.whereDup()
			if err := rr.LookupWhere(ctx, newArgon2Conf, where, args...); err != nil {
				if err != db.ErrRecordNotFound {
					return err
				}
				newArgon2Conf = c.clone()
				if err := w.Create(ctx, newArgon2Conf, db.WithOplog(r.wrapper, c.oplog(oplog.OpType_OP_TYPE_CREATE))); err != nil {
					return err
				}
			}

			a.PasswordConfId = newArgon2Conf.PrivateId
			rowsUpdated, err := w.Update(ctx, a, []string{"PasswordConfId"}, nil, db.WithOplog(r.wrapper, a.oplog(oplog.OpType_OP_TYPE_UPDATE)))
			if err == nil && rowsUpdated > 1 {
				return db.ErrMultipleRecords
			}
			return err
		},
	)
	if err != nil {
		return nil, err
	}
	return newArgon2Conf, nil
}

type currentConfig struct {
	ConfType          string
	MinUserNameLength int
	MinPasswordLength int

	*Argon2Configuration
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

func (r *Repository) currentConfigForAccount(ctx context.Context, accountId string) (*currentConfig, error) {
	var confs []currentConfig
	tx, err := r.reader.DB()
	if err != nil {
		return nil, err
	}
	rows, err := tx.Query(currentConfigForAccountQuery, accountId)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	for rows.Next() {
		var conf currentConfig
		if err := r.reader.ScanRows(rows, &conf); err != nil {
			return nil, err
		}
		confs = append(confs, conf)
	}

	var cc currentConfig
	switch {
	case len(confs) == 0:
		return nil, nil
	case len(confs) > 1:
		// this should never happen
		return nil, fmt.Errorf("multiple current configs returned for account")
	default:
		cc = confs[0]
	}
	return &cc, nil
}

func (c *currentConfig) argon2() *Argon2Configuration {
	if c.ConfType != "argon2" {
		return nil
	}
	return c.Argon2Configuration
}
