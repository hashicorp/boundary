// Copyright IBM Corp. 2020, 2025
// SPDX-License-Identifier: BUSL-1.1

package password

import (
	"context"
	"database/sql"

	"github.com/hashicorp/boundary/internal/auth/password/store"
	"github.com/hashicorp/boundary/internal/db"
	"github.com/hashicorp/boundary/internal/errors"
	"github.com/hashicorp/boundary/internal/kms"
	"github.com/hashicorp/boundary/internal/oplog"
)

// A Configuration is an interface holding one of the configuration types
// for a specific key derivation function. Argon2Configuration is currently
// the only configuration type.
type Configuration interface {
	AuthMethodId() string
	validate(context.Context) error
}

// GetConfiguration returns the current configuration for authMethodId.
func (r *Repository) GetConfiguration(ctx context.Context, authMethodId string) (Configuration, error) {
	const op = "password.(Repository).GetConfiguration"
	if authMethodId == "" {
		return nil, errors.New(ctx, errors.InvalidParameter, op, "missing auth method id")
	}
	cc, err := r.currentConfig(ctx, authMethodId)
	if err != nil {
		return nil, errors.Wrap(ctx, err, op)
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
func (r *Repository) SetConfiguration(ctx context.Context, scopeId string, c Configuration) (Configuration, error) {
	const op = "password.(Repository).SetConfiguration"
	if c == nil {
		return nil, errors.New(ctx, errors.InvalidParameter, op, "missing configuration")
	}
	if c.AuthMethodId() == "" {
		return nil, errors.New(ctx, errors.InvalidParameter, op, "missing auth method id")
	}
	if err := c.validate(ctx); err != nil {
		return nil, errors.Wrap(ctx, err, op)
	}

	switch v := c.(type) {
	case *Argon2Configuration:
		out, err := r.setArgon2Conf(ctx, scopeId, v)
		if err != nil {
			return nil, errors.Wrap(ctx, err, op)
		}
		return out, nil
	default:
		return nil, errors.New(ctx, errors.PasswordUnsupportedConfiguration, op, "unknown configuration")
	}
}

func (r *Repository) setArgon2Conf(ctx context.Context, scopeId string, c *Argon2Configuration) (*Argon2Configuration, error) {
	const op = "password.(Repository).setArgon2Conf"
	c = c.clone()

	id, err := newArgon2ConfigurationId(ctx)
	if err != nil {
		return nil, errors.Wrap(ctx, err, op)
	}
	c.PrivateId = id

	a := &AuthMethod{
		AuthMethod: &store.AuthMethod{
			PublicId: c.PasswordMethodId,
		},
	}

	oplogWrapper, err := r.kms.GetWrapper(ctx, scopeId, kms.KeyPurposeOplog)
	if err != nil {
		return nil, errors.Wrap(ctx, err, op, errors.WithCode(errors.Encrypt), errors.WithMsg("unable to get oplog wrapper"))
	}

	newArgon2Conf := &Argon2Configuration{Argon2Configuration: &store.Argon2Configuration{}}

	_, err = r.writer.DoTx(ctx, db.StdRetryCnt, db.ExpBackoff{},
		func(rr db.Reader, w db.Writer) error {
			where, args := c.whereDup()
			if err := rr.LookupWhere(ctx, newArgon2Conf, where, args); err != nil {
				if !errors.IsNotFoundError(err) {
					return errors.Wrap(ctx, err, op)
				}
				newArgon2Conf = c.clone()
				if err := w.Create(ctx, newArgon2Conf, db.WithOplog(oplogWrapper, c.oplog(oplog.OpType_OP_TYPE_CREATE))); err != nil {
					return errors.Wrap(ctx, err, op)
				}
			}

			a.PasswordConfId = newArgon2Conf.PrivateId
			rowsUpdated, err := w.Update(ctx, a, []string{"PasswordConfId"}, nil, db.WithOplog(oplogWrapper, a.oplog(oplog.OpType_OP_TYPE_UPDATE)))
			if err != nil {
				return errors.Wrap(ctx, err, op)
			}
			if rowsUpdated > 1 {
				return errors.New(ctx, errors.MultipleRecords, op, "more than 1 resource would have been updated")
			}
			return nil
		},
	)
	if err != nil {
		return nil, errors.Wrap(ctx, err, op)
	}
	return newArgon2Conf, nil
}

type currentConfig struct {
	ConfType           string
	MinLoginNameLength int
	MinPasswordLength  int

	*Argon2Configuration
}

func (c *currentConfig) TableName() string {
	return "auth_password_current_conf"
}

func (r *Repository) currentConfig(ctx context.Context, authMethodId string) (*currentConfig, error) {
	const op = "password.(Repository).currentConfig"
	var cc currentConfig
	if err := r.reader.LookupWhere(ctx, &cc, "password_method_id = ?", []any{authMethodId}); err != nil {
		return nil, errors.Wrap(ctx, err, op)
	}
	return &cc, nil
}

func (r *Repository) currentConfigForAccount(ctx context.Context, accountId string) (*currentConfig, error) {
	const op = "password.(Repository).currentConfigForAccount"
	var confs []currentConfig

	rows, err := r.reader.Query(ctx, currentConfigForAccountQuery, []any{sql.Named("public_id", accountId)})
	if err != nil {
		return nil, errors.Wrap(ctx, err, op)
	}
	defer rows.Close()
	for rows.Next() {
		var conf currentConfig
		if err := r.reader.ScanRows(ctx, rows, &conf); err != nil {
			return nil, errors.Wrap(ctx, err, op)
		}
		confs = append(confs, conf)
	}
	if err := rows.Err(); err != nil {
		return nil, errors.Wrap(ctx, err, op)
	}
	var cc currentConfig
	switch {
	case len(confs) == 0:
		return nil, nil
	case len(confs) > 1:
		// this should never happen
		return nil, errors.New(ctx, errors.Unknown, op, "multiple current configs returned for account")
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
