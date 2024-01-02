// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: BUSL-1.1


package connect

import (
	"fmt"
	"os"
	"strings"

	"github.com/hashicorp/boundary/internal/cmd/base"
	"github.com/posener/complete"
)

const (
	postgresSynopsis = "Authorize a session against a target and invoke a Postgres client to connect"
)

func postgresOptions(c *Command, set *base.FlagSets) {
	f := set.NewFlagSet("Postgres Options")

	f.StringVar(&base.StringVar{
		Name:       "style",
		Target:     &c.flagPostgresStyle,
		EnvVar:     "BOUNDARY_CONNECT_POSTGRES_STYLE",
		Completion: complete.PredictSet("psql"),
		Default:    "psql",
		Usage:      `Specifies how the CLI will attempt to invoke a Postgres client. This will also set a suitable default for -exec if a value was not specified. Currently-understood values are "psql".`,
	})

	f.StringVar(&base.StringVar{
		Name:       "username",
		Target:     &c.flagUsername,
		EnvVar:     "BOUNDARY_CONNECT_USERNAME",
		Completion: complete.PredictNothing,
		Usage:      `Specifies the username to pass through to the client. May be overridden by credentials sourced from a credential store.`,
	})

	f.StringVar(&base.StringVar{
		Name:       "dbname",
		Target:     &c.flagDbname,
		EnvVar:     "BOUNDARY_CONNECT_DBNAME",
		Completion: complete.PredictNothing,
		Usage:      `Specifies the database name to pass through to the client.`,
	})
}

type postgresFlags struct {
	flagPostgresStyle string
}

func (p *postgresFlags) defaultExec() string {
	return strings.ToLower(p.flagPostgresStyle)
}

func (p *postgresFlags) buildArgs(c *Command, port, ip, _ string, creds credentials) (args, envs []string, retCreds credentials, retErr error) {
	var username, password string

	retCreds = creds
	if len(retCreds.usernamePassword) > 0 {
		// Mark credential as consumed so it is not printed to user
		retCreds.usernamePassword[0].consumed = true

		// For now just grab the first username password credential brokered
		username = retCreds.usernamePassword[0].Username
		password = retCreds.usernamePassword[0].Password
	}

	switch p.flagPostgresStyle {
	case "psql":
		args = append(args, "-p", port, "-h", ip)

		if c.flagDbname != "" {
			args = append(args, "-d", c.flagDbname)
		}

		switch {
		case username != "":
			args = append(args, "-U", username)
		case c.flagUsername != "":
			args = append(args, "-U", c.flagUsername)
		}

		if password != "" {
			passfile, err := os.CreateTemp("", "*")
			if err != nil {
				return nil, nil, credentials{}, fmt.Errorf("Error saving postgres password to tmp file: %w", err)
			}
			c.cleanupFuncs = append(c.cleanupFuncs, func() error {
				if err := os.Remove(passfile.Name()); err != nil {
					return fmt.Errorf("Error removing temporary password file; consider removing %s manually: %w", passfile.Name(), err)
				}
				return nil
			})
			_, err = passfile.WriteString(fmt.Sprintf("*:*:*:*:%s", password))
			if err != nil {
				return nil, nil, credentials{}, fmt.Errorf("Error writing password file to %s: %w", passfile.Name(), err)
			}
			if err := passfile.Close(); err != nil {
				return nil, nil, credentials{}, fmt.Errorf("Error closing password file after writing to %s: %w", passfile.Name(), err)
			}
			envs = append(envs, fmt.Sprintf("PGPASSFILE=%s", passfile.Name()))

			if c.flagDbname == "" {
				c.UI.Warn("Credentials are being brokered but no -dbname parameter provided. psql may misinterpret another parameter as the database name.")
			}
		}
	}
	return
}
