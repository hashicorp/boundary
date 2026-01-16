// Copyright IBM Corp. 2020, 2025
// SPDX-License-Identifier: BUSL-1.1

package connect

import (
	"fmt"
	"os"
	"strings"

	"github.com/hashicorp/boundary/api/proxy"
	"github.com/hashicorp/boundary/internal/cmd/base"
	"github.com/posener/complete"
)

const (
	mysqlSynopsis = "Authorize a session against a target and invoke a MySQL client to connect"
)

func mysqlOptions(c *Command, set *base.FlagSets) {
	f := set.NewFlagSet("MySQL Options")

	f.StringVar(&base.StringVar{
		Name:       "style",
		Target:     &c.flagMySQLStyle,
		EnvVar:     "BOUNDARY_CONNECT_MYSQL_STYLE",
		Completion: complete.PredictSet("mysql"),
		Default:    "mysql",
		Usage:      `Specifies how the CLI will attempt to invoke a MySQL client. This will also set a suitable default for -exec if a value was not specified. Currently-understood values are "mysql".`,
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

type mysqlFlags struct {
	flagMySQLStyle string
}

func (m *mysqlFlags) defaultExec() string {
	return strings.ToLower(m.flagMySQLStyle)
}

func (m *mysqlFlags) buildArgs(c *Command, port, ip, _ string, creds proxy.Credentials) (args, envs []string, retCreds proxy.Credentials, retErr error) {
	var username, password string

	retCreds = creds
	if len(retCreds.UsernamePassword) > 0 {
		// Mark credential as consumed so it is not printed to user
		retCreds.UsernamePassword[0].Consumed = true

		// For now just grab the first username password credential brokered
		username = retCreds.UsernamePassword[0].Username
		password = retCreds.UsernamePassword[0].Password
	}

	switch m.flagMySQLStyle {
	case "mysql":
		// Handle password first - defaults-file must be the first argument
		if password != "" {
			passfile, err := os.CreateTemp("", "*")
			if err != nil {
				return nil, nil, proxy.Credentials{}, fmt.Errorf("Error saving MySQL password to tmp file: %w", err)
			}
			c.cleanupFuncs = append(c.cleanupFuncs, func() error {
				if err := os.Remove(passfile.Name()); err != nil {
					return fmt.Errorf("Error removing temporary password file; consider removing %s manually: %w", passfile.Name(), err)
				}
				return nil
			})
			_, err = passfile.Write([]byte("[client]\npassword=" + password))
			if err != nil {
				_ = passfile.Close()
				return nil, nil, proxy.Credentials{}, fmt.Errorf("Error writing password file to %s: %w", passfile.Name(), err)
			}
			if err := passfile.Close(); err != nil {
				return nil, nil, proxy.Credentials{}, fmt.Errorf("Error closing password file after writing to %s: %w", passfile.Name(), err)
			}
			// --defaults-file must be the first argument
			args = append([]string{"--defaults-file=" + passfile.Name()}, args...)

			if c.flagDbname == "" {
				c.UI.Warn("Credentials are being brokered but no -dbname parameter provided. mysql may misinterpret another parameter as the database name.")
			}
		} else {
			// If no password provided, add -p to prompt for password
			args = append(args, "-p")
		}

		if port != "" {
			args = append(args, "-P", port)
		}
		args = append(args, "-h", ip)

		if c.flagDbname != "" {
			args = append(args, "-D", c.flagDbname)
		}

		switch {
		case username != "":
			args = append(args, "-u", username)
		case c.flagUsername != "":
			args = append(args, "-u", c.flagUsername)
		}
	}
	return args, envs, retCreds, retErr
}
