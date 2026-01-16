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
	cassandraSynopsis = "Authorize a session against a target and invoke a Cassandra client to connect"
)

func cassandraOptions(c *Command, set *base.FlagSets) {
	f := set.NewFlagSet("Cassandra Options")

	f.StringVar(&base.StringVar{
		Name:       "style",
		Target:     &c.flagCassandraStyle,
		EnvVar:     "BOUNDARY_CONNECT_CASSANDRA_STYLE",
		Completion: complete.PredictSet("cqlsh"),
		Default:    "cqlsh",
		Usage:      `Specifies how the CLI will attempt to invoke a Cassandra client. This will also set a suitable default for -exec if a value was not specified. Currently-understood values are "cqlsh".`,
	})

	f.StringVar(&base.StringVar{
		Name:       "username",
		Target:     &c.flagUsername,
		EnvVar:     "BOUNDARY_CONNECT_USERNAME",
		Completion: complete.PredictNothing,
		Usage:      `Specifies the username to pass through to the client. May be overridden by credentials sourced from a credential store.`,
	})

	f.StringVar(&base.StringVar{
		Name:       "keyspace",
		Target:     &c.flagDbname,
		EnvVar:     "BOUNDARY_CONNECT_KEYSPACE",
		Completion: complete.PredictNothing,
		Usage:      `Specifies the keyspace name to pass through to the client.`,
	})
}

type cassandraFlags struct {
	flagCassandraStyle string
}

func (m *cassandraFlags) defaultExec() string {
	return strings.ToLower(m.flagCassandraStyle)
}

func (m *cassandraFlags) buildArgs(c *Command, port, ip, _ string, creds proxy.Credentials) (args, envs []string, retCreds proxy.Credentials, retErr error) {
	var username, password string

	retCreds = creds
	if len(retCreds.UsernamePassword) > 0 {
		// Mark credential as consumed, such that it is not printed to the user
		retCreds.UsernamePassword[0].Consumed = true

		// Grab the first available username/password credential brokered
		username = retCreds.UsernamePassword[0].Username
		password = retCreds.UsernamePassword[0].Password
	}

	switch m.flagCassandraStyle {
	case "cqlsh":
		switch {
		case username != "":
			args = append(args, "-u", username)
		case c.flagUsername != "":
			args = append(args, "-u", c.flagUsername)
		}

		if c.flagDbname != "" {
			args = append(args, "-k", c.flagDbname)
		} else {
			c.UI.Warn("Credentials are being brokered but no -keyspace parameter provided. cqlsh may misinterpret another parameter as the keyspace name.")
		}

		if password != "" {
			passfile, err := os.CreateTemp("", "*")
			if err != nil {
				return nil, nil, proxy.Credentials{}, fmt.Errorf("Error saving cassandra password to tmp file: %w", err)
			}

			c.cleanupFuncs = append(c.cleanupFuncs, func() error {
				if err := os.Remove(passfile.Name()); err != nil {
					return fmt.Errorf("Error removing temporary password file; consider removing %s manually: %w", passfile.Name(), err)
				}
				return nil
			})

			_, err = passfile.WriteString("[PlainTextAuthProvider]\npassword = " + password)
			if err != nil {
				passfile.Close()
				return nil, nil, proxy.Credentials{}, fmt.Errorf("Error writing password file to %s: %w", passfile.Name(), err)
			}

			if err := passfile.Close(); err != nil {
				return nil, nil, proxy.Credentials{}, fmt.Errorf("Error closing password file after writing to %s: %w", passfile.Name(), err)
			}

			args = append(args, "--credentials", passfile.Name())
		}

		args = append(args, ip)
		if port != "" {
			args = append(args, port)
		}
	}
	return args, envs, retCreds, retErr
}
