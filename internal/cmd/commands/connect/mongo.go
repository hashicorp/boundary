// Copyright IBM Corp. 2020, 2025
// SPDX-License-Identifier: BUSL-1.1

package connect

import (
	"fmt"
	"strings"

	"github.com/hashicorp/boundary/api/proxy"
	"github.com/hashicorp/boundary/internal/cmd/base"
	"github.com/posener/complete"
)

const (
	mongoSynopsis = "Authorize a session against a target and invoke a MongoDB client to connect"
)

func mongoOptions(c *Command, set *base.FlagSets) {
	f := set.NewFlagSet("MongoDB Options")

	f.StringVar(&base.StringVar{
		Name:       "style",
		Target:     &c.flagMongoStyle,
		EnvVar:     "BOUNDARY_CONNECT_MONGO_STYLE",
		Completion: complete.PredictSet("mongosh"),
		Default:    "mongosh",
		Usage:      `Specifies how the CLI will attempt to invoke a MongoDB client. Currently only "mongosh" is supported.`,
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

	f.StringVar(&base.StringVar{
		Name:       "authentication-database",
		Target:     &c.flagMongoDbAuthenticationDatabase,
		EnvVar:     "BOUNDARY_CONNECT_MONGO_AUTHENTICATION_DATABASE",
		Completion: complete.PredictNothing,
		Default:    "",
		Usage:      `Specifies the authentication database for MongoDB. If omitted, mongosh defaults authSource to the database name (dbname); if none is specified, it defaults to "admin".`,
	})
}

type mongoFlags struct {
	flagMongoStyle string
}

func (m *mongoFlags) defaultExec() string {
	return strings.ToLower(m.flagMongoStyle)
}

func (m *mongoFlags) buildArgs(c *Command, port, ip, _ string, creds proxy.Credentials) (args, envs []string, retCreds proxy.Credentials, retErr error) {
	var username, password string

	retCreds = creds
	if len(retCreds.UsernamePassword) > 0 {
		// Mark credential as consumed so it is not printed to user
		retCreds.UsernamePassword[0].Consumed = true

		// For now just grab the first username password credential brokered
		username = retCreds.UsernamePassword[0].Username
		password = retCreds.UsernamePassword[0].Password
	}

	switch m.flagMongoStyle {
	case "mongosh":
		if port != "" {
			args = append(args, "--port", port)
		}
		args = append(args, "--host", ip)

		if c.flagDbname != "" {
			args = append(args, c.flagDbname)
		}

		switch {
		case username != "":
			args = append(args, "-u", username)
		case c.flagUsername != "":
			args = append(args, "-u", c.flagUsername)
		}

		if password != "" {
			args = append(args, "-p", password)
			if c.flagDbname == "" {
				c.UI.Warn("Credentials are being brokered but no -dbname parameter provided. mongosh will default the database to 'test'.")
			}
		}

		if c.flagMongoDbAuthenticationDatabase != "" {
			args = append(args, "--authenticationDatabase", c.flagMongoDbAuthenticationDatabase)
		}
	default:
		return nil, nil, proxy.Credentials{}, fmt.Errorf("unsupported MongoDB style: %s", m.flagMongoStyle)
	}
	return args, envs, retCreds, retErr
}
