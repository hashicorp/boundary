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
	mongoSynopsis = "Authorize a session against a target and invoke a MongoDB client to connect"
)

func mongoOptions(c *Command, set *base.FlagSets) {
	f := set.NewFlagSet("MongoDB Options")

	f.StringVar(&base.StringVar{
		Name:       "style",
		Target:     &c.flagMongoStyle,
		EnvVar:     "BOUNDARY_CONNECT_MONGO_STYLE",
		Completion: complete.PredictSet("mongo"),
		Default:    "mongo",
		Usage:      `Specifies how the CLI will attempt to invoke a MongoDB client. This will also set a suitable default for -exec if a value was not specified. Currently-understood values are "mongo".`,
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
	case "mongo":
		// Handle password first - create a temporary file for MongoDB connection string
		if password != "" {
			passfile, err := os.CreateTemp("", "*")
			if err != nil {
				return nil, nil, proxy.Credentials{}, fmt.Errorf("Error saving MongoDB password to tmp file: %w", err)
			}
			c.cleanupFuncs = append(c.cleanupFuncs, func() error {
				if err := os.Remove(passfile.Name()); err != nil {
					return fmt.Errorf("Error removing temporary password file; consider removing %s manually: %w", passfile.Name(), err)
				}
				return nil
			})
			_, err = passfile.Write([]byte(password))
			if err != nil {
				_ = passfile.Close()
				return nil, nil, proxy.Credentials{}, fmt.Errorf("Error writing password file to %s: %w", passfile.Name(), err)
			}
			if err := passfile.Close(); err != nil {
				return nil, nil, proxy.Credentials{}, fmt.Errorf("Error closing password file after writing to %s: %w", passfile.Name(), err)
			}
			// Set password file as environment variable for MongoDB client
			envs = append(envs, "MONGODB_PASSWORD_FILE="+passfile.Name())

			if c.flagDbname == "" {
				c.UI.Warn("Credentials are being brokered but no -dbname parameter provided. mongo may misinterpret another parameter as the database name.")
			}
		}

		// Build MongoDB connection string
		connectionString := "mongodb://"
		
		// Add username and password to connection string
		if username != "" {
			connectionString += username
			if password != "" {
				connectionString += ":" + password
			}
			connectionString += "@"
		} else if c.flagUsername != "" {
			connectionString += c.flagUsername
			if password != "" {
				connectionString += ":" + password
			}
			connectionString += "@"
		}

		// Add host and port
		connectionString += ip
		if port != "" {
			connectionString += ":" + port
		}

		// Add database name
		if c.flagDbname != "" {
			connectionString += "/" + c.flagDbname
		}

		args = append(args, connectionString)
	}
	return
}
