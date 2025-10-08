package connect

import (
	"fmt"
	"net/url"
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
		Name:       "auth-source",
		Target:     &c.flagAuthSource,
		EnvVar:     "BOUNDARY_CONNECT_MONGO_AUTH_SOURCE",
		Completion: complete.PredictNothing,
		Default:    "",
		Usage:      `Specifies the authentication database for MongoDB. If omitted, mongosh defaults authSource to the database specified in the connection string (dbname); if none is specified, it defaults to "admin".`,
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
		u := &url.URL{Scheme: "mongodb"}

		var userInfo *url.Userinfo
		if username != "" {
			if password != "" {
				userInfo = url.UserPassword(username, password)
			} else {
				userInfo = url.User(username)
			}
		} else if c.flagUsername != "" {
			if password != "" {
				userInfo = url.UserPassword(c.flagUsername, password)
			} else {
				userInfo = url.User(c.flagUsername)
			}
		}
		if userInfo != nil {
			u.User = userInfo
		}

		host := ip
		if port != "" {
			host = host + ":" + port
		}
		u.Host = host

		if c.flagDbname != "" {
			u.Path = "/" + c.flagDbname
		}

		if c.flagDbname == "" {
			c.UI.Warn("No -dbname parameter provided. mongosh will default the database to 'test'. You may need to run 'use <db>' or pass -dbname.")
		}

		if c.flagAuthSource != "" {
			q := u.Query()
			// do not overwrite if already present (defensive, though we control construction)
			hasAuthSource := false
			for key := range q {
				if strings.EqualFold(key, "authSource") {
					hasAuthSource = true
					break
				}
			}
			if !hasAuthSource {
				q.Set("authSource", c.flagAuthSource)
				u.RawQuery = q.Encode()
			}
		}

		args = append(args, u.String())
	default:
		return nil, nil, proxy.Credentials{}, fmt.Errorf("unsupported MongoDB style: %s", m.flagMongoStyle)
	}
	return
}
