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
	redisSynopsis = "Authorize a session against a target and invoke a redis client to connect"
)

func redisOptions(c *Command, set *base.FlagSets) {
	f := set.NewFlagSet("Redis Options")

	f.StringVar(&base.StringVar{
		Name:       "style",
		Target:     &c.flagRedisStyle,
		EnvVar:     "BOUNDARY_CONNECT_REDIS_STYLE",
		Completion: complete.PredictSet("redis-cli"),
		Default:    "redis-cli",
		Usage:      `Specifies how the CLI will attempt to invoke a Redis client. This will also set a suitable default for -exec if a value was not specified. Currently-understood values are "redis-cli".`,
	})

	f.StringVar(&base.StringVar{
		Name:       "username",
		Target:     &c.flagUsername,
		EnvVar:     "BOUNDARY_CONNECT_USERNAME",
		Completion: complete.PredictNothing,
		Usage:      `Specifies the username to pass through to the client. May be overridden by credentials sourced from a credential store.`,
	})
}

type redisFlags struct {
	flagRedisStyle string
}

func (r *redisFlags) defaultExec() string {
	return strings.ToLower(r.flagRedisStyle)
}

func (r *redisFlags) buildArgs(c *Command, port, ip, _ string, creds proxy.Credentials) (args, envs []string, retCreds proxy.Credentials, retErr error) {
	var username, password string

	retCreds = creds
	switch {
	case len(retCreds.UsernamePassword) > 0:
		// Mark credential as consumed, such that it is not printed to the user
		retCreds.UsernamePassword[0].Consumed = true

		// Grab the first available username/password credential brokered
		username = retCreds.UsernamePassword[0].Username
		password = retCreds.UsernamePassword[0].Password

	case len(retCreds.Password) > 0:
		// Mark credential as consumed, such that it is not printed to the user
		retCreds.Password[0].Consumed = true

		// Grab the first available password credential brokered
		password = retCreds.Password[0].Password
	}

	switch r.flagRedisStyle {
	case "redis-cli":
		args = append(args, "-h", ip)
		if port != "" {
			args = append(args, "-p", port)
		}

		switch {
		case username != "":
			args = append(args, "--user", username)
		case c.flagUsername != "":
			args = append(args, "--user", c.flagUsername)
		}

		if password != "" {
			envs = append(envs, fmt.Sprintf("REDISCLI_AUTH=%s", password))
		} else {
			// prompt for password if it wasn't provided
			envs = append(envs, "--askpass")
		}
	}

	return args, envs, retCreds, retErr
}
