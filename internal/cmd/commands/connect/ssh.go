package connect

import (
	"errors"
	"fmt"
	"strings"

	"github.com/hashicorp/boundary/internal/cmd/base"
	"github.com/posener/complete"
)

const (
	sshSynopsis = "Authorize a session against a target and invoke an SSH client to connect"
)

func sshOptions(c *Command, set *base.FlagSets) {
	f := set.NewFlagSet("SSH Options")

	f.StringVar(&base.StringVar{
		Name:       "style",
		Target:     &c.flagSshStyle,
		EnvVar:     "BOUNDARY_CONNECT_SSH_STYLE",
		Completion: complete.PredictSet("ssh", "putty", "sshpass"),
		Default:    "ssh",
		Usage:      `Specifies how the CLI will attempt to invoke an SSH client. This will also set a suitable default for -exec if a value was not specified. Currently-understood values are "ssh" and "putty".`,
	})

	f.StringVar(&base.StringVar{
		Name:       "username",
		Target:     &c.flagUsername,
		EnvVar:     "BOUNDARY_CONNECT_USERNAME",
		Completion: complete.PredictNothing,
		Usage:      `Specifies the username to pass through to the client`,
	})
}

type sshFlags struct {
	flagSshStyle string
}

func (s *sshFlags) defaultExec() string {
	return strings.ToLower(s.flagSshStyle)
}

func (s *sshFlags) buildArgs(c *Command, port, ip, addr string) (args, envs []string, retErr error) {
	var cred usernamePasswordCredentials
	if c.sessionAuthz != nil {
		creds, err := parseCredentials(c.sessionAuthz.Credentials)
		if err != nil {
			return nil, nil, fmt.Errorf("Error interpreting secret: %w", err)
		}
		if len(creds) > 0 {
			// Just use first credentials returned
			cred = creds[0]
		}
	}

	switch strings.ToLower(s.flagSshStyle) {
	case "ssh":
		// Might want -t for ssh or -tt but seems fine without it for now...
		args = append(args, "-p", port, ip)

		// SSH detects a host key change when localhost proxy port changes, disable localhost
		// host key verification to avoid 'WARNING: REMOTE HOST IDENTIFICATION HAS CHANGED...'
		args = append(args, "-o", "NoHostAuthenticationForLocalhost=yes")

	case "sshpass":
		if cred.Password == "" {
			return nil, nil, errors.New("Password is required when using sshpass")
		}
		// sshpass requires that the password is passed as env-var "SSHPASS"
		// when the using env-vars.
		envs = append(envs, fmt.Sprintf("SSHPASS=%s", cred.Password))
		args = append(args, "-e", "ssh")
		args = append(args, "-p", port, ip)

		// sshpass cannot handle host key checking, disable localhost key verification
		// to avoid error: 'SSHPASS detected host authentication prompt. Exiting.'
		args = append(args, "-o", "NoHostAuthenticationForLocalhost=yes")

	case "putty":
		args = append(args, "-P", port, ip)
	}

	switch {
	case cred.Username != "":
		args = append(args, "-l", cred.Username)
	case c.flagUsername != "":
		args = append(args, "-l", c.flagUsername)
	}

	return args, envs, nil
}
