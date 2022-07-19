package connect

import (
	"errors"
	"fmt"
	"io/ioutil"
	"os"
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

func (s *sshFlags) buildArgs(c *Command, port, ip, addr string) (args, envs []string, consumedCreds bool, retErr error) {
	var username, password, privateKey string
	if c.sessionAuthz != nil {
		creds, err := parseCredentials(c.sessionAuthz.Credentials)
		if err != nil {
			return nil, nil, false, fmt.Errorf("Error interpreting secret: %w", err)
		}
		if len(creds) > 0 {
			// Just use first credential returned
			switch v := creds[0].(type) {
			case usernamePasswordCredential:
				username = v.Username
				password = v.Password

			case sshPrivateKeyCredential:
				username = v.Username
				privateKey = v.PrivateKey
			}
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
		if password == "" {
			return nil, nil, false, errors.New("Password is required when using sshpass")
		}

		// Set consumedCreds to true so they are not printed to user
		consumedCreds = true

		// sshpass requires that the password is passed as env-var "SSHPASS"
		// when the using env-vars.
		envs = append(envs, fmt.Sprintf("SSHPASS=%s", password))
		args = append(args, "-e", "ssh")
		args = append(args, "-p", port, ip)

		// sshpass cannot handle host key checking, disable localhost key verification
		// to avoid error: 'SSHPASS detected host authentication prompt. Exiting.'
		args = append(args, "-o", "NoHostAuthenticationForLocalhost=yes")

	case "putty":
		args = append(args, "-P", port, ip)
	}

	if privateKey != "" {
		// Set consumedCreds to true so they are not printed to user
		consumedCreds = true

		pkFile, err := ioutil.TempFile("", "*")
		if err != nil {
			return nil, nil, false, fmt.Errorf("Error saving ssh private key to tmp file: %w", err)
		}
		c.cleanupFuncs = append(c.cleanupFuncs, func() error {
			if err := os.Remove(pkFile.Name()); err != nil {
				return fmt.Errorf("Error removing temporary ssh private key file; consider removing %s manually: %w", pkFile.Name(), err)
			}
			return nil
		})
		_, err = pkFile.WriteString(privateKey)
		if err != nil {
			return nil, nil, false, fmt.Errorf("Error writing private key file to %s: %w", pkFile.Name(), err)
		}
		if err := pkFile.Close(); err != nil {
			return nil, nil, false, fmt.Errorf("Error closing private key file after writing to %s: %w", pkFile.Name(), err)
		}
		args = append(args, "-i", pkFile.Name())
		consumedCreds = true
	}

	switch {
	case username != "":
		args = append(args, "-l", username)
	case c.flagUsername != "":
		args = append(args, "-l", c.flagUsername)
	}

	return args, envs, consumedCreds, nil
}
