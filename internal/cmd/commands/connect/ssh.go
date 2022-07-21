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

func (s *sshFlags) buildArgs(c *Command, port, ip, addr string, creds credentials) (args, envs []string, retCreds credentials, retErr error) {
	var username string
	retCreds = creds

	switch strings.ToLower(s.flagSshStyle) {
	case "ssh":
		// Might want -t for ssh or -tt but seems fine without it for now...
		args = append(args, "-p", port, ip)

		// SSH detects a host key change when localhost proxy port changes, disable localhost
		// host key verification to avoid 'WARNING: REMOTE HOST IDENTIFICATION HAS CHANGED...'
		args = append(args, "-o", "NoHostAuthenticationForLocalhost=yes")

	case "sshpass":
		var password string
		if len(retCreds.usernamePassword) > 0 {
			// For now just grab the first username password credential brokered
			// Mark credential as consumed so it is not printed to user
			retCreds.usernamePassword[0].consumed = true

			username = retCreds.usernamePassword[0].Username
			password = retCreds.usernamePassword[0].Password
		}

		if password == "" {
			return nil, nil, credentials{}, errors.New("Password is required when using sshpass")
		}

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

	// Check if we got credentials to attempt to use for ssh or putty,
	// sshpass style has already be handled above as username password.
	switch strings.ToLower(s.flagSshStyle) {
	case "putty", "ssh":

		switch {
		// First check if we have a private key available
		case len(creds.sshPrivateKey) > 0:
			// For now just grab the first ssh private key credential brokered
			// Mark credential as consumed so it is not printed to user
			retCreds.sshPrivateKey[0].consumed = true

			username = retCreds.sshPrivateKey[0].Username
			privateKey := retCreds.sshPrivateKey[0].PrivateKey

			pkFile, err := ioutil.TempFile("", "*")
			if err != nil {
				return nil, nil, credentials{}, fmt.Errorf("Error saving ssh private key to tmp file: %w", err)
			}
			c.cleanupFuncs = append(c.cleanupFuncs, func() error {
				if err := os.Remove(pkFile.Name()); err != nil {
					return fmt.Errorf("Error removing temporary ssh private key file; consider removing %s manually: %w", pkFile.Name(), err)
				}
				return nil
			})
			// SSH requires the private key file to end with a newline.
			// When injesting a ssh_private_key from a file:// Boundary calls strings.TrimSpace
			// which will also trim newlines.
			if !strings.HasSuffix(privateKey, "\n") {
				privateKey = fmt.Sprintln(privateKey)
			}
			_, err = pkFile.WriteString(privateKey)
			if err != nil {
				return nil, nil, credentials{}, fmt.Errorf("Error writing private key file to %s: %w", pkFile.Name(), err)
			}
			if err := pkFile.Close(); err != nil {
				return nil, nil, credentials{}, fmt.Errorf("Error closing private key file after writing to %s: %w", pkFile.Name(), err)
			}
			args = append(args, "-i", pkFile.Name())

		// Next check if we have a username password credential
		case len(creds.usernamePassword) > 0:
			// We cannot use the password of the credential outside of sshpass but we
			// can use the username.
			// N.B. Do not mark credential as consumed, as user will still need enter
			// the password when prompted.

			if c.flagUsername == "" {
				// If the user did not actively provide a username flag set the
				// username to that of the first credential we got.
				username = retCreds.usernamePassword[0].Username
			}
		}
	}

	switch {
	case username != "":
		args = append(args, "-l", username)
	case c.flagUsername != "":
		args = append(args, "-l", c.flagUsername)
	}

	return args, envs, retCreds, nil
}
