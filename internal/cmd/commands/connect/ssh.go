package connect

import (
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
		Completion: complete.PredictSet("ssh", "putty"),
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

func (s *sshFlags) buildArgs(c *Command, port, ip, addr string) []string {
	// Might want -t for ssh or -tt but seems fine without it for now...
	var args []string
	switch s.flagSshStyle {
	case "ssh":
		args = append(args, "-p", port, ip)
		args = append(args, "-o", fmt.Sprintf("HostKeyAlias=%s", c.sessionAuthzData.HostId))
	case "putty":
		args = append(args, "-P", port, ip)
	}
	if c.flagUsername != "" {
		args = append(args, "-l", c.flagUsername)
	}
	return args
}
