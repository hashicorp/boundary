package connect

import (
	"strings"

	"github.com/hashicorp/boundary/internal/cmd/base"
	"github.com/posener/complete"
)

const (
	postgresSynopsis = "Authorize a session against a target and invoke a Postgres client to connect"
)

func postgresOptions(c *Command, set *base.FlagSets) {
	f := set.NewFlagSet("Postgres Options")

	f.StringVar(&base.StringVar{
		Name:       "style",
		Target:     &c.flagPostgresStyle,
		EnvVar:     "BOUNDARY_CONNECT_POSTGRES_STYLE",
		Completion: complete.PredictSet("psql"),
		Default:    "psql",
		Usage:      `Specifies how the CLI will attempt to invoke a Postgres client. This will also set a suitable default for -exec if a value was not specified. Currently-understood values are "psql".`,
	})

	f.StringVar(&base.StringVar{
		Name:       "username",
		Target:     &c.flagUsername,
		EnvVar:     "BOUNDARY_CONNECT_USERNAME",
		Completion: complete.PredictNothing,
		Usage:      `Specifies the username to pass through to the client`,
	})
}

type postgresFlags struct {
	flagPostgresStyle string
}

func (p *postgresFlags) defaultExec() string {
	return strings.ToLower(p.flagPostgresStyle)
}

func (p *postgresFlags) buildArgs(c *Command, port, ip, addr string) []string {
	var args []string
	switch p.flagPostgresStyle {
	case "psql":
		args = append(args, "-p", port, "-h", ip)
		if c.flagUsername != "" {
			args = append(args, "-U", c.flagUsername)
		}
	}
	return args
}
