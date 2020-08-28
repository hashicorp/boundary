package cmd

import (
	"os"
	"os/signal"
	"syscall"

	"github.com/hashicorp/boundary/internal/cmd/base"
	"github.com/hashicorp/boundary/internal/cmd/commands/authenticate"
	"github.com/hashicorp/boundary/internal/cmd/commands/authmethods"
	"github.com/hashicorp/boundary/internal/cmd/commands/authtokens"
	"github.com/hashicorp/boundary/internal/cmd/commands/config"
	"github.com/hashicorp/boundary/internal/cmd/commands/controller"
	"github.com/hashicorp/boundary/internal/cmd/commands/dev"
	"github.com/hashicorp/boundary/internal/cmd/commands/groups"
	"github.com/hashicorp/boundary/internal/cmd/commands/hostcatalogs"
	"github.com/hashicorp/boundary/internal/cmd/commands/hosts"
	"github.com/hashicorp/boundary/internal/cmd/commands/roles"
	"github.com/hashicorp/boundary/internal/cmd/commands/scopes"
	"github.com/hashicorp/boundary/internal/cmd/commands/users"
	"github.com/hashicorp/boundary/internal/cmd/commands/worker"

	"github.com/mitchellh/cli"
)

// Commands is the mapping of all the available commands.
var Commands map[string]cli.CommandFactory

func initCommands(ui, serverCmdUi cli.Ui, runOpts *RunOptions) {
	Commands = map[string]cli.CommandFactory{
		"controller": func() (cli.Command, error) {
			return &controller.Command{
				Server: base.NewServer(&base.Command{
					UI:         serverCmdUi,
					ShutdownCh: base.MakeShutdownCh(),
				}),
				SighupCh:  MakeSighupCh(),
				SigUSR2Ch: MakeSigUSR2Ch(),
			}, nil
		},
		"worker": func() (cli.Command, error) {
			return &worker.Command{
				Server: base.NewServer(&base.Command{
					UI:         serverCmdUi,
					ShutdownCh: base.MakeShutdownCh(),
				}),
				SighupCh:  MakeSighupCh(),
				SigUSR2Ch: MakeSigUSR2Ch(),
			}, nil
		},
		"dev": func() (cli.Command, error) {
			return &dev.Command{
				Server: base.NewServer(&base.Command{
					UI:         serverCmdUi,
					ShutdownCh: base.MakeShutdownCh(),
				}),
				SighupCh:  MakeSighupCh(),
				SigUSR2Ch: MakeSigUSR2Ch(),
			}, nil
		},

		"authenticate": func() (cli.Command, error) {
			return &authenticate.Command{
				Command: base.NewCommand(ui),
			}, nil
		},
		"authenticate password": func() (cli.Command, error) {
			return &authenticate.PasswordCommand{
				Command: base.NewCommand(ui),
			}, nil
		},

		"auth-methods": func() (cli.Command, error) {
			return &authmethods.Command{
				Command: base.NewCommand(ui),
			}, nil
		},
		"auth-methods read": func() (cli.Command, error) {
			return &authmethods.Command{
				Command: base.NewCommand(ui),
				Func:    "read",
			}, nil
		},
		"auth-methods delete": func() (cli.Command, error) {
			return &authmethods.Command{
				Command: base.NewCommand(ui),
				Func:    "delete",
			}, nil
		},
		"auth-methods list": func() (cli.Command, error) {
			return &authmethods.Command{
				Command: base.NewCommand(ui),
				Func:    "list",
			}, nil
		},
		"auth-methods password": func() (cli.Command, error) {
			return &authmethods.Command{
				Command: base.NewCommand(ui),
				Func:    "password",
			}, nil
		},
		"auth-methods password create": func() (cli.Command, error) {
			return &authmethods.PasswordCommand{
				Command: base.NewCommand(ui),
				Func:    "create",
			}, nil
		},

		"auth-methods password update": func() (cli.Command, error) {
			return &authmethods.PasswordCommand{
				Command: base.NewCommand(ui),
				Func:    "update",
			}, nil
		},

		"auth-tokens": func() (cli.Command, error) {
			return &authtokens.Command{
				Command: base.NewCommand(ui),
			}, nil
		},
		"auth-tokens read": func() (cli.Command, error) {
			return &authtokens.Command{
				Command: base.NewCommand(ui),
				Func:    "read",
			}, nil
		},
		"auth-tokens delete": func() (cli.Command, error) {
			return &authtokens.Command{
				Command: base.NewCommand(ui),
				Func:    "delete",
			}, nil
		},
		"auth-tokens list": func() (cli.Command, error) {
			return &authtokens.Command{
				Command: base.NewCommand(ui),
				Func:    "list",
			}, nil
		},

		"config": func() (cli.Command, error) {
			return &config.Command{
				Command: base.NewCommand(ui),
			}, nil
		},
		"config encrypt": func() (cli.Command, error) {
			return &config.EncryptDecryptCommand{
				Command: base.NewCommand(ui),
				Func:    "encrypt",
			}, nil
		},
		"config decrypt": func() (cli.Command, error) {
			return &config.EncryptDecryptCommand{
				Command: base.NewCommand(ui),
				Func:    "decrypt",
			}, nil
		},

		"groups": func() (cli.Command, error) {
			return &groups.Command{
				Command: base.NewCommand(ui),
			}, nil
		},
		"groups create": func() (cli.Command, error) {
			return &groups.Command{
				Command: base.NewCommand(ui),
				Func:    "create",
			}, nil
		},
		"groups update": func() (cli.Command, error) {
			return &groups.Command{
				Command: base.NewCommand(ui),
				Func:    "update",
			}, nil
		},
		"groups read": func() (cli.Command, error) {
			return &groups.Command{
				Command: base.NewCommand(ui),
				Func:    "read",
			}, nil
		},
		"groups delete": func() (cli.Command, error) {
			return &groups.Command{
				Command: base.NewCommand(ui),
				Func:    "delete",
			}, nil
		},
		"groups list": func() (cli.Command, error) {
			return &groups.Command{
				Command: base.NewCommand(ui),
				Func:    "list",
			}, nil
		},
		"groups add-members": func() (cli.Command, error) {
			return &groups.Command{
				Command: base.NewCommand(ui),
				Func:    "add-members",
			}, nil
		},
		"groups set-members": func() (cli.Command, error) {
			return &groups.Command{
				Command: base.NewCommand(ui),
				Func:    "set-members",
			}, nil
		},
		"groups remove-members": func() (cli.Command, error) {
			return &groups.Command{
				Command: base.NewCommand(ui),
				Func:    "remove-members",
			}, nil
		},

		"host-catalogs": func() (cli.Command, error) {
			return &hostcatalogs.Command{
				Command: base.NewCommand(ui),
			}, nil
		},
		"host-catalogs read": func() (cli.Command, error) {
			return &hostcatalogs.Command{
				Command: base.NewCommand(ui),
				Func:    "read",
			}, nil
		},
		"host-catalogs delete": func() (cli.Command, error) {
			return &hostcatalogs.Command{
				Command: base.NewCommand(ui),
				Func:    "delete",
			}, nil
		},
		"host-catalogs list": func() (cli.Command, error) {
			return &hostcatalogs.Command{
				Command: base.NewCommand(ui),
				Func:    "list",
			}, nil
		},
		"host-catalogs static": func() (cli.Command, error) {
			return &hostcatalogs.Command{
				Command: base.NewCommand(ui),
				Func:    "static",
			}, nil
		},
		"host-catalogs static create": func() (cli.Command, error) {
			return &hostcatalogs.StaticCommand{
				Command: base.NewCommand(ui),
				Func:    "create",
			}, nil
		},

		"host-catalogs static update": func() (cli.Command, error) {
			return &hostcatalogs.StaticCommand{
				Command: base.NewCommand(ui),
				Func:    "update",
			}, nil
		},

		"hosts create": func() (cli.Command, error) {
			return &hosts.CreateCommand{
				Command: base.NewCommand(ui),
			}, nil
		},

		"roles": func() (cli.Command, error) {
			return &roles.Command{
				Command: base.NewCommand(ui),
			}, nil
		},
		"roles create": func() (cli.Command, error) {
			return &roles.Command{
				Command: base.NewCommand(ui),
				Func:    "create",
			}, nil
		},
		"roles update": func() (cli.Command, error) {
			return &roles.Command{
				Command: base.NewCommand(ui),
				Func:    "update",
			}, nil
		},
		"roles read": func() (cli.Command, error) {
			return &roles.Command{
				Command: base.NewCommand(ui),
				Func:    "read",
			}, nil
		},
		"roles delete": func() (cli.Command, error) {
			return &roles.Command{
				Command: base.NewCommand(ui),
				Func:    "delete",
			}, nil
		},
		"roles list": func() (cli.Command, error) {
			return &roles.Command{
				Command: base.NewCommand(ui),
				Func:    "list",
			}, nil
		},
		"roles add-principals": func() (cli.Command, error) {
			return &roles.Command{
				Command: base.NewCommand(ui),
				Func:    "add-principals",
			}, nil
		},
		"roles set-principals": func() (cli.Command, error) {
			return &roles.Command{
				Command: base.NewCommand(ui),
				Func:    "set-principals",
			}, nil
		},
		"roles remove-principals": func() (cli.Command, error) {
			return &roles.Command{
				Command: base.NewCommand(ui),
				Func:    "remove-principals",
			}, nil
		},
		"roles add-grants": func() (cli.Command, error) {
			return &roles.Command{
				Command: base.NewCommand(ui),
				Func:    "add-grants",
			}, nil
		},
		"roles set-grants": func() (cli.Command, error) {
			return &roles.Command{
				Command: base.NewCommand(ui),
				Func:    "set-grants",
			}, nil
		},
		"roles remove-grants": func() (cli.Command, error) {
			return &roles.Command{
				Command: base.NewCommand(ui),
				Func:    "remove-grants",
			}, nil
		},

		"scopes": func() (cli.Command, error) {
			return &scopes.Command{
				Command: base.NewCommand(ui),
			}, nil
		},
		"scopes create": func() (cli.Command, error) {
			return &scopes.Command{
				Command: base.NewCommand(ui),
				Func:    "create",
			}, nil
		},
		"scopes read": func() (cli.Command, error) {
			return &scopes.Command{
				Command: base.NewCommand(ui),
				Func:    "read",
			}, nil
		},
		"scopes update": func() (cli.Command, error) {
			return &scopes.Command{
				Command: base.NewCommand(ui),
				Func:    "update",
			}, nil
		},
		"scopes delete": func() (cli.Command, error) {
			return &scopes.Command{
				Command: base.NewCommand(ui),
				Func:    "delete",
			}, nil
		},
		"scopes list": func() (cli.Command, error) {
			return &scopes.Command{
				Command: base.NewCommand(ui),
				Func:    "list",
			}, nil
		},

		"users": func() (cli.Command, error) {
			return &users.Command{
				Command: base.NewCommand(ui),
			}, nil
		},
		"users create": func() (cli.Command, error) {
			return &users.Command{
				Command: base.NewCommand(ui),
				Func:    "create",
			}, nil
		},
		"users read": func() (cli.Command, error) {
			return &users.Command{
				Command: base.NewCommand(ui),
				Func:    "read",
			}, nil
		},
		"users update": func() (cli.Command, error) {
			return &users.Command{
				Command: base.NewCommand(ui),
				Func:    "update",
			}, nil
		},
		"users delete": func() (cli.Command, error) {
			return &users.Command{
				Command: base.NewCommand(ui),
				Func:    "delete",
			}, nil
		},
		"users list": func() (cli.Command, error) {
			return &users.Command{
				Command: base.NewCommand(ui),
				Func:    "list",
			}, nil
		},
	}
}

// MakeSighupCh returns a channel that can be used for SIGHUP
// reloading. This channel will send a message for every
// SIGHUP received.
func MakeSighupCh() chan struct{} {
	resultCh := make(chan struct{})

	signalCh := make(chan os.Signal, 4)
	signal.Notify(signalCh, syscall.SIGHUP)
	go func() {
		for {
			<-signalCh
			resultCh <- struct{}{}
		}
	}()
	return resultCh
}
