package cmd

import (
	"github.com/hashicorp/boundary/internal/cmd/base"
	"github.com/hashicorp/boundary/internal/cmd/commands/accountscmd"
	"github.com/hashicorp/boundary/internal/cmd/commands/authenticate"
	"github.com/hashicorp/boundary/internal/cmd/commands/authmethodscmd"
	"github.com/hashicorp/boundary/internal/cmd/commands/authtokenscmd"
	"github.com/hashicorp/boundary/internal/cmd/commands/config"
	"github.com/hashicorp/boundary/internal/cmd/commands/connect"
	"github.com/hashicorp/boundary/internal/cmd/commands/database"
	"github.com/hashicorp/boundary/internal/cmd/commands/dev"
	"github.com/hashicorp/boundary/internal/cmd/commands/groupscmd"
	"github.com/hashicorp/boundary/internal/cmd/commands/hostcatalogscmd"
	"github.com/hashicorp/boundary/internal/cmd/commands/hostscmd"
	"github.com/hashicorp/boundary/internal/cmd/commands/hostsetscmd"
	"github.com/hashicorp/boundary/internal/cmd/commands/rolescmd"
	"github.com/hashicorp/boundary/internal/cmd/commands/scopescmd"
	"github.com/hashicorp/boundary/internal/cmd/commands/server"
	"github.com/hashicorp/boundary/internal/cmd/commands/sessionscmd"
	"github.com/hashicorp/boundary/internal/cmd/commands/targetscmd"
	"github.com/hashicorp/boundary/internal/cmd/commands/userscmd"
	"github.com/hashicorp/boundary/internal/cmd/commands/version"

	"github.com/mitchellh/cli"
)

// Commands is the mapping of all the available commands.
var Commands map[string]cli.CommandFactory

func initCommands(ui, serverCmdUi cli.Ui, runOpts *RunOptions) {
	Commands = map[string]cli.CommandFactory{
		"server": func() (cli.Command, error) {
			return &server.Command{
				Server:    base.NewServer(base.NewCommand(serverCmdUi)),
				SighupCh:  base.MakeSighupCh(),
				SigUSR2Ch: MakeSigUSR2Ch(),
			}, nil
		},
		"dev": func() (cli.Command, error) {
			return &dev.Command{
				Server:    base.NewServer(base.NewCommand(serverCmdUi)),
				SighupCh:  base.MakeSighupCh(),
				SigUSR2Ch: MakeSigUSR2Ch(),
			}, nil
		},
		"version": func() (cli.Command, error) {
			return &version.Command{
				Command: base.NewCommand(ui),
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

		"accounts": func() (cli.Command, error) {
			return &accountscmd.Command{
				Command: base.NewCommand(ui),
			}, nil
		},
		"accounts read": func() (cli.Command, error) {
			return &accountscmd.Command{
				Command: base.NewCommand(ui),
				Func:    "read",
			}, nil
		},
		"accounts delete": func() (cli.Command, error) {
			return &accountscmd.Command{
				Command: base.NewCommand(ui),
				Func:    "delete",
			}, nil
		},
		"accounts list": func() (cli.Command, error) {
			return &accountscmd.Command{
				Command: base.NewCommand(ui),
				Func:    "list",
			}, nil
		},
		"accounts set-password": func() (cli.Command, error) {
			return &accountscmd.Command{
				Command: base.NewCommand(ui),
				Func:    "set-password",
			}, nil
		},
		"accounts change-password": func() (cli.Command, error) {
			return &accountscmd.Command{
				Command: base.NewCommand(ui),
				Func:    "change-password",
			}, nil
		},
		"accounts create": func() (cli.Command, error) {
			return &accountscmd.Command{
				Command: base.NewCommand(ui),
				Func:    "create",
			}, nil
		},
		"accounts create password": func() (cli.Command, error) {
			return &accountscmd.PasswordCommand{
				Command: base.NewCommand(ui),
				Func:    "create",
			}, nil
		},
		"accounts update": func() (cli.Command, error) {
			return &accountscmd.Command{
				Command: base.NewCommand(ui),
				Func:    "update",
			}, nil
		},
		"accounts update password": func() (cli.Command, error) {
			return &accountscmd.PasswordCommand{
				Command: base.NewCommand(ui),
				Func:    "update",
			}, nil
		},

		"auth-methods": func() (cli.Command, error) {
			return &authmethodscmd.Command{
				Command: base.NewCommand(ui),
			}, nil
		},
		"auth-methods read": func() (cli.Command, error) {
			return &authmethodscmd.Command{
				Command: base.NewCommand(ui),
				Func:    "read",
			}, nil
		},
		"auth-methods delete": func() (cli.Command, error) {
			return &authmethodscmd.Command{
				Command: base.NewCommand(ui),
				Func:    "delete",
			}, nil
		},
		"auth-methods list": func() (cli.Command, error) {
			return &authmethodscmd.Command{
				Command: base.NewCommand(ui),
				Func:    "list",
			}, nil
		},
		"auth-methods create": func() (cli.Command, error) {
			return &authmethodscmd.Command{
				Command: base.NewCommand(ui),
				Func:    "create",
			}, nil
		},
		"auth-methods create password": func() (cli.Command, error) {
			return &authmethodscmd.PasswordCommand{
				Command: base.NewCommand(ui),
				Func:    "create",
			}, nil
		},
		"auth-methods update": func() (cli.Command, error) {
			return &authmethodscmd.Command{
				Command: base.NewCommand(ui),
				Func:    "update",
			}, nil
		},
		"auth-methods update password": func() (cli.Command, error) {
			return &authmethodscmd.PasswordCommand{
				Command: base.NewCommand(ui),
				Func:    "update",
			}, nil
		},

		"auth-tokens": func() (cli.Command, error) {
			return &authtokenscmd.Command{
				Command: base.NewCommand(ui),
			}, nil
		},
		"auth-tokens read": func() (cli.Command, error) {
			return &authtokenscmd.Command{
				Command: base.NewCommand(ui),
				Func:    "read",
			}, nil
		},
		"auth-tokens delete": func() (cli.Command, error) {
			return &authtokenscmd.Command{
				Command: base.NewCommand(ui),
				Func:    "delete",
			}, nil
		},
		"auth-tokens list": func() (cli.Command, error) {
			return &authtokenscmd.Command{
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
		"config get-token": func() (cli.Command, error) {
			return &config.TokenCommand{
				Command: base.NewCommand(ui),
				Func:    "get-token",
			}, nil
		},
		"config autocomplete": func() (cli.Command, error) {
			return &config.AutocompleteCommand{
				Command: base.NewCommand(ui),
				Func:    "base",
			}, nil
		},
		"config autocomplete install": func() (cli.Command, error) {
			return &config.AutocompleteCommand{
				Command: base.NewCommand(ui),
				Func:    "install",
			}, nil
		},
		"config autocomplete uninstall": func() (cli.Command, error) {
			return &config.AutocompleteCommand{
				Command: base.NewCommand(ui),
				Func:    "uninstall",
			}, nil
		},

		"connect": func() (cli.Command, error) {
			return &connect.Command{
				Command: base.NewCommand(ui),
				Func:    "connect",
			}, nil
		},
		"connect http": func() (cli.Command, error) {
			return &connect.Command{
				Command: base.NewCommand(ui),
				Func:    "http",
			}, nil
		},
		"connect kube": func() (cli.Command, error) {
			return &connect.Command{
				Command: base.NewCommand(ui),
				Func:    "kube",
			}, nil
		},
		"connect postgres": func() (cli.Command, error) {
			return &connect.Command{
				Command: base.NewCommand(ui),
				Func:    "postgres",
			}, nil
		},
		"connect rdp": func() (cli.Command, error) {
			return &connect.Command{
				Command: base.NewCommand(ui),
				Func:    "rdp",
			}, nil
		},
		"connect ssh": func() (cli.Command, error) {
			return &connect.Command{
				Command: base.NewCommand(ui),
				Func:    "ssh",
			}, nil
		},

		"database": func() (cli.Command, error) {
			return &database.Command{
				Command: base.NewCommand(ui),
			}, nil
		},
		"database init": func() (cli.Command, error) {
			return &database.InitCommand{
				Command: base.NewCommand(ui),
			}, nil
		},
		"database migrate": func() (cli.Command, error) {
			return &database.MigrateCommand{
				Command: base.NewCommand(ui),
			}, nil
		},

		"groups": func() (cli.Command, error) {
			return &groupscmd.Command{
				Command: base.NewCommand(ui),
			}, nil
		},
		"groups create": func() (cli.Command, error) {
			return &groupscmd.Command{
				Command: base.NewCommand(ui),
				Func:    "create",
			}, nil
		},
		"groups update": func() (cli.Command, error) {
			return &groupscmd.Command{
				Command: base.NewCommand(ui),
				Func:    "update",
			}, nil
		},
		"groups read": func() (cli.Command, error) {
			return &groupscmd.Command{
				Command: base.NewCommand(ui),
				Func:    "read",
			}, nil
		},
		"groups delete": func() (cli.Command, error) {
			return &groupscmd.Command{
				Command: base.NewCommand(ui),
				Func:    "delete",
			}, nil
		},
		"groups list": func() (cli.Command, error) {
			return &groupscmd.Command{
				Command: base.NewCommand(ui),
				Func:    "list",
			}, nil
		},
		"groups add-members": func() (cli.Command, error) {
			return &groupscmd.Command{
				Command: base.NewCommand(ui),
				Func:    "add-members",
			}, nil
		},
		"groups set-members": func() (cli.Command, error) {
			return &groupscmd.Command{
				Command: base.NewCommand(ui),
				Func:    "set-members",
			}, nil
		},
		"groups remove-members": func() (cli.Command, error) {
			return &groupscmd.Command{
				Command: base.NewCommand(ui),
				Func:    "remove-members",
			}, nil
		},

		"host-catalogs": func() (cli.Command, error) {
			return &hostcatalogscmd.Command{
				Command: base.NewCommand(ui),
			}, nil
		},
		"host-catalogs read": func() (cli.Command, error) {
			return &hostcatalogscmd.Command{
				Command: base.NewCommand(ui),
				Func:    "read",
			}, nil
		},
		"host-catalogs delete": func() (cli.Command, error) {
			return &hostcatalogscmd.Command{
				Command: base.NewCommand(ui),
				Func:    "delete",
			}, nil
		},
		"host-catalogs list": func() (cli.Command, error) {
			return &hostcatalogscmd.Command{
				Command: base.NewCommand(ui),
				Func:    "list",
			}, nil
		},
		"host-catalogs create": func() (cli.Command, error) {
			return &hostcatalogscmd.Command{
				Command: base.NewCommand(ui),
				Func:    "create",
			}, nil
		},
		"host-catalogs create static": func() (cli.Command, error) {
			return &hostcatalogscmd.StaticCommand{
				Command: base.NewCommand(ui),
				Func:    "create",
			}, nil
		},
		"host-catalogs update": func() (cli.Command, error) {
			return &hostcatalogscmd.Command{
				Command: base.NewCommand(ui),
				Func:    "update",
			}, nil
		},
		"host-catalogs update static": func() (cli.Command, error) {
			return &hostcatalogscmd.StaticCommand{
				Command: base.NewCommand(ui),
				Func:    "update",
			}, nil
		},

		"host-sets": func() (cli.Command, error) {
			return &hostsetscmd.Command{
				Command: base.NewCommand(ui),
			}, nil
		},
		"host-sets read": func() (cli.Command, error) {
			return &hostsetscmd.Command{
				Command: base.NewCommand(ui),
				Func:    "read",
			}, nil
		},
		"host-sets delete": func() (cli.Command, error) {
			return &hostsetscmd.Command{
				Command: base.NewCommand(ui),
				Func:    "delete",
			}, nil
		},
		"host-sets list": func() (cli.Command, error) {
			return &hostsetscmd.Command{
				Command: base.NewCommand(ui),
				Func:    "list",
			}, nil
		},
		"host-sets create": func() (cli.Command, error) {
			return &hostsetscmd.Command{
				Command: base.NewCommand(ui),
				Func:    "create",
			}, nil
		},
		"host-sets create static": func() (cli.Command, error) {
			return &hostsetscmd.StaticCommand{
				Command: base.NewCommand(ui),
				Func:    "create",
			}, nil
		},
		"host-sets update": func() (cli.Command, error) {
			return &hostsetscmd.Command{
				Command: base.NewCommand(ui),
				Func:    "update",
			}, nil
		},
		"host-sets update static": func() (cli.Command, error) {
			return &hostsetscmd.StaticCommand{
				Command: base.NewCommand(ui),
				Func:    "update",
			}, nil
		},
		"host-sets add-hosts": func() (cli.Command, error) {
			return &hostsetscmd.Command{
				Command: base.NewCommand(ui),
				Func:    "add-hosts",
			}, nil
		},
		"host-sets remove-hosts": func() (cli.Command, error) {
			return &hostsetscmd.Command{
				Command: base.NewCommand(ui),
				Func:    "remove-hosts",
			}, nil
		},
		"host-sets set-hosts": func() (cli.Command, error) {
			return &hostsetscmd.Command{
				Command: base.NewCommand(ui),
				Func:    "set-hosts",
			}, nil
		},

		"hosts": func() (cli.Command, error) {
			return &hostscmd.Command{
				Command: base.NewCommand(ui),
			}, nil
		},
		"hosts read": func() (cli.Command, error) {
			return &hostscmd.Command{
				Command: base.NewCommand(ui),
				Func:    "read",
			}, nil
		},
		"hosts delete": func() (cli.Command, error) {
			return &hostscmd.Command{
				Command: base.NewCommand(ui),
				Func:    "delete",
			}, nil
		},
		"hosts list": func() (cli.Command, error) {
			return &hostscmd.Command{
				Command: base.NewCommand(ui),
				Func:    "list",
			}, nil
		},
		"hosts create": func() (cli.Command, error) {
			return &hostscmd.Command{
				Command: base.NewCommand(ui),
				Func:    "create",
			}, nil
		},
		"hosts create static": func() (cli.Command, error) {
			return &hostscmd.StaticCommand{
				Command: base.NewCommand(ui),
				Func:    "create",
			}, nil
		},
		"hosts update": func() (cli.Command, error) {
			return &hostscmd.Command{
				Command: base.NewCommand(ui),
				Func:    "update",
			}, nil
		},
		"hosts update static": func() (cli.Command, error) {
			return &hostscmd.StaticCommand{
				Command: base.NewCommand(ui),
				Func:    "update",
			}, nil
		},

		"roles": func() (cli.Command, error) {
			return &rolescmd.Command{
				Command: base.NewCommand(ui),
			}, nil
		},
		"roles create": func() (cli.Command, error) {
			return &rolescmd.Command{
				Command: base.NewCommand(ui),
				Func:    "create",
			}, nil
		},
		"roles update": func() (cli.Command, error) {
			return &rolescmd.Command{
				Command: base.NewCommand(ui),
				Func:    "update",
			}, nil
		},
		"roles read": func() (cli.Command, error) {
			return &rolescmd.Command{
				Command: base.NewCommand(ui),
				Func:    "read",
			}, nil
		},
		"roles delete": func() (cli.Command, error) {
			return &rolescmd.Command{
				Command: base.NewCommand(ui),
				Func:    "delete",
			}, nil
		},
		"roles list": func() (cli.Command, error) {
			return &rolescmd.Command{
				Command: base.NewCommand(ui),
				Func:    "list",
			}, nil
		},
		"roles add-principals": func() (cli.Command, error) {
			return &rolescmd.Command{
				Command: base.NewCommand(ui),
				Func:    "add-principals",
			}, nil
		},
		"roles set-principals": func() (cli.Command, error) {
			return &rolescmd.Command{
				Command: base.NewCommand(ui),
				Func:    "set-principals",
			}, nil
		},
		"roles remove-principals": func() (cli.Command, error) {
			return &rolescmd.Command{
				Command: base.NewCommand(ui),
				Func:    "remove-principals",
			}, nil
		},
		"roles add-grants": func() (cli.Command, error) {
			return &rolescmd.Command{
				Command: base.NewCommand(ui),
				Func:    "add-grants",
			}, nil
		},
		"roles set-grants": func() (cli.Command, error) {
			return &rolescmd.Command{
				Command: base.NewCommand(ui),
				Func:    "set-grants",
			}, nil
		},
		"roles remove-grants": func() (cli.Command, error) {
			return &rolescmd.Command{
				Command: base.NewCommand(ui),
				Func:    "remove-grants",
			}, nil
		},

		"scopes": func() (cli.Command, error) {
			return &scopescmd.Command{
				Command: base.NewCommand(ui),
			}, nil
		},
		"scopes create": func() (cli.Command, error) {
			return &scopescmd.Command{
				Command: base.NewCommand(ui),
				Func:    "create",
			}, nil
		},
		"scopes read": func() (cli.Command, error) {
			return &scopescmd.Command{
				Command: base.NewCommand(ui),
				Func:    "read",
			}, nil
		},
		"scopes update": func() (cli.Command, error) {
			return &scopescmd.Command{
				Command: base.NewCommand(ui),
				Func:    "update",
			}, nil
		},
		"scopes delete": func() (cli.Command, error) {
			return &scopescmd.Command{
				Command: base.NewCommand(ui),
				Func:    "delete",
			}, nil
		},
		"scopes list": func() (cli.Command, error) {
			return &scopescmd.Command{
				Command: base.NewCommand(ui),
				Func:    "list",
			}, nil
		},

		"sessions": func() (cli.Command, error) {
			return &sessionscmd.Command{
				Command: base.NewCommand(ui),
			}, nil
		},
		"sessions read": func() (cli.Command, error) {
			return &sessionscmd.Command{
				Command: base.NewCommand(ui),
				Func:    "read",
			}, nil
		},
		"sessions list": func() (cli.Command, error) {
			return &sessionscmd.Command{
				Command: base.NewCommand(ui),
				Func:    "list",
			}, nil
		},
		"sessions cancel": func() (cli.Command, error) {
			return &sessionscmd.Command{
				Command: base.NewCommand(ui),
				Func:    "cancel",
			}, nil
		},

		"targets": func() (cli.Command, error) {
			return &targetscmd.Command{
				Command: base.NewCommand(ui),
			}, nil
		},
		"targets authorize-session": func() (cli.Command, error) {
			return &targetscmd.Command{
				Command: base.NewCommand(ui),
				Func:    "authorize-session",
			}, nil
		},
		"targets read": func() (cli.Command, error) {
			return &targetscmd.Command{
				Command: base.NewCommand(ui),
				Func:    "read",
			}, nil
		},
		"targets delete": func() (cli.Command, error) {
			return &targetscmd.Command{
				Command: base.NewCommand(ui),
				Func:    "delete",
			}, nil
		},
		"targets list": func() (cli.Command, error) {
			return &targetscmd.Command{
				Command: base.NewCommand(ui),
				Func:    "list",
			}, nil
		},
		"targets create": func() (cli.Command, error) {
			return &targetscmd.Command{
				Command: base.NewCommand(ui),
				Func:    "create",
			}, nil
		},
		"targets create tcp": func() (cli.Command, error) {
			return &targetscmd.TcpCommand{
				Command: base.NewCommand(ui),
				Func:    "create",
			}, nil
		},
		"targets update": func() (cli.Command, error) {
			return &targetscmd.Command{
				Command: base.NewCommand(ui),
				Func:    "update",
			}, nil
		},
		"targets update tcp": func() (cli.Command, error) {
			return &targetscmd.TcpCommand{
				Command: base.NewCommand(ui),
				Func:    "update",
			}, nil
		},
		"targets add-host-sets": func() (cli.Command, error) {
			return &targetscmd.Command{
				Command: base.NewCommand(ui),
				Func:    "add-host-sets",
			}, nil
		},
		"targets remove-host-sets": func() (cli.Command, error) {
			return &targetscmd.Command{
				Command: base.NewCommand(ui),
				Func:    "remove-host-sets",
			}, nil
		},
		"targets set-host-sets": func() (cli.Command, error) {
			return &targetscmd.Command{
				Command: base.NewCommand(ui),
				Func:    "set-host-sets",
			}, nil
		},

		"users": func() (cli.Command, error) {
			return &userscmd.Command{
				Command: base.NewCommand(ui),
			}, nil
		},
		"users create": func() (cli.Command, error) {
			return &userscmd.Command{
				Command: base.NewCommand(ui),
				Func:    "create",
			}, nil
		},
		"users read": func() (cli.Command, error) {
			return &userscmd.Command{
				Command: base.NewCommand(ui),
				Func:    "read",
			}, nil
		},
		"users update": func() (cli.Command, error) {
			return &userscmd.Command{
				Command: base.NewCommand(ui),
				Func:    "update",
			}, nil
		},
		"users delete": func() (cli.Command, error) {
			return &userscmd.Command{
				Command: base.NewCommand(ui),
				Func:    "delete",
			}, nil
		},
		"users list": func() (cli.Command, error) {
			return &userscmd.Command{
				Command: base.NewCommand(ui),
				Func:    "list",
			}, nil
		},
		"users add-accounts": func() (cli.Command, error) {
			return &userscmd.Command{
				Command: base.NewCommand(ui),
				Func:    "add-accounts",
			}, nil
		},
		"users set-accounts": func() (cli.Command, error) {
			return &userscmd.Command{
				Command: base.NewCommand(ui),
				Func:    "set-accounts",
			}, nil
		},
		"users remove-accounts": func() (cli.Command, error) {
			return &userscmd.Command{
				Command: base.NewCommand(ui),
				Func:    "remove-accounts",
			}, nil
		},
	}
}
