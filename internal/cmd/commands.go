package cmd

import (
	"github.com/hashicorp/boundary/internal/cmd/base"
	"github.com/hashicorp/boundary/internal/cmd/commands/accountscmd"
	"github.com/hashicorp/boundary/internal/cmd/commands/authenticate"
	"github.com/hashicorp/boundary/internal/cmd/commands/authmethodscmd"
	"github.com/hashicorp/boundary/internal/cmd/commands/authtokenscmd"
	"github.com/hashicorp/boundary/internal/cmd/commands/config"
	"github.com/hashicorp/boundary/internal/cmd/commands/connect"
	"github.com/hashicorp/boundary/internal/cmd/commands/credentiallibrariescmd"
	"github.com/hashicorp/boundary/internal/cmd/commands/credentialscmd"
	"github.com/hashicorp/boundary/internal/cmd/commands/credentialstorescmd"
	"github.com/hashicorp/boundary/internal/cmd/commands/database"
	"github.com/hashicorp/boundary/internal/cmd/commands/dev"
	"github.com/hashicorp/boundary/internal/cmd/commands/groupscmd"
	"github.com/hashicorp/boundary/internal/cmd/commands/hostcatalogscmd"
	"github.com/hashicorp/boundary/internal/cmd/commands/hostscmd"
	"github.com/hashicorp/boundary/internal/cmd/commands/hostsetscmd"
	"github.com/hashicorp/boundary/internal/cmd/commands/logout"
	"github.com/hashicorp/boundary/internal/cmd/commands/managedgroupscmd"
	"github.com/hashicorp/boundary/internal/cmd/commands/rolescmd"
	"github.com/hashicorp/boundary/internal/cmd/commands/scopescmd"
	"github.com/hashicorp/boundary/internal/cmd/commands/server"
	"github.com/hashicorp/boundary/internal/cmd/commands/sessionscmd"
	"github.com/hashicorp/boundary/internal/cmd/commands/targetscmd"
	"github.com/hashicorp/boundary/internal/cmd/commands/userscmd"
	"github.com/hashicorp/boundary/internal/cmd/commands/version"
	"github.com/hashicorp/boundary/internal/cmd/commands/workerscmd"

	"github.com/mitchellh/cli"
)

// Commands is the mapping of all the available commands.
var Commands map[string]cli.CommandFactory

func initCommands(ui, serverCmdUi cli.Ui, runOpts *RunOptions) {
	Commands = map[string]cli.CommandFactory{
		"server": func() (cli.Command, error) {
			return &server.Command{
				Server:    base.NewServer(base.NewServerCommand(serverCmdUi)),
				SighupCh:  base.MakeSighupCh(),
				SigUSR2Ch: MakeSigUSR2Ch(),
			}, nil
		},
		"dev": func() (cli.Command, error) {
			return &dev.Command{
				Server:    base.NewServer(base.NewServerCommand(serverCmdUi)),
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
		"authenticate oidc": func() (cli.Command, error) {
			return &authenticate.OidcCommand{
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
		"accounts create oidc": func() (cli.Command, error) {
			return &accountscmd.OidcCommand{
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
		"accounts update oidc": func() (cli.Command, error) {
			return &accountscmd.OidcCommand{
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
		"auth-methods create oidc": func() (cli.Command, error) {
			return &authmethodscmd.OidcCommand{
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
		"auth-methods update oidc": func() (cli.Command, error) {
			return &authmethodscmd.OidcCommand{
				Command: base.NewCommand(ui),
				Func:    "update",
			}, nil
		},
		"auth-methods change-state oidc": func() (cli.Command, error) {
			return &authmethodscmd.OidcCommand{
				Command: base.NewCommand(ui),
				Func:    "change-state",
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
				Server: base.NewServer(base.NewCommand(ui)),
			}, nil
		},
		"database migrate": func() (cli.Command, error) {
			return &database.MigrateCommand{
				Command: base.NewCommand(ui),
			}, nil
		},

		"credential-libraries": func() (cli.Command, error) {
			return &credentiallibrariescmd.Command{
				Command: base.NewCommand(ui),
			}, nil
		},
		"credential-libraries read": func() (cli.Command, error) {
			return &credentiallibrariescmd.Command{
				Command: base.NewCommand(ui),
				Func:    "read",
			}, nil
		},
		"credential-libraries delete": func() (cli.Command, error) {
			return &credentiallibrariescmd.Command{
				Command: base.NewCommand(ui),
				Func:    "delete",
			}, nil
		},
		"credential-libraries list": func() (cli.Command, error) {
			return &credentiallibrariescmd.Command{
				Command: base.NewCommand(ui),
				Func:    "list",
			}, nil
		},
		"credential-libraries create": func() (cli.Command, error) {
			return &credentiallibrariescmd.Command{
				Command: base.NewCommand(ui),
				Func:    "create",
			}, nil
		},
		"credential-libraries create vault": func() (cli.Command, error) {
			return &credentiallibrariescmd.VaultCommand{
				Command: base.NewCommand(ui),
				Func:    "create",
			}, nil
		},
		"credential-libraries update": func() (cli.Command, error) {
			return &credentiallibrariescmd.Command{
				Command: base.NewCommand(ui),
				Func:    "update",
			}, nil
		},
		"credential-libraries update vault": func() (cli.Command, error) {
			return &credentiallibrariescmd.VaultCommand{
				Command: base.NewCommand(ui),
				Func:    "update",
			}, nil
		},

		"credential-stores": func() (cli.Command, error) {
			return &credentialstorescmd.Command{
				Command: base.NewCommand(ui),
			}, nil
		},
		"credential-stores read": func() (cli.Command, error) {
			return &credentialstorescmd.Command{
				Command: base.NewCommand(ui),
				Func:    "read",
			}, nil
		},
		"credential-stores delete": func() (cli.Command, error) {
			return &credentialstorescmd.Command{
				Command: base.NewCommand(ui),
				Func:    "delete",
			}, nil
		},
		"credential-stores list": func() (cli.Command, error) {
			return &credentialstorescmd.Command{
				Command: base.NewCommand(ui),
				Func:    "list",
			}, nil
		},
		"credential-stores create": func() (cli.Command, error) {
			return &credentialstorescmd.Command{
				Command: base.NewCommand(ui),
				Func:    "create",
			}, nil
		},
		"credential-stores create vault": func() (cli.Command, error) {
			return &credentialstorescmd.VaultCommand{
				Command: base.NewCommand(ui),
				Func:    "create",
			}, nil
		},
		"credential-stores create static": func() (cli.Command, error) {
			return &credentialstorescmd.StaticCommand{
				Command: base.NewCommand(ui),
				Func:    "create",
			}, nil
		},
		"credential-stores update": func() (cli.Command, error) {
			return &credentialstorescmd.Command{
				Command: base.NewCommand(ui),
				Func:    "update",
			}, nil
		},
		"credential-stores update vault": func() (cli.Command, error) {
			return &credentialstorescmd.VaultCommand{
				Command: base.NewCommand(ui),
				Func:    "update",
			}, nil
		},
		"credential-stores update static": func() (cli.Command, error) {
			return &credentialstorescmd.StaticCommand{
				Command: base.NewCommand(ui),
				Func:    "update",
			}, nil
		},

		"credentials": func() (cli.Command, error) {
			return &credentialscmd.Command{
				Command: base.NewCommand(ui),
			}, nil
		},
		"credentials read": func() (cli.Command, error) {
			return &credentialscmd.Command{
				Command: base.NewCommand(ui),
				Func:    "read",
			}, nil
		},
		"credentials delete": func() (cli.Command, error) {
			return &credentialscmd.Command{
				Command: base.NewCommand(ui),
				Func:    "delete",
			}, nil
		},
		"credentials list": func() (cli.Command, error) {
			return &credentialscmd.Command{
				Command: base.NewCommand(ui),
				Func:    "list",
			}, nil
		},
		"credentials create": func() (cli.Command, error) {
			return &credentialscmd.Command{
				Command: base.NewCommand(ui),
				Func:    "create",
			}, nil
		},
		"credentials create username-password": func() (cli.Command, error) {
			return &credentialscmd.UsernamePasswordCommand{
				Command: base.NewCommand(ui),
				Func:    "create",
			}, nil
		},
		"credentials create ssh-private-key": func() (cli.Command, error) {
			return &credentialscmd.SshPrivateKeyCommand{
				Command: base.NewCommand(ui),
				Func:    "create",
			}, nil
		},
		"credentials create json": func() (cli.Command, error) {
			return &credentialscmd.JsonCommand{
				Command: base.NewCommand(ui),
				Func:    "create",
			}, nil
		},
		"credentials update": func() (cli.Command, error) {
			return &credentialscmd.Command{
				Command: base.NewCommand(ui),
				Func:    "update",
			}, nil
		},
		"credentials update username-password": func() (cli.Command, error) {
			return &credentialscmd.UsernamePasswordCommand{
				Command: base.NewCommand(ui),
				Func:    "update",
			}, nil
		},
		"credentials update ssh-private-key": func() (cli.Command, error) {
			return &credentialscmd.SshPrivateKeyCommand{
				Command: base.NewCommand(ui),
				Func:    "update",
			}, nil
		},
		"credentials update json": func() (cli.Command, error) {
			return &credentialscmd.JsonCommand{
				Command: base.NewCommand(ui),
				Func:    "update",
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
		"host-catalogs create plugin": func() (cli.Command, error) {
			return &hostcatalogscmd.PluginCommand{
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
		"host-catalogs update plugin": func() (cli.Command, error) {
			return &hostcatalogscmd.PluginCommand{
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
		"host-sets create plugin": func() (cli.Command, error) {
			return &hostsetscmd.PluginCommand{
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
		"host-sets update plugin": func() (cli.Command, error) {
			return &hostsetscmd.PluginCommand{
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

		"logout": func() (cli.Command, error) {
			return &logout.LogoutCommand{
				Command: base.NewCommand(ui),
			}, nil
		},

		"managed-groups": func() (cli.Command, error) {
			return &managedgroupscmd.Command{
				Command: base.NewCommand(ui),
			}, nil
		},
		"managed-groups read": func() (cli.Command, error) {
			return &managedgroupscmd.Command{
				Command: base.NewCommand(ui),
				Func:    "read",
			}, nil
		},
		"managed-groups delete": func() (cli.Command, error) {
			return &managedgroupscmd.Command{
				Command: base.NewCommand(ui),
				Func:    "delete",
			}, nil
		},
		"managed-groups list": func() (cli.Command, error) {
			return &managedgroupscmd.Command{
				Command: base.NewCommand(ui),
				Func:    "list",
			}, nil
		},
		"managed-groups create": func() (cli.Command, error) {
			return &managedgroupscmd.Command{
				Command: base.NewCommand(ui),
				Func:    "create",
			}, nil
		},
		"managed-groups create oidc": func() (cli.Command, error) {
			return &managedgroupscmd.OidcCommand{
				Command: base.NewCommand(ui),
				Func:    "create",
			}, nil
		},
		"managed-groups update": func() (cli.Command, error) {
			return &managedgroupscmd.Command{
				Command: base.NewCommand(ui),
				Func:    "update",
			}, nil
		},
		"managed-groups update oidc": func() (cli.Command, error) {
			return &managedgroupscmd.OidcCommand{
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
		"scopes list-keys": func() (cli.Command, error) {
			return &scopescmd.ListKeysCommand{
				Command: base.NewCommand(ui),
			}, nil
		},
		"scopes rotate-keys": func() (cli.Command, error) {
			return &scopescmd.RotateKeysCommand{
				Command: base.NewCommand(ui),
			}, nil
		},
		"scopes list-key-version-destruction-jobs": func() (cli.Command, error) {
			return &scopescmd.ListKeyVersionDestructionJobsCommand{
				Command: base.NewCommand(ui),
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
		"targets create ssh": func() (cli.Command, error) {
			return &targetscmd.SshCommand{
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
		"targets update ssh": func() (cli.Command, error) {
			return &targetscmd.SshCommand{
				Command: base.NewCommand(ui),
				Func:    "update",
			}, nil
		},
		"targets add-host-sources": func() (cli.Command, error) {
			return &targetscmd.Command{
				Command: base.NewCommand(ui),
				Func:    "add-host-sources",
			}, nil
		},
		"targets remove-host-sources": func() (cli.Command, error) {
			return &targetscmd.Command{
				Command: base.NewCommand(ui),
				Func:    "remove-host-sources",
			}, nil
		},
		"targets set-host-sources": func() (cli.Command, error) {
			return &targetscmd.Command{
				Command: base.NewCommand(ui),
				Func:    "set-host-sources",
			}, nil
		},
		"targets add-credential-sources": func() (cli.Command, error) {
			return &targetscmd.Command{
				Command: base.NewCommand(ui),
				Func:    "add-credential-sources",
			}, nil
		},
		"targets remove-credential-sources": func() (cli.Command, error) {
			return &targetscmd.Command{
				Command: base.NewCommand(ui),
				Func:    "remove-credential-sources",
			}, nil
		},
		"targets set-credential-sources": func() (cli.Command, error) {
			return &targetscmd.Command{
				Command: base.NewCommand(ui),
				Func:    "set-credential-sources",
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

		"workers": func() (cli.Command, error) {
			return &workerscmd.Command{
				Command: base.NewCommand(ui),
			}, nil
		},
		"workers create": func() (cli.Command, error) {
			return &workerscmd.Command{
				Command: base.NewCommand(ui),
				Func:    "create",
			}, nil
		},
		"workers create worker-led": func() (cli.Command, error) {
			return &workerscmd.WorkerLedCommand{
				Command: base.NewCommand(ui),
				Func:    "create",
			}, nil
		},
		"workers create controller-led": func() (cli.Command, error) {
			return &workerscmd.ControllerLedCommand{
				Command: base.NewCommand(ui),
				Func:    "create",
			}, nil
		},
		"workers read": func() (cli.Command, error) {
			return &workerscmd.Command{
				Command: base.NewCommand(ui),
				Func:    "read",
			}, nil
		},
		"workers update": func() (cli.Command, error) {
			return &workerscmd.Command{
				Command: base.NewCommand(ui),
				Func:    "update",
			}, nil
		},
		"workers delete": func() (cli.Command, error) {
			return &workerscmd.Command{
				Command: base.NewCommand(ui),
				Func:    "delete",
			}, nil
		},
		"workers list": func() (cli.Command, error) {
			return &workerscmd.Command{
				Command: base.NewCommand(ui),
				Func:    "list",
			}, nil
		},
		"workers add-worker-tags": func() (cli.Command, error) {
			return &workerscmd.Command{
				Command: base.NewCommand(ui),
				Func:    "add-worker-tags",
			}, nil
		},
		"workers set-worker-tags": func() (cli.Command, error) {
			return &workerscmd.Command{
				Command: base.NewCommand(ui),
				Func:    "set-worker-tags",
			}, nil
		},
		"workers remove-worker-tags": func() (cli.Command, error) {
			return &workerscmd.Command{
				Command: base.NewCommand(ui),
				Func:    "remove-worker-tags",
			}, nil
		},
		"workers certificate-authority": func() (cli.Command, error) {
			return &workerscmd.WorkerCACommand{
				Command: base.NewCommand(ui),
			}, nil
		},
		"workers certificate-authority read": func() (cli.Command, error) {
			return &workerscmd.WorkerCACommand{
				Command: base.NewCommand(ui),
				Func:    "read",
			}, nil
		},
		"workers certificate-authority reinitialize": func() (cli.Command, error) {
			return &workerscmd.WorkerCACommand{
				Command: base.NewCommand(ui),
				Func:    "reinitialize",
			}, nil
		},
	}

	for _, fn := range extraCommandsFuncs {
		if fn != nil {
			fn()
		}
	}
}

var extraCommandsFuncs []func()
