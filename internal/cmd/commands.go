// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: BUSL-1.1

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
	"github.com/hashicorp/boundary/internal/cmd/commands/daemon"
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
	"github.com/hashicorp/boundary/internal/cmd/commands/search"
	"github.com/hashicorp/boundary/internal/cmd/commands/server"
	"github.com/hashicorp/boundary/internal/cmd/commands/sessionrecordingscmd"
	"github.com/hashicorp/boundary/internal/cmd/commands/sessionscmd"
	"github.com/hashicorp/boundary/internal/cmd/commands/storagebucketscmd"
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

		"authenticate": daemon.Wrap(ui,
			&authenticate.Command{
				Command: base.NewCommand(ui),
			}),
		"authenticate password": daemon.Wrap(ui,
			&authenticate.PasswordCommand{
				Command: base.NewCommand(ui),
			}),
		"authenticate oidc": daemon.Wrap(ui,
			&authenticate.OidcCommand{
				Command: base.NewCommand(ui),
			}),
		"authenticate ldap": daemon.Wrap(ui,
			&authenticate.LdapCommand{
				Command: base.NewCommand(ui),
			}),

		"accounts": func() (cli.Command, error) {
			return &accountscmd.Command{
				Command: base.NewCommand(ui),
			}, nil
		},
		"accounts read": daemon.Wrap(ui,
			&accountscmd.Command{
				Command: base.NewCommand(ui),
				Func:    "read",
			}),
		"accounts delete": daemon.Wrap(ui,
			&accountscmd.Command{
				Command: base.NewCommand(ui),
				Func:    "delete",
			}),
		"accounts list": daemon.Wrap(ui,
			&accountscmd.Command{
				Command: base.NewCommand(ui),
				Func:    "list",
			}),
		"accounts set-password": daemon.Wrap(ui,
			&accountscmd.Command{
				Command: base.NewCommand(ui),
				Func:    "set-password",
			}),
		"accounts change-password": daemon.Wrap(ui,
			&accountscmd.Command{
				Command: base.NewCommand(ui),
				Func:    "change-password",
			}),
		"accounts create": daemon.Wrap(ui,
			&accountscmd.Command{
				Command: base.NewCommand(ui),
				Func:    "create",
			}),
		"accounts create password": daemon.Wrap(ui,
			&accountscmd.PasswordCommand{
				Command: base.NewCommand(ui),
				Func:    "create",
			}),
		"accounts create oidc": daemon.Wrap(ui,
			&accountscmd.OidcCommand{
				Command: base.NewCommand(ui),
				Func:    "create",
			}),
		"accounts create ldap": daemon.Wrap(ui,
			&accountscmd.LdapCommand{
				Command: base.NewCommand(ui),
				Func:    "create",
			}),
		"accounts update": daemon.Wrap(ui,
			&accountscmd.Command{
				Command: base.NewCommand(ui),
				Func:    "update",
			}),
		"accounts update password": daemon.Wrap(ui,
			&accountscmd.PasswordCommand{
				Command: base.NewCommand(ui),
				Func:    "update",
			}),
		"accounts update oidc": daemon.Wrap(ui,
			&accountscmd.OidcCommand{
				Command: base.NewCommand(ui),
				Func:    "update",
			}),
		"accounts update ldap": daemon.Wrap(ui,
			&accountscmd.LdapCommand{
				Command: base.NewCommand(ui),
				Func:    "update",
			}),

		"auth-methods": func() (cli.Command, error) {
			return &authmethodscmd.Command{
				Command: base.NewCommand(ui),
			}, nil
		},
		"auth-methods read": daemon.Wrap(ui,
			&authmethodscmd.Command{
				Command: base.NewCommand(ui),
				Func:    "read",
			}),
		"auth-methods delete": daemon.Wrap(ui,
			&authmethodscmd.Command{
				Command: base.NewCommand(ui),
				Func:    "delete",
			}),
		"auth-methods list": daemon.Wrap(ui,
			&authmethodscmd.Command{
				Command: base.NewCommand(ui),
				Func:    "list",
			}),
		"auth-methods create": daemon.Wrap(ui,
			&authmethodscmd.Command{
				Command: base.NewCommand(ui),
				Func:    "create",
			}),
		"auth-methods create password": daemon.Wrap(ui,
			&authmethodscmd.PasswordCommand{
				Command: base.NewCommand(ui),
				Func:    "create",
			}),
		"auth-methods create oidc": daemon.Wrap(ui,
			&authmethodscmd.OidcCommand{
				Command: base.NewCommand(ui),
				Func:    "create",
			}),
		"auth-methods create ldap": daemon.Wrap(ui,
			&authmethodscmd.LdapCommand{
				Command: base.NewCommand(ui),
				Func:    "create",
			}),
		"auth-methods update": daemon.Wrap(ui,
			&authmethodscmd.Command{
				Command: base.NewCommand(ui),
				Func:    "update",
			}),
		"auth-methods update password": daemon.Wrap(ui,
			&authmethodscmd.PasswordCommand{
				Command: base.NewCommand(ui),
				Func:    "update",
			}),
		"auth-methods update oidc": daemon.Wrap(ui,
			&authmethodscmd.OidcCommand{
				Command: base.NewCommand(ui),
				Func:    "update",
			}),
		"auth-methods update ldap": daemon.Wrap(ui,
			&authmethodscmd.LdapCommand{
				Command: base.NewCommand(ui),
				Func:    "update",
			}),
		"auth-methods change-state oidc": daemon.Wrap(ui,
			&authmethodscmd.OidcCommand{
				Command: base.NewCommand(ui),
				Func:    "change-state",
			}),

		"auth-tokens": func() (cli.Command, error) {
			return &authtokenscmd.Command{
				Command: base.NewCommand(ui),
			}, nil
		},
		"auth-tokens read": daemon.Wrap(ui,
			&authtokenscmd.Command{
				Command: base.NewCommand(ui),
				Func:    "read",
			}),
		"auth-tokens delete": daemon.Wrap(ui,
			&authtokenscmd.Command{
				Command: base.NewCommand(ui),
				Func:    "delete",
			}),
		"auth-tokens list": daemon.Wrap(ui,
			&authtokenscmd.Command{
				Command: base.NewCommand(ui),
				Func:    "list",
			}),

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

		"connect": daemon.Wrap(ui,
			&connect.Command{
				Command: base.NewCommand(ui),
				Func:    "connect",
			}),
		"connect http": daemon.Wrap(ui,
			&connect.Command{
				Command: base.NewCommand(ui),
				Func:    "http",
			}),
		"connect kube": daemon.Wrap(ui,
			&connect.Command{
				Command: base.NewCommand(ui),
				Func:    "kube",
			}),
		"connect postgres": daemon.Wrap(ui,
			&connect.Command{
				Command: base.NewCommand(ui),
				Func:    "postgres",
			}),
		"connect rdp": daemon.Wrap(ui,
			&connect.Command{
				Command: base.NewCommand(ui),
				Func:    "rdp",
			}),
		"connect ssh": daemon.Wrap(ui,
			&connect.Command{
				Command: base.NewCommand(ui),
				Func:    "ssh",
			}),

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

		"daemon start": func() (cli.Command, error) {
			return &daemon.StartCommand{
				Command: base.NewCommand(ui),
			}, nil
		},

		"daemon stop": func() (cli.Command, error) {
			return &daemon.StopCommand{
				Command: base.NewCommand(ui),
			}, nil
		},

		"daemon add-token": func() (cli.Command, error) {
			return &daemon.AddTokenCommand{
				Command: base.NewCommand(ui),
			}, nil
		},

		"credential-libraries": func() (cli.Command, error) {
			return &credentiallibrariescmd.Command{
				Command: base.NewCommand(ui),
			}, nil
		},
		"credential-libraries read": daemon.Wrap(ui,
			&credentiallibrariescmd.Command{
				Command: base.NewCommand(ui),
				Func:    "read",
			}),
		"credential-libraries delete": daemon.Wrap(ui,
			&credentiallibrariescmd.Command{
				Command: base.NewCommand(ui),
				Func:    "delete",
			}),
		"credential-libraries list": daemon.Wrap(ui,
			&credentiallibrariescmd.Command{
				Command: base.NewCommand(ui),
				Func:    "list",
			}),
		"credential-libraries create": daemon.Wrap(ui,
			&credentiallibrariescmd.Command{
				Command: base.NewCommand(ui),
				Func:    "create",
			}),
		"credential-libraries create vault": daemon.Wrap(ui,
			&credentiallibrariescmd.VaultCommand{
				Command: base.NewCommand(ui),
				Func:    "create",
			}),
		"credential-libraries create vault-generic": daemon.Wrap(ui,
			&credentiallibrariescmd.VaultGenericCommand{
				Command: base.NewCommand(ui),
				Func:    "create",
			}),
		"credential-libraries create vault-ssh-certificate": daemon.Wrap(ui,
			&credentiallibrariescmd.VaultSshCertificateCommand{
				Command: base.NewCommand(ui),
				Func:    "create",
			}),
		"credential-libraries update": daemon.Wrap(ui,
			&credentiallibrariescmd.Command{
				Command: base.NewCommand(ui),
				Func:    "update",
			}),
		"credential-libraries update vault": daemon.Wrap(ui,
			&credentiallibrariescmd.VaultGenericCommand{
				Command: base.NewCommand(ui),
				Func:    "update",
			}),
		"credential-libraries update vault-generic": daemon.Wrap(ui,
			&credentiallibrariescmd.VaultGenericCommand{
				Command: base.NewCommand(ui),
				Func:    "update",
			}),
		"credential-libraries update vault-ssh-certificate": daemon.Wrap(ui,
			&credentiallibrariescmd.VaultSshCertificateCommand{
				Command: base.NewCommand(ui),
				Func:    "update",
			}),

		"credential-stores": func() (cli.Command, error) {
			return &credentialstorescmd.Command{
				Command: base.NewCommand(ui),
			}, nil
		},
		"credential-stores read": daemon.Wrap(ui,
			&credentialstorescmd.Command{
				Command: base.NewCommand(ui),
				Func:    "read",
			}),
		"credential-stores delete": daemon.Wrap(ui,
			&credentialstorescmd.Command{
				Command: base.NewCommand(ui),
				Func:    "delete",
			}),
		"credential-stores list": daemon.Wrap(ui,
			&credentialstorescmd.Command{
				Command: base.NewCommand(ui),
				Func:    "list",
			}),
		"credential-stores create": daemon.Wrap(ui,
			&credentialstorescmd.Command{
				Command: base.NewCommand(ui),
				Func:    "create",
			}),
		"credential-stores create vault": daemon.Wrap(ui,
			&credentialstorescmd.VaultCommand{
				Command: base.NewCommand(ui),
				Func:    "create",
			}),
		"credential-stores create static": daemon.Wrap(ui,
			&credentialstorescmd.StaticCommand{
				Command: base.NewCommand(ui),
				Func:    "create",
			}),
		"credential-stores update": daemon.Wrap(ui,
			&credentialstorescmd.Command{
				Command: base.NewCommand(ui),
				Func:    "update",
			}),
		"credential-stores update vault": daemon.Wrap(ui,
			&credentialstorescmd.VaultCommand{
				Command: base.NewCommand(ui),
				Func:    "update",
			}),
		"credential-stores update static": daemon.Wrap(ui,
			&credentialstorescmd.StaticCommand{
				Command: base.NewCommand(ui),
				Func:    "update",
			}),

		"credentials": func() (cli.Command, error) {
			return &credentialscmd.Command{
				Command: base.NewCommand(ui),
			}, nil
		},
		"credentials read": daemon.Wrap(ui,
			&credentialscmd.Command{
				Command: base.NewCommand(ui),
				Func:    "read",
			}),
		"credentials delete": daemon.Wrap(ui,
			&credentialscmd.Command{
				Command: base.NewCommand(ui),
				Func:    "delete",
			}),
		"credentials list": daemon.Wrap(ui,
			&credentialscmd.Command{
				Command: base.NewCommand(ui),
				Func:    "list",
			}),
		"credentials create": daemon.Wrap(ui,
			&credentialscmd.Command{
				Command: base.NewCommand(ui),
				Func:    "create",
			}),
		"credentials create username-password": daemon.Wrap(ui,
			&credentialscmd.UsernamePasswordCommand{
				Command: base.NewCommand(ui),
				Func:    "create",
			}),
		"credentials create ssh-private-key": daemon.Wrap(ui,
			&credentialscmd.SshPrivateKeyCommand{
				Command: base.NewCommand(ui),
				Func:    "create",
			}),
		"credentials create json": daemon.Wrap(ui,
			&credentialscmd.JsonCommand{
				Command: base.NewCommand(ui),
				Func:    "create",
			}),
		"credentials update": daemon.Wrap(ui,
			&credentialscmd.Command{
				Command: base.NewCommand(ui),
				Func:    "update",
			}),
		"credentials update username-password": daemon.Wrap(ui,
			&credentialscmd.UsernamePasswordCommand{
				Command: base.NewCommand(ui),
				Func:    "update",
			}),
		"credentials update ssh-private-key": daemon.Wrap(ui,
			&credentialscmd.SshPrivateKeyCommand{
				Command: base.NewCommand(ui),
				Func:    "update",
			}),
		"credentials update json": daemon.Wrap(ui,
			&credentialscmd.JsonCommand{
				Command: base.NewCommand(ui),
				Func:    "update",
			}),

		"groups": func() (cli.Command, error) {
			return &groupscmd.Command{
				Command: base.NewCommand(ui),
			}, nil
		},
		"groups create": daemon.Wrap(ui,
			&groupscmd.Command{
				Command: base.NewCommand(ui),
				Func:    "create",
			}),
		"groups update": daemon.Wrap(ui,
			&groupscmd.Command{
				Command: base.NewCommand(ui),
				Func:    "update",
			}),
		"groups read": daemon.Wrap(ui,
			&groupscmd.Command{
				Command: base.NewCommand(ui),
				Func:    "read",
			}),
		"groups delete": daemon.Wrap(ui,
			&groupscmd.Command{
				Command: base.NewCommand(ui),
				Func:    "delete",
			}),
		"groups list": daemon.Wrap(ui,
			&groupscmd.Command{
				Command: base.NewCommand(ui),
				Func:    "list",
			}),
		"groups add-members": daemon.Wrap(ui,
			&groupscmd.Command{
				Command: base.NewCommand(ui),
				Func:    "add-members",
			}),
		"groups set-members": daemon.Wrap(ui,
			&groupscmd.Command{
				Command: base.NewCommand(ui),
				Func:    "set-members",
			}),
		"groups remove-members": daemon.Wrap(ui,
			&groupscmd.Command{
				Command: base.NewCommand(ui),
				Func:    "remove-members",
			}),

		"host-catalogs": func() (cli.Command, error) {
			return &hostcatalogscmd.Command{
				Command: base.NewCommand(ui),
			}, nil
		},
		"host-catalogs read": daemon.Wrap(ui,
			&hostcatalogscmd.Command{
				Command: base.NewCommand(ui),
				Func:    "read",
			}),
		"host-catalogs delete": daemon.Wrap(ui,
			&hostcatalogscmd.Command{
				Command: base.NewCommand(ui),
				Func:    "delete",
			}),
		"host-catalogs list": daemon.Wrap(ui,
			&hostcatalogscmd.Command{
				Command: base.NewCommand(ui),
				Func:    "list",
			}),
		"host-catalogs create": daemon.Wrap(ui,
			&hostcatalogscmd.Command{
				Command: base.NewCommand(ui),
				Func:    "create",
			}),
		"host-catalogs create static": daemon.Wrap(ui,
			&hostcatalogscmd.StaticCommand{
				Command: base.NewCommand(ui),
				Func:    "create",
			}),
		"host-catalogs create plugin": daemon.Wrap(ui,
			&hostcatalogscmd.PluginCommand{
				Command: base.NewCommand(ui),
				Func:    "create",
			}),
		"host-catalogs update": daemon.Wrap(ui,
			&hostcatalogscmd.Command{
				Command: base.NewCommand(ui),
				Func:    "update",
			}),
		"host-catalogs update static": daemon.Wrap(ui,
			&hostcatalogscmd.StaticCommand{
				Command: base.NewCommand(ui),
				Func:    "update",
			}),
		"host-catalogs update plugin": daemon.Wrap(ui,
			&hostcatalogscmd.PluginCommand{
				Command: base.NewCommand(ui),
				Func:    "update",
			}),

		"host-sets": func() (cli.Command, error) {
			return &hostsetscmd.Command{
				Command: base.NewCommand(ui),
			}, nil
		},
		"host-sets read": daemon.Wrap(ui,
			&hostsetscmd.Command{
				Command: base.NewCommand(ui),
				Func:    "read",
			}),
		"host-sets delete": daemon.Wrap(ui,
			&hostsetscmd.Command{
				Command: base.NewCommand(ui),
				Func:    "delete",
			}),
		"host-sets list": daemon.Wrap(ui,
			&hostsetscmd.Command{
				Command: base.NewCommand(ui),
				Func:    "list",
			}),
		"host-sets create": daemon.Wrap(ui,
			&hostsetscmd.Command{
				Command: base.NewCommand(ui),
				Func:    "create",
			}),
		"host-sets create static": daemon.Wrap(ui,
			&hostsetscmd.StaticCommand{
				Command: base.NewCommand(ui),
				Func:    "create",
			}),
		"host-sets create plugin": daemon.Wrap(ui,
			&hostsetscmd.PluginCommand{
				Command: base.NewCommand(ui),
				Func:    "create",
			}),
		"host-sets update": daemon.Wrap(ui,
			&hostsetscmd.Command{
				Command: base.NewCommand(ui),
				Func:    "update",
			}),
		"host-sets update static": daemon.Wrap(ui,
			&hostsetscmd.StaticCommand{
				Command: base.NewCommand(ui),
				Func:    "update",
			}),
		"host-sets update plugin": daemon.Wrap(ui,
			&hostsetscmd.PluginCommand{
				Command: base.NewCommand(ui),
				Func:    "update",
			}),
		"host-sets add-hosts": daemon.Wrap(ui,
			&hostsetscmd.Command{
				Command: base.NewCommand(ui),
				Func:    "add-hosts",
			}),
		"host-sets remove-hosts": daemon.Wrap(ui,
			&hostsetscmd.Command{
				Command: base.NewCommand(ui),
				Func:    "remove-hosts",
			}),
		"host-sets set-hosts": daemon.Wrap(ui,
			&hostsetscmd.Command{
				Command: base.NewCommand(ui),
				Func:    "set-hosts",
			}),

		"hosts": func() (cli.Command, error) {
			return &hostscmd.Command{
				Command: base.NewCommand(ui),
			}, nil
		},
		"hosts read": daemon.Wrap(ui,
			&hostscmd.Command{
				Command: base.NewCommand(ui),
				Func:    "read",
			}),
		"hosts delete": daemon.Wrap(ui,
			&hostscmd.Command{
				Command: base.NewCommand(ui),
				Func:    "delete",
			}),
		"hosts list": daemon.Wrap(ui,
			&hostscmd.Command{
				Command: base.NewCommand(ui),
				Func:    "list",
			}),
		"hosts create": daemon.Wrap(ui,
			&hostscmd.Command{
				Command: base.NewCommand(ui),
				Func:    "create",
			}),
		"hosts create static": daemon.Wrap(ui,
			&hostscmd.StaticCommand{
				Command: base.NewCommand(ui),
				Func:    "create",
			}),
		"hosts update": daemon.Wrap(ui,
			&hostscmd.Command{
				Command: base.NewCommand(ui),
				Func:    "update",
			}),
		"hosts update static": daemon.Wrap(ui,
			&hostscmd.StaticCommand{
				Command: base.NewCommand(ui),
				Func:    "update",
			}),

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
		"managed-groups read": daemon.Wrap(ui,
			&managedgroupscmd.Command{
				Command: base.NewCommand(ui),
				Func:    "read",
			}),
		"managed-groups delete": daemon.Wrap(ui,
			&managedgroupscmd.Command{
				Command: base.NewCommand(ui),
				Func:    "delete",
			}),
		"managed-groups list": daemon.Wrap(ui,
			&managedgroupscmd.Command{
				Command: base.NewCommand(ui),
				Func:    "list",
			}),
		"managed-groups create": daemon.Wrap(ui,
			&managedgroupscmd.Command{
				Command: base.NewCommand(ui),
				Func:    "create",
			}),
		"managed-groups create oidc": daemon.Wrap(ui,
			&managedgroupscmd.OidcCommand{
				Command: base.NewCommand(ui),
				Func:    "create",
			}),
		"managed-groups create ldap": daemon.Wrap(ui,
			&managedgroupscmd.LdapCommand{
				Command: base.NewCommand(ui),
				Func:    "create",
			}),
		"managed-groups update": daemon.Wrap(ui,
			&managedgroupscmd.Command{
				Command: base.NewCommand(ui),
				Func:    "update",
			}),
		"managed-groups update oidc": daemon.Wrap(ui,
			&managedgroupscmd.OidcCommand{
				Command: base.NewCommand(ui),
				Func:    "update",
			}),
		"managed-groups update ldap": daemon.Wrap(ui,
			&managedgroupscmd.LdapCommand{
				Command: base.NewCommand(ui),
				Func:    "update",
			}),

		"roles": func() (cli.Command, error) {
			return &rolescmd.Command{
				Command: base.NewCommand(ui),
			}, nil
		},
		"roles create": daemon.Wrap(ui,
			&rolescmd.Command{
				Command: base.NewCommand(ui),
				Func:    "create",
			}),
		"roles update": daemon.Wrap(ui,
			&rolescmd.Command{
				Command: base.NewCommand(ui),
				Func:    "update",
			}),
		"roles read": daemon.Wrap(ui,
			&rolescmd.Command{
				Command: base.NewCommand(ui),
				Func:    "read",
			}),
		"roles delete": daemon.Wrap(ui,
			&rolescmd.Command{
				Command: base.NewCommand(ui),
				Func:    "delete",
			}),
		"roles list": daemon.Wrap(ui,
			&rolescmd.Command{
				Command: base.NewCommand(ui),
				Func:    "list",
			}),
		"roles add-principals": daemon.Wrap(ui,
			&rolescmd.Command{
				Command: base.NewCommand(ui),
				Func:    "add-principals",
			}),
		"roles set-principals": daemon.Wrap(ui,
			&rolescmd.Command{
				Command: base.NewCommand(ui),
				Func:    "set-principals",
			}),
		"roles remove-principals": daemon.Wrap(ui,
			&rolescmd.Command{
				Command: base.NewCommand(ui),
				Func:    "remove-principals",
			}),
		"roles add-grants": daemon.Wrap(ui,
			&rolescmd.Command{
				Command: base.NewCommand(ui),
				Func:    "add-grants",
			}),
		"roles set-grants": daemon.Wrap(ui,
			&rolescmd.Command{
				Command: base.NewCommand(ui),
				Func:    "set-grants",
			}),
		"roles remove-grants": daemon.Wrap(ui,
			&rolescmd.Command{
				Command: base.NewCommand(ui),
				Func:    "remove-grants",
			}),

		"scopes": func() (cli.Command, error) {
			return &scopescmd.Command{
				Command: base.NewCommand(ui),
			}, nil
		},
		"scopes create": daemon.Wrap(ui,
			&scopescmd.Command{
				Command: base.NewCommand(ui),
				Func:    "create",
			}),
		"scopes read": daemon.Wrap(ui,
			&scopescmd.Command{
				Command: base.NewCommand(ui),
				Func:    "read",
			}),
		"scopes update": daemon.Wrap(ui,
			&scopescmd.Command{
				Command: base.NewCommand(ui),
				Func:    "update",
			}),
		"scopes delete": daemon.Wrap(ui,
			&scopescmd.Command{
				Command: base.NewCommand(ui),
				Func:    "delete",
			}),
		"scopes list": daemon.Wrap(ui,
			&scopescmd.Command{
				Command: base.NewCommand(ui),
				Func:    "list",
			}),
		"scopes list-keys": daemon.Wrap(ui,
			&scopescmd.ListKeysCommand{
				Command: base.NewCommand(ui),
			}),
		"scopes rotate-keys": daemon.Wrap(ui,
			&scopescmd.RotateKeysCommand{
				Command: base.NewCommand(ui),
			}),
		"scopes list-key-version-destruction-jobs": daemon.Wrap(ui,
			&scopescmd.ListKeyVersionDestructionJobsCommand{
				Command: base.NewCommand(ui),
			}),
		"scopes destroy-key-version": daemon.Wrap(ui,
			&scopescmd.DestroyKeyVersionCommand{
				Command: base.NewCommand(ui),
			}),

		"search": func() (cli.Command, error) {
			return &search.SearchCommand{
				Command: base.NewCommand(ui),
			}, nil
		},

		"sessions": func() (cli.Command, error) {
			return &sessionscmd.Command{
				Command: base.NewCommand(ui),
			}, nil
		},
		"sessions read": daemon.Wrap(ui,
			&sessionscmd.Command{
				Command: base.NewCommand(ui),
				Func:    "read",
			}),
		"sessions list": daemon.Wrap(ui,
			&sessionscmd.Command{
				Command: base.NewCommand(ui),
				Func:    "list",
			}),
		"sessions cancel": daemon.Wrap(ui,
			&sessionscmd.Command{
				Command: base.NewCommand(ui),
				Func:    "cancel",
			}),

		"session-recordings": func() (cli.Command, error) {
			return &sessionrecordingscmd.Command{
				Command: base.NewCommand(ui),
			}, nil
		},
		"session-recordings read": daemon.Wrap(ui,
			&sessionrecordingscmd.Command{
				Command: base.NewCommand(ui),
				Func:    "read",
			}),
		"session-recordings list": daemon.Wrap(ui,
			&sessionrecordingscmd.Command{
				Command: base.NewCommand(ui),
				Func:    "list",
			}),
		"session-recordings download": daemon.Wrap(ui,
			&sessionrecordingscmd.DownloadCommand{
				Command: base.NewCommand(ui),
			}),

		"storage-buckets": func() (cli.Command, error) {
			return &storagebucketscmd.Command{
				Command: base.NewCommand(ui),
			}, nil
		},
		"storage-buckets read": daemon.Wrap(ui,
			&storagebucketscmd.Command{
				Command: base.NewCommand(ui),
				Func:    "read",
			}),
		"storage-buckets delete": daemon.Wrap(ui,
			&storagebucketscmd.Command{
				Command: base.NewCommand(ui),
				Func:    "delete",
			}),
		"storage-buckets list": daemon.Wrap(ui,
			&storagebucketscmd.Command{
				Command: base.NewCommand(ui),
				Func:    "list",
			}),
		"storage-buckets create": daemon.Wrap(ui,
			&storagebucketscmd.Command{
				Command: base.NewCommand(ui),
				Func:    "create",
			}),
		"storage-buckets update": daemon.Wrap(ui,
			&storagebucketscmd.Command{
				Command: base.NewCommand(ui),
				Func:    "update",
			}),

		"targets": func() (cli.Command, error) {
			return &targetscmd.Command{
				Command: base.NewCommand(ui),
			}, nil
		},
		"targets authorize-session": daemon.Wrap(ui,
			&targetscmd.Command{
				Command: base.NewCommand(ui),
				Func:    "authorize-session",
			}),
		"targets read": daemon.Wrap(ui,
			&targetscmd.Command{
				Command: base.NewCommand(ui),
				Func:    "read",
			}),
		"targets delete": daemon.Wrap(ui,
			&targetscmd.Command{
				Command: base.NewCommand(ui),
				Func:    "delete",
			}),
		"targets list": daemon.Wrap(ui,
			&targetscmd.Command{
				Command: base.NewCommand(ui),
				Func:    "list",
			}),
		"targets create": daemon.Wrap(ui,
			&targetscmd.Command{
				Command: base.NewCommand(ui),
				Func:    "create",
			}),
		"targets create tcp": daemon.Wrap(ui,
			&targetscmd.TcpCommand{
				Command: base.NewCommand(ui),
				Func:    "create",
			}),
		"targets create ssh": daemon.Wrap(ui,
			&targetscmd.SshCommand{
				Command: base.NewCommand(ui),
				Func:    "create",
			}),
		"targets update": daemon.Wrap(ui,
			&targetscmd.Command{
				Command: base.NewCommand(ui),
				Func:    "update",
			}),
		"targets update tcp": daemon.Wrap(ui,
			&targetscmd.TcpCommand{
				Command: base.NewCommand(ui),
				Func:    "update",
			}),
		"targets update ssh": daemon.Wrap(ui,
			&targetscmd.SshCommand{
				Command: base.NewCommand(ui),
				Func:    "update",
			}),
		"targets add-host-sources": daemon.Wrap(ui,
			&targetscmd.Command{
				Command: base.NewCommand(ui),
				Func:    "add-host-sources",
			}),
		"targets remove-host-sources": daemon.Wrap(ui,
			&targetscmd.Command{
				Command: base.NewCommand(ui),
				Func:    "remove-host-sources",
			}),
		"targets set-host-sources": daemon.Wrap(ui,
			&targetscmd.Command{
				Command: base.NewCommand(ui),
				Func:    "set-host-sources",
			}),
		"targets add-credential-sources": daemon.Wrap(ui,
			&targetscmd.Command{
				Command: base.NewCommand(ui),
				Func:    "add-credential-sources",
			}),
		"targets remove-credential-sources": daemon.Wrap(ui,
			&targetscmd.Command{
				Command: base.NewCommand(ui),
				Func:    "remove-credential-sources",
			}),
		"targets set-credential-sources": daemon.Wrap(ui,
			&targetscmd.Command{
				Command: base.NewCommand(ui),
				Func:    "set-credential-sources",
			}),

		"users": func() (cli.Command, error) {
			return &userscmd.Command{
				Command: base.NewCommand(ui),
			}, nil
		},
		"users create": daemon.Wrap(ui,
			&userscmd.Command{
				Command: base.NewCommand(ui),
				Func:    "create",
			}),
		"users read": daemon.Wrap(ui,
			&userscmd.Command{
				Command: base.NewCommand(ui),
				Func:    "read",
			}),
		"users update": daemon.Wrap(ui,
			&userscmd.Command{
				Command: base.NewCommand(ui),
				Func:    "update",
			}),
		"users delete": daemon.Wrap(ui,
			&userscmd.Command{
				Command: base.NewCommand(ui),
				Func:    "delete",
			}),
		"users list": daemon.Wrap(ui,
			&userscmd.Command{
				Command: base.NewCommand(ui),
				Func:    "list",
			}),
		"users add-accounts": daemon.Wrap(ui,
			&userscmd.Command{
				Command: base.NewCommand(ui),
				Func:    "add-accounts",
			}),
		"users set-accounts": daemon.Wrap(ui,
			&userscmd.Command{
				Command: base.NewCommand(ui),
				Func:    "set-accounts",
			}),
		"users remove-accounts": daemon.Wrap(ui,
			&userscmd.Command{
				Command: base.NewCommand(ui),
				Func:    "remove-accounts",
			}),

		"workers": func() (cli.Command, error) {
			return &workerscmd.Command{
				Command: base.NewCommand(ui),
			}, nil
		},
		"workers create": daemon.Wrap(ui,
			&workerscmd.Command{
				Command: base.NewCommand(ui),
				Func:    "create",
			}),
		"workers create worker-led": daemon.Wrap(ui,
			&workerscmd.WorkerLedCommand{
				Command: base.NewCommand(ui),
				Func:    "create",
			}),
		"workers create controller-led": daemon.Wrap(ui,
			&workerscmd.ControllerLedCommand{
				Command: base.NewCommand(ui),
				Func:    "create",
			}),
		"workers read": daemon.Wrap(ui,
			&workerscmd.Command{
				Command: base.NewCommand(ui),
				Func:    "read",
			}),
		"workers update": daemon.Wrap(ui,
			&workerscmd.Command{
				Command: base.NewCommand(ui),
				Func:    "update",
			}),
		"workers delete": daemon.Wrap(ui,
			&workerscmd.Command{
				Command: base.NewCommand(ui),
				Func:    "delete",
			}),
		"workers list": daemon.Wrap(ui,
			&workerscmd.Command{
				Command: base.NewCommand(ui),
				Func:    "list",
			}),
		"workers add-worker-tags": daemon.Wrap(ui,
			&workerscmd.Command{
				Command: base.NewCommand(ui),
				Func:    "add-worker-tags",
			}),
		"workers set-worker-tags": daemon.Wrap(ui,
			&workerscmd.Command{
				Command: base.NewCommand(ui),
				Func:    "set-worker-tags",
			}),
		"workers remove-worker-tags": daemon.Wrap(ui,
			&workerscmd.Command{
				Command: base.NewCommand(ui),
				Func:    "remove-worker-tags",
			}),
		"workers certificate-authority": daemon.Wrap(ui,
			&workerscmd.WorkerCACommand{
				Command: base.NewCommand(ui),
			}),
		"workers certificate-authority read": daemon.Wrap(ui,
			&workerscmd.WorkerCACommand{
				Command: base.NewCommand(ui),
				Func:    "read",
			}),
		"workers certificate-authority reinitialize": daemon.Wrap(ui,
			&workerscmd.WorkerCACommand{
				Command: base.NewCommand(ui),
				Func:    "reinitialize",
			}),
	}

	for _, fn := range extraCommandsFuncs {
		if fn != nil {
			fn()
		}
	}
}

var extraCommandsFuncs []func()
