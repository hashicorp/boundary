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
	"github.com/hashicorp/boundary/internal/cmd/commands/database"
	"github.com/hashicorp/boundary/internal/cmd/commands/dev"
	"github.com/hashicorp/boundary/internal/cmd/commands/genericcmd"
	"github.com/hashicorp/boundary/internal/cmd/commands/groupscmd"
	"github.com/hashicorp/boundary/internal/cmd/commands/hostcatalogscmd"
	"github.com/hashicorp/boundary/internal/cmd/commands/hostscmd"
	"github.com/hashicorp/boundary/internal/cmd/commands/hostsetscmd"
	"github.com/hashicorp/boundary/internal/cmd/commands/logout"
	"github.com/hashicorp/boundary/internal/cmd/commands/managedgroupscmd"
	"github.com/hashicorp/boundary/internal/cmd/commands/policiescmd"
	"github.com/hashicorp/boundary/internal/cmd/commands/rolescmd"
	"github.com/hashicorp/boundary/internal/cmd/commands/scopescmd"
	"github.com/hashicorp/boundary/internal/cmd/commands/server"
	"github.com/hashicorp/boundary/internal/cmd/commands/sessionrecordingscmd"
	"github.com/hashicorp/boundary/internal/cmd/commands/sessionscmd"
	"github.com/hashicorp/boundary/internal/cmd/commands/storagebucketscmd"
	"github.com/hashicorp/boundary/internal/cmd/commands/targetscmd"
	"github.com/hashicorp/boundary/internal/cmd/commands/unsupported"
	"github.com/hashicorp/boundary/internal/cmd/commands/userscmd"
	"github.com/hashicorp/boundary/internal/cmd/commands/version"
	"github.com/hashicorp/boundary/internal/cmd/commands/workerscmd"

	"github.com/mitchellh/cli"
)

// Commands is the mapping of all the available commands.
var Commands map[string]cli.CommandFactory

func initCommands(ui, serverCmdUi cli.Ui, runOpts *RunOptions) {
	var opts []base.Option
	if runOpts.ImplicitId != "" {
		opts = append(opts, base.WithImplicitId(runOpts.ImplicitId))
	}
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
				Command: base.NewCommand(ui, opts...),
			}, nil
		},

		"authenticate": clientCacheWrapper(
			&authenticate.Command{
				Command: base.NewCommand(ui, opts...),
			}),
		"authenticate password": clientCacheWrapper(
			&authenticate.PasswordCommand{
				Command: base.NewCommand(ui, opts...),
			}),
		"authenticate oidc": clientCacheWrapper(
			&authenticate.OidcCommand{
				Command: base.NewCommand(ui, opts...),
			}),
		"authenticate ldap": clientCacheWrapper(
			&authenticate.LdapCommand{
				Command: base.NewCommand(ui, opts...),
			}),

		"accounts": func() (cli.Command, error) {
			return &accountscmd.Command{
				Command: base.NewCommand(ui, opts...),
			}, nil
		},
		"accounts read": clientCacheWrapper(
			&accountscmd.Command{
				Command: base.NewCommand(ui, opts...),
				Func:    "read",
			}),
		"accounts delete": clientCacheWrapper(
			&accountscmd.Command{
				Command: base.NewCommand(ui, opts...),
				Func:    "delete",
			}),
		"accounts list": clientCacheWrapper(
			&accountscmd.Command{
				Command: base.NewCommand(ui, opts...),
				Func:    "list",
			}),
		"accounts set-password": clientCacheWrapper(
			&accountscmd.Command{
				Command: base.NewCommand(ui, opts...),
				Func:    "set-password",
			}),
		"accounts change-password": clientCacheWrapper(
			&accountscmd.Command{
				Command: base.NewCommand(ui, opts...),
				Func:    "change-password",
			}),
		"accounts create": clientCacheWrapper(
			&accountscmd.Command{
				Command: base.NewCommand(ui, opts...),
				Func:    "create",
			}),
		"accounts create password": clientCacheWrapper(
			&accountscmd.PasswordCommand{
				Command: base.NewCommand(ui, opts...),
				Func:    "create",
			}),
		"accounts create oidc": clientCacheWrapper(
			&accountscmd.OidcCommand{
				Command: base.NewCommand(ui, opts...),
				Func:    "create",
			}),
		"accounts create ldap": clientCacheWrapper(
			&accountscmd.LdapCommand{
				Command: base.NewCommand(ui, opts...),
				Func:    "create",
			}),
		"accounts update": clientCacheWrapper(
			&accountscmd.Command{
				Command: base.NewCommand(ui, opts...),
				Func:    "update",
			}),
		"accounts update password": clientCacheWrapper(
			&accountscmd.PasswordCommand{
				Command: base.NewCommand(ui, opts...),
				Func:    "update",
			}),
		"accounts update oidc": clientCacheWrapper(
			&accountscmd.OidcCommand{
				Command: base.NewCommand(ui, opts...),
				Func:    "update",
			}),
		"accounts update ldap": clientCacheWrapper(
			&accountscmd.LdapCommand{
				Command: base.NewCommand(ui, opts...),
				Func:    "update",
			}),

		"auth-methods": func() (cli.Command, error) {
			return &authmethodscmd.Command{
				Command: base.NewCommand(ui, opts...),
			}, nil
		},
		"auth-methods read": clientCacheWrapper(
			&authmethodscmd.Command{
				Command: base.NewCommand(ui, opts...),
				Func:    "read",
			}),
		"auth-methods delete": clientCacheWrapper(
			&authmethodscmd.Command{
				Command: base.NewCommand(ui, opts...),
				Func:    "delete",
			}),
		"auth-methods list": clientCacheWrapper(
			&authmethodscmd.Command{
				Command: base.NewCommand(ui, opts...),
				Func:    "list",
			}),
		"auth-methods create": clientCacheWrapper(
			&authmethodscmd.Command{
				Command: base.NewCommand(ui, opts...),
				Func:    "create",
			}),
		"auth-methods create password": clientCacheWrapper(
			&authmethodscmd.PasswordCommand{
				Command: base.NewCommand(ui, opts...),
				Func:    "create",
			}),
		"auth-methods create oidc": clientCacheWrapper(
			&authmethodscmd.OidcCommand{
				Command: base.NewCommand(ui, opts...),
				Func:    "create",
			}),
		"auth-methods create ldap": clientCacheWrapper(
			&authmethodscmd.LdapCommand{
				Command: base.NewCommand(ui, opts...),
				Func:    "create",
			}),
		"auth-methods update": clientCacheWrapper(
			&authmethodscmd.Command{
				Command: base.NewCommand(ui, opts...),
				Func:    "update",
			}),
		"auth-methods update password": clientCacheWrapper(
			&authmethodscmd.PasswordCommand{
				Command: base.NewCommand(ui, opts...),
				Func:    "update",
			}),
		"auth-methods update oidc": clientCacheWrapper(
			&authmethodscmd.OidcCommand{
				Command: base.NewCommand(ui, opts...),
				Func:    "update",
			}),
		"auth-methods update ldap": clientCacheWrapper(
			&authmethodscmd.LdapCommand{
				Command: base.NewCommand(ui, opts...),
				Func:    "update",
			}),
		"auth-methods change-state oidc": clientCacheWrapper(
			&authmethodscmd.OidcCommand{
				Command: base.NewCommand(ui, opts...),
				Func:    "change-state",
			}),

		"auth-tokens": func() (cli.Command, error) {
			return &authtokenscmd.Command{
				Command: base.NewCommand(ui, opts...),
			}, nil
		},
		"auth-tokens read": clientCacheWrapper(
			&authtokenscmd.Command{
				Command: base.NewCommand(ui, opts...),
				Func:    "read",
			}),
		"auth-tokens delete": clientCacheWrapper(
			&authtokenscmd.Command{
				Command: base.NewCommand(ui, opts...),
				Func:    "delete",
			}),
		"auth-tokens list": clientCacheWrapper(
			&authtokenscmd.Command{
				Command: base.NewCommand(ui, opts...),
				Func:    "list",
			}),

		"config": func() (cli.Command, error) {
			return &config.Command{
				Command: base.NewCommand(ui, opts...),
			}, nil
		},
		"config encrypt": func() (cli.Command, error) {
			return &config.EncryptDecryptCommand{
				Command: base.NewCommand(ui, opts...),
				Func:    "encrypt",
			}, nil
		},
		"config decrypt": func() (cli.Command, error) {
			return &config.EncryptDecryptCommand{
				Command: base.NewCommand(ui, opts...),
				Func:    "decrypt",
			}, nil
		},
		"config get-token": func() (cli.Command, error) {
			return &config.TokenCommand{
				Command: base.NewCommand(ui, opts...),
				Func:    "get-token",
			}, nil
		},
		"config autocomplete": func() (cli.Command, error) {
			return &config.AutocompleteCommand{
				Command: base.NewCommand(ui, opts...),
				Func:    "base",
			}, nil
		},
		"config autocomplete install": func() (cli.Command, error) {
			return &config.AutocompleteCommand{
				Command: base.NewCommand(ui, opts...),
				Func:    "install",
			}, nil
		},
		"config autocomplete uninstall": func() (cli.Command, error) {
			return &config.AutocompleteCommand{
				Command: base.NewCommand(ui, opts...),
				Func:    "uninstall",
			}, nil
		},

		"connect": clientCacheWrapper(
			&connect.Command{
				Command: base.NewCommand(ui, opts...),
				Func:    "connect",
			}),
		"connect http": clientCacheWrapper(
			&connect.Command{
				Command: base.NewCommand(ui, opts...),
				Func:    "http",
			}),
		"connect kube": clientCacheWrapper(
			&connect.Command{
				Command: base.NewCommand(ui, opts...),
				Func:    "kube",
			}),
		"connect postgres": clientCacheWrapper(
			&connect.Command{
				Command: base.NewCommand(ui, opts...),
				Func:    "postgres",
			}),
		"connect rdp": clientCacheWrapper(
			&connect.Command{
				Command: base.NewCommand(ui, opts...),
				Func:    "rdp",
			}),
		"connect ssh": clientCacheWrapper(
			&connect.Command{
				Command: base.NewCommand(ui, opts...),
				Func:    "ssh",
			}),

		"database": func() (cli.Command, error) {
			return &database.Command{
				Command: base.NewCommand(ui, opts...),
			}, nil
		},
		"database init": func() (cli.Command, error) {
			return &database.InitCommand{
				Server: base.NewServer(base.NewCommand(ui, opts...)),
			}, nil
		},
		"database migrate": func() (cli.Command, error) {
			return &database.MigrateCommand{
				Command: base.NewCommand(ui, opts...),
			}, nil
		},

		"credential-libraries": func() (cli.Command, error) {
			return &credentiallibrariescmd.Command{
				Command: base.NewCommand(ui, opts...),
			}, nil
		},
		"credential-libraries read": clientCacheWrapper(
			&credentiallibrariescmd.Command{
				Command: base.NewCommand(ui, opts...),
				Func:    "read",
			}),
		"credential-libraries delete": clientCacheWrapper(
			&credentiallibrariescmd.Command{
				Command: base.NewCommand(ui, opts...),
				Func:    "delete",
			}),
		"credential-libraries list": clientCacheWrapper(
			&credentiallibrariescmd.Command{
				Command: base.NewCommand(ui, opts...),
				Func:    "list",
			}),
		"credential-libraries create": clientCacheWrapper(
			&credentiallibrariescmd.Command{
				Command: base.NewCommand(ui, opts...),
				Func:    "create",
			}),
		"credential-libraries create vault": clientCacheWrapper(
			&credentiallibrariescmd.VaultCommand{
				Command: base.NewCommand(ui, opts...),
				Func:    "create",
			}),
		"credential-libraries create vault-generic": clientCacheWrapper(
			&credentiallibrariescmd.VaultGenericCommand{
				Command: base.NewCommand(ui, opts...),
				Func:    "create",
			}),
		"credential-libraries create vault-ssh-certificate": clientCacheWrapper(
			&credentiallibrariescmd.VaultSshCertificateCommand{
				Command: base.NewCommand(ui, opts...),
				Func:    "create",
			}),
		"credential-libraries update": clientCacheWrapper(
			&credentiallibrariescmd.Command{
				Command: base.NewCommand(ui, opts...),
				Func:    "update",
			}),
		"credential-libraries update vault": clientCacheWrapper(
			&credentiallibrariescmd.VaultGenericCommand{
				Command: base.NewCommand(ui, opts...),
				Func:    "update",
			}),
		"credential-libraries update vault-generic": clientCacheWrapper(
			&credentiallibrariescmd.VaultGenericCommand{
				Command: base.NewCommand(ui, opts...),
				Func:    "update",
			}),
		"credential-libraries update vault-ssh-certificate": clientCacheWrapper(
			&credentiallibrariescmd.VaultSshCertificateCommand{
				Command: base.NewCommand(ui, opts...),
				Func:    "update",
			}),

		"credential-stores": func() (cli.Command, error) {
			return &credentialstorescmd.Command{
				Command: base.NewCommand(ui, opts...),
			}, nil
		},
		"credential-stores read": clientCacheWrapper(
			&credentialstorescmd.Command{
				Command: base.NewCommand(ui, opts...),
				Func:    "read",
			}),
		"credential-stores delete": clientCacheWrapper(
			&credentialstorescmd.Command{
				Command: base.NewCommand(ui, opts...),
				Func:    "delete",
			}),
		"credential-stores list": clientCacheWrapper(
			&credentialstorescmd.Command{
				Command: base.NewCommand(ui, opts...),
				Func:    "list",
			}),
		"credential-stores create": clientCacheWrapper(
			&credentialstorescmd.Command{
				Command: base.NewCommand(ui, opts...),
				Func:    "create",
			}),
		"credential-stores create vault": clientCacheWrapper(
			&credentialstorescmd.VaultCommand{
				Command: base.NewCommand(ui, opts...),
				Func:    "create",
			}),
		"credential-stores create static": clientCacheWrapper(
			&credentialstorescmd.StaticCommand{
				Command: base.NewCommand(ui, opts...),
				Func:    "create",
			}),
		"credential-stores update": clientCacheWrapper(
			&credentialstorescmd.Command{
				Command: base.NewCommand(ui, opts...),
				Func:    "update",
			}),
		"credential-stores update vault": clientCacheWrapper(
			&credentialstorescmd.VaultCommand{
				Command: base.NewCommand(ui, opts...),
				Func:    "update",
			}),
		"credential-stores update static": clientCacheWrapper(
			&credentialstorescmd.StaticCommand{
				Command: base.NewCommand(ui, opts...),
				Func:    "update",
			}),

		"credentials": func() (cli.Command, error) {
			return &credentialscmd.Command{
				Command: base.NewCommand(ui, opts...),
			}, nil
		},
		"credentials read": clientCacheWrapper(
			&credentialscmd.Command{
				Command: base.NewCommand(ui, opts...),
				Func:    "read",
			}),
		"credentials delete": clientCacheWrapper(
			&credentialscmd.Command{
				Command: base.NewCommand(ui, opts...),
				Func:    "delete",
			}),
		"credentials list": clientCacheWrapper(
			&credentialscmd.Command{
				Command: base.NewCommand(ui, opts...),
				Func:    "list",
			}),
		"credentials create": clientCacheWrapper(
			&credentialscmd.Command{
				Command: base.NewCommand(ui, opts...),
				Func:    "create",
			}),
		"credentials create username-password": clientCacheWrapper(
			&credentialscmd.UsernamePasswordCommand{
				Command: base.NewCommand(ui, opts...),
				Func:    "create",
			}),
		"credentials create ssh-private-key": clientCacheWrapper(
			&credentialscmd.SshPrivateKeyCommand{
				Command: base.NewCommand(ui, opts...),
				Func:    "create",
			}),
		"credentials create json": clientCacheWrapper(
			&credentialscmd.JsonCommand{
				Command: base.NewCommand(ui, opts...),
				Func:    "create",
			}),
		"credentials update": clientCacheWrapper(
			&credentialscmd.Command{
				Command: base.NewCommand(ui, opts...),
				Func:    "update",
			}),
		"credentials update username-password": clientCacheWrapper(
			&credentialscmd.UsernamePasswordCommand{
				Command: base.NewCommand(ui, opts...),
				Func:    "update",
			}),
		"credentials update ssh-private-key": clientCacheWrapper(
			&credentialscmd.SshPrivateKeyCommand{
				Command: base.NewCommand(ui, opts...),
				Func:    "update",
			}),
		"credentials update json": clientCacheWrapper(
			&credentialscmd.JsonCommand{
				Command: base.NewCommand(ui, opts...),
				Func:    "update",
			}),

		"daemon": func() (cli.Command, error) {
			return &unsupported.UnsupportedCommand{
				Command:     base.NewCommand(ui, opts...),
				CommandName: "daemon",
			}, nil
		},

		"delete": func() (cli.Command, error) {
			return &genericcmd.Command{
				Command: base.NewCommand(ui, opts...),
				Func:    "delete",
			}, nil
		},

		"groups": func() (cli.Command, error) {
			return &groupscmd.Command{
				Command: base.NewCommand(ui, opts...),
			}, nil
		},
		"groups create": clientCacheWrapper(
			&groupscmd.Command{
				Command: base.NewCommand(ui, opts...),
				Func:    "create",
			}),
		"groups update": clientCacheWrapper(
			&groupscmd.Command{
				Command: base.NewCommand(ui, opts...),
				Func:    "update",
			}),
		"groups read": clientCacheWrapper(
			&groupscmd.Command{
				Command: base.NewCommand(ui, opts...),
				Func:    "read",
			}),
		"groups delete": clientCacheWrapper(
			&groupscmd.Command{
				Command: base.NewCommand(ui, opts...),
				Func:    "delete",
			}),
		"groups list": clientCacheWrapper(
			&groupscmd.Command{
				Command: base.NewCommand(ui, opts...),
				Func:    "list",
			}),
		"groups add-members": clientCacheWrapper(
			&groupscmd.Command{
				Command: base.NewCommand(ui, opts...),
				Func:    "add-members",
			}),
		"groups set-members": clientCacheWrapper(
			&groupscmd.Command{
				Command: base.NewCommand(ui, opts...),
				Func:    "set-members",
			}),
		"groups remove-members": clientCacheWrapper(
			&groupscmd.Command{
				Command: base.NewCommand(ui, opts...),
				Func:    "remove-members",
			}),

		"host-catalogs": func() (cli.Command, error) {
			return &hostcatalogscmd.Command{
				Command: base.NewCommand(ui, opts...),
			}, nil
		},
		"host-catalogs read": clientCacheWrapper(
			&hostcatalogscmd.Command{
				Command: base.NewCommand(ui, opts...),
				Func:    "read",
			}),
		"host-catalogs delete": clientCacheWrapper(
			&hostcatalogscmd.Command{
				Command: base.NewCommand(ui, opts...),
				Func:    "delete",
			}),
		"host-catalogs list": clientCacheWrapper(
			&hostcatalogscmd.Command{
				Command: base.NewCommand(ui, opts...),
				Func:    "list",
			}),
		"host-catalogs create": clientCacheWrapper(
			&hostcatalogscmd.Command{
				Command: base.NewCommand(ui, opts...),
				Func:    "create",
			}),
		"host-catalogs create static": clientCacheWrapper(
			&hostcatalogscmd.StaticCommand{
				Command: base.NewCommand(ui, opts...),
				Func:    "create",
			}),
		"host-catalogs create plugin": clientCacheWrapper(
			&hostcatalogscmd.PluginCommand{
				Command: base.NewCommand(ui, opts...),
				Func:    "create",
			}),
		"host-catalogs update": clientCacheWrapper(
			&hostcatalogscmd.Command{
				Command: base.NewCommand(ui, opts...),
				Func:    "update",
			}),
		"host-catalogs update static": clientCacheWrapper(
			&hostcatalogscmd.StaticCommand{
				Command: base.NewCommand(ui, opts...),
				Func:    "update",
			}),
		"host-catalogs update plugin": clientCacheWrapper(
			&hostcatalogscmd.PluginCommand{
				Command: base.NewCommand(ui, opts...),
				Func:    "update",
			}),

		"host-sets": func() (cli.Command, error) {
			return &hostsetscmd.Command{
				Command: base.NewCommand(ui, opts...),
			}, nil
		},
		"host-sets read": clientCacheWrapper(
			&hostsetscmd.Command{
				Command: base.NewCommand(ui, opts...),
				Func:    "read",
			}),
		"host-sets delete": clientCacheWrapper(
			&hostsetscmd.Command{
				Command: base.NewCommand(ui, opts...),
				Func:    "delete",
			}),
		"host-sets list": clientCacheWrapper(
			&hostsetscmd.Command{
				Command: base.NewCommand(ui, opts...),
				Func:    "list",
			}),
		"host-sets create": clientCacheWrapper(
			&hostsetscmd.Command{
				Command: base.NewCommand(ui, opts...),
				Func:    "create",
			}),
		"host-sets create static": clientCacheWrapper(
			&hostsetscmd.StaticCommand{
				Command: base.NewCommand(ui, opts...),
				Func:    "create",
			}),
		"host-sets create plugin": clientCacheWrapper(
			&hostsetscmd.PluginCommand{
				Command: base.NewCommand(ui, opts...),
				Func:    "create",
			}),
		"host-sets update": clientCacheWrapper(
			&hostsetscmd.Command{
				Command: base.NewCommand(ui, opts...),
				Func:    "update",
			}),
		"host-sets update static": clientCacheWrapper(
			&hostsetscmd.StaticCommand{
				Command: base.NewCommand(ui, opts...),
				Func:    "update",
			}),
		"host-sets update plugin": clientCacheWrapper(
			&hostsetscmd.PluginCommand{
				Command: base.NewCommand(ui, opts...),
				Func:    "update",
			}),
		"host-sets add-hosts": clientCacheWrapper(
			&hostsetscmd.Command{
				Command: base.NewCommand(ui, opts...),
				Func:    "add-hosts",
			}),
		"host-sets remove-hosts": clientCacheWrapper(
			&hostsetscmd.Command{
				Command: base.NewCommand(ui, opts...),
				Func:    "remove-hosts",
			}),
		"host-sets set-hosts": clientCacheWrapper(
			&hostsetscmd.Command{
				Command: base.NewCommand(ui, opts...),
				Func:    "set-hosts",
			}),

		"hosts": func() (cli.Command, error) {
			return &hostscmd.Command{
				Command: base.NewCommand(ui, opts...),
			}, nil
		},
		"hosts read": clientCacheWrapper(
			&hostscmd.Command{
				Command: base.NewCommand(ui, opts...),
				Func:    "read",
			}),
		"hosts delete": clientCacheWrapper(
			&hostscmd.Command{
				Command: base.NewCommand(ui, opts...),
				Func:    "delete",
			}),
		"hosts list": clientCacheWrapper(
			&hostscmd.Command{
				Command: base.NewCommand(ui, opts...),
				Func:    "list",
			}),
		"hosts create": clientCacheWrapper(
			&hostscmd.Command{
				Command: base.NewCommand(ui, opts...),
				Func:    "create",
			}),
		"hosts create static": clientCacheWrapper(
			&hostscmd.StaticCommand{
				Command: base.NewCommand(ui, opts...),
				Func:    "create",
			}),
		"hosts update": clientCacheWrapper(
			&hostscmd.Command{
				Command: base.NewCommand(ui, opts...),
				Func:    "update",
			}),
		"hosts update static": clientCacheWrapper(
			&hostscmd.StaticCommand{
				Command: base.NewCommand(ui, opts...),
				Func:    "update",
			}),

		"logout": func() (cli.Command, error) {
			return &logout.LogoutCommand{
				Command: base.NewCommand(ui, opts...),
			}, nil
		},

		"managed-groups": func() (cli.Command, error) {
			return &managedgroupscmd.Command{
				Command: base.NewCommand(ui, opts...),
			}, nil
		},
		"managed-groups read": clientCacheWrapper(
			&managedgroupscmd.Command{
				Command: base.NewCommand(ui, opts...),
				Func:    "read",
			}),
		"managed-groups delete": clientCacheWrapper(
			&managedgroupscmd.Command{
				Command: base.NewCommand(ui, opts...),
				Func:    "delete",
			}),
		"managed-groups list": clientCacheWrapper(
			&managedgroupscmd.Command{
				Command: base.NewCommand(ui, opts...),
				Func:    "list",
			}),
		"managed-groups create": clientCacheWrapper(
			&managedgroupscmd.Command{
				Command: base.NewCommand(ui, opts...),
				Func:    "create",
			}),
		"managed-groups create oidc": clientCacheWrapper(
			&managedgroupscmd.OidcCommand{
				Command: base.NewCommand(ui, opts...),
				Func:    "create",
			}),
		"managed-groups create ldap": clientCacheWrapper(
			&managedgroupscmd.LdapCommand{
				Command: base.NewCommand(ui, opts...),
				Func:    "create",
			}),
		"managed-groups update": clientCacheWrapper(
			&managedgroupscmd.Command{
				Command: base.NewCommand(ui, opts...),
				Func:    "update",
			}),
		"managed-groups update oidc": clientCacheWrapper(
			&managedgroupscmd.OidcCommand{
				Command: base.NewCommand(ui, opts...),
				Func:    "update",
			}),
		"managed-groups update ldap": clientCacheWrapper(
			&managedgroupscmd.LdapCommand{
				Command: base.NewCommand(ui, opts...),
				Func:    "update",
			}),

		"policies": func() (cli.Command, error) {
			return &policiescmd.Command{
				Command: base.NewCommand(ui, opts...),
			}, nil
		},
		"policies read": func() (cli.Command, error) {
			return &policiescmd.Command{
				Command: base.NewCommand(ui, opts...),
				Func:    "read",
			}, nil
		},
		"policies delete": func() (cli.Command, error) {
			return &policiescmd.Command{
				Command: base.NewCommand(ui, opts...),
				Func:    "delete",
			}, nil
		},
		"policies list": func() (cli.Command, error) {
			return &policiescmd.Command{
				Command: base.NewCommand(ui, opts...),
				Func:    "list",
			}, nil
		},
		"policies create": func() (cli.Command, error) {
			return &policiescmd.Command{
				Command: base.NewCommand(ui, opts...),
				Func:    "create",
			}, nil
		},
		"policies create storage": func() (cli.Command, error) {
			return &policiescmd.StorageCommand{
				Command: base.NewCommand(ui, opts...),
				Func:    "create",
			}, nil
		},
		"policies update": func() (cli.Command, error) {
			return &policiescmd.Command{
				Command: base.NewCommand(ui, opts...),
				Func:    "update",
			}, nil
		},
		"policies update storage": func() (cli.Command, error) {
			return &policiescmd.StorageCommand{
				Command: base.NewCommand(ui, opts...),
				Func:    "update",
			}, nil
		},

		"read": func() (cli.Command, error) {
			return &genericcmd.Command{
				Command: base.NewCommand(ui, opts...),
				Func:    "read",
			}, nil
		},

		"roles": func() (cli.Command, error) {
			return &rolescmd.Command{
				Command: base.NewCommand(ui, opts...),
			}, nil
		},
		"roles create": clientCacheWrapper(
			&rolescmd.Command{
				Command: base.NewCommand(ui, opts...),
				Func:    "create",
			}),
		"roles update": clientCacheWrapper(
			&rolescmd.Command{
				Command: base.NewCommand(ui, opts...),
				Func:    "update",
			}),
		"roles read": clientCacheWrapper(
			&rolescmd.Command{
				Command: base.NewCommand(ui, opts...),
				Func:    "read",
			}),
		"roles delete": clientCacheWrapper(
			&rolescmd.Command{
				Command: base.NewCommand(ui, opts...),
				Func:    "delete",
			}),
		"roles list": clientCacheWrapper(
			&rolescmd.Command{
				Command: base.NewCommand(ui, opts...),
				Func:    "list",
			}),
		"roles add-principals": clientCacheWrapper(
			&rolescmd.Command{
				Command: base.NewCommand(ui, opts...),
				Func:    "add-principals",
			}),
		"roles set-principals": clientCacheWrapper(
			&rolescmd.Command{
				Command: base.NewCommand(ui, opts...),
				Func:    "set-principals",
			}),
		"roles remove-principals": clientCacheWrapper(
			&rolescmd.Command{
				Command: base.NewCommand(ui, opts...),
				Func:    "remove-principals",
			}),
		"roles add-grants": clientCacheWrapper(
			&rolescmd.Command{
				Command: base.NewCommand(ui, opts...),
				Func:    "add-grants",
			}),
		"roles set-grants": clientCacheWrapper(
			&rolescmd.Command{
				Command: base.NewCommand(ui, opts...),
				Func:    "set-grants",
			}),
		"roles remove-grants": clientCacheWrapper(
			&rolescmd.Command{
				Command: base.NewCommand(ui, opts...),
				Func:    "remove-grants",
			}),

		"scopes": func() (cli.Command, error) {
			return &scopescmd.Command{
				Command: base.NewCommand(ui, opts...),
			}, nil
		},
		"scopes create": clientCacheWrapper(
			&scopescmd.Command{
				Command: base.NewCommand(ui, opts...),
				Func:    "create",
			}),
		"scopes read": clientCacheWrapper(
			&scopescmd.Command{
				Command: base.NewCommand(ui, opts...),
				Func:    "read",
			}),
		"scopes update": clientCacheWrapper(
			&scopescmd.Command{
				Command: base.NewCommand(ui, opts...),
				Func:    "update",
			}),
		"scopes delete": clientCacheWrapper(
			&scopescmd.Command{
				Command: base.NewCommand(ui, opts...),
				Func:    "delete",
			}),
		"scopes list": clientCacheWrapper(
			&scopescmd.Command{
				Command: base.NewCommand(ui, opts...),
				Func:    "list",
			}),
		"scopes list-keys": clientCacheWrapper(
			&scopescmd.ListKeysCommand{
				Command: base.NewCommand(ui, opts...),
			}),
		"scopes rotate-keys": clientCacheWrapper(
			&scopescmd.RotateKeysCommand{
				Command: base.NewCommand(ui, opts...),
			}),
		"scopes list-key-version-destruction-jobs": clientCacheWrapper(
			&scopescmd.ListKeyVersionDestructionJobsCommand{
				Command: base.NewCommand(ui, opts...),
			}),
		"scopes destroy-key-version": clientCacheWrapper(
			&scopescmd.DestroyKeyVersionCommand{
				Command: base.NewCommand(ui, opts...),
			}),
		"scopes attach-storage-policy": clientCacheWrapper(
			&scopescmd.Command{
				Command: base.NewCommand(ui, opts...),
				Func:    "attach-storage-policy",
			}),
		"scopes detach-storage-policy": clientCacheWrapper(
			&scopescmd.Command{
				Command: base.NewCommand(ui, opts...),
				Func:    "detach-storage-policy",
			}),

		"search": func() (cli.Command, error) {
			return &unsupported.UnsupportedCommand{
				Command:     base.NewCommand(ui, opts...),
				CommandName: "search",
			}, nil
		},

		"sessions": func() (cli.Command, error) {
			return &sessionscmd.Command{
				Command: base.NewCommand(ui, opts...),
			}, nil
		},
		"sessions read": clientCacheWrapper(
			&sessionscmd.Command{
				Command: base.NewCommand(ui, opts...),
				Func:    "read",
			}),
		"sessions list": clientCacheWrapper(
			&sessionscmd.Command{
				Command: base.NewCommand(ui, opts...),
				Func:    "list",
			}),
		"sessions cancel": clientCacheWrapper(
			&sessionscmd.Command{
				Command: base.NewCommand(ui, opts...),
				Func:    "cancel",
			}),

		"session-recordings": func() (cli.Command, error) {
			return &sessionrecordingscmd.Command{
				Command: base.NewCommand(ui, opts...),
			}, nil
		},
		"session-recordings read": clientCacheWrapper(
			&sessionrecordingscmd.Command{
				Command: base.NewCommand(ui, opts...),
				Func:    "read",
			}),
		"session-recordings list": clientCacheWrapper(
			&sessionrecordingscmd.Command{
				Command: base.NewCommand(ui, opts...),
				Func:    "list",
			}),
		"session-recordings download": clientCacheWrapper(
			&sessionrecordingscmd.DownloadCommand{
				Command: base.NewCommand(ui, opts...),
			}),
		"session-recordings delete": clientCacheWrapper(
			&sessionrecordingscmd.Command{
				Command: base.NewCommand(ui, opts...),
				Func:    "delete",
			}),
		"session-recordings reapply-storage-policy": clientCacheWrapper(
			&sessionrecordingscmd.ReApplyStoragePolicyCommand{
				Command: base.NewCommand(ui, opts...),
			}),

		"storage-buckets": func() (cli.Command, error) {
			return &storagebucketscmd.Command{
				Command: base.NewCommand(ui, opts...),
			}, nil
		},
		"storage-buckets read": clientCacheWrapper(
			&storagebucketscmd.Command{
				Command: base.NewCommand(ui, opts...),
				Func:    "read",
			}),
		"storage-buckets delete": clientCacheWrapper(
			&storagebucketscmd.Command{
				Command: base.NewCommand(ui, opts...),
				Func:    "delete",
			}),
		"storage-buckets list": clientCacheWrapper(
			&storagebucketscmd.Command{
				Command: base.NewCommand(ui, opts...),
				Func:    "list",
			}),
		"storage-buckets create": clientCacheWrapper(
			&storagebucketscmd.Command{
				Command: base.NewCommand(ui, opts...),
				Func:    "create",
			}),
		"storage-buckets update": clientCacheWrapper(
			&storagebucketscmd.Command{
				Command: base.NewCommand(ui, opts...),
				Func:    "update",
			}),

		"targets": func() (cli.Command, error) {
			return &targetscmd.Command{
				Command: base.NewCommand(ui, opts...),
			}, nil
		},
		"targets authorize-session": clientCacheWrapper(
			&targetscmd.Command{
				Command: base.NewCommand(ui, opts...),
				Func:    "authorize-session",
			}),
		"targets read": clientCacheWrapper(
			&targetscmd.Command{
				Command: base.NewCommand(ui, opts...),
				Func:    "read",
			}),
		"targets delete": clientCacheWrapper(
			&targetscmd.Command{
				Command: base.NewCommand(ui, opts...),
				Func:    "delete",
			}),
		"targets list": clientCacheWrapper(
			&targetscmd.Command{
				Command: base.NewCommand(ui, opts...),
				Func:    "list",
			}),
		"targets create": clientCacheWrapper(
			&targetscmd.Command{
				Command: base.NewCommand(ui, opts...),
				Func:    "create",
			}),
		"targets create tcp": clientCacheWrapper(
			&targetscmd.TcpCommand{
				Command: base.NewCommand(ui, opts...),
				Func:    "create",
			}),
		"targets create ssh": clientCacheWrapper(
			&targetscmd.SshCommand{
				Command: base.NewCommand(ui, opts...),
				Func:    "create",
			}),
		"targets update": clientCacheWrapper(
			&targetscmd.Command{
				Command: base.NewCommand(ui, opts...),
				Func:    "update",
			}),
		"targets update tcp": clientCacheWrapper(
			&targetscmd.TcpCommand{
				Command: base.NewCommand(ui, opts...),
				Func:    "update",
			}),
		"targets update ssh": clientCacheWrapper(
			&targetscmd.SshCommand{
				Command: base.NewCommand(ui, opts...),
				Func:    "update",
			}),
		"targets add-host-sources": clientCacheWrapper(
			&targetscmd.Command{
				Command: base.NewCommand(ui, opts...),
				Func:    "add-host-sources",
			}),
		"targets remove-host-sources": clientCacheWrapper(
			&targetscmd.Command{
				Command: base.NewCommand(ui, opts...),
				Func:    "remove-host-sources",
			}),
		"targets set-host-sources": clientCacheWrapper(
			&targetscmd.Command{
				Command: base.NewCommand(ui, opts...),
				Func:    "set-host-sources",
			}),
		"targets add-credential-sources": clientCacheWrapper(
			&targetscmd.Command{
				Command: base.NewCommand(ui, opts...),
				Func:    "add-credential-sources",
			}),
		"targets remove-credential-sources": clientCacheWrapper(
			&targetscmd.Command{
				Command: base.NewCommand(ui, opts...),
				Func:    "remove-credential-sources",
			}),
		"targets set-credential-sources": clientCacheWrapper(
			&targetscmd.Command{
				Command: base.NewCommand(ui, opts...),
				Func:    "set-credential-sources",
			}),

		"update": func() (cli.Command, error) {
			return &genericcmd.Command{
				Command: base.NewCommand(ui, opts...),
				Func:    "update",
			}, nil
		},

		"users": func() (cli.Command, error) {
			return &userscmd.Command{
				Command: base.NewCommand(ui, opts...),
			}, nil
		},
		"users create": clientCacheWrapper(
			&userscmd.Command{
				Command: base.NewCommand(ui, opts...),
				Func:    "create",
			}),
		"users read": clientCacheWrapper(
			&userscmd.Command{
				Command: base.NewCommand(ui, opts...),
				Func:    "read",
			}),
		"users update": clientCacheWrapper(
			&userscmd.Command{
				Command: base.NewCommand(ui, opts...),
				Func:    "update",
			}),
		"users delete": clientCacheWrapper(
			&userscmd.Command{
				Command: base.NewCommand(ui, opts...),
				Func:    "delete",
			}),
		"users list": clientCacheWrapper(
			&userscmd.Command{
				Command: base.NewCommand(ui, opts...),
				Func:    "list",
			}),
		"users add-accounts": clientCacheWrapper(
			&userscmd.Command{
				Command: base.NewCommand(ui, opts...),
				Func:    "add-accounts",
			}),
		"users set-accounts": clientCacheWrapper(
			&userscmd.Command{
				Command: base.NewCommand(ui, opts...),
				Func:    "set-accounts",
			}),
		"users remove-accounts": clientCacheWrapper(
			&userscmd.Command{
				Command: base.NewCommand(ui, opts...),
				Func:    "remove-accounts",
			}),

		"workers": func() (cli.Command, error) {
			return &workerscmd.Command{
				Command: base.NewCommand(ui, opts...),
			}, nil
		},
		"workers create": clientCacheWrapper(
			&workerscmd.Command{
				Command: base.NewCommand(ui, opts...),
				Func:    "create",
			}),
		"workers create worker-led": clientCacheWrapper(
			&workerscmd.WorkerLedCommand{
				Command: base.NewCommand(ui, opts...),
				Func:    "create",
			}),
		"workers create controller-led": clientCacheWrapper(
			&workerscmd.ControllerLedCommand{
				Command: base.NewCommand(ui, opts...),
				Func:    "create",
			}),
		"workers read": clientCacheWrapper(
			&workerscmd.Command{
				Command: base.NewCommand(ui, opts...),
				Func:    "read",
			}),
		"workers update": clientCacheWrapper(
			&workerscmd.Command{
				Command: base.NewCommand(ui, opts...),
				Func:    "update",
			}),
		"workers delete": clientCacheWrapper(
			&workerscmd.Command{
				Command: base.NewCommand(ui, opts...),
				Func:    "delete",
			}),
		"workers list": clientCacheWrapper(
			&workerscmd.Command{
				Command: base.NewCommand(ui, opts...),
				Func:    "list",
			}),
		"workers add-worker-tags": clientCacheWrapper(
			&workerscmd.Command{
				Command: base.NewCommand(ui, opts...),
				Func:    "add-worker-tags",
			}),
		"workers set-worker-tags": clientCacheWrapper(
			&workerscmd.Command{
				Command: base.NewCommand(ui, opts...),
				Func:    "set-worker-tags",
			}),
		"workers remove-worker-tags": clientCacheWrapper(
			&workerscmd.Command{
				Command: base.NewCommand(ui, opts...),
				Func:    "remove-worker-tags",
			}),
		"workers certificate-authority": clientCacheWrapper(
			&workerscmd.WorkerCACommand{
				Command: base.NewCommand(ui, opts...),
			}),
		"workers certificate-authority read": clientCacheWrapper(
			&workerscmd.WorkerCACommand{
				Command: base.NewCommand(ui, opts...),
				Func:    "read",
			}),
		"workers certificate-authority reinitialize": clientCacheWrapper(
			&workerscmd.WorkerCACommand{
				Command: base.NewCommand(ui, opts...),
				Func:    "reinitialize",
			}),
	}

	for _, fn := range extraCommandsFuncs {
		if fn != nil {
			fn(ui, serverCmdUi, runOpts)
		}
	}
}

var extraCommandsFuncs []func(ui, serverCmdUi cli.Ui, runOpts *RunOptions)

// Keep this interface aligned with the interface at internal/clientcache/cmd/daemon/command_wrapper.go
type cacheEnabledCommand interface {
	cli.Command
	BaseCommand() *base.Command
}

// clientCacheWrapper wraps all short lived, non server, command factories.
// The default func is a noop.
var clientCacheWrapper = func(c cacheEnabledCommand) cli.CommandFactory {
	return func() (cli.Command, error) {
		return c, nil
	}
}
