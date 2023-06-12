// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: BUSL-1.1

package cmd

import (
	"github.com/hashicorp/boundary/api"
	"github.com/hashicorp/boundary/api/authtokens"
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

		"authenticate": commandFactoryWrapper(ui,
			&authenticate.Command{
				Command: base.NewCommand(ui),
			}),
		"authenticate password": commandFactoryWrapper(ui,
			&authenticate.PasswordCommand{
				Command: base.NewCommand(ui),
			}),
		"authenticate oidc": commandFactoryWrapper(ui,
			&authenticate.OidcCommand{
				Command: base.NewCommand(ui),
			}),
		"authenticate ldap": commandFactoryWrapper(ui,
			&authenticate.LdapCommand{
				Command: base.NewCommand(ui),
			}),

		"accounts": func() (cli.Command, error) {
			return &accountscmd.Command{
				Command: base.NewCommand(ui, opts...),
			}, nil
		},
		"accounts read": commandFactoryWrapper(ui,
			&accountscmd.Command{
				Command: base.NewCommand(ui),
				Func:    "read",
			}),
		"accounts delete": commandFactoryWrapper(ui,
			&accountscmd.Command{
				Command: base.NewCommand(ui),
				Func:    "delete",
			}),
		"accounts list": commandFactoryWrapper(ui,
			&accountscmd.Command{
				Command: base.NewCommand(ui),
				Func:    "list",
			}),
		"accounts set-password": commandFactoryWrapper(ui,
			&accountscmd.Command{
				Command: base.NewCommand(ui),
				Func:    "set-password",
			}),
		"accounts change-password": commandFactoryWrapper(ui,
			&accountscmd.Command{
				Command: base.NewCommand(ui),
				Func:    "change-password",
			}),
		"accounts create": commandFactoryWrapper(ui,
			&accountscmd.Command{
				Command: base.NewCommand(ui),
				Func:    "create",
			}),
		"accounts create password": commandFactoryWrapper(ui,
			&accountscmd.PasswordCommand{
				Command: base.NewCommand(ui),
				Func:    "create",
			}),
		"accounts create oidc": commandFactoryWrapper(ui,
			&accountscmd.OidcCommand{
				Command: base.NewCommand(ui),
				Func:    "create",
			}),
		"accounts create ldap": commandFactoryWrapper(ui,
			&accountscmd.LdapCommand{
				Command: base.NewCommand(ui),
				Func:    "create",
			}),
		"accounts update": commandFactoryWrapper(ui,
			&accountscmd.Command{
				Command: base.NewCommand(ui),
				Func:    "update",
			}),
		"accounts update password": commandFactoryWrapper(ui,
			&accountscmd.PasswordCommand{
				Command: base.NewCommand(ui),
				Func:    "update",
			}),
		"accounts update oidc": commandFactoryWrapper(ui,
			&accountscmd.OidcCommand{
				Command: base.NewCommand(ui),
				Func:    "update",
			}),
		"accounts update ldap": commandFactoryWrapper(ui,
			&accountscmd.LdapCommand{
				Command: base.NewCommand(ui),
				Func:    "update",
			}),

		"auth-methods": func() (cli.Command, error) {
			return &authmethodscmd.Command{
				Command: base.NewCommand(ui, opts...),
			}, nil
		},
		"auth-methods read": commandFactoryWrapper(ui,
			&authmethodscmd.Command{
				Command: base.NewCommand(ui),
				Func:    "read",
			}),
		"auth-methods delete": commandFactoryWrapper(ui,
			&authmethodscmd.Command{
				Command: base.NewCommand(ui),
				Func:    "delete",
			}),
		"auth-methods list": commandFactoryWrapper(ui,
			&authmethodscmd.Command{
				Command: base.NewCommand(ui),
				Func:    "list",
			}),
		"auth-methods create": commandFactoryWrapper(ui,
			&authmethodscmd.Command{
				Command: base.NewCommand(ui),
				Func:    "create",
			}),
		"auth-methods create password": commandFactoryWrapper(ui,
			&authmethodscmd.PasswordCommand{
				Command: base.NewCommand(ui),
				Func:    "create",
			}),
		"auth-methods create oidc": commandFactoryWrapper(ui,
			&authmethodscmd.OidcCommand{
				Command: base.NewCommand(ui),
				Func:    "create",
			}),
		"auth-methods create ldap": commandFactoryWrapper(ui,
			&authmethodscmd.LdapCommand{
				Command: base.NewCommand(ui),
				Func:    "create",
			}),
		"auth-methods update": commandFactoryWrapper(ui,
			&authmethodscmd.Command{
				Command: base.NewCommand(ui),
				Func:    "update",
			}),
		"auth-methods update password": commandFactoryWrapper(ui,
			&authmethodscmd.PasswordCommand{
				Command: base.NewCommand(ui),
				Func:    "update",
			}),
		"auth-methods update oidc": commandFactoryWrapper(ui,
			&authmethodscmd.OidcCommand{
				Command: base.NewCommand(ui),
				Func:    "update",
			}),
		"auth-methods update ldap": commandFactoryWrapper(ui,
			&authmethodscmd.LdapCommand{
				Command: base.NewCommand(ui),
				Func:    "update",
			}),
		"auth-methods change-state oidc": commandFactoryWrapper(ui,
			&authmethodscmd.OidcCommand{
				Command: base.NewCommand(ui),
				Func:    "change-state",
			}),

		"auth-tokens": func() (cli.Command, error) {
			return &authtokenscmd.Command{
				Command: base.NewCommand(ui, opts...),
			}, nil
		},
		"auth-tokens read": commandFactoryWrapper(ui,
			&authtokenscmd.Command{
				Command: base.NewCommand(ui),
				Func:    "read",
			}),
		"auth-tokens delete": commandFactoryWrapper(ui,
			&authtokenscmd.Command{
				Command: base.NewCommand(ui),
				Func:    "delete",
			}),
		"auth-tokens list": commandFactoryWrapper(ui,
			&authtokenscmd.Command{
				Command: base.NewCommand(ui),
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

		"connect": commandFactoryWrapper(ui,
			&connect.Command{
				Command: base.NewCommand(ui),
				Func:    "connect",
			}),
		"connect http": commandFactoryWrapper(ui,
			&connect.Command{
				Command: base.NewCommand(ui),
				Func:    "http",
			}),
		"connect kube": commandFactoryWrapper(ui,
			&connect.Command{
				Command: base.NewCommand(ui),
				Func:    "kube",
			}),
		"connect postgres": commandFactoryWrapper(ui,
			&connect.Command{
				Command: base.NewCommand(ui),
				Func:    "postgres",
			}),
		"connect rdp": commandFactoryWrapper(ui,
			&connect.Command{
				Command: base.NewCommand(ui),
				Func:    "rdp",
			}),
		"connect ssh": commandFactoryWrapper(ui,
			&connect.Command{
				Command: base.NewCommand(ui),
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
		"credential-libraries read": commandFactoryWrapper(ui,
			&credentiallibrariescmd.Command{
				Command: base.NewCommand(ui),
				Func:    "read",
			}),
		"credential-libraries delete": commandFactoryWrapper(ui,
			&credentiallibrariescmd.Command{
				Command: base.NewCommand(ui),
				Func:    "delete",
			}),
		"credential-libraries list": commandFactoryWrapper(ui,
			&credentiallibrariescmd.Command{
				Command: base.NewCommand(ui),
				Func:    "list",
			}),
		"credential-libraries create": commandFactoryWrapper(ui,
			&credentiallibrariescmd.Command{
				Command: base.NewCommand(ui),
				Func:    "create",
			}),
		"credential-libraries create vault": commandFactoryWrapper(ui,
			&credentiallibrariescmd.VaultCommand{
				Command: base.NewCommand(ui),
				Func:    "create",
			}),
		"credential-libraries create vault-generic": commandFactoryWrapper(ui,
			&credentiallibrariescmd.VaultGenericCommand{
				Command: base.NewCommand(ui),
				Func:    "create",
			}),
		"credential-libraries create vault-ssh-certificate": commandFactoryWrapper(ui,
			&credentiallibrariescmd.VaultSshCertificateCommand{
				Command: base.NewCommand(ui),
				Func:    "create",
			}),
		"credential-libraries update": commandFactoryWrapper(ui,
			&credentiallibrariescmd.Command{
				Command: base.NewCommand(ui),
				Func:    "update",
			}),
		"credential-libraries update vault": commandFactoryWrapper(ui,
			&credentiallibrariescmd.VaultGenericCommand{
				Command: base.NewCommand(ui),
				Func:    "update",
			}),
		"credential-libraries update vault-generic": commandFactoryWrapper(ui,
			&credentiallibrariescmd.VaultGenericCommand{
				Command: base.NewCommand(ui),
				Func:    "update",
			}),
		"credential-libraries update vault-ssh-certificate": commandFactoryWrapper(ui,
			&credentiallibrariescmd.VaultSshCertificateCommand{
				Command: base.NewCommand(ui),
				Func:    "update",
			}),

		"credential-stores": func() (cli.Command, error) {
			return &credentialstorescmd.Command{
				Command: base.NewCommand(ui, opts...),
			}, nil
		},
		"credential-stores read": commandFactoryWrapper(ui,
			&credentialstorescmd.Command{
				Command: base.NewCommand(ui),
				Func:    "read",
			}),
		"credential-stores delete": commandFactoryWrapper(ui,
			&credentialstorescmd.Command{
				Command: base.NewCommand(ui),
				Func:    "delete",
			}),
		"credential-stores list": commandFactoryWrapper(ui,
			&credentialstorescmd.Command{
				Command: base.NewCommand(ui),
				Func:    "list",
			}),
		"credential-stores create": commandFactoryWrapper(ui,
			&credentialstorescmd.Command{
				Command: base.NewCommand(ui),
				Func:    "create",
			}),
		"credential-stores create vault": commandFactoryWrapper(ui,
			&credentialstorescmd.VaultCommand{
				Command: base.NewCommand(ui),
				Func:    "create",
			}),
		"credential-stores create static": commandFactoryWrapper(ui,
			&credentialstorescmd.StaticCommand{
				Command: base.NewCommand(ui),
				Func:    "create",
			}),
		"credential-stores update": commandFactoryWrapper(ui,
			&credentialstorescmd.Command{
				Command: base.NewCommand(ui),
				Func:    "update",
			}),
		"credential-stores update vault": commandFactoryWrapper(ui,
			&credentialstorescmd.VaultCommand{
				Command: base.NewCommand(ui),
				Func:    "update",
			}),
		"credential-stores update static": commandFactoryWrapper(ui,
			&credentialstorescmd.StaticCommand{
				Command: base.NewCommand(ui),
				Func:    "update",
			}),

		"credentials": func() (cli.Command, error) {
			return &credentialscmd.Command{
				Command: base.NewCommand(ui, opts...),
			}, nil
		},
		"credentials read": commandFactoryWrapper(ui,
			&credentialscmd.Command{
				Command: base.NewCommand(ui),
				Func:    "read",
			}),
		"credentials delete": commandFactoryWrapper(ui,
			&credentialscmd.Command{
				Command: base.NewCommand(ui),
				Func:    "delete",
			}),
		"credentials list": commandFactoryWrapper(ui,
			&credentialscmd.Command{
				Command: base.NewCommand(ui),
				Func:    "list",
			}),
		"credentials create": commandFactoryWrapper(ui,
			&credentialscmd.Command{
				Command: base.NewCommand(ui),
				Func:    "create",
			}),
		"credentials create username-password": commandFactoryWrapper(ui,
			&credentialscmd.UsernamePasswordCommand{
				Command: base.NewCommand(ui),
				Func:    "create",
			}),
		"credentials create ssh-private-key": commandFactoryWrapper(ui,
			&credentialscmd.SshPrivateKeyCommand{
				Command: base.NewCommand(ui),
				Func:    "create",
			}),
		"credentials create json": commandFactoryWrapper(ui,
			&credentialscmd.JsonCommand{
				Command: base.NewCommand(ui),
				Func:    "create",
			}),
		"credentials update": commandFactoryWrapper(ui,
			&credentialscmd.Command{
				Command: base.NewCommand(ui),
				Func:    "update",
			}),
		"credentials update username-password": commandFactoryWrapper(ui,
			&credentialscmd.UsernamePasswordCommand{
				Command: base.NewCommand(ui),
				Func:    "update",
			}),
		"credentials update ssh-private-key": commandFactoryWrapper(ui,
			&credentialscmd.SshPrivateKeyCommand{
				Command: base.NewCommand(ui),
				Func:    "update",
			}),
		"credentials update json": commandFactoryWrapper(ui,
			&credentialscmd.JsonCommand{
				Command: base.NewCommand(ui),
				Func:    "update",
			}),

		"daemon": func() (cli.Command, error) {
			return &unsupported.UnsupportedCommand{
				Command:     base.NewCommand(ui),
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
		"groups create": commandFactoryWrapper(ui,
			&groupscmd.Command{
				Command: base.NewCommand(ui),
				Func:    "create",
			}),
		"groups update": commandFactoryWrapper(ui,
			&groupscmd.Command{
				Command: base.NewCommand(ui),
				Func:    "update",
			}),
		"groups read": commandFactoryWrapper(ui,
			&groupscmd.Command{
				Command: base.NewCommand(ui),
				Func:    "read",
			}),
		"groups delete": commandFactoryWrapper(ui,
			&groupscmd.Command{
				Command: base.NewCommand(ui),
				Func:    "delete",
			}),
		"groups list": commandFactoryWrapper(ui,
			&groupscmd.Command{
				Command: base.NewCommand(ui),
				Func:    "list",
			}),
		"groups add-members": commandFactoryWrapper(ui,
			&groupscmd.Command{
				Command: base.NewCommand(ui),
				Func:    "add-members",
			}),
		"groups set-members": commandFactoryWrapper(ui,
			&groupscmd.Command{
				Command: base.NewCommand(ui),
				Func:    "set-members",
			}),
		"groups remove-members": commandFactoryWrapper(ui,
			&groupscmd.Command{
				Command: base.NewCommand(ui),
				Func:    "remove-members",
			}),

		"host-catalogs": func() (cli.Command, error) {
			return &hostcatalogscmd.Command{
				Command: base.NewCommand(ui, opts...),
			}, nil
		},
		"host-catalogs read": commandFactoryWrapper(ui,
			&hostcatalogscmd.Command{
				Command: base.NewCommand(ui),
				Func:    "read",
			}),
		"host-catalogs delete": commandFactoryWrapper(ui,
			&hostcatalogscmd.Command{
				Command: base.NewCommand(ui),
				Func:    "delete",
			}),
		"host-catalogs list": commandFactoryWrapper(ui,
			&hostcatalogscmd.Command{
				Command: base.NewCommand(ui),
				Func:    "list",
			}),
		"host-catalogs create": commandFactoryWrapper(ui,
			&hostcatalogscmd.Command{
				Command: base.NewCommand(ui),
				Func:    "create",
			}),
		"host-catalogs create static": commandFactoryWrapper(ui,
			&hostcatalogscmd.StaticCommand{
				Command: base.NewCommand(ui),
				Func:    "create",
			}),
		"host-catalogs create plugin": commandFactoryWrapper(ui,
			&hostcatalogscmd.PluginCommand{
				Command: base.NewCommand(ui),
				Func:    "create",
			}),
		"host-catalogs update": commandFactoryWrapper(ui,
			&hostcatalogscmd.Command{
				Command: base.NewCommand(ui),
				Func:    "update",
			}),
		"host-catalogs update static": commandFactoryWrapper(ui,
			&hostcatalogscmd.StaticCommand{
				Command: base.NewCommand(ui),
				Func:    "update",
			}),
		"host-catalogs update plugin": commandFactoryWrapper(ui,
			&hostcatalogscmd.PluginCommand{
				Command: base.NewCommand(ui),
				Func:    "update",
			}),

		"host-sets": func() (cli.Command, error) {
			return &hostsetscmd.Command{
				Command: base.NewCommand(ui, opts...),
			}, nil
		},
		"host-sets read": commandFactoryWrapper(ui,
			&hostsetscmd.Command{
				Command: base.NewCommand(ui),
				Func:    "read",
			}),
		"host-sets delete": commandFactoryWrapper(ui,
			&hostsetscmd.Command{
				Command: base.NewCommand(ui),
				Func:    "delete",
			}),
		"host-sets list": commandFactoryWrapper(ui,
			&hostsetscmd.Command{
				Command: base.NewCommand(ui),
				Func:    "list",
			}),
		"host-sets create": commandFactoryWrapper(ui,
			&hostsetscmd.Command{
				Command: base.NewCommand(ui),
				Func:    "create",
			}),
		"host-sets create static": commandFactoryWrapper(ui,
			&hostsetscmd.StaticCommand{
				Command: base.NewCommand(ui),
				Func:    "create",
			}),
		"host-sets create plugin": commandFactoryWrapper(ui,
			&hostsetscmd.PluginCommand{
				Command: base.NewCommand(ui),
				Func:    "create",
			}),
		"host-sets update": commandFactoryWrapper(ui,
			&hostsetscmd.Command{
				Command: base.NewCommand(ui),
				Func:    "update",
			}),
		"host-sets update static": commandFactoryWrapper(ui,
			&hostsetscmd.StaticCommand{
				Command: base.NewCommand(ui),
				Func:    "update",
			}),
		"host-sets update plugin": commandFactoryWrapper(ui,
			&hostsetscmd.PluginCommand{
				Command: base.NewCommand(ui),
				Func:    "update",
			}),
		"host-sets add-hosts": commandFactoryWrapper(ui,
			&hostsetscmd.Command{
				Command: base.NewCommand(ui),
				Func:    "add-hosts",
			}),
		"host-sets remove-hosts": commandFactoryWrapper(ui,
			&hostsetscmd.Command{
				Command: base.NewCommand(ui),
				Func:    "remove-hosts",
			}),
		"host-sets set-hosts": commandFactoryWrapper(ui,
			&hostsetscmd.Command{
				Command: base.NewCommand(ui),
				Func:    "set-hosts",
			}),

		"hosts": func() (cli.Command, error) {
			return &hostscmd.Command{
				Command: base.NewCommand(ui, opts...),
			}, nil
		},
		"hosts read": commandFactoryWrapper(ui,
			&hostscmd.Command{
				Command: base.NewCommand(ui),
				Func:    "read",
			}),
		"hosts delete": commandFactoryWrapper(ui,
			&hostscmd.Command{
				Command: base.NewCommand(ui),
				Func:    "delete",
			}),
		"hosts list": commandFactoryWrapper(ui,
			&hostscmd.Command{
				Command: base.NewCommand(ui),
				Func:    "list",
			}),
		"hosts create": commandFactoryWrapper(ui,
			&hostscmd.Command{
				Command: base.NewCommand(ui),
				Func:    "create",
			}),
		"hosts create static": commandFactoryWrapper(ui,
			&hostscmd.StaticCommand{
				Command: base.NewCommand(ui),
				Func:    "create",
			}),
		"hosts update": commandFactoryWrapper(ui,
			&hostscmd.Command{
				Command: base.NewCommand(ui),
				Func:    "update",
			}),
		"hosts update static": commandFactoryWrapper(ui,
			&hostscmd.StaticCommand{
				Command: base.NewCommand(ui),
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
		"managed-groups read": commandFactoryWrapper(ui,
			&managedgroupscmd.Command{
				Command: base.NewCommand(ui),
				Func:    "read",
			}),
		"managed-groups delete": commandFactoryWrapper(ui,
			&managedgroupscmd.Command{
				Command: base.NewCommand(ui),
				Func:    "delete",
			}),
		"managed-groups list": commandFactoryWrapper(ui,
			&managedgroupscmd.Command{
				Command: base.NewCommand(ui),
				Func:    "list",
			}),
		"managed-groups create": commandFactoryWrapper(ui,
			&managedgroupscmd.Command{
				Command: base.NewCommand(ui),
				Func:    "create",
			}),
		"managed-groups create oidc": commandFactoryWrapper(ui,
			&managedgroupscmd.OidcCommand{
				Command: base.NewCommand(ui),
				Func:    "create",
			}),
		"managed-groups create ldap": commandFactoryWrapper(ui,
			&managedgroupscmd.LdapCommand{
				Command: base.NewCommand(ui),
				Func:    "create",
			}),
		"managed-groups update": commandFactoryWrapper(ui,
			&managedgroupscmd.Command{
				Command: base.NewCommand(ui),
				Func:    "update",
			}),
		"managed-groups update oidc": commandFactoryWrapper(ui,
			&managedgroupscmd.OidcCommand{
				Command: base.NewCommand(ui),
				Func:    "update",
			}),
		"managed-groups update ldap": commandFactoryWrapper(ui,
			&managedgroupscmd.LdapCommand{
				Command: base.NewCommand(ui),
				Func:    "update",
			}),

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
		"roles create": commandFactoryWrapper(ui,
			&rolescmd.Command{
				Command: base.NewCommand(ui),
				Func:    "create",
			}),
		"roles update": commandFactoryWrapper(ui,
			&rolescmd.Command{
				Command: base.NewCommand(ui),
				Func:    "update",
			}),
		"roles read": commandFactoryWrapper(ui,
			&rolescmd.Command{
				Command: base.NewCommand(ui),
				Func:    "read",
			}),
		"roles delete": commandFactoryWrapper(ui,
			&rolescmd.Command{
				Command: base.NewCommand(ui),
				Func:    "delete",
			}),
		"roles list": commandFactoryWrapper(ui,
			&rolescmd.Command{
				Command: base.NewCommand(ui),
				Func:    "list",
			}),
		"roles add-principals": commandFactoryWrapper(ui,
			&rolescmd.Command{
				Command: base.NewCommand(ui),
				Func:    "add-principals",
			}),
		"roles set-principals": commandFactoryWrapper(ui,
			&rolescmd.Command{
				Command: base.NewCommand(ui),
				Func:    "set-principals",
			}),
		"roles remove-principals": commandFactoryWrapper(ui,
			&rolescmd.Command{
				Command: base.NewCommand(ui),
				Func:    "remove-principals",
			}),
		"roles add-grants": commandFactoryWrapper(ui,
			&rolescmd.Command{
				Command: base.NewCommand(ui),
				Func:    "add-grants",
			}),
		"roles set-grants": commandFactoryWrapper(ui,
			&rolescmd.Command{
				Command: base.NewCommand(ui),
				Func:    "set-grants",
			}),
		"roles remove-grants": commandFactoryWrapper(ui,
			&rolescmd.Command{
				Command: base.NewCommand(ui),
				Func:    "remove-grants",
			}),

		"scopes": func() (cli.Command, error) {
			return &scopescmd.Command{
				Command: base.NewCommand(ui, opts...),
			}, nil
		},
		"scopes create": commandFactoryWrapper(ui,
			&scopescmd.Command{
				Command: base.NewCommand(ui),
				Func:    "create",
			}),
		"scopes read": commandFactoryWrapper(ui,
			&scopescmd.Command{
				Command: base.NewCommand(ui),
				Func:    "read",
			}),
		"scopes update": commandFactoryWrapper(ui,
			&scopescmd.Command{
				Command: base.NewCommand(ui),
				Func:    "update",
			}),
		"scopes delete": commandFactoryWrapper(ui,
			&scopescmd.Command{
				Command: base.NewCommand(ui),
				Func:    "delete",
			}),
		"scopes list": commandFactoryWrapper(ui,
			&scopescmd.Command{
				Command: base.NewCommand(ui),
				Func:    "list",
			}),
		"scopes list-keys": commandFactoryWrapper(ui,
			&scopescmd.ListKeysCommand{
				Command: base.NewCommand(ui),
			}),
		"scopes rotate-keys": commandFactoryWrapper(ui,
			&scopescmd.RotateKeysCommand{
				Command: base.NewCommand(ui),
			}),
		"scopes list-key-version-destruction-jobs": commandFactoryWrapper(ui,
			&scopescmd.ListKeyVersionDestructionJobsCommand{
				Command: base.NewCommand(ui),
			}),
		"scopes destroy-key-version": commandFactoryWrapper(ui,
			&scopescmd.DestroyKeyVersionCommand{
				Command: base.NewCommand(ui),
			}),

		"search": func() (cli.Command, error) {
			return &unsupported.UnsupportedCommand{
				Command:     base.NewCommand(ui),
				CommandName: "search",
			}, nil
		},

		"sessions": func() (cli.Command, error) {
			return &sessionscmd.Command{
				Command: base.NewCommand(ui, opts...),
			}, nil
		},
		"sessions read": commandFactoryWrapper(ui,
			&sessionscmd.Command{
				Command: base.NewCommand(ui),
				Func:    "read",
			}),
		"sessions list": commandFactoryWrapper(ui,
			&sessionscmd.Command{
				Command: base.NewCommand(ui),
				Func:    "list",
			}),
		"sessions cancel": commandFactoryWrapper(ui,
			&sessionscmd.Command{
				Command: base.NewCommand(ui),
				Func:    "cancel",
			}),

		"session-recordings": func() (cli.Command, error) {
			return &sessionrecordingscmd.Command{
				Command: base.NewCommand(ui, opts...),
			}, nil
		},
		"session-recordings read": commandFactoryWrapper(ui,
			&sessionrecordingscmd.Command{
				Command: base.NewCommand(ui),
				Func:    "read",
			}),
		"session-recordings list": commandFactoryWrapper(ui,
			&sessionrecordingscmd.Command{
				Command: base.NewCommand(ui),
				Func:    "list",
			}),
		"session-recordings download": commandFactoryWrapper(ui,
			&sessionrecordingscmd.DownloadCommand{
				Command: base.NewCommand(ui),
			}),

		"storage-buckets": func() (cli.Command, error) {
			return &storagebucketscmd.Command{
				Command: base.NewCommand(ui, opts...),
			}, nil
		},
		"storage-buckets read": commandFactoryWrapper(ui,
			&storagebucketscmd.Command{
				Command: base.NewCommand(ui),
				Func:    "read",
			}),
		"storage-buckets delete": commandFactoryWrapper(ui,
			&storagebucketscmd.Command{
				Command: base.NewCommand(ui),
				Func:    "delete",
			}),
		"storage-buckets list": commandFactoryWrapper(ui,
			&storagebucketscmd.Command{
				Command: base.NewCommand(ui),
				Func:    "list",
			}),
		"storage-buckets create": commandFactoryWrapper(ui,
			&storagebucketscmd.Command{
				Command: base.NewCommand(ui),
				Func:    "create",
			}),
		"storage-buckets update": commandFactoryWrapper(ui,
			&storagebucketscmd.Command{
				Command: base.NewCommand(ui),
				Func:    "update",
			}),

		"targets": func() (cli.Command, error) {
			return &targetscmd.Command{
				Command: base.NewCommand(ui, opts...),
			}, nil
		},
		"targets authorize-session": commandFactoryWrapper(ui,
			&targetscmd.Command{
				Command: base.NewCommand(ui),
				Func:    "authorize-session",
			}),
		"targets read": commandFactoryWrapper(ui,
			&targetscmd.Command{
				Command: base.NewCommand(ui),
				Func:    "read",
			}),
		"targets delete": commandFactoryWrapper(ui,
			&targetscmd.Command{
				Command: base.NewCommand(ui),
				Func:    "delete",
			}),
		"targets list": commandFactoryWrapper(ui,
			&targetscmd.Command{
				Command: base.NewCommand(ui),
				Func:    "list",
			}),
		"targets create": commandFactoryWrapper(ui,
			&targetscmd.Command{
				Command: base.NewCommand(ui),
				Func:    "create",
			}),
		"targets create tcp": commandFactoryWrapper(ui,
			&targetscmd.TcpCommand{
				Command: base.NewCommand(ui),
				Func:    "create",
			}),
		"targets create ssh": commandFactoryWrapper(ui,
			&targetscmd.SshCommand{
				Command: base.NewCommand(ui),
				Func:    "create",
			}),
		"targets update": commandFactoryWrapper(ui,
			&targetscmd.Command{
				Command: base.NewCommand(ui),
				Func:    "update",
			}),
		"targets update tcp": commandFactoryWrapper(ui,
			&targetscmd.TcpCommand{
				Command: base.NewCommand(ui),
				Func:    "update",
			}),
		"targets update ssh": commandFactoryWrapper(ui,
			&targetscmd.SshCommand{
				Command: base.NewCommand(ui),
				Func:    "update",
			}),
		"targets add-host-sources": commandFactoryWrapper(ui,
			&targetscmd.Command{
				Command: base.NewCommand(ui),
				Func:    "add-host-sources",
			}),
		"targets remove-host-sources": commandFactoryWrapper(ui,
			&targetscmd.Command{
				Command: base.NewCommand(ui),
				Func:    "remove-host-sources",
			}),
		"targets set-host-sources": commandFactoryWrapper(ui,
			&targetscmd.Command{
				Command: base.NewCommand(ui),
				Func:    "set-host-sources",
			}),
		"targets add-credential-sources": commandFactoryWrapper(ui,
			&targetscmd.Command{
				Command: base.NewCommand(ui),
				Func:    "add-credential-sources",
			}),
		"targets remove-credential-sources": commandFactoryWrapper(ui,
			&targetscmd.Command{
				Command: base.NewCommand(ui),
				Func:    "remove-credential-sources",
			}),
		"targets set-credential-sources": commandFactoryWrapper(ui,
			&targetscmd.Command{
				Command: base.NewCommand(ui),
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
		"users create": commandFactoryWrapper(ui,
			&userscmd.Command{
				Command: base.NewCommand(ui),
				Func:    "create",
			}),
		"users read": commandFactoryWrapper(ui,
			&userscmd.Command{
				Command: base.NewCommand(ui),
				Func:    "read",
			}),
		"users update": commandFactoryWrapper(ui,
			&userscmd.Command{
				Command: base.NewCommand(ui),
				Func:    "update",
			}),
		"users delete": commandFactoryWrapper(ui,
			&userscmd.Command{
				Command: base.NewCommand(ui),
				Func:    "delete",
			}),
		"users list": commandFactoryWrapper(ui,
			&userscmd.Command{
				Command: base.NewCommand(ui),
				Func:    "list",
			}),
		"users add-accounts": commandFactoryWrapper(ui,
			&userscmd.Command{
				Command: base.NewCommand(ui),
				Func:    "add-accounts",
			}),
		"users set-accounts": commandFactoryWrapper(ui,
			&userscmd.Command{
				Command: base.NewCommand(ui),
				Func:    "set-accounts",
			}),
		"users remove-accounts": commandFactoryWrapper(ui,
			&userscmd.Command{
				Command: base.NewCommand(ui),
				Func:    "remove-accounts",
			}),

		"workers": func() (cli.Command, error) {
			return &workerscmd.Command{
				Command: base.NewCommand(ui, opts...),
			}, nil
		},
		"workers create": commandFactoryWrapper(ui,
			&workerscmd.Command{
				Command: base.NewCommand(ui),
				Func:    "create",
			}),
		"workers create worker-led": commandFactoryWrapper(ui,
			&workerscmd.WorkerLedCommand{
				Command: base.NewCommand(ui),
				Func:    "create",
			}),
		"workers create controller-led": commandFactoryWrapper(ui,
			&workerscmd.ControllerLedCommand{
				Command: base.NewCommand(ui),
				Func:    "create",
			}),
		"workers read": commandFactoryWrapper(ui,
			&workerscmd.Command{
				Command: base.NewCommand(ui),
				Func:    "read",
			}),
		"workers update": commandFactoryWrapper(ui,
			&workerscmd.Command{
				Command: base.NewCommand(ui),
				Func:    "update",
			}),
		"workers delete": commandFactoryWrapper(ui,
			&workerscmd.Command{
				Command: base.NewCommand(ui),
				Func:    "delete",
			}),
		"workers list": commandFactoryWrapper(ui,
			&workerscmd.Command{
				Command: base.NewCommand(ui),
				Func:    "list",
			}),
		"workers add-worker-tags": commandFactoryWrapper(ui,
			&workerscmd.Command{
				Command: base.NewCommand(ui),
				Func:    "add-worker-tags",
			}),
		"workers set-worker-tags": commandFactoryWrapper(ui,
			&workerscmd.Command{
				Command: base.NewCommand(ui),
				Func:    "set-worker-tags",
			}),
		"workers remove-worker-tags": commandFactoryWrapper(ui,
			&workerscmd.Command{
				Command: base.NewCommand(ui),
				Func:    "remove-worker-tags",
			}),
		"workers certificate-authority": commandFactoryWrapper(ui,
			&workerscmd.WorkerCACommand{
				Command: base.NewCommand(ui),
			}),
		"workers certificate-authority read": commandFactoryWrapper(ui,
			&workerscmd.WorkerCACommand{
				Command: base.NewCommand(ui),
				Func:    "read",
			}),
		"workers certificate-authority reinitialize": commandFactoryWrapper(ui,
			&workerscmd.WorkerCACommand{
				Command: base.NewCommand(ui),
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

type clientAndTokenProvider interface {
	Client(opt ...base.Option) (*api.Client, error)
	DiscoverKeyringTokenInfo() (string, string, error)
	ReadTokenFromKeyring(keyringType, tokenName string) *authtokens.AuthToken
}

type wrappableCommand interface {
	cli.Command
	clientAndTokenProvider
}

// commandFactoryWrapper wraps all short lived, non server, command factories.
// The default func is a noop.
var commandFactoryWrapper = func(ui cli.Ui, c wrappableCommand) cli.CommandFactory {
	return func() (cli.Command, error) {
		return c, nil
	}
}
