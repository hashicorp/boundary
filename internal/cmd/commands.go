// Copyright IBM Corp. 2020, 2025
// SPDX-License-Identifier: BUSL-1.1

package cmd

import (
	"github.com/hashicorp/boundary/internal/cmd/base"
	"github.com/hashicorp/boundary/internal/cmd/commands/accountscmd"
	"github.com/hashicorp/boundary/internal/cmd/commands/aliasescmd"
	"github.com/hashicorp/boundary/internal/cmd/commands/authenticate"
	"github.com/hashicorp/boundary/internal/cmd/commands/authmethodscmd"
	"github.com/hashicorp/boundary/internal/cmd/commands/authtokenscmd"
	"github.com/hashicorp/boundary/internal/cmd/commands/billingcmd"
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
	"github.com/hashicorp/boundary/internal/cmd/wrapper"

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

		"authenticate": wrapper.Wrap(func() wrapper.WrappableCommand {
			return &authenticate.Command{
				Command: base.NewCommand(ui, opts...),
			}
		}),
		"authenticate password": wrapper.Wrap(func() wrapper.WrappableCommand {
			return &authenticate.PasswordCommand{
				Command: base.NewCommand(ui, opts...),
			}
		}),
		"authenticate oidc": wrapper.Wrap(func() wrapper.WrappableCommand {
			return &authenticate.OidcCommand{
				Command: base.NewCommand(ui, opts...),
			}
		}),
		"authenticate ldap": wrapper.Wrap(func() wrapper.WrappableCommand {
			return &authenticate.LdapCommand{
				Command: base.NewCommand(ui, opts...),
			}
		}),

		"accounts": func() (cli.Command, error) {
			return &accountscmd.Command{
				Command: base.NewCommand(ui, opts...),
			}, nil
		},
		"accounts read": wrapper.Wrap(func() wrapper.WrappableCommand {
			return &accountscmd.Command{
				Command: base.NewCommand(ui, opts...),
				Func:    "read",
			}
		}),
		"accounts delete": wrapper.Wrap(func() wrapper.WrappableCommand {
			return &accountscmd.Command{
				Command: base.NewCommand(ui, opts...),
				Func:    "delete",
			}
		}),
		"accounts list": wrapper.Wrap(func() wrapper.WrappableCommand {
			return &accountscmd.Command{
				Command: base.NewCommand(ui, opts...),
				Func:    "list",
			}
		}),
		"accounts set-password": wrapper.Wrap(func() wrapper.WrappableCommand {
			return &accountscmd.Command{
				Command: base.NewCommand(ui, opts...),
				Func:    "set-password",
			}
		}),
		"accounts change-password": wrapper.Wrap(func() wrapper.WrappableCommand {
			return &accountscmd.Command{
				Command: base.NewCommand(ui, opts...),
				Func:    "change-password",
			}
		}),
		"accounts create": wrapper.Wrap(func() wrapper.WrappableCommand {
			return &accountscmd.Command{
				Command: base.NewCommand(ui, opts...),
				Func:    "create",
			}
		}),
		"accounts create password": wrapper.Wrap(func() wrapper.WrappableCommand {
			return &accountscmd.PasswordCommand{
				Command: base.NewCommand(ui, opts...),
				Func:    "create",
			}
		}),
		"accounts create oidc": wrapper.Wrap(func() wrapper.WrappableCommand {
			return &accountscmd.OidcCommand{
				Command: base.NewCommand(ui, opts...),
				Func:    "create",
			}
		}),
		"accounts create ldap": wrapper.Wrap(func() wrapper.WrappableCommand {
			return &accountscmd.LdapCommand{
				Command: base.NewCommand(ui, opts...),
				Func:    "create",
			}
		}),
		"accounts update": wrapper.Wrap(func() wrapper.WrappableCommand {
			return &accountscmd.Command{
				Command: base.NewCommand(ui, opts...),
				Func:    "update",
			}
		}),
		"accounts update password": wrapper.Wrap(func() wrapper.WrappableCommand {
			return &accountscmd.PasswordCommand{
				Command: base.NewCommand(ui, opts...),
				Func:    "update",
			}
		}),
		"accounts update oidc": wrapper.Wrap(func() wrapper.WrappableCommand {
			return &accountscmd.OidcCommand{
				Command: base.NewCommand(ui, opts...),
				Func:    "update",
			}
		}),
		"accounts update ldap": wrapper.Wrap(func() wrapper.WrappableCommand {
			return &accountscmd.LdapCommand{
				Command: base.NewCommand(ui, opts...),
				Func:    "update",
			}
		}),

		"aliases": func() (cli.Command, error) {
			return &aliasescmd.Command{
				Command: base.NewCommand(ui, opts...),
			}, nil
		},
		"aliases read": wrapper.Wrap(func() wrapper.WrappableCommand {
			return &aliasescmd.Command{
				Command: base.NewCommand(ui, opts...),
				Func:    "read",
			}
		}),
		"aliases delete": wrapper.Wrap(func() wrapper.WrappableCommand {
			return &aliasescmd.Command{
				Command: base.NewCommand(ui, opts...),
				Func:    "delete",
			}
		}),
		"aliases list": wrapper.Wrap(func() wrapper.WrappableCommand {
			return &aliasescmd.Command{
				Command: base.NewCommand(ui, opts...),
				Func:    "list",
			}
		}),
		"aliases create": wrapper.Wrap(func() wrapper.WrappableCommand {
			return &aliasescmd.Command{
				Command: base.NewCommand(ui, opts...),
				Func:    "create",
			}
		}),
		"aliases update": wrapper.Wrap(func() wrapper.WrappableCommand {
			return &aliasescmd.Command{
				Command: base.NewCommand(ui, opts...),
				Func:    "update",
			}
		}),
		"aliases create target": wrapper.Wrap(func() wrapper.WrappableCommand {
			return &aliasescmd.TargetCommand{
				Command: base.NewCommand(ui, opts...),
				Func:    "create",
			}
		}),
		"aliases update target": wrapper.Wrap(func() wrapper.WrappableCommand {
			return &aliasescmd.TargetCommand{
				Command: base.NewCommand(ui, opts...),
				Func:    "update",
			}
		}),

		"auth-methods": func() (cli.Command, error) {
			return &authmethodscmd.Command{
				Command: base.NewCommand(ui, opts...),
			}, nil
		},
		"auth-methods read": wrapper.Wrap(func() wrapper.WrappableCommand {
			return &authmethodscmd.Command{
				Command: base.NewCommand(ui, opts...),
				Func:    "read",
			}
		}),
		"auth-methods delete": wrapper.Wrap(func() wrapper.WrappableCommand {
			return &authmethodscmd.Command{
				Command: base.NewCommand(ui, opts...),
				Func:    "delete",
			}
		}),
		"auth-methods list": wrapper.Wrap(func() wrapper.WrappableCommand {
			return &authmethodscmd.Command{
				Command: base.NewCommand(ui, opts...),
				Func:    "list",
			}
		}),
		"auth-methods create": wrapper.Wrap(func() wrapper.WrappableCommand {
			return &authmethodscmd.Command{
				Command: base.NewCommand(ui, opts...),
				Func:    "create",
			}
		}),
		"auth-methods create password": wrapper.Wrap(func() wrapper.WrappableCommand {
			return &authmethodscmd.PasswordCommand{
				Command: base.NewCommand(ui, opts...),
				Func:    "create",
			}
		}),
		"auth-methods create oidc": wrapper.Wrap(func() wrapper.WrappableCommand {
			return &authmethodscmd.OidcCommand{
				Command: base.NewCommand(ui, opts...),
				Func:    "create",
			}
		}),
		"auth-methods create ldap": wrapper.Wrap(func() wrapper.WrappableCommand {
			return &authmethodscmd.LdapCommand{
				Command: base.NewCommand(ui, opts...),
				Func:    "create",
			}
		}),
		"auth-methods update": wrapper.Wrap(func() wrapper.WrappableCommand {
			return &authmethodscmd.Command{
				Command: base.NewCommand(ui, opts...),
				Func:    "update",
			}
		}),
		"auth-methods update password": wrapper.Wrap(func() wrapper.WrappableCommand {
			return &authmethodscmd.PasswordCommand{
				Command: base.NewCommand(ui, opts...),
				Func:    "update",
			}
		}),
		"auth-methods update oidc": wrapper.Wrap(func() wrapper.WrappableCommand {
			return &authmethodscmd.OidcCommand{
				Command: base.NewCommand(ui, opts...),
				Func:    "update",
			}
		}),
		"auth-methods update ldap": wrapper.Wrap(func() wrapper.WrappableCommand {
			return &authmethodscmd.LdapCommand{
				Command: base.NewCommand(ui, opts...),
				Func:    "update",
			}
		}),
		"auth-methods change-state oidc": wrapper.Wrap(func() wrapper.WrappableCommand {
			return &authmethodscmd.OidcCommand{
				Command: base.NewCommand(ui, opts...),
				Func:    "change-state",
			}
		}),

		"auth-tokens": func() (cli.Command, error) {
			return &authtokenscmd.Command{
				Command: base.NewCommand(ui, opts...),
			}, nil
		},
		"auth-tokens read": wrapper.Wrap(func() wrapper.WrappableCommand {
			return &authtokenscmd.Command{
				Command: base.NewCommand(ui, opts...),
				Func:    "read",
			}
		}),
		"auth-tokens delete": wrapper.Wrap(func() wrapper.WrappableCommand {
			return &authtokenscmd.Command{
				Command: base.NewCommand(ui, opts...),
				Func:    "delete",
			}
		}),
		"auth-tokens list": wrapper.Wrap(func() wrapper.WrappableCommand {
			return &authtokenscmd.Command{
				Command: base.NewCommand(ui, opts...),
				Func:    "list",
			}
		}),

		"billing": func() (cli.Command, error) {
			return &billingcmd.Command{
				Command: base.NewCommand(ui, opts...),
			}, nil
		},
		"billing monthly-active-users": wrapper.Wrap(func() wrapper.WrappableCommand {
			return &billingcmd.Command{
				Command: base.NewCommand(ui),
				Func:    "monthly-active-users",
			}
		}),

		"client-agent": func() (cli.Command, error) {
			return &unsupported.UnsupportedCommand{
				Command:     base.NewCommand(ui, opts...),
				CommandName: "client-agent",
			}, nil
		},

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

		"connect": wrapper.Wrap(func() wrapper.WrappableCommand {
			return &connect.Command{
				Command: base.NewCommand(ui, opts...),
				Func:    "connect",
			}
		}),
		"connect http": wrapper.Wrap(func() wrapper.WrappableCommand {
			return &connect.Command{
				Command: base.NewCommand(ui, opts...),
				Func:    "http",
			}
		}),
		"connect kube": wrapper.Wrap(func() wrapper.WrappableCommand {
			return &connect.Command{
				Command: base.NewCommand(ui, opts...),
				Func:    "kube",
			}
		}),
		"connect postgres": wrapper.Wrap(func() wrapper.WrappableCommand {
			return &connect.Command{
				Command: base.NewCommand(ui, opts...),
				Func:    "postgres",
			}
		}),
		"connect mysql": wrapper.Wrap(func() wrapper.WrappableCommand {
			return &connect.Command{
				Command: base.NewCommand(ui, opts...),
				Func:    "mysql",
			}
		}),
		"connect mongo": wrapper.Wrap(func() wrapper.WrappableCommand {
			return &connect.Command{
				Command: base.NewCommand(ui, opts...),
				Func:    "mongo",
			}
		}),
		"connect cassandra": wrapper.Wrap(func() wrapper.WrappableCommand {
			return &connect.Command{
				Command: base.NewCommand(ui, opts...),
				Func:    "cassandra",
			}
		}),
		"connect redis": wrapper.Wrap(func() wrapper.WrappableCommand {
			return &connect.Command{
				Command: base.NewCommand(ui, opts...),
				Func:    "redis",
			}
		}),
		"connect rdp": wrapper.Wrap(func() wrapper.WrappableCommand {
			return &connect.Command{
				Command: base.NewCommand(ui, opts...),
				Func:    "rdp",
			}
		}),
		"connect ssh": wrapper.Wrap(func() wrapper.WrappableCommand {
			return &connect.Command{
				Command: base.NewCommand(ui, opts...),
				Func:    "ssh",
			}
		}),

		"credential-libraries": func() (cli.Command, error) {
			return &credentiallibrariescmd.Command{
				Command: base.NewCommand(ui, opts...),
			}, nil
		},
		"credential-libraries read": wrapper.Wrap(func() wrapper.WrappableCommand {
			return &credentiallibrariescmd.Command{
				Command: base.NewCommand(ui, opts...),
				Func:    "read",
			}
		}),
		"credential-libraries delete": wrapper.Wrap(func() wrapper.WrappableCommand {
			return &credentiallibrariescmd.Command{
				Command: base.NewCommand(ui, opts...),
				Func:    "delete",
			}
		}),
		"credential-libraries list": wrapper.Wrap(func() wrapper.WrappableCommand {
			return &credentiallibrariescmd.Command{
				Command: base.NewCommand(ui, opts...),
				Func:    "list",
			}
		}),
		"credential-libraries create": wrapper.Wrap(func() wrapper.WrappableCommand {
			return &credentiallibrariescmd.Command{
				Command: base.NewCommand(ui, opts...),
				Func:    "create",
			}
		}),
		"credential-libraries create vault": wrapper.Wrap(func() wrapper.WrappableCommand {
			return &credentiallibrariescmd.VaultCommand{
				Command: base.NewCommand(ui, opts...),
				Func:    "create",
			}
		}),
		"credential-libraries create vault-generic": wrapper.Wrap(func() wrapper.WrappableCommand {
			return &credentiallibrariescmd.VaultGenericCommand{
				Command: base.NewCommand(ui, opts...),
				Func:    "create",
			}
		}),
		"credential-libraries create vault-ssh-certificate": wrapper.Wrap(func() wrapper.WrappableCommand {
			return &credentiallibrariescmd.VaultSshCertificateCommand{
				Command: base.NewCommand(ui, opts...),
				Func:    "create",
			}
		}),
		"credential-libraries create vault-ldap": wrapper.Wrap(func() wrapper.WrappableCommand {
			return &credentiallibrariescmd.VaultLdapCommand{
				Command: base.NewCommand(ui, opts...),
				Func:    "create",
			}
		}),
		"credential-libraries update": wrapper.Wrap(func() wrapper.WrappableCommand {
			return &credentiallibrariescmd.Command{
				Command: base.NewCommand(ui, opts...),
				Func:    "update",
			}
		}),
		"credential-libraries update vault": wrapper.Wrap(func() wrapper.WrappableCommand {
			return &credentiallibrariescmd.VaultGenericCommand{
				Command: base.NewCommand(ui, opts...),
				Func:    "update",
			}
		}),
		"credential-libraries update vault-generic": wrapper.Wrap(func() wrapper.WrappableCommand {
			return &credentiallibrariescmd.VaultGenericCommand{
				Command: base.NewCommand(ui, opts...),
				Func:    "update",
			}
		}),
		"credential-libraries update vault-ssh-certificate": wrapper.Wrap(func() wrapper.WrappableCommand {
			return &credentiallibrariescmd.VaultSshCertificateCommand{
				Command: base.NewCommand(ui, opts...),
				Func:    "update",
			}
		}),
		"credential-libraries update vault-ldap": wrapper.Wrap(func() wrapper.WrappableCommand {
			return &credentiallibrariescmd.VaultLdapCommand{
				Command: base.NewCommand(ui, opts...),
				Func:    "update",
			}
		}),

		"credential-stores": func() (cli.Command, error) {
			return &credentialstorescmd.Command{
				Command: base.NewCommand(ui, opts...),
			}, nil
		},
		"credential-stores read": wrapper.Wrap(func() wrapper.WrappableCommand {
			return &credentialstorescmd.Command{
				Command: base.NewCommand(ui, opts...),
				Func:    "read",
			}
		}),
		"credential-stores delete": wrapper.Wrap(func() wrapper.WrappableCommand {
			return &credentialstorescmd.Command{
				Command: base.NewCommand(ui, opts...),
				Func:    "delete",
			}
		}),
		"credential-stores list": wrapper.Wrap(func() wrapper.WrappableCommand {
			return &credentialstorescmd.Command{
				Command: base.NewCommand(ui, opts...),
				Func:    "list",
			}
		}),
		"credential-stores create": wrapper.Wrap(func() wrapper.WrappableCommand {
			return &credentialstorescmd.Command{
				Command: base.NewCommand(ui, opts...),
				Func:    "create",
			}
		}),
		"credential-stores create vault": wrapper.Wrap(func() wrapper.WrappableCommand {
			return &credentialstorescmd.VaultCommand{
				Command: base.NewCommand(ui, opts...),
				Func:    "create",
			}
		}),
		"credential-stores create static": wrapper.Wrap(func() wrapper.WrappableCommand {
			return &credentialstorescmd.StaticCommand{
				Command: base.NewCommand(ui, opts...),
				Func:    "create",
			}
		}),
		"credential-stores update": wrapper.Wrap(func() wrapper.WrappableCommand {
			return &credentialstorescmd.Command{
				Command: base.NewCommand(ui, opts...),
				Func:    "update",
			}
		}),
		"credential-stores update vault": wrapper.Wrap(func() wrapper.WrappableCommand {
			return &credentialstorescmd.VaultCommand{
				Command: base.NewCommand(ui, opts...),
				Func:    "update",
			}
		}),
		"credential-stores update static": wrapper.Wrap(func() wrapper.WrappableCommand {
			return &credentialstorescmd.StaticCommand{
				Command: base.NewCommand(ui, opts...),
				Func:    "update",
			}
		}),

		"credentials": func() (cli.Command, error) {
			return &credentialscmd.Command{
				Command: base.NewCommand(ui, opts...),
			}, nil
		},
		"credentials read": wrapper.Wrap(func() wrapper.WrappableCommand {
			return &credentialscmd.Command{
				Command: base.NewCommand(ui, opts...),
				Func:    "read",
			}
		}),
		"credentials delete": wrapper.Wrap(func() wrapper.WrappableCommand {
			return &credentialscmd.Command{
				Command: base.NewCommand(ui, opts...),
				Func:    "delete",
			}
		}),
		"credentials list": wrapper.Wrap(func() wrapper.WrappableCommand {
			return &credentialscmd.Command{
				Command: base.NewCommand(ui, opts...),
				Func:    "list",
			}
		}),
		"credentials create": wrapper.Wrap(func() wrapper.WrappableCommand {
			return &credentialscmd.Command{
				Command: base.NewCommand(ui, opts...),
				Func:    "create",
			}
		}),
		"credentials create password": wrapper.Wrap(func() wrapper.WrappableCommand {
			return &credentialscmd.PasswordCommand{
				Command: base.NewCommand(ui, opts...),
				Func:    "create",
			}
		}),
		"credentials create username-password": wrapper.Wrap(func() wrapper.WrappableCommand {
			return &credentialscmd.UsernamePasswordCommand{
				Command: base.NewCommand(ui, opts...),
				Func:    "create",
			}
		}),
		"credentials create username-password-domain": wrapper.Wrap(func() wrapper.WrappableCommand {
			return &credentialscmd.UsernamePasswordDomainCommand{
				Command: base.NewCommand(ui, opts...),
				Func:    "create",
			}
		}),
		"credentials create ssh-private-key": wrapper.Wrap(func() wrapper.WrappableCommand {
			return &credentialscmd.SshPrivateKeyCommand{
				Command: base.NewCommand(ui, opts...),
				Func:    "create",
			}
		}),
		"credentials create json": wrapper.Wrap(func() wrapper.WrappableCommand {
			return &credentialscmd.JsonCommand{
				Command: base.NewCommand(ui, opts...),
				Func:    "create",
			}
		}),
		"credentials update": wrapper.Wrap(func() wrapper.WrappableCommand {
			return &credentialscmd.Command{
				Command: base.NewCommand(ui, opts...),
				Func:    "update",
			}
		}),
		"credentials update password": wrapper.Wrap(func() wrapper.WrappableCommand {
			return &credentialscmd.PasswordCommand{
				Command: base.NewCommand(ui, opts...),
				Func:    "update",
			}
		}),
		"credentials update username-password": wrapper.Wrap(func() wrapper.WrappableCommand {
			return &credentialscmd.UsernamePasswordCommand{
				Command: base.NewCommand(ui, opts...),
				Func:    "update",
			}
		}),
		"credentials update username-password-domain": wrapper.Wrap(func() wrapper.WrappableCommand {
			return &credentialscmd.UsernamePasswordDomainCommand{
				Command: base.NewCommand(ui, opts...),
				Func:    "update",
			}
		}),
		"credentials update ssh-private-key": wrapper.Wrap(func() wrapper.WrappableCommand {
			return &credentialscmd.SshPrivateKeyCommand{
				Command: base.NewCommand(ui, opts...),
				Func:    "update",
			}
		}),
		"credentials update json": wrapper.Wrap(func() wrapper.WrappableCommand {
			return &credentialscmd.JsonCommand{
				Command: base.NewCommand(ui, opts...),
				Func:    "update",
			}
		}),

		"daemon": func() (cli.Command, error) {
			return &unsupported.UnsupportedCommand{
				Command:     base.NewCommand(ui, opts...),
				CommandName: "daemon",
			}, nil
		},

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
		"groups create": wrapper.Wrap(func() wrapper.WrappableCommand {
			return &groupscmd.Command{
				Command: base.NewCommand(ui, opts...),
				Func:    "create",
			}
		}),
		"groups update": wrapper.Wrap(func() wrapper.WrappableCommand {
			return &groupscmd.Command{
				Command: base.NewCommand(ui, opts...),
				Func:    "update",
			}
		}),
		"groups read": wrapper.Wrap(func() wrapper.WrappableCommand {
			return &groupscmd.Command{
				Command: base.NewCommand(ui, opts...),
				Func:    "read",
			}
		}),
		"groups delete": wrapper.Wrap(func() wrapper.WrappableCommand {
			return &groupscmd.Command{
				Command: base.NewCommand(ui, opts...),
				Func:    "delete",
			}
		}),
		"groups list": wrapper.Wrap(func() wrapper.WrappableCommand {
			return &groupscmd.Command{
				Command: base.NewCommand(ui, opts...),
				Func:    "list",
			}
		}),
		"groups add-members": wrapper.Wrap(func() wrapper.WrappableCommand {
			return &groupscmd.Command{
				Command: base.NewCommand(ui, opts...),
				Func:    "add-members",
			}
		}),
		"groups set-members": wrapper.Wrap(func() wrapper.WrappableCommand {
			return &groupscmd.Command{
				Command: base.NewCommand(ui, opts...),
				Func:    "set-members",
			}
		}),
		"groups remove-members": wrapper.Wrap(func() wrapper.WrappableCommand {
			return &groupscmd.Command{
				Command: base.NewCommand(ui, opts...),
				Func:    "remove-members",
			}
		}),

		"host-catalogs": func() (cli.Command, error) {
			return &hostcatalogscmd.Command{
				Command: base.NewCommand(ui, opts...),
			}, nil
		},
		"host-catalogs read": wrapper.Wrap(func() wrapper.WrappableCommand {
			return &hostcatalogscmd.Command{
				Command: base.NewCommand(ui, opts...),
				Func:    "read",
			}
		}),
		"host-catalogs delete": wrapper.Wrap(func() wrapper.WrappableCommand {
			return &hostcatalogscmd.Command{
				Command: base.NewCommand(ui, opts...),
				Func:    "delete",
			}
		}),
		"host-catalogs list": wrapper.Wrap(func() wrapper.WrappableCommand {
			return &hostcatalogscmd.Command{
				Command: base.NewCommand(ui, opts...),
				Func:    "list",
			}
		}),
		"host-catalogs create": wrapper.Wrap(func() wrapper.WrappableCommand {
			return &hostcatalogscmd.Command{
				Command: base.NewCommand(ui, opts...),
				Func:    "create",
			}
		}),
		"host-catalogs create static": wrapper.Wrap(func() wrapper.WrappableCommand {
			return &hostcatalogscmd.StaticCommand{
				Command: base.NewCommand(ui, opts...),
				Func:    "create",
			}
		}),
		"host-catalogs create plugin": wrapper.Wrap(func() wrapper.WrappableCommand {
			return &hostcatalogscmd.PluginCommand{
				Command: base.NewCommand(ui, opts...),
				Func:    "create",
			}
		}),
		"host-catalogs update": wrapper.Wrap(func() wrapper.WrappableCommand {
			return &hostcatalogscmd.Command{
				Command: base.NewCommand(ui, opts...),
				Func:    "update",
			}
		}),
		"host-catalogs update static": wrapper.Wrap(func() wrapper.WrappableCommand {
			return &hostcatalogscmd.StaticCommand{
				Command: base.NewCommand(ui, opts...),
				Func:    "update",
			}
		}),
		"host-catalogs update plugin": wrapper.Wrap(func() wrapper.WrappableCommand {
			return &hostcatalogscmd.PluginCommand{
				Command: base.NewCommand(ui, opts...),
				Func:    "update",
			}
		}),

		"host-sets": func() (cli.Command, error) {
			return &hostsetscmd.Command{
				Command: base.NewCommand(ui, opts...),
			}, nil
		},
		"host-sets read": wrapper.Wrap(func() wrapper.WrappableCommand {
			return &hostsetscmd.Command{
				Command: base.NewCommand(ui, opts...),
				Func:    "read",
			}
		}),
		"host-sets delete": wrapper.Wrap(func() wrapper.WrappableCommand {
			return &hostsetscmd.Command{
				Command: base.NewCommand(ui, opts...),
				Func:    "delete",
			}
		}),
		"host-sets list": wrapper.Wrap(func() wrapper.WrappableCommand {
			return &hostsetscmd.Command{
				Command: base.NewCommand(ui, opts...),
				Func:    "list",
			}
		}),
		"host-sets create": wrapper.Wrap(func() wrapper.WrappableCommand {
			return &hostsetscmd.Command{
				Command: base.NewCommand(ui, opts...),
				Func:    "create",
			}
		}),
		"host-sets create static": wrapper.Wrap(func() wrapper.WrappableCommand {
			return &hostsetscmd.StaticCommand{
				Command: base.NewCommand(ui, opts...),
				Func:    "create",
			}
		}),
		"host-sets create plugin": wrapper.Wrap(func() wrapper.WrappableCommand {
			return &hostsetscmd.PluginCommand{
				Command: base.NewCommand(ui, opts...),
				Func:    "create",
			}
		}),
		"host-sets update": wrapper.Wrap(func() wrapper.WrappableCommand {
			return &hostsetscmd.Command{
				Command: base.NewCommand(ui, opts...),
				Func:    "update",
			}
		}),
		"host-sets update static": wrapper.Wrap(func() wrapper.WrappableCommand {
			return &hostsetscmd.StaticCommand{
				Command: base.NewCommand(ui, opts...),
				Func:    "update",
			}
		}),
		"host-sets update plugin": wrapper.Wrap(func() wrapper.WrappableCommand {
			return &hostsetscmd.PluginCommand{
				Command: base.NewCommand(ui, opts...),
				Func:    "update",
			}
		}),
		"host-sets add-hosts": wrapper.Wrap(func() wrapper.WrappableCommand {
			return &hostsetscmd.Command{
				Command: base.NewCommand(ui, opts...),
				Func:    "add-hosts",
			}
		}),
		"host-sets remove-hosts": wrapper.Wrap(func() wrapper.WrappableCommand {
			return &hostsetscmd.Command{
				Command: base.NewCommand(ui, opts...),
				Func:    "remove-hosts",
			}
		}),
		"host-sets set-hosts": wrapper.Wrap(func() wrapper.WrappableCommand {
			return &hostsetscmd.Command{
				Command: base.NewCommand(ui, opts...),
				Func:    "set-hosts",
			}
		}),

		"hosts": func() (cli.Command, error) {
			return &hostscmd.Command{
				Command: base.NewCommand(ui, opts...),
			}, nil
		},
		"hosts read": wrapper.Wrap(func() wrapper.WrappableCommand {
			return &hostscmd.Command{
				Command: base.NewCommand(ui, opts...),
				Func:    "read",
			}
		}),
		"hosts delete": wrapper.Wrap(func() wrapper.WrappableCommand {
			return &hostscmd.Command{
				Command: base.NewCommand(ui, opts...),
				Func:    "delete",
			}
		}),
		"hosts list": wrapper.Wrap(func() wrapper.WrappableCommand {
			return &hostscmd.Command{
				Command: base.NewCommand(ui, opts...),
				Func:    "list",
			}
		}),
		"hosts create": wrapper.Wrap(func() wrapper.WrappableCommand {
			return &hostscmd.Command{
				Command: base.NewCommand(ui, opts...),
				Func:    "create",
			}
		}),
		"hosts create static": wrapper.Wrap(func() wrapper.WrappableCommand {
			return &hostscmd.StaticCommand{
				Command: base.NewCommand(ui, opts...),
				Func:    "create",
			}
		}),
		"hosts update": wrapper.Wrap(func() wrapper.WrappableCommand {
			return &hostscmd.Command{
				Command: base.NewCommand(ui, opts...),
				Func:    "update",
			}
		}),
		"hosts update static": wrapper.Wrap(func() wrapper.WrappableCommand {
			return &hostscmd.StaticCommand{
				Command: base.NewCommand(ui, opts...),
				Func:    "update",
			}
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
		"managed-groups read": wrapper.Wrap(func() wrapper.WrappableCommand {
			return &managedgroupscmd.Command{
				Command: base.NewCommand(ui, opts...),
				Func:    "read",
			}
		}),
		"managed-groups delete": wrapper.Wrap(func() wrapper.WrappableCommand {
			return &managedgroupscmd.Command{
				Command: base.NewCommand(ui, opts...),
				Func:    "delete",
			}
		}),
		"managed-groups list": wrapper.Wrap(func() wrapper.WrappableCommand {
			return &managedgroupscmd.Command{
				Command: base.NewCommand(ui, opts...),
				Func:    "list",
			}
		}),
		"managed-groups create": wrapper.Wrap(func() wrapper.WrappableCommand {
			return &managedgroupscmd.Command{
				Command: base.NewCommand(ui, opts...),
				Func:    "create",
			}
		}),
		"managed-groups create oidc": wrapper.Wrap(func() wrapper.WrappableCommand {
			return &managedgroupscmd.OidcCommand{
				Command: base.NewCommand(ui, opts...),
				Func:    "create",
			}
		}),
		"managed-groups create ldap": wrapper.Wrap(func() wrapper.WrappableCommand {
			return &managedgroupscmd.LdapCommand{
				Command: base.NewCommand(ui, opts...),
				Func:    "create",
			}
		}),
		"managed-groups update": wrapper.Wrap(func() wrapper.WrappableCommand {
			return &managedgroupscmd.Command{
				Command: base.NewCommand(ui, opts...),
				Func:    "update",
			}
		}),
		"managed-groups update oidc": wrapper.Wrap(func() wrapper.WrappableCommand {
			return &managedgroupscmd.OidcCommand{
				Command: base.NewCommand(ui, opts...),
				Func:    "update",
			}
		}),
		"managed-groups update ldap": wrapper.Wrap(func() wrapper.WrappableCommand {
			return &managedgroupscmd.LdapCommand{
				Command: base.NewCommand(ui, opts...),
				Func:    "update",
			}
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
		"roles create": wrapper.Wrap(func() wrapper.WrappableCommand {
			return &rolescmd.Command{
				Command: base.NewCommand(ui, opts...),
				Func:    "create",
			}
		}),
		"roles update": wrapper.Wrap(func() wrapper.WrappableCommand {
			return &rolescmd.Command{
				Command: base.NewCommand(ui, opts...),
				Func:    "update",
			}
		}),
		"roles read": wrapper.Wrap(func() wrapper.WrappableCommand {
			return &rolescmd.Command{
				Command: base.NewCommand(ui, opts...),
				Func:    "read",
			}
		}),
		"roles delete": wrapper.Wrap(func() wrapper.WrappableCommand {
			return &rolescmd.Command{
				Command: base.NewCommand(ui, opts...),
				Func:    "delete",
			}
		}),
		"roles list": wrapper.Wrap(func() wrapper.WrappableCommand {
			return &rolescmd.Command{
				Command: base.NewCommand(ui, opts...),
				Func:    "list",
			}
		}),
		"roles add-principals": wrapper.Wrap(func() wrapper.WrappableCommand {
			return &rolescmd.Command{
				Command: base.NewCommand(ui, opts...),
				Func:    "add-principals",
			}
		}),
		"roles set-principals": wrapper.Wrap(func() wrapper.WrappableCommand {
			return &rolescmd.Command{
				Command: base.NewCommand(ui, opts...),
				Func:    "set-principals",
			}
		}),
		"roles remove-principals": wrapper.Wrap(func() wrapper.WrappableCommand {
			return &rolescmd.Command{
				Command: base.NewCommand(ui, opts...),
				Func:    "remove-principals",
			}
		}),
		"roles add-grants": wrapper.Wrap(func() wrapper.WrappableCommand {
			return &rolescmd.Command{
				Command: base.NewCommand(ui, opts...),
				Func:    "add-grants",
			}
		}),
		"roles set-grants": wrapper.Wrap(func() wrapper.WrappableCommand {
			return &rolescmd.Command{
				Command: base.NewCommand(ui, opts...),
				Func:    "set-grants",
			}
		}),
		"roles remove-grants": wrapper.Wrap(func() wrapper.WrappableCommand {
			return &rolescmd.Command{
				Command: base.NewCommand(ui, opts...),
				Func:    "remove-grants",
			}
		}),
		"roles add-grant-scopes": wrapper.Wrap(func() wrapper.WrappableCommand {
			return &rolescmd.Command{
				Command: base.NewCommand(ui, opts...),
				Func:    "add-grant-scopes",
			}
		}),
		"roles set-grant-scopes": wrapper.Wrap(func() wrapper.WrappableCommand {
			return &rolescmd.Command{
				Command: base.NewCommand(ui, opts...),
				Func:    "set-grant-scopes",
			}
		}),
		"roles remove-grant-scopes": wrapper.Wrap(func() wrapper.WrappableCommand {
			return &rolescmd.Command{
				Command: base.NewCommand(ui, opts...),
				Func:    "remove-grant-scopes",
			}
		}),

		"scopes": func() (cli.Command, error) {
			return &scopescmd.Command{
				Command: base.NewCommand(ui, opts...),
			}, nil
		},
		"scopes create": wrapper.Wrap(func() wrapper.WrappableCommand {
			return &scopescmd.Command{
				Command: base.NewCommand(ui, opts...),
				Func:    "create",
			}
		}),
		"scopes read": wrapper.Wrap(func() wrapper.WrappableCommand {
			return &scopescmd.Command{
				Command: base.NewCommand(ui, opts...),
				Func:    "read",
			}
		}),
		"scopes update": wrapper.Wrap(func() wrapper.WrappableCommand {
			return &scopescmd.Command{
				Command: base.NewCommand(ui, opts...),
				Func:    "update",
			}
		}),
		"scopes delete": wrapper.Wrap(func() wrapper.WrappableCommand {
			return &scopescmd.Command{
				Command: base.NewCommand(ui, opts...),
				Func:    "delete",
			}
		}),
		"scopes list": wrapper.Wrap(func() wrapper.WrappableCommand {
			return &scopescmd.Command{
				Command: base.NewCommand(ui, opts...),
				Func:    "list",
			}
		}),
		"scopes list-keys": wrapper.Wrap(func() wrapper.WrappableCommand {
			return &scopescmd.ListKeysCommand{
				Command: base.NewCommand(ui, opts...),
			}
		}),
		"scopes rotate-keys": wrapper.Wrap(func() wrapper.WrappableCommand {
			return &scopescmd.RotateKeysCommand{
				Command: base.NewCommand(ui, opts...),
			}
		}),
		"scopes list-key-version-destruction-jobs": wrapper.Wrap(func() wrapper.WrappableCommand {
			return &scopescmd.ListKeyVersionDestructionJobsCommand{
				Command: base.NewCommand(ui, opts...),
			}
		}),
		"scopes destroy-key-version": wrapper.Wrap(func() wrapper.WrappableCommand {
			return &scopescmd.DestroyKeyVersionCommand{
				Command: base.NewCommand(ui, opts...),
			}
		}),
		"scopes attach-storage-policy": wrapper.Wrap(func() wrapper.WrappableCommand {
			return &scopescmd.Command{
				Command: base.NewCommand(ui, opts...),
				Func:    "attach-storage-policy",
			}
		}),
		"scopes detach-storage-policy": wrapper.Wrap(func() wrapper.WrappableCommand {
			return &scopescmd.Command{
				Command: base.NewCommand(ui, opts...),
				Func:    "detach-storage-policy",
			}
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
		"sessions read": wrapper.Wrap(func() wrapper.WrappableCommand {
			return &sessionscmd.Command{
				Command: base.NewCommand(ui, opts...),
				Func:    "read",
			}
		}),
		"sessions list": wrapper.Wrap(func() wrapper.WrappableCommand {
			return &sessionscmd.Command{
				Command: base.NewCommand(ui, opts...),
				Func:    "list",
			}
		}),
		"sessions cancel": wrapper.Wrap(func() wrapper.WrappableCommand {
			return &sessionscmd.Command{
				Command: base.NewCommand(ui, opts...),
				Func:    "cancel",
			}
		}),

		"session-recordings": func() (cli.Command, error) {
			return &sessionrecordingscmd.Command{
				Command: base.NewCommand(ui, opts...),
			}, nil
		},
		"session-recordings read": wrapper.Wrap(func() wrapper.WrappableCommand {
			return &sessionrecordingscmd.Command{
				Command: base.NewCommand(ui, opts...),
				Func:    "read",
			}
		}),
		"session-recordings list": wrapper.Wrap(func() wrapper.WrappableCommand {
			return &sessionrecordingscmd.Command{
				Command: base.NewCommand(ui, opts...),
				Func:    "list",
			}
		}),
		"session-recordings download": wrapper.Wrap(func() wrapper.WrappableCommand {
			return &sessionrecordingscmd.DownloadCommand{
				Command: base.NewCommand(ui, opts...),
			}
		}),
		"session-recordings delete": wrapper.Wrap(func() wrapper.WrappableCommand {
			return &sessionrecordingscmd.Command{
				Command: base.NewCommand(ui, opts...),
				Func:    "delete",
			}
		}),
		"session-recordings reapply-storage-policy": wrapper.Wrap(func() wrapper.WrappableCommand {
			return &sessionrecordingscmd.ReApplyStoragePolicyCommand{
				Command: base.NewCommand(ui, opts...),
			}
		}),

		"storage-buckets": func() (cli.Command, error) {
			return &storagebucketscmd.Command{
				Command: base.NewCommand(ui, opts...),
			}, nil
		},
		"storage-buckets read": wrapper.Wrap(func() wrapper.WrappableCommand {
			return &storagebucketscmd.Command{
				Command: base.NewCommand(ui, opts...),
				Func:    "read",
			}
		}),
		"storage-buckets delete": wrapper.Wrap(func() wrapper.WrappableCommand {
			return &storagebucketscmd.Command{
				Command: base.NewCommand(ui, opts...),
				Func:    "delete",
			}
		}),
		"storage-buckets list": wrapper.Wrap(func() wrapper.WrappableCommand {
			return &storagebucketscmd.Command{
				Command: base.NewCommand(ui, opts...),
				Func:    "list",
			}
		}),
		"storage-buckets create": wrapper.Wrap(func() wrapper.WrappableCommand {
			return &storagebucketscmd.Command{
				Command: base.NewCommand(ui, opts...),
				Func:    "create",
			}
		}),
		"storage-buckets update": wrapper.Wrap(func() wrapper.WrappableCommand {
			return &storagebucketscmd.Command{
				Command: base.NewCommand(ui, opts...),
				Func:    "update",
			}
		}),

		"targets": func() (cli.Command, error) {
			return &targetscmd.Command{
				Command: base.NewCommand(ui, opts...),
			}, nil
		},
		"targets authorize-session": wrapper.Wrap(func() wrapper.WrappableCommand {
			return &targetscmd.Command{
				Command: base.NewCommand(ui, opts...),
				Func:    "authorize-session",
			}
		}),
		"targets read": wrapper.Wrap(func() wrapper.WrappableCommand {
			return &targetscmd.Command{
				Command: base.NewCommand(ui, opts...),
				Func:    "read",
			}
		}),
		"targets delete": wrapper.Wrap(func() wrapper.WrappableCommand {
			return &targetscmd.Command{
				Command: base.NewCommand(ui, opts...),
				Func:    "delete",
			}
		}),
		"targets list": wrapper.Wrap(func() wrapper.WrappableCommand {
			return &targetscmd.Command{
				Command: base.NewCommand(ui, opts...),
				Func:    "list",
			}
		}),
		"targets create": wrapper.Wrap(func() wrapper.WrappableCommand {
			return &targetscmd.Command{
				Command: base.NewCommand(ui, opts...),
				Func:    "create",
			}
		}),
		"targets create tcp": wrapper.Wrap(func() wrapper.WrappableCommand {
			return &targetscmd.TcpCommand{
				Command: base.NewCommand(ui, opts...),
				Func:    "create",
			}
		}),
		"targets create ssh": wrapper.Wrap(func() wrapper.WrappableCommand {
			return &targetscmd.SshCommand{
				Command: base.NewCommand(ui, opts...),
				Func:    "create",
			}
		}),
		"targets create rdp": wrapper.Wrap(func() wrapper.WrappableCommand {
			return &targetscmd.RdpCommand{
				Command: base.NewCommand(ui, opts...),
				Func:    "create",
			}
		}),
		"targets update": wrapper.Wrap(func() wrapper.WrappableCommand {
			return &targetscmd.Command{
				Command: base.NewCommand(ui, opts...),
				Func:    "update",
			}
		}),
		"targets update tcp": wrapper.Wrap(func() wrapper.WrappableCommand {
			return &targetscmd.TcpCommand{
				Command: base.NewCommand(ui, opts...),
				Func:    "update",
			}
		}),
		"targets update rdp": wrapper.Wrap(func() wrapper.WrappableCommand {
			return &targetscmd.RdpCommand{
				Command: base.NewCommand(ui, opts...),
				Func:    "update",
			}
		}),
		"targets update ssh": wrapper.Wrap(func() wrapper.WrappableCommand {
			return &targetscmd.SshCommand{
				Command: base.NewCommand(ui, opts...),
				Func:    "update",
			}
		}),
		"targets add-host-sources": wrapper.Wrap(func() wrapper.WrappableCommand {
			return &targetscmd.Command{
				Command: base.NewCommand(ui, opts...),
				Func:    "add-host-sources",
			}
		}),
		"targets remove-host-sources": wrapper.Wrap(func() wrapper.WrappableCommand {
			return &targetscmd.Command{
				Command: base.NewCommand(ui, opts...),
				Func:    "remove-host-sources",
			}
		}),
		"targets set-host-sources": wrapper.Wrap(func() wrapper.WrappableCommand {
			return &targetscmd.Command{
				Command: base.NewCommand(ui, opts...),
				Func:    "set-host-sources",
			}
		}),
		"targets add-credential-sources": wrapper.Wrap(func() wrapper.WrappableCommand {
			return &targetscmd.Command{
				Command: base.NewCommand(ui, opts...),
				Func:    "add-credential-sources",
			}
		}),
		"targets remove-credential-sources": wrapper.Wrap(func() wrapper.WrappableCommand {
			return &targetscmd.Command{
				Command: base.NewCommand(ui, opts...),
				Func:    "remove-credential-sources",
			}
		}),
		"targets set-credential-sources": wrapper.Wrap(func() wrapper.WrappableCommand {
			return &targetscmd.Command{
				Command: base.NewCommand(ui, opts...),
				Func:    "set-credential-sources",
			}
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
		"users create": wrapper.Wrap(func() wrapper.WrappableCommand {
			return &userscmd.Command{
				Command: base.NewCommand(ui, opts...),
				Func:    "create",
			}
		}),
		"users read": wrapper.Wrap(func() wrapper.WrappableCommand {
			return &userscmd.Command{
				Command: base.NewCommand(ui, opts...),
				Func:    "read",
			}
		}),
		"users update": wrapper.Wrap(func() wrapper.WrappableCommand {
			return &userscmd.Command{
				Command: base.NewCommand(ui, opts...),
				Func:    "update",
			}
		}),
		"users delete": wrapper.Wrap(func() wrapper.WrappableCommand {
			return &userscmd.Command{
				Command: base.NewCommand(ui, opts...),
				Func:    "delete",
			}
		}),
		"users list": wrapper.Wrap(func() wrapper.WrappableCommand {
			return &userscmd.Command{
				Command: base.NewCommand(ui, opts...),
				Func:    "list",
			}
		}),
		"users add-accounts": wrapper.Wrap(func() wrapper.WrappableCommand {
			return &userscmd.Command{
				Command: base.NewCommand(ui, opts...),
				Func:    "add-accounts",
			}
		}),
		"users set-accounts": wrapper.Wrap(func() wrapper.WrappableCommand {
			return &userscmd.Command{
				Command: base.NewCommand(ui, opts...),
				Func:    "set-accounts",
			}
		}),
		"users remove-accounts": wrapper.Wrap(func() wrapper.WrappableCommand {
			return &userscmd.Command{
				Command: base.NewCommand(ui, opts...),
				Func:    "remove-accounts",
			}
		}),

		"workers": func() (cli.Command, error) {
			return &workerscmd.Command{
				Command: base.NewCommand(ui, opts...),
			}, nil
		},
		"workers create": wrapper.Wrap(func() wrapper.WrappableCommand {
			return &workerscmd.Command{
				Command: base.NewCommand(ui, opts...),
				Func:    "create",
			}
		}),
		"workers create worker-led": wrapper.Wrap(func() wrapper.WrappableCommand {
			return &workerscmd.WorkerLedCommand{
				Command: base.NewCommand(ui, opts...),
				Func:    "create",
			}
		}),
		"workers create controller-led": wrapper.Wrap(func() wrapper.WrappableCommand {
			return &workerscmd.ControllerLedCommand{
				Command: base.NewCommand(ui, opts...),
				Func:    "create",
			}
		}),
		"workers read": wrapper.Wrap(func() wrapper.WrappableCommand {
			return &workerscmd.Command{
				Command: base.NewCommand(ui, opts...),
				Func:    "read",
			}
		}),
		"workers update": wrapper.Wrap(func() wrapper.WrappableCommand {
			return &workerscmd.Command{
				Command: base.NewCommand(ui, opts...),
				Func:    "update",
			}
		}),
		"workers delete": wrapper.Wrap(func() wrapper.WrappableCommand {
			return &workerscmd.Command{
				Command: base.NewCommand(ui, opts...),
				Func:    "delete",
			}
		}),
		"workers list": wrapper.Wrap(func() wrapper.WrappableCommand {
			return &workerscmd.Command{
				Command: base.NewCommand(ui, opts...),
				Func:    "list",
			}
		}),
		"workers add-worker-tags": wrapper.Wrap(func() wrapper.WrappableCommand {
			return &workerscmd.Command{
				Command: base.NewCommand(ui, opts...),
				Func:    "add-worker-tags",
			}
		}),
		"workers set-worker-tags": wrapper.Wrap(func() wrapper.WrappableCommand {
			return &workerscmd.Command{
				Command: base.NewCommand(ui, opts...),
				Func:    "set-worker-tags",
			}
		}),
		"workers remove-worker-tags": wrapper.Wrap(func() wrapper.WrappableCommand {
			return &workerscmd.Command{
				Command: base.NewCommand(ui, opts...),
				Func:    "remove-worker-tags",
			}
		}),
		"workers certificate-authority": wrapper.Wrap(func() wrapper.WrappableCommand {
			return &workerscmd.WorkerCACommand{
				Command: base.NewCommand(ui, opts...),
			}
		}),
		"workers certificate-authority read": wrapper.Wrap(func() wrapper.WrappableCommand {
			return &workerscmd.WorkerCACommand{
				Command: base.NewCommand(ui, opts...),
				Func:    "read",
			}
		}),
		"workers certificate-authority reinitialize": wrapper.Wrap(func() wrapper.WrappableCommand {
			return &workerscmd.WorkerCACommand{
				Command: base.NewCommand(ui, opts...),
				Func:    "reinitialize",
			}
		}),
	}

	for _, fn := range extraCommandsFuncs {
		if fn != nil {
			fn(ui, serverCmdUi, runOpts)
		}
	}
}

var extraCommandsFuncs []func(ui, serverCmdUi cli.Ui, runOpts *RunOptions)
