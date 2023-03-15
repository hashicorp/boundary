// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package authenticate

import (
	"errors"
	"fmt"
	"strings"

	"github.com/hashicorp/boundary/api/authmethods"
	"github.com/hashicorp/boundary/globals"
	"github.com/hashicorp/boundary/internal/cmd/base"
	"github.com/hashicorp/boundary/internal/cmd/common"
	"github.com/hashicorp/boundary/internal/types/scope"
	"github.com/mitchellh/cli"
	"github.com/mitchellh/go-wordwrap"
)

var _ cli.Command = (*Command)(nil)

type Command struct {
	*base.Command
}

func (c *Command) Synopsis() string {
	return wordwrap.WrapString("Authenticate the Boundary command-line client", base.TermWidth)
}

func (c *Command) Help() string {
	return base.WrapForHelpText([]string{
		"Usage: boundary authenticate [sub command] [options] [args]",
		"",
		"  This command authenticates the Boundary commandline client using a specified auth method. Examples:",
		"",
		"    Authenticate with the primary auth method in the global scope:",
		"",
		"      $ boundary authenticate",
		"",
		"    Authenticate using the primary auth method in a specific scope",
		"",
		"      $ boundary authenticate password -scope-id o_1234567890",
		"",
		"    Authenticate with a password auth method using a specific auth method ID:",
		"",
		"      $ boundary authenticate password -auth-method-id ampw_1234567890",
		"",
		"    Authenticate with an OIDC auth method using a specific auth method ID:",
		"",
		"      $ boundary authenticate oidc -auth-method-id amoidc_1234567890",
		"",
		"    Authenticate with an LDAP auth method:",
		"",
		"      $ boundary authenticate ldap -auth-method-id amldap_1234567890",
		"",
		"  Please see the auth method subcommand help for detailed usage information.",
	}) + c.Flags().Help()
}

func (c *Command) Flags() *base.FlagSets {
	set := c.FlagSet(base.FlagSetHTTP | base.FlagSetClient | base.FlagSetOutputFormat)
	f := set.NewFlagSet("Command Options")

	f.StringVar(&base.StringVar{
		Name:   "scope-id",
		EnvVar: "BOUNDARY_SCOPE_ID",
		Target: &c.FlagScopeId,
		Usage:  "The scope to use for the operation",
	})

	return set
}

func (c *Command) Run(args []string) int {
	client, err := c.Client(base.WithNoTokenScope(), base.WithNoTokenValue())
	if c.WrapperCleanupFunc != nil {
		defer func() {
			if err := c.WrapperCleanupFunc(); err != nil {
				c.PrintCliError(fmt.Errorf("Error cleaning kms wrapper: %w", err))
			}
		}()
	}
	if err != nil {
		c.PrintCliError(fmt.Errorf("Error creating API client: %w", err))
		return base.CommandCliError
	}

	f := c.Flags()

	if err := f.Parse(args); err != nil {
		c.PrintCliError(err)
		return base.CommandUserError
	}

	// Lookup the primary auth method ID in the global scope
	aClient := authmethods.NewClient(client)
	pri, err := getPrimaryAuthMethodId(c.Context, aClient, scope.Global.String(), "")
	if err != nil {
		c.PrintCliError(errors.New("Error looking up primary auth method ID for the global scope. Try setting a primary auth method for the global scope, or use an auth method subcommand (see 'boundary authenticate -h' for available sub command usage)."))
		return base.CommandUserError
	}

	c.FlagAuthMethodId = pri

	switch {
	case strings.HasPrefix(c.FlagAuthMethodId, globals.PasswordAuthMethodPrefix):
		cmd := PasswordCommand{Command: c.Command, Opts: []common.Option{common.WithSkipScopeIdFlag(true)}}
		cmd.Run([]string{})

	case strings.HasPrefix(c.FlagAuthMethodId, globals.OidcAuthMethodPrefix):
		cmd := OidcCommand{Command: c.Command, Opts: []common.Option{common.WithSkipScopeIdFlag(true)}}
		cmd.Run([]string{})

	case strings.HasPrefix(c.FlagAuthMethodId, globals.LdapAuthMethodPrefix):
		cmd := LdapCommand{Command: c.Command, Opts: []common.Option{common.WithSkipScopeIdFlag(true)}}
		cmd.Run([]string{})

	default:
		c.PrintCliError(fmt.Errorf("The primary auth method was of an unsupported type. The given ID was %s; only 'ampw' (password), 'amoidc' (OIDC) and 'amldap' (LDAP) auth method prefixes are supported.", c.FlagAuthMethodId))
		return cli.RunResultHelp
	}

	return 0
}
