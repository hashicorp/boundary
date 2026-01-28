// Copyright IBM Corp. 2020, 2025
// SPDX-License-Identifier: BUSL-1.1

package authenticate

import (
	"errors"
	"fmt"
	"os"
	"strings"

	"github.com/hashicorp/boundary/api"
	"github.com/hashicorp/boundary/api/authmethods"
	"github.com/hashicorp/boundary/globals"
	"github.com/hashicorp/boundary/internal/cmd/base"
	"github.com/hashicorp/boundary/internal/types/scope"
	"github.com/hashicorp/go-secure-stdlib/parseutil"
	"github.com/hashicorp/go-secure-stdlib/password"
	"github.com/mitchellh/cli"
	"github.com/mitchellh/go-wordwrap"
	"github.com/posener/complete"
)

var (
	_ cli.Command             = (*PasswordCommand)(nil)
	_ cli.CommandAutocomplete = (*PasswordCommand)(nil)
)

type LdapCommand struct {
	*base.Command

	flagLoginName string
	flagPassword  string
	parsedOpts    base.Options
}

func (c *LdapCommand) Synopsis() string {
	return wordwrap.WrapString("Invoke the ldap auth method to authenticate with Boundary", base.TermWidth)
}

func (c *LdapCommand) Help() string {
	return base.WrapForHelpText([]string{
		"Usage: boundary authenticate ldap [options] [args]",
		"",
		"  Invoke the ldap auth method to authenticate the Boundary CLI. Example:",
		"",
		`    $ boundary authenticate ldap -auth-method-id amldap_1234567890 -login-name foo`,
		"",
		"",
	}) + c.Flags().Help()
}

func (c *LdapCommand) Flags() *base.FlagSets {
	set := c.FlagSet(base.FlagSetHTTP | base.FlagSetClient | base.FlagSetOutputFormat)
	f := set.NewFlagSet("Command Options")

	f.StringVar(&base.StringVar{
		Name:   "login-name",
		Target: &c.flagLoginName,
		EnvVar: envLoginName,
		Usage:  "The login name corresponding to an account within the given auth method.",
	})

	f.StringVar(&base.StringVar{
		Name:   "password",
		Target: &c.flagPassword,
		EnvVar: envPassword,
		Usage:  "The password associated with the login name. If blank, the command will prompt for the password to be entered interactively in a non-echoing way. Otherwise, this can refer to a file on disk (file://) from which a password will be read or an env var (env://) from which the password will be read.",
	})

	f.StringVar(&base.StringVar{
		Name:   "auth-method-id",
		EnvVar: "BOUNDARY_AUTH_METHOD_ID",
		Target: &c.FlagAuthMethodId,
		Usage:  "The auth-method resource to use for the operation.",
	})

	if !c.parsedOpts.WithSkipScopeIdFlag {
		f.StringVar(&base.StringVar{
			Name:   "scope-id",
			EnvVar: "BOUNDARY_SCOPE_ID",
			Target: &c.FlagScopeId,
			Usage:  "The scope ID to use for the operation.",
		})
	}

	return set
}

func (c *LdapCommand) AutocompleteArgs() complete.Predictor {
	return complete.PredictAnything
}

func (c *LdapCommand) AutocompleteFlags() complete.Flags {
	return c.Flags().Completions()
}

func (c *LdapCommand) Run(args []string) int {
	c.parsedOpts = base.GetOpts(c.Opts...)

	f := c.Flags()
	if err := f.Parse(args); err != nil {
		c.PrintCliError(err)
		return base.CommandUserError
	}

	switch c.flagLoginName {
	case "":
		var input string
		fmt.Print("Please enter the login name: ")
		_, err := fmt.Scanln(&input)
		if err != nil {
			c.UI.Error(fmt.Sprintf("An error occurred attempting to read the login name. The raw error message is shown below but usually this is because you attempted to pipe a value into the command or you are executing outside of a terminal (TTY). The raw error was:\n\n%s", err.Error()))
			return base.CommandUserError
		}
		c.flagLoginName = strings.TrimSpace(input)
	}

	switch c.flagPassword {
	case "":
		fmt.Print("Please enter the password (it will be hidden): ")
		value, err := password.Read(os.Stdin)
		fmt.Print("\n")
		if err != nil {
			c.UI.Error(fmt.Sprintf("An error occurred attempting to read the password. The raw error message is shown below but usually this is because you attempted to pipe a value into the command or you are executing outside of a terminal (TTY). The raw error was:\n\n%s", err.Error()))
			return base.CommandUserError
		}
		c.flagPassword = strings.TrimSpace(value)

	default:
		password, err := parseutil.MustParsePath(c.flagPassword)
		switch {
		case err == nil:
		case errors.Is(err, parseutil.ErrNotParsed):
			c.UI.Error("Password flag must be used with env:// or file:// syntax or left empty for an interactive prompt")
			return base.CommandUserError
		default:
			c.UI.Error(fmt.Sprintf("Error parsing password flag: %v", err))
			return base.CommandUserError
		}
		c.flagPassword = password
	}

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

	aClient := authmethods.NewClient(client)

	// if auth method ID isn't passed on the CLI, try looking up the primary auth method ID
	if c.FlagAuthMethodId == "" {
		// if flag for scope is empty try looking up global
		if c.FlagScopeId == "" {
			c.FlagScopeId = scope.Global.String()
		}

		pri, err := getPrimaryAuthMethodId(c.Context, aClient, c.FlagScopeId, globals.LdapAuthMethodPrefix)
		if err != nil {
			c.PrintCliError(err)
			return base.CommandUserError
		}

		c.FlagAuthMethodId = pri
	}

	result, err := aClient.Authenticate(c.Context, c.FlagAuthMethodId, "login",
		map[string]any{
			"login_name": c.flagLoginName,
			"password":   c.flagPassword,
		})
	if err != nil {
		if apiErr := api.AsServerError(err); apiErr != nil {
			c.PrintApiError(apiErr, "Error from controller when performing authentication")
			return base.CommandApiError
		}
		c.PrintCliError(fmt.Errorf("Error trying to perform authentication: %w", err))
		return base.CommandCliError
	}

	return saveAndOrPrintToken(c.Command, result, c.Opts...)
}
