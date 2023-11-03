// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: BUSL-1.1

package daemon

import (
	"context"
	stderr "errors"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/hashicorp/boundary/api"
	"github.com/hashicorp/boundary/internal/clientcache/internal/daemon"
	"github.com/hashicorp/boundary/internal/cmd/base"
	"github.com/hashicorp/boundary/version"
	"github.com/mitchellh/cli"
	"github.com/posener/complete"
)

var errDaemonNotRunning = stderr.New("daemon is not running")

var (
	_ cli.Command             = (*AddTokenCommand)(nil)
	_ cli.CommandAutocomplete = (*AddTokenCommand)(nil)
)

type StatusCommand struct {
	*base.Command
}

func (c *StatusCommand) Synopsis() string {
	return "Get the status information of the running boundary daemon"
}

func (c *StatusCommand) Help() string {
	helpText := `
Usage: boundary daemon status [options]

  Get the status of the boundary daemon:

      $ boundary daemon status

  For a full list of examples, please see the documentation.

` + c.Flags().Help()
	return strings.TrimSpace(helpText)
}

func (c *StatusCommand) Flags() *base.FlagSets {
	set := c.FlagSet(base.FlagSetClient | base.FlagSetOutputFormat)
	return set
}

func (c *StatusCommand) AutocompleteArgs() complete.Predictor {
	return complete.PredictNothing
}

func (c *StatusCommand) AutocompleteFlags() complete.Flags {
	return c.Flags().Completions()
}

func (c *StatusCommand) Run(args []string) int {
	ctx := c.Context
	f := c.Flags()
	if err := f.Parse(args); err != nil {
		c.PrintCliError(err)
		return base.CommandUserError
	}

	resp, err := c.Status(ctx)
	if err != nil {
		c.PrintCliError(err)
		return base.CommandCliError
	}

	res := &daemon.StatusResult{}
	apiErr, err := resp.Decode(res)
	if err != nil {
		c.PrintCliError(err)
		return base.CommandCliError
	}
	if apiErr != nil {
		c.PrintApiError(apiErr, "Error from daemon when getting the status")
		return base.CommandApiError

	}
	switch base.Format(c.UI) {
	case "json":
		c.UI.Output(resp.Body.String())
	default:
		c.UI.Output(printStatusTable(res))
	}
	return base.CommandSuccess
}

func (c *StatusCommand) Status(ctx context.Context) (*api.Response, error) {
	dotPath, err := DefaultDotDirectory(ctx)
	if err != nil {
		return nil, err
	}

	return status(ctx, dotPath)
}

func status(ctx context.Context, daemonPath string) (*api.Response, error) {
	client, err := api.NewClient(nil)
	if err != nil {
		return nil, fmt.Errorf("Error creating a new API client: %w", err)
	}
	addr, err := daemon.SocketAddress(daemonPath)
	if err != nil {
		return nil, fmt.Errorf("Error getting socket address: %w", err)
	}
	_, err = os.Stat(addr.Path)
	if addr.Scheme == "unix" && err != nil {
		return nil, errDaemonNotRunning
	}
	if err := client.SetAddr(addr.String()); err != nil {
		return nil, fmt.Errorf("Error when setting the client's address: %w", err)
	}
	// Because this is using the real lib it can pick up from stored locations
	// like the system keychain. Explicitly clear the token for now
	client.SetToken("")

	req, err := client.NewRequest(ctx, "GET", "/status", nil)
	if err != nil {
		return nil, err
	}
	req.Header.Add(daemon.VersionHeaderKey, version.Get().VersionNumber())
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	return resp, nil
}

func printStatusTable(status *daemon.StatusResult) string {
	nonAttributeMap := map[string]any{
		"User Count": len(status.Users),
	}
	if len(status.SocketAddress) > 0 {
		nonAttributeMap["Domain Socket"] = status.SocketAddress
	}
	if status.Uptime > 0 {
		nonAttributeMap["Uptime"] = status.Uptime.Round(time.Second)
	}

	maxLength := base.MaxAttributesLength(nonAttributeMap, nil, nil)

	ret := []string{
		"",
		"Status:",
		base.WrapMap(2, maxLength+2, nonAttributeMap),
	}

	if len(status.Users) > 0 {
		ret = append(ret, printUsersTable(status.Users)...)
	}
	return base.WrapForHelpText(ret)
}

func printUsersTable(us []daemon.UserStatus) []string {
	ret := []string{
		"",
	}
	for _, u := range us {
		ret = append(ret, "  User:")
		nonAttributeMap := map[string]any{
			"Id":              u.Id,
			"Address":         u.Address,
			"AuthToken Count": len(u.AuthTokens),
		}
		maxLength := base.MaxAttributesLength(nonAttributeMap, nil, nil)
		ret = append(ret,
			base.WrapMap(4, maxLength+4, nonAttributeMap),
		)

		for _, at := range u.AuthTokens {
			nonAttributeMap := map[string]any{
				"Id": at.Id,
			}
			if at.KeyringReferences > 0 {
				nonAttributeMap["In Keyring"] = "true"
			}
			maxLength := base.MaxAttributesLength(nonAttributeMap, nil, nil)
			ret = append(ret,
				"    AuthToken:",
				base.WrapMap(6, maxLength+6, nonAttributeMap),
			)
		}

		for _, r := range u.Resources {
			nonAttributeMap := map[string]any{
				"Count": r.Count,
			}
			if r.RefreshToken != nil {
				nonAttributeMap["Since Last Refresh"] = r.RefreshToken.LastUsed.Round(time.Second)
				nonAttributeMap["Since Full Fetch"] = r.RefreshToken.Age.Round(time.Second)
			}
			if r.LastError != nil {
				nonAttributeMap["Since Last Error"] = r.LastError.LastReturned.Round(time.Second)
				nonAttributeMap["Last Error Message"] = r.LastError.Error
			}
			maxLength := base.MaxAttributesLength(nonAttributeMap, nil, nil)
			ret = append(ret,
				fmt.Sprintf("    %s:", strings.Title(r.Name)),
				base.WrapMap(6, maxLength+6, nonAttributeMap),
			)
		}
	}
	return ret
}
