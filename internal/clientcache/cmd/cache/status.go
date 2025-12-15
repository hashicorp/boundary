// Copyright IBM Corp. 2020, 2025
// SPDX-License-Identifier: BUSL-1.1

package cache

import (
	"context"
	stderr "errors"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/hashicorp/boundary/api"
	"github.com/hashicorp/boundary/internal/clientcache/internal/client"
	"github.com/hashicorp/boundary/internal/clientcache/internal/daemon"
	"github.com/hashicorp/boundary/internal/cmd/base"
	"github.com/hashicorp/boundary/internal/errors"
	"github.com/mitchellh/cli"
	"github.com/posener/complete"
	"golang.org/x/text/cases"
	"golang.org/x/text/language"
)

var errCacheNotRunning = stderr.New("The cache process is not running.")

var (
	_ cli.Command             = (*AddTokenCommand)(nil)
	_ cli.CommandAutocomplete = (*AddTokenCommand)(nil)
)

type StatusCommand struct {
	*base.Command
}

func (c *StatusCommand) Synopsis() string {
	return "Get the status information of the running boundary cache"
}

func (c *StatusCommand) Help() string {
	helpText := `
Usage: boundary cache status [options]

  Get the status of the boundary cache:

      $ boundary cache status

  For a full list of examples, please see the documentation.

` + c.Flags().Help()
	return strings.TrimSpace(helpText)
}

func (c *StatusCommand) Flags() *base.FlagSets {
	set := c.FlagSet(base.FlagSetOutputFormat)
	f := set.NewFlagSet("Client Options")

	f.BoolVar(&base.BoolVar{
		Name:   "output-curl-string",
		Target: &c.FlagOutputCurlString,
		Usage:  "Instead of executing the request, print an equivalent cURL command string and exit.",
	})

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

	resp, result, apiErr, err := c.Status(ctx)
	if err != nil {
		c.PrintCliError(err)
		return base.CommandCliError
	}
	if apiErr != nil {
		c.PrintApiError(apiErr, "Error from cache when getting the status")
		return base.CommandApiError
	}

	switch base.Format(c.UI) {
	case "json":
		if ok := c.PrintJsonItem(resp); !ok {
			return base.CommandCliError
		}
	default:
		c.UI.Output(printStatusTable(result))
	}
	return base.CommandSuccess
}

func (c *StatusCommand) Status(ctx context.Context) (*api.Response, *daemon.StatusResult, *api.Error, error) {
	dotPath, err := DefaultDotDirectory(ctx)
	if err != nil {
		return nil, nil, nil, err
	}
	var opts []client.Option
	if c.FlagOutputCurlString {
		opts = append(opts, client.WithOutputCurlString())
	}

	return status(ctx, dotPath, opts...)
}

func status(ctx context.Context, daemonPath string, opt ...client.Option) (*api.Response, *daemon.StatusResult, *api.Error, error) {
	const op = "cache.status"
	addr := daemon.SocketAddress(daemonPath)
	_, err := os.Stat(addr.Path)
	if addr.Scheme == "unix" && err != nil {
		return nil, nil, nil, errCacheNotRunning
	}
	c, err := client.New(ctx, addr)
	if err != nil {
		return nil, nil, nil, err
	}

	resp, err := c.Get(ctx, "/v1/status", nil, opt...)
	if err != nil {
		return nil, nil, nil, errors.Wrap(ctx, err, op, errors.WithMsg("client do failed"))
	}

	res := &daemon.StatusResult{}
	apiErr, err := resp.Decode(&res)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("Error when sending request to the cache: %w.", err)
	}
	if apiErr != nil {
		return resp, nil, apiErr, nil
	}
	return resp, res, nil, nil
}

func printStatusTable(status *daemon.StatusResult) string {
	nonAttributeMap := map[string]any{
		"User Count": len(status.Users),
	}
	if len(status.SocketAddress) > 0 {
		nonAttributeMap["Domain Socket"] = status.SocketAddress
	}
	if len(status.LogLocation) > 0 {
		nonAttributeMap["Log Location"] = status.LogLocation
	}
	if len(status.Version) > 0 {
		nonAttributeMap["Version"] = status.Version
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
			"Address":         u.BoundaryInstance.Address,
			"AuthToken Count": len(u.AuthTokens),
			"Search Support":  u.BoundaryInstance.CacheSupport,
		}
		if u.BoundaryInstance.LastSupportCheck > 0 {
			nonAttributeMap["Since Search Support Check"] = u.BoundaryInstance.LastSupportCheck.Round(time.Second)
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
				nonAttributeMap["Since Initial Fetch"] = r.RefreshToken.Age.Round(time.Second)
			}
			if r.LastError != nil {
				nonAttributeMap["Since Last Error"] = r.LastError.LastReturned.Round(time.Second)
				nonAttributeMap["Last Error Message"] = r.LastError.Error
			}
			maxLength := base.MaxAttributesLength(nonAttributeMap, nil, nil)
			ret = append(ret,
				fmt.Sprintf("    %s:", cases.Title(language.English).String(r.Name)),
				base.WrapMap(6, maxLength+6, nonAttributeMap),
			)
		}
	}
	return ret
}
