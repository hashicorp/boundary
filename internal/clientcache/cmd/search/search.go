// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: BUSL-1.1

package search

import (
	"context"
	stderrors "errors"
	"fmt"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/hashicorp/boundary/api"
	"github.com/hashicorp/boundary/api/sessions"
	"github.com/hashicorp/boundary/api/targets"
	daemoncmd "github.com/hashicorp/boundary/internal/clientcache/cmd/daemon"
	"github.com/hashicorp/boundary/internal/clientcache/internal/client"
	"github.com/hashicorp/boundary/internal/clientcache/internal/daemon"
	"github.com/hashicorp/boundary/internal/cmd/base"
	"github.com/mitchellh/cli"
	"github.com/posener/complete"
	"golang.org/x/exp/slices"
)

var (
	_ cli.Command             = (*SearchCommand)(nil)
	_ cli.CommandAutocomplete = (*SearchCommand)(nil)

	supportedResourceTypes = []string{
		"targets",
		"sessions",
	}

	errDaemonNotRunning = stderrors.New("The deamon process is not running.")
)

type SearchCommand struct {
	*base.Command
	flagQuery        string
	flagResource     string
	flagForceRefresh bool
}

func (c *SearchCommand) Synopsis() string {
	return "Search Boundary resources using client side cache"
}

func (c *SearchCommand) Help() string {
	helpText := `
Usage: boundary search [options]

  Search a boundary resource:

      $ boundary search -resource targets -query 'name="foo"'

  For a full list of examples, please see the documentation.

` + c.Flags().Help()
	return strings.TrimSpace(helpText)
}

func (c *SearchCommand) Flags() *base.FlagSets {
	set := c.FlagSet(base.FlagSetClient | base.FlagSetOutputFormat)

	f := set.NewFlagSet("Command Options")
	f.StringVar(&base.StringVar{
		Name:   "query",
		Target: &c.flagQuery,
		Usage:  `If set, specifies the resource search query`,
	})
	f.StringVar(&base.StringVar{
		Name:   "filter",
		Target: &c.FlagFilter,
		Usage:  "The filter operates against each item in the response. Using single quotes is recommended as filters contain double quotes. The format is the same as the filters used when performing a list. See https://www.boundaryproject.io/docs/concepts/filtering/resource-listing for details on filters when listing.",
	})
	f.StringVar(&base.StringVar{
		Name:       "resource",
		Target:     &c.flagResource,
		Usage:      `Specifies the resource type to search over`,
		Completion: complete.PredictSet(supportedResourceTypes...),
	})
	f.BoolVar(&base.BoolVar{
		Name:   "force-refresh",
		Target: &c.flagForceRefresh,
		Usage:  `Forces a refresh to be attempted prior to performing the search`,
		Hidden: true,
	})

	return set
}

func (c *SearchCommand) AutocompleteArgs() complete.Predictor {
	return complete.PredictNothing
}

func (c *SearchCommand) AutocompleteFlags() complete.Flags {
	return c.Flags().Completions()
}

func (c *SearchCommand) Run(args []string) int {
	ctx := c.Context
	f := c.Flags()
	if err := f.Parse(args); err != nil {
		c.PrintCliError(err)
		return base.CommandUserError
	}

	switch {
	case slices.Contains(supportedResourceTypes, c.flagResource):
	case c.flagResource == "":
		c.PrintCliError(stderrors.New("Resource is required but not passed in via -resource"))
		return base.CommandUserError
	default:
		c.PrintCliError(stderrors.New("The value passed in with -resource is not currently supported in search"))
		return base.CommandUserError
	}

	resp, result, apiErr, err := c.Search(ctx)
	if err != nil {
		c.PrintCliError(err)
		return base.CommandCliError
	}
	if apiErr != nil {
		c.PrintApiError(apiErr, "Error from daemon when performing search")
		return base.CommandApiError
	}

	switch base.Format(c.UI) {
	case "json":
		if ok := c.PrintJsonItem(resp); !ok {
			return base.CommandCliError
		}
	default:
		switch {
		case len(result.Targets) > 0:
			c.UI.Output(printTargetListTable(result.Targets))
		case len(result.Sessions) > 0:
			c.UI.Output(printSessionListTable(result.Sessions))
		default:
			c.UI.Output("No items found")
		}
	}
	return base.CommandSuccess
}

func (c *SearchCommand) Search(ctx context.Context) (*api.Response, *daemon.SearchResult, *api.Error, error) {
	cl, err := c.Client()
	if err != nil {
		return nil, nil, nil, err
	}
	t := cl.Token()
	if t == "" {
		return nil, nil, nil, fmt.Errorf("Auth Token selected for searching is empty.")
	}
	tSlice := strings.SplitN(t, "_", 3)
	if len(tSlice) != 3 {
		return nil, nil, nil, fmt.Errorf("Auth Token selected for searching is in an unexpected format.")
	}

	tf := filterBy{
		flagFilter:   c.FlagFilter,
		flagQuery:    c.flagQuery,
		resource:     c.flagResource,
		authTokenId:  strings.Join(tSlice[:2], "_"),
		forceRefresh: c.flagForceRefresh,
	}
	var opts []client.Option
	if c.FlagOutputCurlString {
		opts = append(opts, client.WithOutputCurlString())
	}

	dotPath, err := daemoncmd.DefaultDotDirectory(ctx)
	if err != nil {
		return nil, nil, nil, err
	}
	return search(ctx, dotPath, tf, opts...)
}

func search(ctx context.Context, daemonPath string, fb filterBy, opt ...client.Option) (*api.Response, *daemon.SearchResult, *api.Error, error) {
	addr := daemon.SocketAddress(daemonPath)
	_, err := os.Stat(addr.Path)
	if addr.Scheme == "unix" && err != nil {
		return nil, nil, nil, errDaemonNotRunning
	}
	c, err := client.New(ctx, addr)
	if err != nil {
		return nil, nil, nil, err
	}

	q := &url.Values{}
	q.Add("auth_token_id", fb.authTokenId)
	q.Add("resource", fb.resource)
	q.Add("query", fb.flagQuery)
	q.Add("filter", fb.flagFilter)
	if fb.forceRefresh {
		q.Add("force_refresh", "true")
	}
	resp, err := c.Get(ctx, "/v1/search", q, opt...)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("Error when sending request to the daemon: %w.", err)
	}
	res := &daemon.SearchResult{}
	apiErr, err := resp.Decode(&res)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("Error when decoding request from the daemon: %w.", err)
	}
	if apiErr != nil {
		return resp, nil, apiErr, nil
	}
	return resp, res, nil, nil
}

func printTargetListTable(items []*targets.Target) string {
	if len(items) == 0 {
		return "No targets found"
	}
	var output []string
	output = []string{
		"",
		"Target information:",
	}
	for i, item := range items {
		if i > 0 {
			output = append(output, "")
		}
		if item.Id != "" {
			output = append(output,
				fmt.Sprintf("  ID:                    %s", item.Id),
			)
		} else {
			output = append(output,
				fmt.Sprintf("  ID:                    %s", "(not available)"),
			)
		}
		if item.ScopeId != "" {
			output = append(output,
				fmt.Sprintf("    Scope ID:            %s", item.ScopeId),
			)
		}
		if item.Version > 0 {
			output = append(output,
				fmt.Sprintf("    Version:             %d", item.Version),
			)
		}
		if item.Type != "" {
			output = append(output,
				fmt.Sprintf("    Type:                %s", item.Type),
			)
		}
		if item.Name != "" {
			output = append(output,
				fmt.Sprintf("    Name:                %s", item.Name),
			)
		}
		if item.Description != "" {
			output = append(output,
				fmt.Sprintf("    Description:         %s", item.Description),
			)
		}
		if item.Address != "" {
			output = append(output,
				fmt.Sprintf("    Address:             %s", item.Address),
			)
		}
		if len(item.AuthorizedActions) > 0 {
			output = append(output,
				"    Authorized Actions:",
				base.WrapSlice(6, item.AuthorizedActions),
			)
		}
	}

	return base.WrapForHelpText(output)
}

func printSessionListTable(items []*sessions.Session) string {
	if len(items) == 0 {
		return "No sessions found"
	}
	var output []string
	output = []string{
		"",
		"Session information:",
	}
	for i, item := range items {
		if i > 0 {
			output = append(output, "")
		}
		if item.Id != "" {
			output = append(output,
				fmt.Sprintf("  ID:                    %s", item.Id),
			)
		} else {
			output = append(output,
				fmt.Sprintf("  ID:                    %s", "(not available)"),
			)
		}
		if item.ScopeId != "" {
			output = append(output,
				fmt.Sprintf("    Scope ID:            %s", item.ScopeId),
			)
		}
		if item.Status != "" {
			output = append(output,
				fmt.Sprintf("    Status:              %s", item.Status),
			)
		}
		if !item.CreatedTime.IsZero() {
			output = append(output,
				fmt.Sprintf("    Created Time:        %s", item.CreatedTime.Local().Format(time.RFC1123)),
			)
		}
		if !item.ExpirationTime.IsZero() {
			output = append(output,
				fmt.Sprintf("    Expiration Time:     %s", item.ExpirationTime.Local().Format(time.RFC1123)),
			)
		}
		if !item.UpdatedTime.IsZero() {
			output = append(output,
				fmt.Sprintf("    Updated Time:        %s", item.UpdatedTime.Local().Format(time.RFC1123)),
			)
		}
		if item.UserId != "" {
			output = append(output,
				fmt.Sprintf("    User ID:             %s", item.UserId),
			)
		}
		if item.TargetId != "" {
			output = append(output,
				fmt.Sprintf("    Target ID:           %s", item.TargetId),
			)
		}
		if len(item.AuthorizedActions) > 0 {
			output = append(output,
				"    Authorized Actions:",
				base.WrapSlice(6, item.AuthorizedActions),
			)
		}
	}

	return base.WrapForHelpText(output)
}

type filterBy struct {
	flagFilter   string
	flagQuery    string
	authTokenId  string
	resource     string
	forceRefresh bool
}
