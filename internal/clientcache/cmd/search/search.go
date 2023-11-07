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
	"github.com/hashicorp/boundary/internal/clientcache/internal/daemon"
	"github.com/hashicorp/boundary/internal/cmd/base"
	"github.com/hashicorp/boundary/internal/errors"
	"github.com/hashicorp/boundary/version"
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
)

type SearchCommand struct {
	*base.Command
	flagNameStartsWith string
	flagQuery          string
	flagResource       string
}

func (c *SearchCommand) Synopsis() string {
	return "Search resources in boundary"
}

func (c *SearchCommand) Help() string {
	helpText := `
Usage: boundary search [options]

  Search a boundary resource:

      $ boundary search -resource targets

  For a full list of examples, please see the documentation.

` + c.Flags().Help()
	return strings.TrimSpace(helpText)
}

func (c *SearchCommand) Flags() *base.FlagSets {
	set := c.FlagSet(base.FlagSetClient | base.FlagSetOutputFormat)

	f := set.NewFlagSet("Command Options")
	f.StringVar(&base.StringVar{
		Name:   "name-starts-with",
		Target: &c.flagNameStartsWith,
		Usage:  `If set, specifies to search for a target that starts with`,
	})
	f.StringVar(&base.StringVar{
		Name:   "query",
		Target: &c.flagQuery,
		Usage:  `If set, specifies the target search query`,
	})
	f.StringVar(&base.StringVar{
		Name:       "resource",
		Target:     &c.flagResource,
		Usage:      `Specifies the resource type to search over`,
		Completion: complete.PredictSet(supportedResourceTypes...),
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

	resp, err := c.Search(ctx)
	if err != nil {
		c.PrintCliError(err)
		return base.CommandCliError
	}
	res := &daemon.SearchResult{}
	apiErr, err := resp.Decode(res)
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
		c.UI.Output(resp.Body.String())
	default:
		switch {
		case len(res.Targets) > 0:
			c.UI.Output(printTargetListTable(res.Targets))
		case len(res.Sessions) > 0:
			c.UI.Output(printSessionListTable(res.Sessions))
		default:
			c.UI.Output("No items found")
		}
	}
	return base.CommandSuccess
}

func (c *SearchCommand) Search(ctx context.Context) (*api.Response, error) {
	client, err := c.Client()
	if err != nil {
		return nil, err
	}
	t := client.Token()
	if t == "" {
		return nil, fmt.Errorf("Auth Token selected for searching is empty.")
	}
	tSlice := strings.SplitN(t, "_", 3)
	if len(tSlice) != 3 {
		return nil, fmt.Errorf("Auth Token selected for searching is in an unexpected format.")
	}

	tf := filterBy{
		flagQuery:   c.flagQuery,
		resource:    c.flagResource,
		authTokenId: strings.Join(tSlice[:2], "_"),
	}

	dotPath, err := daemoncmd.DefaultDotDirectory(ctx)
	if err != nil {
		return nil, err
	}
	return search(ctx, dotPath, tf)
}

func search(ctx context.Context, daemonPath string, fb filterBy) (*api.Response, error) {
	const op = "search.search"
	client, err := api.NewClient(nil)
	if err != nil {
		return nil, errors.Wrap(ctx, err, op)
	}
	addr, err := daemon.SocketAddress(daemonPath)
	if err != nil {
		return nil, errors.Wrap(ctx, err, op)
	}
	if _, err := os.Stat(addr.Path); addr.Scheme == "unix" && err == os.ErrNotExist {
		return nil, errors.New(ctx, errors.Internal, op, "daemon unix socket is not setup")
	}
	if err := client.SetAddr(addr.String()); err != nil {
		return nil, errors.Wrap(ctx, err, op)
	}

	req, err := client.NewRequest(ctx, "GET", "/search", nil)
	if err != nil {
		return nil, errors.Wrap(ctx, err, op, errors.WithMsg("new client request error"))
	}
	req.Header.Add(daemon.VersionHeaderKey, version.Get().VersionNumber())
	q := url.Values{}
	q.Add("auth_token_id", fb.authTokenId)
	q.Add("resource", fb.resource)
	q.Add("query", fb.flagQuery)
	req.URL.RawQuery = q.Encode()
	resp, err := client.Do(req)
	if err != nil {
		return nil, errors.Wrap(ctx, err, op, errors.WithMsg("client do failed"))
	}
	return resp, err
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
	flagQuery   string
	authTokenId string
	resource    string
}
