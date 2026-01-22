// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: BUSL-1.1

package search

import (
	"context"
	stderrors "errors"
	"fmt"
	"math"
	"net/url"
	"os"
	"slices"
	"strings"
	"time"

	"github.com/hashicorp/boundary/api"
	"github.com/hashicorp/boundary/api/aliases"
	"github.com/hashicorp/boundary/api/scopes"
	"github.com/hashicorp/boundary/api/sessions"
	"github.com/hashicorp/boundary/api/targets"
	cachecmd "github.com/hashicorp/boundary/internal/clientcache/cmd/cache"
	"github.com/hashicorp/boundary/internal/clientcache/internal/client"
	"github.com/hashicorp/boundary/internal/clientcache/internal/daemon"
	"github.com/hashicorp/boundary/internal/cmd/base"
	"github.com/mitchellh/cli"
	"github.com/posener/complete"
)

var (
	_ cli.Command             = (*SearchCommand)(nil)
	_ cli.CommandAutocomplete = (*SearchCommand)(nil)

	supportedResourceTypes = []string{
		"resolvable-aliases",
		"targets",
		"sessions",
		"implicit-scopes",
	}

	errCacheNotRunning = stderrors.New("The cache process is not running.")
	sortDirections     = []string{"asc", "desc"}
)

type SearchCommand struct {
	*base.Command
	flagQuery            string
	flagResource         string
	flagForceRefresh     bool
	flagMaxResultSetSize int64
	flagSortBy           string
	flagSortDirection    string
}

func (c *SearchCommand) Synopsis() string {
	return "Search Boundary resources using client cache"
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
	set := c.FlagSet(base.FlagSetOutputFormat)

	f := set.NewFlagSet("Client Options")

	f.StringVar(&base.StringVar{
		Name:   "token-name",
		Target: &c.FlagTokenName,
		EnvVar: base.EnvTokenName,
		Usage:  `If specified, the given value will be used as the name when storing the token in the system credential store. This can allow switching user identities for different commands.`,
	})

	f.StringVar(&base.StringVar{
		Name:    "keyring-type",
		Target:  &c.FlagKeyringType,
		Default: "auto",
		EnvVar:  base.EnvKeyringType,
		Usage:   `The type of keyring to use. Defaults to "auto" which will use the Windows credential manager, OSX keychain, or cross-platform password store depending on platform. Set to "none" to disable keyring functionality. Available types, depending on platform, are: "wincred", "keychain", "pass", and "secret-service".`,
	})

	f.StringVar(&base.StringVar{
		Name:   "token",
		Target: &c.FlagToken,
		Usage:  `A URL pointing to a file on disk (file://) from which a token will be read or an env var (env://) from which the token will be read. Overrides the "token-name" parameter.`,
	})

	f.BoolVar(&base.BoolVar{
		Name:   "output-curl-string",
		Target: &c.FlagOutputCurlString,
		Usage:  "Instead of executing the request, print an equivalent cURL command string and exit.",
	})

	f = set.NewFlagSet("Command Options")
	f.StringVar(&base.StringVar{
		Name:   "query",
		Target: &c.flagQuery,
		Usage:  `If set, specifies the resource search query. See https://www.boundaryproject.io/docs/commands/search for more information.`,
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
	f.Int64Var(&base.Int64Var{
		Name:       "max-result-set-size",
		Target:     &c.flagMaxResultSetSize,
		Usage:      `Specifies an override to the default maximum result set size. Set to -1 to disable the limit. 0 will use the default.`,
		Completion: complete.PredictNothing,
	})
	f.BoolVar(&base.BoolVar{
		Name:   "force-refresh",
		Target: &c.flagForceRefresh,
		Usage:  `Forces a refresh to be attempted prior to performing the search`,
		Hidden: true,
	})
	f.StringVar(&base.StringVar{
		Name:       "sort-by",
		Target:     &c.flagSortBy,
		Usage:      `Specifies which column to sort resources by. Use sort-direction to control which direction to sort results by.`,
		Completion: complete.PredictSet(getSortableResources()...),
	})
	f.StringVar(&base.StringVar{
		Name:       "sort-direction",
		Target:     &c.flagSortDirection,
		Usage:      `Specifies which direction to sort results by. Requires sort-by and defaults to asc.`,
		Completion: complete.PredictSet(sortDirections...),
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

	switch {
	case c.flagMaxResultSetSize < -1:
		c.PrintCliError(stderrors.New("Max result set size must be greater than or equal to -1"))
		return base.CommandUserError
	case c.flagMaxResultSetSize > math.MaxInt:
		c.PrintCliError(stderrors.New(fmt.Sprintf("Max result set size must be less than or equal to the %v", math.MaxInt)))
		return base.CommandUserError
	}

	if c.flagSortDirection != "" && c.flagSortBy == "" {
		c.PrintCliError(stderrors.New("sort-direction requires sort-by"))
		return base.CommandUserError
	}

	resp, result, apiErr, err := c.Search(ctx)
	if err != nil {
		c.PrintCliError(err)
		return base.CommandCliError
	}
	if apiErr != nil {
		c.PrintApiError(apiErr, "Error from cache when performing search")
		return base.CommandApiError
	}

	switch base.Format(c.UI) {
	case "json":
		if ok := c.PrintJsonItem(resp); !ok {
			return base.CommandCliError
		}
	default:
		switch {
		case len(result.ResolvableAliases) > 0:
			c.UI.Output(printAliasListTable(result.ResolvableAliases))
		case len(result.Targets) > 0:
			c.UI.Output(printTargetListTable(result.Targets))
		case len(result.Sessions) > 0:
			c.UI.Output(printSessionListTable(result.Sessions))
		case len(result.ImplicitScopes) > 0:
			c.UI.Output(printImplicitScopesListTable(result.ImplicitScopes))
		default:
			c.UI.Output("No items found")
		}

		// Put this at the end or people may not see it as they may not scroll
		// all the way up.
		if result.Incomplete {
			c.UI.Warn("The maximum result set size was reached and the search results are incomplete. Please narrow your search or adjust the -max-result-set-size parameter.")
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
	if c.flagMaxResultSetSize != 0 {
		tf.maxResultSetSize = int(c.flagMaxResultSetSize)
	}
	var opts []client.Option
	if c.FlagOutputCurlString {
		opts = append(opts, client.WithOutputCurlString())
	}

	dotPath, err := cachecmd.DefaultDotDirectory(ctx)
	if err != nil {
		return nil, nil, nil, err
	}
	return search(ctx, dotPath, tf, c.flagSortBy, c.flagSortDirection, opts...)
}

func search(ctx context.Context, daemonPath string, fb filterBy, sortBy string, sortDirection string, opt ...client.Option) (*api.Response, *daemon.SearchResult, *api.Error, error) {
	addr := daemon.SocketAddress(daemonPath)
	_, err := os.Stat(addr.Path)
	if addr.Scheme == "unix" && err != nil {
		return nil, nil, nil, errCacheNotRunning
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
	if fb.maxResultSetSize != 0 {
		q.Add("max_result_set_size", fmt.Sprintf("%d", fb.maxResultSetSize))
	}

	if sortBy != "" {
		q.Add(daemon.SortByKey, sortBy)
		if sortDirection != "" {
			q.Add(daemon.SortDirectionKey, sortDirection)
		}
	}

	resp, err := c.Get(ctx, "/v1/search", q, opt...)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("Error when sending request to the cache: %w.", err)
	}
	res := &daemon.SearchResult{}
	apiErr, err := resp.Decode(&res)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("Error when decoding request from the cache: %w.", err)
	}
	if apiErr != nil {
		return resp, nil, apiErr, nil
	}
	return resp, res, nil, nil
}

func printAliasListTable(items []*aliases.Alias) string {
	if len(items) == 0 {
		return "No resolvable aliases found"
	}
	var output []string
	output = []string{
		"",
		"Resolvable Alias information:",
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
		if item.DestinationId != "" {
			output = append(output,
				fmt.Sprintf("    DestinationId:       %s", item.DestinationId),
			)
		}
		if item.Value != "" {
			output = append(output,
				fmt.Sprintf("    Value:               %s", item.Value),
			)
		}
	}

	return base.WrapForHelpText(output)
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

func printImplicitScopesListTable(items []*scopes.Scope) string {
	if len(items) == 0 {
		return "No implicit scopes found"
	}
	var output []string
	output = []string{
		"",
		"Scope information:",
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
	}

	return base.WrapForHelpText(output)
}

type filterBy struct {
	flagFilter       string
	flagQuery        string
	authTokenId      string
	resource         string
	forceRefresh     bool
	maxResultSetSize int
}

func getSortableResources() []string {
	ret := []string{}
	for sr := range daemon.SortableColumnsForResource {
		ret = append(ret, string(sr))
	}
	return ret
}
