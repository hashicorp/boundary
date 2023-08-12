// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: BUSL-1.1

package search

import (
	"bytes"
	"context"
	stderrors "errors"
	"fmt"
	"net/url"
	"strings"

	"github.com/hashicorp/boundary/api"
	"github.com/hashicorp/boundary/api/targets"
	"github.com/hashicorp/boundary/internal/cmd/base"
	"github.com/hashicorp/boundary/internal/cmd/commands/daemon"
	"github.com/hashicorp/boundary/internal/errors"
	"github.com/mitchellh/cli"
	"github.com/posener/complete"
	"golang.org/x/exp/slices"
)

var (
	_ cli.Command             = (*SearchCommand)(nil)
	_ cli.CommandAutocomplete = (*SearchCommand)(nil)

	supportedResourceTypes = []string{
		"targets",
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
	const op = "search.(SearchCommand).Run"
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

	keyringType, tokenName, err := c.DiscoverKeyringTokenInfo()
	if err != nil {
		c.UI.Error(err.Error())
		return base.CommandUserError
	}
	client, err := c.Client()
	if err != nil {
		c.UI.Error(err.Error())
		return base.CommandUserError
	}

	tf := filterBy{
		boundaryAddr:       client.Addr(),
		tokenName:          tokenName,
		keyringType:        keyringType,
		flagNameStartsWith: c.flagNameStartsWith,
		flagQuery:          c.flagQuery,
		resource:           c.flagResource,
	}
	resp, err := search(ctx, tf, c.FlagOutputCurlString)
	if err != nil {
		c.PrintCliError(err)
		return base.CommandUserError
	}
	marshaledResp := struct {
		Items []*targets.Target `json:"items"`
	}{}

	if resp.StatusCode() >= 400 {
		resp.Body = new(bytes.Buffer)
		if _, err := resp.Body.ReadFrom(resp.HttpResponse().Body); err != nil {
			c.PrintCliError(err)
			return base.CommandUserError
		}
		if resp.Body.Len() > 0 {
			c.PrintCliError(fmt.Errorf(resp.Body.String()))
			return base.CommandUserError
		}
		c.PrintCliError(fmt.Errorf("error reading response body: status was %d", resp.StatusCode()))
		return base.CommandUserError
	}
	apiError, err := resp.Decode(&marshaledResp)
	switch {
	case err != nil:
		c.PrintCliError(err)
		return base.CommandUserError
	case apiError != nil:
		c.PrintCliError(fmt.Errorf(apiError.Error()))
		return base.CommandUserError
	}
	switch base.Format(c.UI) {
	case "json":
		if ok := c.PrintJsonItems(resp); !ok {
			return base.CommandCliError
		}
	default:
		c.UI.Output(c.printListTable(marshaledResp.Items))
	}
	return base.CommandSuccess
}

func (c *SearchCommand) printListTable(items []*targets.Target) string {
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
		if c.FlagRecursive && item.ScopeId != "" {
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

func SearchClient(ctx context.Context, flagOutputCurl bool) (*api.Client, error) {
	const op = "search.SearchClient"
	client, err := api.NewClient(nil)
	if err != nil {
		return nil, errors.Wrap(ctx, err, op)
	}
	addr, err := daemon.SocketAddress()
	if err != nil {
		return nil, errors.Wrap(ctx, err, op)
	}
	if err := client.SetAddr(addr); err != nil {
		return nil, errors.Wrap(ctx, err, op)
	}
	// Because this is using the real lib it can pick up from stored locations
	// like the system keychain. Explicitly clear the token for now
	client.SetToken("")
	if flagOutputCurl {
		client.SetOutputCurlString(true)
	}

	return client, nil
}

type filterBy struct {
	flagNameStartsWith string
	flagQuery          string
	tokenName          string
	keyringType        string
	boundaryAddr       string
	resource           string
}

func search(ctx context.Context, filterBy filterBy, flagOutputCurl bool) (*api.Response, error) {
	const op = "search.search"
	client, err := SearchClient(ctx, flagOutputCurl)
	if err != nil {
		return nil, errors.Wrap(ctx, err, op)
	}
	req, err := client.NewRequest(ctx, "GET", "/search", nil)
	if err != nil {
		return nil, errors.Wrap(ctx, err, op, errors.WithMsg("new client request error: %s", err.Error()))
	}
	q := url.Values{}
	q.Add("token_name", filterBy.tokenName)
	q.Add("keyring_type", filterBy.keyringType)
	q.Add("boundary_addr", filterBy.boundaryAddr)
	q.Add("resource", filterBy.resource)
	q.Add("name_starts_with", filterBy.flagNameStartsWith)
	q.Add("query", filterBy.flagQuery)
	req.URL.RawQuery = q.Encode()
	resp, err := client.Do(req)
	if err != nil {
		return nil, errors.Wrap(ctx, err, op, errors.WithMsg("client do failed: %w", err))
	}
	return resp, nil
}
