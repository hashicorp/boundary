package cache

import (
	"context"
	"fmt"
	"net/url"
	"strings"

	"github.com/hashicorp/boundary/api"
	"github.com/hashicorp/boundary/api/targets"
	"github.com/hashicorp/boundary/internal/cmd/base"
	"github.com/hashicorp/boundary/internal/errors"
	"github.com/mitchellh/cli"
	"github.com/posener/complete"
)

var (
	_ cli.Command             = (*SearchTargetsCommand)(nil)
	_ cli.CommandAutocomplete = (*SearchTargetsCommand)(nil)
)

type SearchTargetsCommand struct {
	*base.Command
	flagPort           uint
	flagNameStartsWith string
	flagQuery          string
}

func (c *SearchTargetsCommand) Synopsis() string {
	return "Start a Boundary cache server"
}

func (c *SearchTargetsCommand) Help() string {
	helpText := `
Usage: boundary cache search [options]

  Search a boundary cache:

      $ boundary cache search

  For a full list of examples, please see the documentation.

` + c.Flags().Help()
	return strings.TrimSpace(helpText)
}

func (c *SearchTargetsCommand) Flags() *base.FlagSets {
	set := c.FlagSet(base.FlagSetClient | base.FlagSetOutputFormat)

	f := set.NewFlagSet("Command Options")
	f.UintVar(&base.UintVar{
		Name:       "port",
		Target:     &c.flagPort,
		Completion: complete.PredictSet("port"),
		Default:    9203,
		Usage:      `Listener port. Default: 9203`,
		Aliases:    []string{"p"},
	})
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

	return set
}

func (c *SearchTargetsCommand) AutocompleteArgs() complete.Predictor {
	return complete.PredictNothing
}

func (c *SearchTargetsCommand) AutocompleteFlags() complete.Flags {
	return c.Flags().Completions()
}

func (c *SearchTargetsCommand) Run(args []string) int {
	const op = "cache.(SearchTargetsCommand).Run"
	ctx := c.Context
	f := c.Flags()
	if err := f.Parse(args); err != nil {
		c.PrintCliError(err)
		return base.CommandUserError
	}

	_, tokenName, err := c.DiscoverKeyringTokenInfo()
	if err != nil {
		c.UI.Error(err.Error())
		return base.CommandUserError
	}

	tf := targetFilterBy{
		tokenName:          tokenName,
		flagNameStartsWith: c.flagNameStartsWith,
		flagQuery:          c.flagQuery,
	}
	resp, err := searchTargets(ctx, tf, c.flagPort, c.FlagOutputCurlString)
	if err != nil {
		c.PrintCliError(err)
		return base.CommandUserError
	}
	marshaledResp := struct {
		Items []*targets.Target `json:"items"`
	}{}

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
func (c *SearchTargetsCommand) printListTable(items []*targets.Target) string {
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

func SearchClient(ctx context.Context, addr string, flagOutputCurl bool) (*api.Client, error) {
	const op = "cache.SearchClient"
	client, err := api.NewClient(nil)
	if err != nil {
		return nil, errors.Wrap(ctx, err, op)
	}
	client.SetAddr(addr)
	// Because this is using the real lib it can pick up from stored locations
	// like the system keychain. Explicitly clear the token for now
	client.SetToken("")
	if flagOutputCurl {
		client.SetOutputCurlString(true)
	}

	return client, nil
}

type targetFilterBy struct {
	flagNameStartsWith string
	flagQuery          string
	tokenName          string
}

func searchTargets(ctx context.Context, filterBy targetFilterBy, flagPort uint, flagOutputCurl bool) (*api.Response, error) {
	const op = "cache.searchTargets"
	client, err := SearchClient(ctx, fmt.Sprintf("http://localhost:%d", flagPort), flagOutputCurl)
	if err != nil {
		return nil, errors.Wrap(ctx, err, op)
	}
	req, err := client.NewRequest(ctx, "GET", "/search/targets", nil)
	if err != nil {
		return nil, errors.Wrap(ctx, err, op, errors.WithMsg("new client request error: %s", err.Error()))
	}
	req.Header.Add("token_name", filterBy.tokenName)
	q := url.Values{}
	q.Add("name_starts_with", filterBy.flagNameStartsWith)
	q.Add("query", filterBy.flagQuery)
	req.URL.RawQuery = q.Encode()
	resp, err := client.Do(req)
	if err != nil {
		return nil, errors.Wrap(ctx, err, op, errors.WithMsg("client do failed: %w", err))
	}
	return resp, nil
}
