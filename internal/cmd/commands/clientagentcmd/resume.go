// Copyright IBM Corp. 2020, 2025
// SPDX-License-Identifier: BUSL-1.1

package clientagentcmd

import (
	"context"
	"strings"
	"time"

	"github.com/hashicorp/boundary/api"
	"github.com/hashicorp/boundary/internal/cmd/base"
	"github.com/hashicorp/boundary/internal/errors"
	"github.com/hashicorp/go-retryablehttp"
	"github.com/mitchellh/cli"
	"github.com/posener/complete"
)

var (
	_ cli.Command             = (*ResumeCommand)(nil)
	_ cli.CommandAutocomplete = (*ResumeCommand)(nil)
)

type ResumeCommand struct {
	*base.Command
}

func (c *ResumeCommand) Synopsis() string {
	return "Resumes the paused boundary client agent"
}

func (c *ResumeCommand) Help() string {
	helpText := `
Usage: boundary client-agent resume

  Resume the boundary client agent:

      $ boundary client-agent resume

  For a full list of examples, please see the documentation.
	
` + c.Flags().Help()
	return strings.TrimSpace(helpText)
}

func (c *ResumeCommand) Flags() *base.FlagSets {
	set := c.FlagSet(base.FlagSetOutputFormat)
	f := set.NewFlagSet("Client Options")

	f.BoolVar(&base.BoolVar{
		Name:   "output-curl-string",
		Target: &c.FlagOutputCurlString,
		Usage:  "Instead of executing the request, print an equivalent cURL command string and exit.",
	})

	f.Uint16Var(&base.Uint16Var{
		Name:    "client-agent-port",
		Target:  &c.FlagClientAgentPort,
		Default: 9300,
		EnvVar:  base.EnvClientAgentPort,
		Usage:   "The port on which the client agent is listening.",
	})

	return set
}

func (c *ResumeCommand) AutocompleteArgs() complete.Predictor {
	return complete.PredictNothing
}

func (c *ResumeCommand) AutocompleteFlags() complete.Flags {
	return c.Flags().Completions()
}

func (c *ResumeCommand) Run(args []string) int {
	ctx := c.Context
	f := c.Flags()
	if err := f.Parse(args); err != nil {
		c.PrintCliError(err)
		return base.CommandUserError
	}

	resp, apiErr, err := c.Resume(ctx)
	if err != nil {
		c.PrintCliError(err)
		return base.CommandCliError
	}
	if apiErr != nil {
		c.PrintApiError(apiErr, "Error from client agent when attempting to resume")
		return base.CommandApiError
	}

	switch base.Format(c.UI) {
	case "json":
		if ok := c.PrintJsonItem(resp); !ok {
			return base.CommandCliError
		}
	default:
		c.UI.Output("The client agent has been successfully resumed.")
	}
	return base.CommandSuccess
}

func (c *ResumeCommand) Resume(ctx context.Context) (*api.Response, *api.Error, error) {
	const op = "clientagentcmd.(ResumeCommand).Resume"
	client := retryablehttp.NewClient()
	client.Logger = nil
	client.RetryWaitMin = 100 * time.Millisecond
	client.RetryWaitMax = 1000 * time.Millisecond

	req, err := retryablehttp.NewRequestWithContext(ctx, "POST", clientAgentUrl(c.FlagClientAgentPort, "v1/resume"), nil)
	if err != nil {
		return nil, nil, err
	}

	if c.FlagOutputCurlString {
		api.LastOutputStringError = &api.OutputStringError{Request: req}
		return nil, nil, api.LastOutputStringError
	}

	resp, err := client.Do(req)
	if err != nil {
		return nil, nil, errors.Wrap(ctx, err, op, errors.WithMsg("client do failed"))
	}
	apiResp := api.NewResponse(resp)

	apiErr, err := apiResp.Decode(nil)
	if err != nil {
		return nil, nil, errors.Wrap(ctx, err, op, errors.WithMsg("error decoding Resume response"))
	}
	if apiErr != nil {
		return nil, apiErr, nil
	}

	return apiResp, nil, nil
}
