// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: BUSL-1.1

package ferry

import (
	"context"
	"fmt"
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
	_ cli.Command             = (*PauseCommand)(nil)
	_ cli.CommandAutocomplete = (*PauseCommand)(nil)
)

type PauseCommand struct {
	*base.Command
}

func (c *PauseCommand) Synopsis() string {
	return "Pauses the running boundary ferry daemon"
}

func (c *PauseCommand) Help() string {
	helpText := `
Usage: boundary ferry pause

  Pause the boundary ferry daemon:

      $ boundary ferry pause

  For a full list of examples, please see the documentation.
	
` + c.Flags().Help()
	return strings.TrimSpace(helpText)
}

func (c *PauseCommand) Flags() *base.FlagSets {
	return c.FlagSet(base.FlagSetNone)
}

func (c *PauseCommand) AutocompleteArgs() complete.Predictor {
	return complete.PredictNothing
}

func (c *PauseCommand) AutocompleteFlags() complete.Flags {
	return c.Flags().Completions()
}

func (c *PauseCommand) Run(args []string) int {
	ctx := c.Context

	resp, apiErr, err := c.Pause(ctx)
	if err != nil {
		c.PrintCliError(err)
		return base.CommandCliError
	}
	if apiErr != nil {
		c.PrintApiError(apiErr, "Error from ferry daemon when attempting to pause")
		return base.CommandApiError
	}

	if ok := c.PrintJsonItem(resp); !ok {
		return base.CommandCliError
	}
	return base.CommandSuccess
}

func (c *PauseCommand) Pause(ctx context.Context) (*api.Response, *api.Error, error) {
	const op = "ferry.(PauseCommand).Status"
	client := retryablehttp.NewClient()
	client.Logger = nil
	client.RetryWaitMin = 100 * time.Millisecond
	client.RetryWaitMax = 1000 * time.Millisecond

	req, err := retryablehttp.NewRequestWithContext(ctx, "POST", ferryUrl(c.FlagFerryDaemonPort, "v1/pause"), nil)
	if err != nil {
		return nil, nil, err
	}
	req.Header.Set("content-type", "application/json")

	if c.FlagOutputCurlString {
		api.LastOutputStringError = &api.OutputStringError{Request: req}
		return nil, nil, api.LastOutputStringError
	}

	resp, err := client.Do(req)
	if err != nil {
		return nil, nil, errors.Wrap(ctx, err, op, errors.WithMsg("client do failed"))
	}
	apiResp := api.NewResponse(resp)

	res := &GetStatusResponse{}
	apiErr, err := apiResp.Decode(&res)
	if err != nil {
		return nil, nil, fmt.Errorf("error when sending request to the ferry daemon: %w", err)
	}
	if apiErr != nil {
		return apiResp, apiErr, nil
	}
	return apiResp, nil, nil
}
