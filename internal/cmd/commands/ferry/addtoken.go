// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: BUSL-1.1

package ferry

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"
	"time"

	"github.com/hashicorp/boundary/api"
	"github.com/hashicorp/boundary/internal/cmd/base"
	"github.com/hashicorp/go-retryablehttp"
	"github.com/mitchellh/cli"
	"github.com/posener/complete"
)

var (
	_ cli.Command             = (*AddTokenCommand)(nil)
	_ cli.CommandAutocomplete = (*AddTokenCommand)(nil)
)

type AddTokenCommand struct {
	*base.Command
}

func (c *AddTokenCommand) Synopsis() string {
	return "Add an auth token to a running Boundary ferry daemon"
}

func (c *AddTokenCommand) Help() string {
	helpText := `
Usage: boundary ferry add-token [options]

  Add an auth token to the ferry daemon:

      $ boundary ferry add-token

  For a full list of examples, please see the documentation.

` + c.Flags().Help()
	return strings.TrimSpace(helpText)
}

func (c *AddTokenCommand) Flags() *base.FlagSets {
	set := c.FlagSet(base.FlagSetOutputFormat)
	f := set.NewFlagSet("Connection Options")

	f.StringVar(&base.StringVar{
		Name:       base.FlagNameAddr,
		Target:     &c.FlagAddr,
		EnvVar:     api.EnvBoundaryAddr,
		Completion: complete.PredictAnything,
		Usage:      "Addr of the Boundary controller, as a complete URL (e.g. https://boundary.example.com:9200).",
	})

	f = set.NewFlagSet("Client Options")

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

	f.UintVar(&base.UintVar{
		Name:    "ferry-port",
		Target:  &c.FlagFerryDaemonPort,
		Default: 9300,
		EnvVar:  base.EnvFerryDaemonPort,
		Usage:   "The port on which the ferry daemon is listening.",
	})

	return set
}

func (c *AddTokenCommand) AutocompleteArgs() complete.Predictor {
	return complete.PredictNothing
}

func (c *AddTokenCommand) AutocompleteFlags() complete.Flags {
	return c.Flags().Completions()
}

func (c *AddTokenCommand) Run(args []string) int {
	ctx := c.Context
	f := c.Flags()
	if err := f.Parse(args); err != nil {
		c.PrintCliError(err)
		return base.CommandUserError
	}
	client, err := c.Client()
	if err != nil {
		c.PrintCliError(err)
		return base.CommandCliError
	}

	resp, apiErr, err := c.Add(ctx, c.UI, client)
	if err != nil {
		c.PrintCliError(err)
		return base.CommandCliError
	}
	if apiErr != nil {
		c.PrintApiError(apiErr, "Error from daemon when adding a token")
		return base.CommandApiError
	}
	switch base.Format(c.UI) {
	case "json":
		if ok := c.PrintJsonItem(resp); !ok {
			return base.CommandCliError
		}
	case "table":
		c.UI.Output("The ferry add-token operation completed successfully.")
	}
	return base.CommandSuccess
}

// userTokenToAdd is the request body to this handler.
type UpsertTokenRequest struct {
	// BoundaryAddr is a required field for all requests
	BoundaryAddr string `json:"boundary_addr,omitempty"`
	// The raw auth token for this user.
	Token string `json:"token,omitempty"`
}

// Add builds the UpsertTokenRequest using the client's address and token.
// It then sends the request to the ferry daemon.
// The passed in cli.Ui is used to print out any errors when looking up the
// auth token from the keyring. This allows background operations calling this
// method to pass in a silent UI to suppress any output.
func (c *AddTokenCommand) Add(ctx context.Context, ui cli.Ui, apiClient *api.Client) (*api.Response, *api.Error, error) {
	const op = "ferry.(AddTokenCommand).Add"
	pa := UpsertTokenRequest{
		BoundaryAddr: apiClient.Addr(),
	}
	token := apiClient.Token()
	if token == "" {
		return nil, nil, errors.New("The client auth token is empty.")
	}
	if parts := strings.SplitN(token, "_", 4); len(parts) != 3 {
		return nil, nil, errors.New("The client provided auth token is not in the proper format.")
	}

	if c.FlagOutputCurlString {
		pa.Token = "/*token*/"
	} else {
		pa.Token = token
	}

	client := retryablehttp.NewClient()
	client.RetryWaitMin = 100 * time.Millisecond
	client.RetryWaitMax = 1500 * time.Millisecond

	req, err := retryablehttp.NewRequestWithContext(ctx, "POST", ferryUrl(c.FlagFerryDaemonPort, "v1/tokens"),
		retryablehttp.ReaderFunc(func() (io.Reader, error) {
			b, err := json.Marshal(&pa)
			if err != nil {
				return nil, fmt.Errorf("error marshaling body: %w", err)
			}
			return bytes.NewReader(b), nil
		}))
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
		return nil, nil, fmt.Errorf("Error when sending request to the ferry daemon: %w.", err)
	}
	apiResp := api.NewResponse(resp)
	apiErr, err := apiResp.Decode(nil)
	return apiResp, apiErr, err
}
