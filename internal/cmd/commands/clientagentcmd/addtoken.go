// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: BUSL-1.1

package clientagentcmd

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
	"github.com/hashicorp/go-retryablehttp"
)

// userTokenToAdd is the request body to this handler.
type UpsertTokenRequest struct {
	// BoundaryAddr is a required field for all requests
	BoundaryAddr string `json:"boundary_addr,omitempty"`
	// The raw auth token for this user.
	Token string `json:"token,omitempty"`
}

// addToken builds the UpsertTokenRequest using the client's address and token.
// It then sends the request to the client agent.
// The passed in cli.Ui is used to print out any errors when looking up the
// auth token from the keyring. This allows background operations calling this
// method to pass in a silent UI to suppress any output.
func addToken(ctx context.Context, apiClient *api.Client, port uint64) (*api.Response, *api.Error, error) {
	pa := UpsertTokenRequest{
		BoundaryAddr: apiClient.Addr(),
	}
	token := apiClient.Token()
	if token == "" {
		return nil, nil, errors.New("The client auth token is empty.")
	}
	if parts := strings.Split(token, "_"); len(parts) != 3 {
		return nil, nil, errors.New("The client provided auth token is not in the proper format.")
	}
	pa.Token = token

	client := retryablehttp.NewClient()
	client.Logger = nil
	client.RetryWaitMin = 100 * time.Millisecond
	client.RetryWaitMax = 1500 * time.Millisecond

	// TODO (ICU-13140): Until we release the client agent, do not retry attempts
	// to connect to the client agent since it adds a noticeably long delay to
	// the command.
	client.RetryMax = 0

	req, err := retryablehttp.NewRequestWithContext(ctx, "POST", clientAgentUrl(port, "v1/tokens"),
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
	resp, err := client.Do(req)
	if err != nil {
		return nil, nil, fmt.Errorf("Error when sending request to the client agent: %w.", err)
	}
	apiResp := api.NewResponse(resp)
	apiErr, err := apiResp.Decode(nil)
	return apiResp, apiErr, err
}
