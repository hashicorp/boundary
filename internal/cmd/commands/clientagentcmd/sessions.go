// Copyright IBM Corp. 2020, 2025
// SPDX-License-Identifier: BUSL-1.1

package clientagentcmd

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/hashicorp/boundary/api"
	"github.com/hashicorp/boundary/api/targets"
	"github.com/hashicorp/boundary/internal/cmd/base"
	"github.com/hashicorp/boundary/internal/errors"
	"github.com/hashicorp/go-retryablehttp"
	"github.com/mitchellh/cli"
	"github.com/posener/complete"
)

var (
	_ cli.Command             = (*SessionsCommand)(nil)
	_ cli.CommandAutocomplete = (*SessionsCommand)(nil)
)

type SessionsCommand struct {
	*base.Command
}

func (c *SessionsCommand) Synopsis() string {
	return "List active transparent sessions managed by the client agent."
}

func (c *SessionsCommand) Help() string {
	helpText := `
Usage: boundary client-agent sessions [options]

  List the active transparent sessions:

      $ boundary client-agent sessions

  For a full list of examples, please see the documentation.

` + c.Flags().Help()
	return strings.TrimSpace(helpText)
}

func (c *SessionsCommand) Flags() *base.FlagSets {
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

func (c *SessionsCommand) AutocompleteArgs() complete.Predictor {
	return complete.PredictNothing
}

func (c *SessionsCommand) AutocompleteFlags() complete.Flags {
	return c.Flags().Completions()
}

func (c *SessionsCommand) Run(args []string) int {
	ctx := c.Context
	f := c.Flags()
	if err := f.Parse(args); err != nil {
		c.PrintCliError(err)
		return base.CommandUserError
	}

	resp, result, apiErr, err := c.Sessions(ctx)
	if err != nil {
		c.PrintCliError(err)
		return base.CommandCliError
	}
	if apiErr != nil {
		c.PrintApiError(apiErr, "Error from client agent when getting its Sessions")
		return base.CommandApiError
	}

	switch base.Format(c.UI) {
	case "json":
		if ok := c.PrintJsonItems(resp); !ok {
			return base.CommandCliError
		}
	default:
		c.UI.Output(c.printListTable(result.Items))
	}
	return base.CommandSuccess
}

type Session struct {
	Alias                string `json:"alias"`
	SessionAuthorization struct {
		SessionId   string                       `json:"session_id"`
		CreatedTime time.Time                    `json:"created_time"`
		Credentials []*targets.SessionCredential `json:"credentials,omitempty"`
	} `json:"session_authorization"`
}

type ListSessionsResponse struct {
	Items []*Session `json:"items"`
}

func (c *SessionsCommand) Sessions(ctx context.Context) (*api.Response, *ListSessionsResponse, *api.Error, error) {
	const op = "clientagentcmd.(SessionsCommand).Sessions"
	client := retryablehttp.NewClient()
	client.Logger = nil
	client.RetryWaitMin = 100 * time.Millisecond
	client.RetryWaitMax = 1500 * time.Millisecond

	req, err := retryablehttp.NewRequestWithContext(ctx, "GET", clientAgentUrl(c.FlagClientAgentPort, "v1/sessions"), nil)
	if err != nil {
		return nil, nil, nil, err
	}
	req.Header.Set("content-type", "application/json")

	if c.FlagOutputCurlString {
		api.LastOutputStringError = &api.OutputStringError{Request: req}
		return nil, nil, nil, api.LastOutputStringError
	}

	resp, err := client.Do(req)
	if err != nil {
		return nil, nil, nil, errors.Wrap(ctx, err, op, errors.WithMsg("client do failed"))
	}
	apiResp := api.NewResponse(resp)

	res := &ListSessionsResponse{}
	apiErr, err := apiResp.Decode(&res)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("Error when sending request to the client agent: %w.", err)
	}
	if apiErr != nil {
		return apiResp, nil, apiErr, nil
	}
	return apiResp, res, nil, nil
}

func generateCredentialTableOutputSlice(prefixIndent int, creds []*targets.SessionCredential) []string {
	var ret []string
	prefixString := strings.Repeat(" ", prefixIndent)

	if len(creds) > 0 {
		// Add credential header
		ret = append(ret, fmt.Sprintf("%sCredentials:", prefixString))
	}
	for _, crd := range creds {
		credMap := map[string]any{
			"Credential Store ID":   crd.CredentialSource.CredentialStoreId,
			"Credential Source ID":  crd.CredentialSource.Id,
			"Credential Store Type": crd.CredentialSource.Type,
		}
		if crd.CredentialSource.Name != "" {
			credMap["Credential Source Name"] = crd.CredentialSource.Name
		}
		if crd.CredentialSource.Description != "" {
			credMap["Credential Source Description"] = crd.CredentialSource.Description
		}
		if crd.CredentialSource.CredentialType != "" {
			credMap["Credential Type"] = crd.CredentialSource.CredentialType
		}
		maxLength := base.MaxAttributesLength(credMap, nil, nil)
		ret = append(ret,
			base.WrapMap(2+prefixIndent, maxLength, credMap),
			fmt.Sprintf("%s  Secret:", prefixString))
		ret = append(ret,
			fmtSecretForTable(2+prefixIndent, crd)...,
		)
		ret = append(ret, "")
	}

	return ret
}

func fmtSecretForTable(indent int, sc *targets.SessionCredential) []string {
	prefixStr := strings.Repeat(" ", indent)
	origSecret := []string{fmt.Sprintf("%s    %s", prefixStr, sc.Secret.Raw)}
	if sc.Credential != nil {
		maxLength := 0
		for k := range sc.Credential {
			if len(k) > maxLength {
				maxLength = len(k)
			}
		}
		return []string{fmt.Sprintf("%s    %s", prefixStr, base.WrapMap(2, maxLength+2, sc.Credential))}
	}

	in, err := base64.StdEncoding.DecodeString(strings.Trim(string(sc.Secret.Raw), `"`))
	if err != nil {
		return origSecret
	}
	dst := new(bytes.Buffer)
	if err := json.Indent(dst, in, fmt.Sprintf("%s    ", prefixStr), fmt.Sprintf("%s  ", prefixStr)); err != nil {
		return origSecret
	}
	secretStr := strings.Split(dst.String(), "\n")
	if len(secretStr) > 0 {
		secretStr[0] = fmt.Sprintf("%s    %s", prefixStr, secretStr[0])
	}
	return secretStr
}

func (c *SessionsCommand) printListTable(items []*Session) string {
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
		output = append(output,
			fmt.Sprintf("  Alias:                     %s", item.Alias),
			"  Session authorization:",
			fmt.Sprintf("    Session ID:              %s", item.SessionAuthorization.SessionId),
			fmt.Sprintf("    Created time:            %s", item.SessionAuthorization.CreatedTime),
		)
		if len(item.SessionAuthorization.Credentials) > 0 {
			output = append(output, generateCredentialTableOutputSlice(4, item.SessionAuthorization.Credentials)...)
		}
	}

	return base.WrapForHelpText(output)
}
