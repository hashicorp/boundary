// Copyright IBM Corp. 2020, 2025
// SPDX-License-Identifier: BUSL-1.1

package workerscmd

import (
	"github.com/hashicorp/boundary/api"
	"github.com/hashicorp/boundary/api/workers"
	"github.com/hashicorp/boundary/internal/cmd/base"
)

func init() {
	executeExtraControllerLedActions = executeExtraControllerLedActionsImpl
}

func (c *ControllerLedCommand) extraControllerLedHelpFunc(helpMap map[string]func() string) string {
	var helpStr string
	switch c.Func {
	case "create":
		helpStr = base.WrapForHelpText([]string{
			"Usage: boundary workers create controller-led [options] [args]",
			"",
			"  Create a worker using the controller-led approach, receiving an activation token for a worker. Example:",
			"",
			`    $ boundary workers create controller-led -name us-east-1-1`,
			"",
			"",
		})
	}
	return helpStr + c.Flags().Help()
}

func executeExtraControllerLedActionsImpl(c *ControllerLedCommand, origResp *api.Response, origItem *workers.Worker, origError error, workerClient *workers.Client, version uint32, opts []workers.Option) (*api.Response, *workers.Worker, error) {
	switch c.Func {
	case "create":
		result, err := workerClient.CreateControllerLed(c.Context, c.FlagScopeId, opts...)
		if err != nil {
			return nil, nil, err
		}
		return result.GetResponse(), result.GetItem(), nil
	}
	return origResp, origItem, origError
}
