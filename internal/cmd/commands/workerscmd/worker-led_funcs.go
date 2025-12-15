// Copyright IBM Corp. 2020, 2025
// SPDX-License-Identifier: BUSL-1.1

package workerscmd

import (
	"github.com/hashicorp/boundary/api"
	"github.com/hashicorp/boundary/api/workers"
	"github.com/hashicorp/boundary/internal/cmd/base"
)

func init() {
	extraWorkerLedActionsFlagsMapFunc = extraWorkerLedActionsFlagsMapFuncImpl
	extraWorkerLedFlagsFunc = extraWorkerLedFlagsFuncImpl
	executeExtraWorkerLedActions = executeExtraWorkerLedActionsImpl
}

type extraWorkerLedCmdVars struct {
	flagWorkerGeneratedAuthToken string
}

func extraWorkerLedActionsFlagsMapFuncImpl() map[string][]string {
	return map[string][]string{
		"create": {"worker-generated-auth-token"},
	}
}

func (c *WorkerLedCommand) extraWorkerLedHelpFunc(helpMap map[string]func() string) string {
	var helpStr string
	switch c.Func {
	case "create":
		helpStr = base.WrapForHelpText([]string{
			"Usage: boundary workers create worker-led [options] [args]",
			"",
			"  Create a worker using the worker-led approach by providing an auth token from the worker. Example:",
			"",
			`    $ boundary workers create worker-led -name us-east-1-1 -worker-generated-auth-token <token>"`,
			"",
			"",
		})
	}
	return helpStr + c.Flags().Help()
}

func extraWorkerLedFlagsFuncImpl(c *WorkerLedCommand, set *base.FlagSets, _ *base.FlagSet) {
	f := set.NewFlagSet("Worker Creation Options")

	for _, name := range flagsWorkerLedMap[c.Func] {
		switch name {
		case "worker-generated-auth-token":
			f.StringVar(&base.StringVar{
				Name:   "worker-generated-auth-token",
				Target: &c.flagWorkerGeneratedAuthToken,
				Usage:  "The auth token provided by the worker to use to register it to Boundary",
			})
		}
	}
}

func executeExtraWorkerLedActionsImpl(c *WorkerLedCommand, origResp *api.Response, origItem *workers.Worker, origError error, workerClient *workers.Client, version uint32, opts []workers.Option) (*api.Response, *workers.Worker, error) {
	switch c.Func {
	case "create":
		result, err := workerClient.CreateWorkerLed(c.Context, c.flagWorkerGeneratedAuthToken, c.FlagScopeId, opts...)
		if err != nil {
			return nil, nil, err
		}
		return result.GetResponse(), result.GetItem(), nil
	}
	return origResp, origItem, origError
}
