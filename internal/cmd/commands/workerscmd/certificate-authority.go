// Copyright IBM Corp. 2020, 2025
// SPDX-License-Identifier: BUSL-1.1

package workerscmd

import (
	"errors"
	"fmt"

	"github.com/hashicorp/boundary/api"
	"github.com/hashicorp/boundary/api/workers"
	"github.com/hashicorp/boundary/internal/cmd/base"
	"github.com/hashicorp/boundary/internal/cmd/common"
	"github.com/hashicorp/go-secure-stdlib/strutil"
	"github.com/mitchellh/cli"
	"github.com/mitchellh/go-wordwrap"
	"github.com/posener/complete"
)

var (
	_ cli.Command             = (*WorkerCACommand)(nil)
	_ cli.CommandAutocomplete = (*WorkerCACommand)(nil)
)

type WorkerCACommand struct {
	*base.Command

	Func string
}

func (c *WorkerCACommand) Synopsis() string {
	switch c.Func {
	case "read":
		return wordwrap.WrapString("Read the certificate authority used to authorize Boundary workers", base.TermWidth)
	case "reinitialize":
		return wordwrap.WrapString("Reinitialize the certificate authority used to authorize Boundary workers", base.TermWidth)
	}
	return wordwrap.WrapString("Manage the certificate authority used to authorize Boundary workers", base.TermWidth)
}

var flagsCertificateAuthority = map[string][]string{
	"reinitialize": {"scope-id"},
	"read":         {"scope-id"},
}

func (c *WorkerCACommand) Help() string {
	switch c.Func {
	case "read":
		return base.WrapForHelpText([]string{
			"Usage: boundary workers certificate-authority read",
			"",
			"  Read the certificate authority used to authorize Boundary workers:",
			"",
			`    $ boundary workers certificate-authority read`,
			"",
			"",
		}) + c.Flags().Help()
	case "reinitialize":
		return base.WrapForHelpText([]string{
			"Usage: boundary workers certificate-authority reinitialize",
			"",
			"  Reinitialize the certificate authority used to authorize Boundary workers:",
			"",
			`    $ boundary workers certificate-authority reinitialize`,
			"",
			"",
		}) + c.Flags().Help()
	}
	return base.WrapForHelpText([]string{
		"Usage: boundary workers certificate-authority [options]",
		"",
		"  This command allows for management of the certificate authority used to authorize Boundary workers. Example:",
		"",
		"    Read the current certificate authority:",
		"",
		`    $ boundary workers certificate-authority read`,
		"",
		"  Please see the certificate-authority subcommand help for detailed usage information.",
		"",
		"",
	})
}

func (c *WorkerCACommand) Flags() *base.FlagSets {
	set := c.FlagSet(base.FlagSetHTTP | base.FlagSetClient | base.FlagSetOutputFormat)
	f := set.NewFlagSet("Worker Certificate Authority Options")
	common.PopulateCommonFlags(c.Command, f, "certificate authority", flagsCertificateAuthority, c.Func)

	return set
}

func (c *WorkerCACommand) AutocompleteArgs() complete.Predictor {
	initFlags()
	return complete.PredictAnything
}

func (c *WorkerCACommand) AutocompleteFlags() complete.Flags {
	initFlags()
	return c.Flags().Completions()
}

func (c *WorkerCACommand) checkFuncError(err error) int {
	if err == nil {
		return 0
	}
	if apiErr := api.AsServerError(err); apiErr != nil {
		c.PrintApiError(apiErr, fmt.Sprintf("Error from controller when performing certificate authority %s", c.Func))
		return base.CommandApiError
	}
	c.PrintCliError(fmt.Errorf("Error trying to %s certificate authority : %s", c.Func, err.Error()))
	return base.CommandCliError
}

func (c *WorkerCACommand) printListTable(item *workers.CertificateAuthority) string {
	if item == nil {
		return "No certificate authority found"
	}

	var output []string
	output = []string{
		"",
		"Worker certificate authority information:",
	}

	for k, ca := range item.Certs {
		if k > 0 {
			output = append(output, "")
		}
		if ca.Id != "" {
			output = append(output,
				fmt.Sprintf("  ID:                        %s", ca.Id),
			)
		} else {
			output = append(output,
				fmt.Sprintf("  ID:                        %s", "(not available)"),
			)
		}
		if ca.PublicKeySha256 != "" {
			output = append(output,
				fmt.Sprintf("  Public Key Sha256:         %s", ca.PublicKeySha256),
			)
		}
		if !ca.NotBeforeTime.IsZero() {
			output = append(output,
				fmt.Sprintf("  Not Before Time:           %s", ca.NotBeforeTime),
			)
		}
		if !ca.NotAfterTime.IsZero() {
			output = append(output,
				fmt.Sprintf("  Not After Time:            %s", ca.NotAfterTime),
			)
		}
	}
	return base.WrapForHelpText(output)
}

func (c *WorkerCACommand) Run(args []string) int {
	initFlags()
	f := c.Flags()

	if err := f.Parse(args); err != nil {
		c.PrintCliError(err)
		return base.CommandUserError
	}

	if strutil.StrListContains(flagsMap[c.Func], "scope-id") {
		switch c.Func {

		case "read":
		case "reinitialize":
			if c.FlagScopeId == "" {
				c.PrintCliError(errors.New("Scope ID must be passed in via -scope-id or BOUNDARY_SCOPE_ID"))
				return base.CommandUserError
			}

		}
	}

	client, err := c.Client()
	if c.WrapperCleanupFunc != nil {
		defer func() {
			if err := c.WrapperCleanupFunc(); err != nil {
				c.PrintCliError(fmt.Errorf("Error cleaning kms wrapper: %w", err))
			}
		}()
	}
	if err != nil {
		c.PrintCliError(fmt.Errorf("Error creating API client: %w", err))
		return base.CommandCliError
	}
	workersClient := workers.NewClient(client)

	var resp *api.Response
	var item *workers.CertificateAuthority

	switch c.Func {
	case "":
		return cli.RunResultHelp
	case "read":
		readResult, err := workersClient.ReadCA(c.Context, c.FlagScopeId)
		if exitCode := c.checkFuncError(err); exitCode > 0 {
			return exitCode
		}
		resp = readResult.GetResponse()
		item = readResult.GetItem()
	case "reinitialize":
		reinitializeResult, err := workersClient.ReinitializeCA(c.Context, c.FlagScopeId)
		if exitCode := c.checkFuncError(err); exitCode > 0 {
			return exitCode
		}
		resp = reinitializeResult.GetResponse()
		item = reinitializeResult.GetItem()
	}

	switch base.Format(c.UI) {
	case "table":
		c.UI.Output(c.printListTable(item))

	case "json":
		if ok := c.PrintJsonItem(resp); !ok {
			return base.CommandCliError
		}
	}

	return base.CommandSuccess
}
