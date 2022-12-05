package scopescmd

import (
	"errors"
	"fmt"
	"time"

	"github.com/hashicorp/boundary/api"
	"github.com/hashicorp/boundary/api/scopes"
	"github.com/hashicorp/boundary/internal/cmd/base"
	"github.com/mitchellh/cli"
	"github.com/mitchellh/go-wordwrap"
	"github.com/posener/complete"
)

var (
	_ cli.Command             = (*ListKeyVersionDestructionJobsCommand)(nil)
	_ cli.CommandAutocomplete = (*ListKeyVersionDestructionJobsCommand)(nil)
)

type ListKeyVersionDestructionJobsCommand struct {
	*base.Command
}

func (c *ListKeyVersionDestructionJobsCommand) Synopsis() string {
	return wordwrap.WrapString("List all pending key version destruction jobs within a scope", base.TermWidth)
}

func (c *ListKeyVersionDestructionJobsCommand) Help() string {
	return base.WrapForHelpText([]string{
		"Usage: boundary scopes list-key-version-destruction-jobs [args]",
		"",
		"  List all pending key version destruction jobs within a scope. A key version",
		"  destruction job asynchronously re-encrypts any existing data with the latest",
		"  key version before destroying the key version. Example:",
		"",
		`    $ boundary scopes list-key-version-destruction-jobs -scope-id global`,
		"",
		"",
	}) + c.Flags().Help()
}

func (c *ListKeyVersionDestructionJobsCommand) Flags() *base.FlagSets {
	set := c.FlagSet(base.FlagSetHTTP | base.FlagSetClient | base.FlagSetOutputFormat)
	f := set.NewFlagSet("Command Options")

	f.StringVar(&base.StringVar{
		Name:   "scope-id",
		Target: &c.FlagScopeId,
		Usage:  "The id of the scope in which to list key version destruction jobs",
	})

	return set
}

func (c *ListKeyVersionDestructionJobsCommand) AutocompleteArgs() complete.Predictor {
	return complete.PredictAnything
}

func (c *ListKeyVersionDestructionJobsCommand) AutocompleteFlags() complete.Flags {
	return c.Flags().Completions()
}

func (c *ListKeyVersionDestructionJobsCommand) printListTable(items []*scopes.KeyVersionDestructionJob) string {
	if len(items) == 0 {
		return "No keys version destruction jobs found"
	}
	output := []string{
		"",
		"Key version destruction job information:",
	}
	for i, item := range items {
		if i > 0 {
			output = append(output, "")
		}
		if true {
			output = append(output,
				fmt.Sprintf("  Key version ID:    %s", item.KeyVersionId),
				fmt.Sprintf("    Scope ID:        %s", item.Scope.Id),
			)
		}
		if !item.CreatedTime.IsZero() {
			output = append(output,
				fmt.Sprintf("    Started:         %s", item.CreatedTime.Local().Format(time.RFC1123)),
			)
		}
		if item.Status != "" {
			output = append(output,
				fmt.Sprintf("    Status:          %s", item.Status),
			)
		}
		if true {
			output = append(output,
				fmt.Sprintf("    Rows completed:  %d", item.CompletedCount),
			)
		}
		if true {
			output = append(output,
				fmt.Sprintf("    Total rows:      %d", item.TotalCount),
			)
		}
	}

	return base.WrapForHelpText(output)
}

func (c *ListKeyVersionDestructionJobsCommand) Run(args []string) int {
	f := c.Flags()

	if err := f.Parse(args); err != nil {
		c.PrintCliError(err)
		return base.CommandUserError
	}

	switch {
	case c.FlagScopeId == "":
		c.PrintCliError(errors.New("Scope ID must be provided via -scope-id"))
		return base.CommandUserError
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

	sClient := scopes.NewClient(client)
	result, err := sClient.ListKeyVersionDestructionJobs(c.Context, c.FlagScopeId)
	if err != nil {
		if apiErr := api.AsServerError(err); apiErr != nil {
			c.PrintApiError(apiErr, "Error from controller when listing key version destruction jobs")
			return base.CommandApiError
		}
		c.PrintCliError(fmt.Errorf("Error trying to list key version destruction jobs: %w", err))
		return base.CommandCliError
	}

	switch base.Format(c.UI) {
	case "json":
		if ok := c.PrintJsonItems(result.GetResponse()); !ok {
			return base.CommandCliError
		}

	default:
		c.UI.Output(c.printListTable(result.GetItems()))
	}

	return base.CommandSuccess
}
