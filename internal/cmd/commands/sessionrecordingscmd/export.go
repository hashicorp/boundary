// Copyright IBM Corp. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package sessionrecordingscmd

import (
	"errors"
	"fmt"
	"time"

	"github.com/hashicorp/boundary/api"
	"github.com/hashicorp/boundary/api/sessionrecordings"
	"github.com/hashicorp/boundary/internal/cmd/base"
	"github.com/mitchellh/go-wordwrap"
	"github.com/posener/complete"
)

// ExportCommandAction defines actions supported by a session recording export
// resource.
type ExportCommandAction string

const (
	// ExportCommandActionCreate defines the export creation action.
	ExportCommandActionCreate ExportCommandAction = "create"
	// ExportCommandActionRead defines the export read action.
	ExportCommandActionRead ExportCommandAction = "read"
	// ExportCommandActionList defines the export listing action.
	ExportCommandActionList ExportCommandAction = "list"
	// ExportCommandActionCancel defines the export cancel action.
	ExportCommandActionCancel ExportCommandAction = "cancel"
)

// ExportCommand defines a session recording export command. This command
// exposes all actions that are available for session recording exports.
// Note: Custom code has to be used as this sub-resource does not fit well with
// the existing cli autogen logic.
type ExportCommand struct {
	*base.Command
	Action ExportCommandAction

	flagMimeType string
}

func (c *ExportCommand) Synopsis() string {
	switch c.Action {
	case ExportCommandActionCreate:
		// Create refers to starting, reading or cancelling because the "export"
		// sub-command is both used to start an export and also as an
		// entry-point for the "export read" and "export cancel" sub-commands.
		return wordwrap.WrapString("Start, read or cancel a session recording export", base.TermWidth)
	case ExportCommandActionRead:
		return wordwrap.WrapString("Read a session recording export", base.TermWidth)
	case ExportCommandActionCancel:
		return wordwrap.WrapString("Cancel a session recording export", base.TermWidth)
	case ExportCommandActionList:
		return wordwrap.WrapString("List session recording exports", base.TermWidth)
	default:
		return wordwrap.WrapString("Perform actions on session recording export resources", base.TermWidth)
	}
}

func (c *ExportCommand) Help() string {
	var out []string

	switch c.Action {
	case ExportCommandActionCreate:
		out = append(out,
			"Usage: boundary session-recordings export [action] [args]",
			"",
			"  Create a new export. Example:",
			"",
			`    $ boundary session-recordings export -id cr_1234567890 -mime-type video/webm`,
			"",
			"  Also used as an entrypoint to read or cancel an existing export.",
			"",
			"  Please see subcommand help for detailed usage information.",
		)
	case ExportCommandActionRead:
		out = append(out,
			"Usage: boundary session-recordings export read [args]",
			"",
			"  Read an existing export. Example:",
			"",
			`    $ boundary session-recordings export read -id exp_1234567890`,
		)
	case ExportCommandActionCancel:
		out = append(out,
			"Usage: boundary session-recordings export cancel [args]",
			"",
			"  Cancel an existing export. Example:",
			"",
			`    $ boundary session-recordings export cancel -id exp_1234567890`,
		)
	case ExportCommandActionList:
		out = append(out,
			"Usage: boundary session-recordings list-exports [args]",
			"",
			"  List exports within an enclosing scope or resource. Example:",
			"",
			`    $ boundary session-recordings list-exports -scope-id global -recursive true`,
		)
	}
	out = append(out, "", "")

	return base.WrapForHelpText(out) + c.Flags().Help()
}

func (c *ExportCommand) Flags() *base.FlagSets {
	set := c.FlagSet(base.FlagSetHTTP | base.FlagSetClient | base.FlagSetOutputFormat)

	fs := set.NewFlagSet("Command Options")
	switch c.Action {
	case ExportCommandActionCreate:
		fs.StringVar(&base.StringVar{
			Name:    "connection-recording-id",
			Target:  &c.FlagId,
			Usage:   "The id of the connection recording to export",
			Aliases: []string{"cr-id"},
		})
		fs.StringVar(&base.StringVar{
			Name:    "mime-type",
			Target:  &c.flagMimeType,
			Usage:   "The export's requested mime-type. Must be a valid Boundary API mime-type",
			Aliases: []string{"mt"},
		})
	case ExportCommandActionRead, ExportCommandActionCancel:
		fs.StringVar(&base.StringVar{
			Name:   "id",
			Target: &c.FlagId,
			Usage:  "The export's id",
		})
	case ExportCommandActionList:
		fs.StringVar(&base.StringVar{
			Name:    "scope-id",
			Target:  &c.FlagScopeId,
			Usage:   "The scope in which to make the request.",
			EnvVar:  "BOUNDARY_SCOPE_ID",
			Default: "global",
		})
		fs.BoolVar(&base.BoolVar{
			Name:    "recursive",
			Target:  &c.FlagRecursive,
			Usage:   "If set, the list operation will be applied recursively into child scopes, if supported by the type.",
			Default: false,
		})
	}

	return set
}

func (c *ExportCommand) AutocompleteArgs() complete.Predictor {
	return complete.PredictAnything
}

func (c *ExportCommand) AutocompleteFlags() complete.Flags {
	return c.Flags().Completions()
}

func (c *ExportCommand) Run(args []string) int {
	fs := c.Flags()
	err := fs.Parse(args)
	if err != nil {
		c.PrintCliError(err)
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

	srCl := sessionrecordings.NewClient(client)
	switch c.Action {
	case ExportCommandActionCreate:
		return c.create(srCl)
	case ExportCommandActionRead:
		return c.read(srCl)
	case ExportCommandActionList:
		return c.list(srCl)
	case ExportCommandActionCancel:
		return c.cancel(srCl)
	}

	return base.CommandSuccess
}

func (c *ExportCommand) create(cl *sessionrecordings.Client) int {
	switch {
	case c.FlagId == "":
		c.PrintCliError(errors.New("Missing connection recording id. Must be provided via -connection-recording-id"))
		return base.CommandUserError
	case c.flagMimeType == "":
		c.PrintCliError(fmt.Errorf("Missing mime-type. Must be provided via -mime-type"))
		return base.CommandUserError
	}

	result, err := cl.Export(c.Context, c.FlagId, c.flagMimeType)
	if err != nil {
		if apiErr := api.AsServerError(err); apiErr != nil {
			c.PrintApiError(apiErr, "Error from controller when starting a session connection recording export")
			return base.CommandApiError
		}
		c.PrintCliError(fmt.Errorf("Session connection recording export error: %w", err))
		return base.CommandCliError
	}

	switch base.Format(c.UI) {
	case "table":
		c.UI.Output(c.printItemTable(result.GetItem(), result.GetResponse()))
	case "json":
		if ok := c.PrintJsonItem(result.GetResponse()); !ok {
			return base.CommandCliError
		}
	}

	return base.CommandSuccess
}

func (c *ExportCommand) read(cl *sessionrecordings.Client) int {
	switch { //nolint:staticcheck // QF1002. For consistency with how we check function inputs.
	case c.FlagId == "":
		c.PrintCliError(fmt.Errorf("Missing export id. Must be provided via -id"))
		return base.CommandUserError
	}

	result, err := cl.ReadExport(c.Context, c.FlagId)
	if err != nil {
		if apiErr := api.AsServerError(err); apiErr != nil {
			c.PrintApiError(apiErr, "Error from controller when reading a session connection recording export")
			return base.CommandApiError
		}
		c.PrintCliError(fmt.Errorf("Session connection recording export read error: %w", err))
		return base.CommandCliError
	}

	switch base.Format(c.UI) {
	case "table":
		c.UI.Output(c.printItemTable(result.GetItem(), result.GetResponse()))
	case "json":
		if ok := c.PrintJsonItem(result.GetResponse()); !ok {
			return base.CommandCliError
		}
	}

	return base.CommandSuccess
}

func (c *ExportCommand) cancel(cl *sessionrecordings.Client) int {
	switch { //nolint:staticcheck // QF1002. For consistency with how we check function inputs.
	case c.FlagId == "":
		c.PrintCliError(fmt.Errorf("Missing export id. Must be provided via -id"))
		return base.CommandUserError
	}

	result, err := cl.CancelExport(c.Context, c.FlagId)
	if err != nil {
		if apiErr := api.AsServerError(err); apiErr != nil {
			c.PrintApiError(apiErr, "Error from controller when cancelling a session connection recording export")
			return base.CommandApiError
		}
		c.PrintCliError(fmt.Errorf("Session connection recording export cancel error: %w", err))
		return base.CommandCliError
	}

	switch base.Format(c.UI) {
	case "table":
		c.UI.Output("The cancel operation completed successfully.")
	case "json":
		if ok := c.PrintJsonItem(result.GetResponse()); !ok {
			return base.CommandCliError
		}
	}

	return base.CommandSuccess
}

func (c *ExportCommand) list(cl *sessionrecordings.Client) int {
	switch { //nolint:staticcheck // QF1002. For consistency with how we check function inputs.
	case c.FlagScopeId == "":
		c.PrintCliError(fmt.Errorf("Missing scope id. Must be provided via -scope-id"))
		return base.CommandUserError
	}

	opts := make([]sessionrecordings.Option, 0, 1)
	if c.FlagRecursive {
		opts = append(opts, sessionrecordings.WithRecursive(true))
	}

	result, err := cl.ListExports(c.Context, c.FlagScopeId, opts...)
	if err != nil {
		if apiErr := api.AsServerError(err); apiErr != nil {
			c.PrintApiError(apiErr, "Error from controller when listing session connection recording exports")
			return base.CommandApiError
		}
		c.PrintCliError(fmt.Errorf("Session connection recording export listing error: %w", err))
		return base.CommandCliError
	}

	switch base.Format(c.UI) {
	case "table":
		c.UI.Output(c.printListTable(result.GetItems()))
	case "json":
		if ok := c.PrintJsonItems(result.GetResponse()); !ok {
			return base.CommandCliError
		}
	}

	return base.CommandSuccess
}

func (c *ExportCommand) printItemTable(item *sessionrecordings.Export, resp *api.Response) string {
	nonAttributeMap := map[string]any{}
	if item.Id != "" {
		nonAttributeMap["ID"] = item.Id
	}
	if item.Scope.Id != "" {
		nonAttributeMap["Scope ID"] = item.Scope.Id
	}
	if item.ConnectionRecordingId != "" {
		nonAttributeMap["Connection Recording ID"] = item.ConnectionRecordingId
	}
	if item.MimeType != "" {
		nonAttributeMap["Mime Type"] = item.MimeType
	}
	if item.State != "" {
		nonAttributeMap["State"] = item.State
	}
	if item.ProgressPercent > 0 {
		nonAttributeMap["Progress (%)"] = item.ProgressPercent
	}
	if item.WorkerId != "" {
		nonAttributeMap["Worker ID"] = item.WorkerId
	}
	if item.Error != "" {
		nonAttributeMap["Error"] = item.Error
	}
	if !item.CreatedTime.IsZero() {
		nonAttributeMap["Created Time"] = item.CreatedTime.Local().Format(time.RFC1123)
	}
	if !item.UpdatedTime.IsZero() {
		nonAttributeMap["Updated Time"] = item.UpdatedTime.Local().Format(time.RFC1123)
	}

	maxLength := base.MaxAttributesLength(nonAttributeMap, nil, nil)
	ret := []string{
		"",
		"Export information:",
		base.WrapMap(2, maxLength+2, nonAttributeMap),
	}
	if item.Scope != nil {
		ret = append(ret,
			"",
			"  Scope:",
			base.ScopeInfoForOutput(item.Scope, maxLength),
		)
	}
	if len(item.AuthorizedActions) > 0 {
		ret = append(ret,
			"",
			"  Authorized Actions:",
			base.WrapSlice(4, item.AuthorizedActions),
		)
	}

	return base.WrapForHelpText(ret)
}

func (c *ExportCommand) printListTable(items []*sessionrecordings.Export) string {
	if len(items) == 0 {
		return "No exports found"
	}

	output := []string{
		"",
		"Export information:",
	}

	for i, item := range items {
		if i > 0 {
			output = append(output, "")
		}
		if item.Id != "" {
			output = append(output,
				fmt.Sprintf("  ID:                        %s", item.Id),
			)
		} else {
			output = append(output,
				fmt.Sprintf("  ID:                        %s", "(not available)"),
			)
		}
		if item.ConnectionRecordingId != "" {
			output = append(output,
				fmt.Sprintf("    Connection Recording ID: %s", item.ConnectionRecordingId),
			)
		}
		if c.FlagRecursive && item.Scope.Id != "" {
			output = append(output,
				fmt.Sprintf("    Scope ID:                %s", item.Scope.Id),
			)
		}
		if !item.CreatedTime.IsZero() {
			output = append(output,
				fmt.Sprintf("    Created Time:            %s", item.CreatedTime.Local().Format(time.RFC1123)),
			)
		}
		if !item.UpdatedTime.IsZero() {
			output = append(output,
				fmt.Sprintf("    Updated Time:            %s", item.UpdatedTime.Local().Format(time.RFC1123)),
			)
		}
		if item.MimeType != "" {
			output = append(output,
				fmt.Sprintf("    Mime Type:               %s", item.MimeType),
			)
		}
		if item.State != "" {
			output = append(output,
				fmt.Sprintf("    State:                   %s", item.State),
			)
		}
		if item.ProgressPercent > 0 {
			output = append(output,
				fmt.Sprintf("    Progress (%%):            %d", item.ProgressPercent),
			)
		}
		if item.WorkerId != "" {
			output = append(output,
				fmt.Sprintf("    Worker ID:               %s", item.WorkerId),
			)
		}
		if item.Error != "" {
			output = append(output,
				fmt.Sprintf("    Error:                   %s", item.Error),
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
