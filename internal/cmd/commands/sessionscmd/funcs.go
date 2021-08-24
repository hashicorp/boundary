package sessionscmd

import (
	"fmt"
	"strings"
	"time"

	"github.com/hashicorp/boundary/api"
	"github.com/hashicorp/boundary/api/sessions"
	"github.com/hashicorp/boundary/internal/cmd/base"
)

func init() {
	extraActionsFlagsMapFunc = extraActionsFlagsMapFuncImpl
	executeExtraActions = executeExtraActionsImpl
}

func extraActionsFlagsMapFuncImpl() map[string][]string {
	return map[string][]string{
		"cancel": {"id"},
	}
}

func (c *Command) extraHelpFunc(helpMap map[string]func() string) string {
	var helpStr string
	switch c.Func {
	case "":
		return base.WrapForHelpText([]string{
			"Usage: boundary sessions [sub command] [options] [args]",
			"",
			"  This command allows operations on Boundary sessions.",
			"",
			"    Read a session:",
			"",
			`      $ boundary sessions read -id s_1234567890`,
			"",
			"  Please see the sessions subcommand help for detailed usage information.",
		})

	case "cancel":
		helpStr = base.WrapForHelpText([]string{
			"Usage: boundary sessions cancel [options] [args]",
			"",
			"  Cancel the session specified by ID. If the session is already canceled, this command succeeds with no effect. Example:",
			"",
			`    $ boundary sessions cancel -id s_1234567890`,
			"",
			"",
		})

	default:
		helpStr = helpMap["base"]()
	}

	return helpStr + c.Flags().Help()
}

func executeExtraActionsImpl(c *Command, origResult api.GenericResult, origError error, sessionClient *sessions.Client, version uint32, opts []sessions.Option) (api.GenericResult, error) {
	switch c.Func {
	case "cancel":
		return sessionClient.Cancel(c.Context, c.FlagId, version, opts...)
	}
	return origResult, origError
}

func (c *Command) printListTable(items []*sessions.Session) string {
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
		if item.Id != "" {
			output = append(output,
				fmt.Sprintf("  ID:                    %s", item.Id),
			)
		} else {
			output = append(output,
				fmt.Sprintf("  ID:                    %s", "(not available)"),
			)
		}
		if c.FlagRecursive && item.ScopeId != "" {
			output = append(output,
				fmt.Sprintf("    Scope ID:            %s", item.ScopeId),
			)
		}
		if item.Status != "" {
			output = append(output,
				fmt.Sprintf("    Status:              %s", item.Status),
			)
		}
		if !item.CreatedTime.IsZero() {
			output = append(output,
				fmt.Sprintf("    Created Time:        %s", item.CreatedTime.Local().Format(time.RFC1123)),
			)
		}
		if !item.ExpirationTime.IsZero() {
			output = append(output,
				fmt.Sprintf("    Expiration Time:     %s", item.ExpirationTime.Local().Format(time.RFC1123)),
			)
		}
		if !item.UpdatedTime.IsZero() {
			output = append(output,
				fmt.Sprintf("    Updated Time:        %s", item.UpdatedTime.Local().Format(time.RFC1123)),
			)
		}
		if item.UserId != "" {
			output = append(output,
				fmt.Sprintf("    User ID:             %s", item.UserId),
			)
		}
		if item.TargetId != "" {
			output = append(output,
				fmt.Sprintf("    Target ID:           %s", item.TargetId),
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

func printItemTable(result api.GenericResult) string {
	item := result.GetItem().(*sessions.Session)
	nonAttributeMap := map[string]interface{}{}
	if item.Id != "" {
		nonAttributeMap["ID"] = item.Id
	}
	if item.Version != 0 {
		nonAttributeMap["Version"] = item.Version
	}
	if item.Type != "" {
		nonAttributeMap["Type"] = item.Type
	}
	if !item.CreatedTime.IsZero() {
		nonAttributeMap["Created Time"] = item.CreatedTime.Local().Format(time.RFC1123)
	}
	if !item.UpdatedTime.IsZero() {
		nonAttributeMap["Updated Time"] = item.UpdatedTime.Local().Format(time.RFC1123)
	}
	if !item.ExpirationTime.IsZero() {
		nonAttributeMap["Expiration Time"] = item.ExpirationTime.Local().Format(time.RFC1123)
	}
	if item.TargetId != "" {
		nonAttributeMap["Target ID"] = item.TargetId
	}
	if item.AuthTokenId != "" {
		nonAttributeMap["Auth Token ID"] = item.AuthTokenId
	}
	if item.UserId != "" {
		nonAttributeMap["User ID"] = item.UserId
	}
	if item.HostSetId != "" {
		nonAttributeMap["Host Set ID"] = item.HostSetId
	}
	if item.HostId != "" {
		nonAttributeMap["Host ID"] = item.HostId
	}
	if item.Endpoint != "" {
		nonAttributeMap["Endpoint"] = item.Endpoint
	}
	if item.Status != "" {
		nonAttributeMap["Status"] = item.Status
	}
	if len(strings.TrimSpace(item.TerminationReason)) > 0 {
		nonAttributeMap["Termination Reason"] = item.TerminationReason
	}

	maxLength := base.MaxAttributesLength(nonAttributeMap, nil, nil)

	var statesMaps []map[string]interface{}
	if len(item.States) > 0 {
		for _, state := range item.States {
			m := map[string]interface{}{
				"Status":     state.Status,
				"Start Time": state.StartTime.Local().Format(time.RFC1123),
			}
			if !state.EndTime.IsZero() {
				m["End Time"] = state.EndTime.Local().Format(time.RFC1123)
			}
			statesMaps = append(statesMaps, m)
		}
		if l := len("Start Time"); l > maxLength {
			maxLength = l
		}
	}

	var workerInfoMaps []map[string]interface{}
	if len(item.WorkerInfo) > 0 {
		for _, wi := range item.WorkerInfo {
			m := map[string]interface{}{
				"Address": wi.Address,
			}
			workerInfoMaps = append(workerInfoMaps, m)
		}
		if l := len("Address"); l > maxLength {
			maxLength = l
		}
	}

	ret := []string{
		"",
		"Session information:",
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

	if len(item.States) > 0 {
		ret = append(ret,
			"",
			"  States:",
		)
		for _, m := range statesMaps {
			ret = append(ret,
				base.WrapMap(4, maxLength, m),
				"",
			)
		}
	}

	if len(item.WorkerInfo) > 0 {
		ret = append(ret,
			fmt.Sprintf("  Worker Info:   %s", ""),
		)
		for _, m := range workerInfoMaps {
			ret = append(ret,
				base.WrapMap(4, maxLength, m),
				"",
			)
		}
	}

	return base.WrapForHelpText(ret)
}
