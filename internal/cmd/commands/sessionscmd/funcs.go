package sessionscmd

import (
	"fmt"
	"strings"
	"time"

	"github.com/hashicorp/boundary/api"
	"github.com/hashicorp/boundary/api/sessions"
	"github.com/hashicorp/boundary/internal/cmd/base"
)

var extraActionsFlagsMap = map[string][]string{
	"cancel": {"id"},
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

func (c *Command) executeExtraActions(origResult api.GenericResult, origError error, sessionClient *sessions.Client, version uint32, opts []sessions.Option) (api.GenericResult, error) {
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
		if true {
			output = append(output,
				fmt.Sprintf("  ID:                    %s", item.Id),
			)
		}
		if c.FlagRecursive {
			output = append(output,
				fmt.Sprintf("    Scope ID:            %s", item.Scope.Id),
			)
		}
		if true {
			output = append(output,
				fmt.Sprintf("    Status:              %s", item.Status),
				fmt.Sprintf("    Created Time:        %s", item.CreatedTime.Local().Format(time.RFC1123)),
				fmt.Sprintf("    Expiration Time:     %s", item.ExpirationTime.Local().Format(time.RFC1123)),
				fmt.Sprintf("    Updated Time:        %s", item.UpdatedTime.Local().Format(time.RFC1123)),
				fmt.Sprintf("    User ID:             %s", item.UserId),
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

func printItemTable(in *sessions.Session) string {
	nonAttributeMap := map[string]interface{}{
		"ID":              in.Id,
		"Target ID":       in.TargetId,
		"Created Time":    in.CreatedTime.Local().Format(time.RFC1123),
		"Updated Time":    in.UpdatedTime.Local().Format(time.RFC1123),
		"Expiration Time": in.ExpirationTime.Local().Format(time.RFC1123),
		"Version":         in.Version,
		"Type":            in.Type,
		"Auth Token ID":   in.AuthTokenId,
		"User ID":         in.UserId,
		"Host Set ID":     in.HostSetId,
		"Host ID":         in.HostId,
		"Endpoint":        in.Endpoint,
		"Status":          in.Status,
	}
	if len(strings.TrimSpace(in.TerminationReason)) > 0 {
		nonAttributeMap["Termination Reason"] = in.TerminationReason
	}

	maxLength := base.MaxAttributesLength(nonAttributeMap, nil, nil)

	var statesMaps []map[string]interface{}
	if len(in.States) > 0 {
		for _, state := range in.States {
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
	if len(in.WorkerInfo) > 0 {
		for _, wi := range in.WorkerInfo {
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
		"",
		"  Scope:",
		base.ScopeInfoForOutput(in.Scope, maxLength),
	}

	if len(in.AuthorizedActions) > 0 {
		ret = append(ret,
			"",
			"  Authorized Actions:",
			base.WrapSlice(4, in.AuthorizedActions),
		)
	}

	if len(in.States) > 0 {
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

	if len(in.WorkerInfo) > 0 {
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
