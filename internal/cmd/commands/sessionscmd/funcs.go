// Copyright IBM Corp. 2020, 2025
// SPDX-License-Identifier: BUSL-1.1

package sessionscmd

import (
	"fmt"
	"net"
	"strconv"
	"strings"
	"time"

	"github.com/hashicorp/boundary/api"
	"github.com/hashicorp/boundary/api/sessions"
	"github.com/hashicorp/boundary/internal/cmd/base"
)

const (
	flagIncludeTerminated = "include-terminated"
)

func init() {
	extraActionsFlagsMapFunc = extraActionsFlagsMapFuncImpl
	extraFlagsFunc = extraFlagsFuncImpl
	extraFlagsHandlingFunc = extraFlagsHandlingFuncImpl
	executeExtraActions = executeExtraActionsImpl
}

func extraActionsFlagsMapFuncImpl() map[string][]string {
	return map[string][]string{
		"cancel": {"id"},
		"list":   {flagIncludeTerminated},
	}
}

type extraCmdVars struct {
	flagIncludeTerminated bool
}

func extraFlagsFuncImpl(c *Command, set *base.FlagSets, f *base.FlagSet) {
	for _, name := range flagsMap[c.Func] {
		switch name {
		case flagIncludeTerminated:
			f.BoolVar(&base.BoolVar{
				Name:   flagIncludeTerminated,
				Target: &c.flagIncludeTerminated,
				Usage:  "If set, terminated sessions will be included in the results.",
			})
		}
	}
}

func extraFlagsHandlingFuncImpl(c *Command, _ *base.FlagSets, opts *[]sessions.Option) bool {
	if c.flagIncludeTerminated {
		*opts = append(*opts, sessions.WithIncludeTerminated(c.flagIncludeTerminated))
	}
	return true
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

func executeExtraActionsImpl(c *Command, origResp *api.Response, origItem *sessions.Session, origItems []*sessions.Session, origError error, sessionClient *sessions.Client, version uint32, opts []sessions.Option) (*api.Response, *sessions.Session, []*sessions.Session, error) {
	switch c.Func {
	case "cancel":
		result, err := sessionClient.Cancel(c.Context, c.FlagId, version, opts...)
		if err != nil {
			return nil, nil, nil, err
		}
		return result.GetResponse(), result.GetItem(), nil, err
	}
	return origResp, origItem, origItems, origError
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

func printItemTable(item *sessions.Session, resp *api.Response) string {
	nonAttributeMap := map[string]any{}
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

	var statesMaps []map[string]any
	if len(item.States) > 0 {
		for _, state := range item.States {
			m := map[string]any{
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

	var connectionsMaps []map[string]any
	for _, sc := range item.Connections {
		cm := map[string]any{
			"Client Address":   net.JoinHostPort(sc.ClientTcpAddress, strconv.FormatUint(uint64(sc.ClientTcpPort), 10)),
			"Endpoint Address": net.JoinHostPort(sc.EndpointTcpAddress, strconv.FormatUint(uint64(sc.EndpointTcpPort), 10)),
			"Bytes Up":         sc.BytesUp,
			"Bytes Down":       sc.BytesDown,
		}
		if len(sc.ClosedReason) != 0 {
			cm["Closed Reason"] = sc.ClosedReason
		}
		connectionsMaps = append(connectionsMaps, cm)
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

	if len(item.Connections) > 0 {
		ret = append(ret,
			"",
			"  Connections:",
		)
		for _, c := range connectionsMaps {
			ret = append(ret,
				base.WrapMap(4, maxLength, c),
				"",
			)
		}
	}

	return base.WrapForHelpText(ret)
}
