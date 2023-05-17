// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package sessionrecordingscmd

import (
	"fmt"
	"strings"
	"time"

	"github.com/hashicorp/boundary/api"
	"github.com/hashicorp/boundary/api/sessionrecordings"
	"github.com/hashicorp/boundary/internal/cmd/base"
)

type extraCmdVars struct{}

func (c *Command) extraHelpFunc(helpMap map[string]func() string) string {
	var helpStr string
	switch c.Func {
	case "":
		return base.WrapForHelpText([]string{
			"Usage: boundary session-recordings [sub command] [options] [args]",
			"",
			"  This command allows operations on Boundary session recordings.",
			"",
			"    Read a session recording:",
			"",
			`      $ boundary session-recordings read -id s_1234567890`,
			"",
			"  Please see the sessions subcommand help for detailed usage information.",
		})

	default:
		helpStr = helpMap["base"]()
	}

	return helpStr + c.Flags().Help()
}

func (c *Command) printListTable(items []*sessionrecordings.SessionRecording) string {
	if len(items) == 0 {
		return "No session recordings found"
	}
	var output []string
	output = []string{
		"",
		"Session Recording information:",
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
		if c.FlagRecursive && item.Scope.Id != "" {
			output = append(output,
				fmt.Sprintf("    Scope ID:            %s", item.Scope.Id),
			)
		}
		if item.SessionId != "" {
			output = append(output,
				fmt.Sprintf("    Session ID:          %s", item.SessionId),
			)
		}
		if item.StorageBucketId != "" {
			output = append(output,
				fmt.Sprintf("    Storage Bucket ID:   %s", item.StorageBucketId),
			)
		}
		if !item.StartTime.IsZero() {
			output = append(output,
				fmt.Sprintf("    Start Time:          %s", item.StartTime.Local().Format(time.RFC1123)),
			)
		}
		if !item.EndTime.IsZero() {
			output = append(output,
				fmt.Sprintf("    End Time:            %s", item.EndTime.Local().Format(time.RFC1123)),
			)
		}
		if item.Type != "" {
			output = append(output,
				fmt.Sprintf("    Type:                %s", item.Type),
			)
		}
		if item.State != "" {
			output = append(output,
				fmt.Sprintf("    State:               %s", item.State),
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

func printItemTable(item *sessionrecordings.SessionRecording, resp *api.Response) string {
	const (
		durationKey = "Duration (Seconds)"
	)
	nonAttributeMap := map[string]any{}
	if item.Id != "" {
		nonAttributeMap["ID"] = item.Id
	}
	if item.Scope.Id != "" {
		nonAttributeMap["Scope ID"] = item.Scope.Id
	}
	if item.SessionId != "" {
		nonAttributeMap["Session ID"] = item.SessionId
	}
	if item.StorageBucketId != "" {
		nonAttributeMap["Storage Bucket ID"] = item.StorageBucketId
	}
	if item.BytesUp != 0 {
		nonAttributeMap["Bytes Up"] = item.BytesUp
	}
	if item.BytesDown != 0 {
		nonAttributeMap["Bytes Down"] = item.BytesDown
	}
	if !item.StartTime.IsZero() {
		nonAttributeMap["Start Time"] = item.StartTime.Local().Format(time.RFC1123)
	}
	if !item.EndTime.IsZero() {
		nonAttributeMap["Updated Time"] = item.EndTime.Local().Format(time.RFC1123)
	}
	if item.Duration.Duration != 0 {
		nonAttributeMap[durationKey] = item.Duration.Seconds()
	}
	if item.Type != "" {
		nonAttributeMap["Type"] = item.Type
	}
	if item.State != "" {
		nonAttributeMap["State"] = item.State
	}
	if item.ErrorDetails != "" {
		nonAttributeMap["Error Details"] = item.ErrorDetails
	}
	if len(item.MimeTypes) > 0 {
		nonAttributeMap["Mime Types"] = strings.Join(item.MimeTypes, ", ")
	}
	if item.Endpoint != "" {
		nonAttributeMap["Endpoint"] = item.Endpoint
	}

	maxLength := base.MaxAttributesLength(nonAttributeMap, nil, nil)

	ret := []string{
		"",
		"Session Recording information:",
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

	if len(item.ConnectionRecordings) > 0 {
		maxAttrLen := len(durationKey)
		ret = append(ret,
			"",
			"  Connections Recordings:",
		)
		for _, cr := range item.ConnectionRecordings {
			cm := map[string]any{
				"ID":            cr.Id,
				"Connection ID": cr.ConnectionId,
			}
			if cr.BytesUp != 0 {
				cm["Bytes Up"] = cr.BytesUp
			}
			if cr.BytesDown != 0 {
				cm["Bytes Down"] = cr.BytesDown
			}
			if !cr.StartTime.IsZero() {
				cm["Start Time"] = cr.StartTime.Local().Format(time.RFC1123)
			}
			if !cr.EndTime.IsZero() {
				cm["End Time"] = cr.EndTime.Local().Format(time.RFC1123)
			}
			if cr.Duration.Duration != 0 {
				cm[durationKey] = cr.Duration.Seconds()
			}
			if len(cr.MimeTypes) > 0 {
				cm["Mime Types"] = strings.Join(cr.MimeTypes, ", ")
			}
			ret = append(ret,
				base.WrapMap(4, maxAttrLen, cm),
				"",
			)

			if len(cr.ChannelRecordings) > 0 {
				var channelRecordings []map[string]any
				for _, chr := range cr.ChannelRecordings {
					chrm := map[string]any{
						"ID": chr.Id,
					}
					if chr.BytesUp != 0 {
						chrm["Bytes Up"] = chr.BytesUp
					}
					if chr.BytesDown != 0 {
						chrm["Bytes Down"] = chr.BytesDown
					}
					if !chr.StartTime.IsZero() {
						chrm["Start Time"] = chr.StartTime.Local().Format(time.RFC1123)
					}
					if !chr.EndTime.IsZero() {
						chrm["End Time"] = chr.EndTime.Local().Format(time.RFC1123)
					}
					if chr.Duration.Duration != 0 {
						chrm[durationKey] = chr.Duration.Seconds()
					}
					if len(chr.MimeTypes) > 0 {
						chrm["Mine Types"] = strings.Join(chr.MimeTypes, ", ")
					}
					channelRecordings = append(channelRecordings, chrm)
				}
				ret = append(ret,
					"",
					"    Channel Recordings:",
				)
				for _, cr := range channelRecordings {
					ret = append(ret,
						base.WrapMap(6, maxAttrLen, cr),
						"",
					)
				}
			}
		}
	}
	return base.WrapForHelpText(ret)
}
