// Copyright IBM Corp. 2020, 2025
// SPDX-License-Identifier: BUSL-1.1

package authtokenscmd

import (
	"errors"
	"fmt"
	"time"

	"github.com/hashicorp/boundary/api"
	"github.com/hashicorp/boundary/api/authtokens"
	"github.com/hashicorp/boundary/internal/cmd/base"
	"github.com/hashicorp/go-secure-stdlib/strutil"
)

const selfFlag = "self"

func init() {
	extraFlagsHandlingFunc = extraFlagsHandlingFuncImpl
}

func extraFlagsHandlingFuncImpl(c *Command, _ *base.FlagSets, _ *[]authtokens.Option) bool {
	if c.Func != "delete" && c.Func != "read" {
		if strutil.StrListContains(flagsMap[c.Func], "id") && c.FlagId == "" {
			c.PrintCliError(errors.New("ID is required but not passed in via -id"))
			return false
		}
		return true
	}

	if c.FlagId == "" {
		fmt.Printf("No ID provided; %s the stored token? (Pass an ID of %q to suppress this question.) y/n: ", c.Func, selfFlag)
		var yesNo string
		fmt.Scanf("%s", &yesNo)
		switch yesNo {
		case "y", "Y":
			c.FlagId = selfFlag
		default:
			c.PrintCliError(errors.New(`"Y" or "y" not provided, refusing to continue`))
			return false
		}
	}

	if c.FlagId == selfFlag {
		// We should have already read this and have it cached
		client, err := c.Client()
		if err != nil {
			c.PrintCliError(fmt.Errorf("Error reading cached API client: %w", err))
			return false
		}
		c.FlagId, err = base.TokenIdFromToken(client.Token())
		if err != nil {
			c.PrintCliError(err)
			return false
		}
	}

	return true
}

func (c *Command) printListTable(items []*authtokens.AuthToken) string {
	if len(items) == 0 {
		return "No auth tokens found"
	}

	var output []string
	output = []string{
		"",
		"Auth Token information:",
	}
	for i, t := range items {
		if i > 0 {
			output = append(output, "")
		}
		if t.Id != "" {
			output = append(output,
				fmt.Sprintf("  ID:                            %s", t.Id),
			)
		}
		if c.FlagRecursive && t.ScopeId != "" {
			output = append(output,
				fmt.Sprintf("    Scope ID:                    %s", t.ScopeId),
			)
		}
		if !t.ApproximateLastUsedTime.IsZero() {
			output = append(output,
				fmt.Sprintf("    Approximate Last Used Time:  %s", t.ApproximateLastUsedTime.Local().Format(time.RFC1123)),
			)
		}
		if t.AuthMethodId != "" {
			output = append(output,
				fmt.Sprintf("    Auth Method ID:              %s", t.AuthMethodId),
			)
		}
		if !t.CreatedTime.IsZero() {
			output = append(output,
				fmt.Sprintf("    Created Time:                %s", t.CreatedTime.Local().Format(time.RFC1123)),
			)
		}
		if !t.ExpirationTime.IsZero() {
			output = append(output,
				fmt.Sprintf("    Expiration Time:             %s", t.ExpirationTime.Local().Format(time.RFC1123)),
			)
		}
		if !t.UpdatedTime.IsZero() {
			output = append(output,
				fmt.Sprintf("    Updated Time:                %s", t.UpdatedTime.Local().Format(time.RFC1123)),
			)
		}
		if t.UserId != "" {
			output = append(output,
				fmt.Sprintf("    User ID:                     %s", t.UserId),
			)
		}
		if len(t.AuthorizedActions) > 0 {
			output = append(output,
				"    Authorized Actions:",
				base.WrapSlice(6, t.AuthorizedActions),
			)
		}
	}

	return base.WrapForHelpText(output)
}

func printItemTable(item *authtokens.AuthToken, resp *api.Response) string {
	nonAttributeMap := map[string]any{
		"ID":                         item.Id,
		"Auth Method ID":             item.AuthMethodId,
		"User ID":                    item.UserId,
		"Created Time":               item.CreatedTime.Local().Format(time.RFC1123),
		"Updated Time":               item.UpdatedTime.Local().Format(time.RFC1123),
		"Expiration Time":            item.ExpirationTime.Local().Format(time.RFC1123),
		"Approximate Last Used Time": item.ApproximateLastUsedTime.Local().Format(time.RFC1123),
	}

	maxLength := base.MaxAttributesLength(nonAttributeMap, nil, nil)

	ret := []string{
		"",
		"Auth Token information:",
		base.WrapMap(2, maxLength+2, nonAttributeMap),
		"",
		"  Scope:",
		base.ScopeInfoForOutput(item.Scope, maxLength),
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
