package authtokenscmd

import (
	"fmt"
	"time"

	"github.com/hashicorp/boundary/api/authtokens"
	"github.com/hashicorp/boundary/internal/cmd/base"
)

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
		if true {
			output = append(output,
				fmt.Sprintf("  ID:                            %s", t.Id),
			)
		}
		if c.FlagRecursive {
			output = append(output,
				fmt.Sprintf("    Scope ID:                    %s", t.Scope.Id),
			)
		}
		if true {
			output = append(output,
				fmt.Sprintf("    Approximate Last Used Time:  %s", t.ApproximateLastUsedTime.Local().Format(time.RFC1123)),
				fmt.Sprintf("    Auth Method ID:              %s", t.AuthMethodId),
				fmt.Sprintf("    Created Time:                %s", t.CreatedTime.Local().Format(time.RFC1123)),
				fmt.Sprintf("    Expiration Time:             %s", t.ExpirationTime.Local().Format(time.RFC1123)),
				fmt.Sprintf("    Updated Time:                %s", t.UpdatedTime.Local().Format(time.RFC1123)),
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

func printItemTable(in *authtokens.AuthToken) string {
	nonAttributeMap := map[string]interface{}{
		"ID":                         in.Id,
		"Auth Method ID":             in.AuthMethodId,
		"User ID":                    in.UserId,
		"Created Time":               in.CreatedTime.Local().Format(time.RFC1123),
		"Updated Time":               in.UpdatedTime.Local().Format(time.RFC1123),
		"Expiration Time":            in.ExpirationTime.Local().Format(time.RFC1123),
		"Approximate Last Used Time": in.ApproximateLastUsedTime.Local().Format(time.RFC1123),
	}

	maxLength := base.MaxAttributesLength(nonAttributeMap, nil, nil)

	ret := []string{
		"",
		"Auth Token information:",
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

	return base.WrapForHelpText(ret)
}
