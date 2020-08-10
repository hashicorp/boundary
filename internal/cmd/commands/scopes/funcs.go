package scopes

import (
	"fmt"
	"time"

	"github.com/hashicorp/boundary/api/scopes"
	"github.com/hashicorp/boundary/internal/cmd/base"
)

func printScope(in *scopes.Scope) string {
	var ret []string
	// This if true is here to line up columns for easy editing
	if true {
		ret = append(ret, []string{
			"",
			"Scope information:",
			fmt.Sprintf("  ID:           %s", in.Id),
			fmt.Sprintf("  Created Time: %s", in.CreatedTime.Local().Format(time.RFC3339)),
			fmt.Sprintf("  Updated Time: %s", in.UpdatedTime.Local().Format(time.RFC3339)),
		}...,
		)
	}
	if in.Name != "" {
		ret = append(ret,
			fmt.Sprintf("  Name:         %s", in.Name),
		)
	}
	if in.Description != "" {
		ret = append(ret,
			fmt.Sprintf("  Description:  %s", in.Description),
		)
	}

	return base.WrapForHelpText(ret)
}
