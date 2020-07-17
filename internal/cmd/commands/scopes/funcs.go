package scopes

import (
	"fmt"
	"time"

	"github.com/hashicorp/watchtower/api/scopes"
	"github.com/hashicorp/watchtower/internal/cmd/base"
)

func printProject(in *scopes.Project) string {
	var ret []string
	// This if true is here to line up columns for easy editing
	if true {
		ret = append(ret, []string{
			"",
			"Project information:",
			fmt.Sprintf("  ID:           %s", in.Id),
			fmt.Sprintf("  Created Time: %s", in.CreatedTime.Local().Format(time.RFC3339)),
			fmt.Sprintf("  Updated Time: %s", in.UpdatedTime.Local().Format(time.RFC3339)),
		}...,
		)
	}
	if in.Name != nil {
		ret = append(ret,
			fmt.Sprintf("  Name:         %s", *in.Name),
		)
	}
	if in.Description != nil {
		ret = append(ret,
			fmt.Sprintf("  Description:  %s", *in.Description),
		)
	}

	return base.WrapForHelpText(ret)
}
