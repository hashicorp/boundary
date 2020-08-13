package scopes

import (
	"fmt"
	"net/textproto"
	"time"

	"github.com/hashicorp/boundary/api/scopes"
	"github.com/hashicorp/boundary/internal/cmd/base"
	"github.com/mitchellh/go-wordwrap"
)

func synopsisFunc(inFunc string) string {
	if inFunc == "" {
		return wordwrap.WrapString("Manage Boundary scopes", base.TermWidth)
	}
	return wordwrap.WrapString(fmt.Sprintf("%s a scope within Boundary", textproto.CanonicalMIMEHeaderKey(inFunc)), base.TermWidth)
}

func baseHelp() string {
	return base.WrapForHelpText([]string{
		"Usage: boundary scopes [sub command] [options] [args]",
		"",
		"  This command allows operations on Boundary scopes. Examples:",
		"",
		"    Create a scope:",
		"",
		`      $ boundary scopes create -name myorg -description "For ProdOps usage"`,
		"",
		"  Please see the scopes subcommand help for detailed usage information.",
	})
}

func createHelp() string {
	return base.WrapForHelpText([]string{
		"Usage: boundary scopes create [options] [args]",
		"",
		"  Create a scope. Example:",
		"",
		`    $ boundary scopes create -name myorg -description "Org for engineering"`,
		"",
		"",
	})
}

func updateHelp() string {
	return base.WrapForHelpText([]string{
		"Usage: boundary scopes update [options] [args]",
		"",
		"  Update a scope given its ID. Example:",
		"",
		`    $ boundary scopes update -id p_1234567890 -description "Project for Team Bar"`,
	})
}

func readHelp() string {
	return base.WrapForHelpText([]string{
		"Usage: boundary scopes read [options] [args]",
		"",
		"  Read a scope given its ID. Example:",
		"",
		`    $ boundary scopes read -id p_1234567890`,
	})
}

func deleteHelp() string {
	return base.WrapForHelpText([]string{
		"Usage: boundary scopes delete [options] [args]",
		"",
		"  Delete a scope given its ID. Example:",
		"",
		`    $ boundary scopes delete -id p_1234567890`,
	})
}

func listHelp() string {
	return base.WrapForHelpText([]string{
		"Usage: boundary scopes list [options] [args]",
		"",
		"  List scopes within a parent scope. Example:",
		"",
		`    $ boundary scopes list -scope o_1234567890`,
	})
}

func generateScopeTableOutput(in *scopes.Scope) string {
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
