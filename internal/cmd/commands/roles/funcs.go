package roles

import (
	"fmt"
	"strings"

	"github.com/hashicorp/watchtower/internal/cmd/base"
	"github.com/mitchellh/go-wordwrap"
)

func synopsisFunc(inFunc string) string {
	return wordwrap.WrapString(fmt.Sprintf("%s a role within Watchtower", strings.ToTitle(inFunc)), 80)
}

func createHelp(flagHelp string) string {
	return base.WrapForHelpText([]string{
		"Usage: watchtower role create [options] [args]",
		"",
		"  Create a role. Example:",
		"",
		`    $ watchtower roles create -name ops -description "Role for ops grants"`,
	}) + flagHelp
}

func updateHelp(flagHelp string) string {
	return base.WrapForHelpText([]string{
		"Usage: watchtower role update [options] [args]",
		"",
		"  Update a role given its ID. Example:",
		"",
		`    $ watchtower roles update -id r_1234567890 -description "Development host grants"`,
	}) + flagHelp
}

func readHelp(flagHelp string) string {
	return base.WrapForHelpText([]string{
		"Usage: watchtower role read [options] [args]",
		"",
		"  Read a role given its ID. Example:",
		"",
		`    $ watchtower roles read -id r_1234567890`,
	}) + flagHelp
}

func deleteHelp(flagHelp string) string {
	return base.WrapForHelpText([]string{
		"Usage: watchtower role delete [options] [args]",
		"",
		"  Delete a role given its ID. Example:",
		"",
		`    $ watchtower roles delete -id r_1234567890`,
	}) + flagHelp
}

func listHelp(flagHelp string) string {
	return base.WrapForHelpText([]string{
		"Usage: watchtower role list [options] [args]",
		"",
		"  List roles within a scope. Example:",
		"",
		`    $ watchtower roles list -org o_1234567890`,
	}) + flagHelp
}

func populateFlags(c *CRUDLCommand, f *base.FlagSet, flagNames []string) {
	for _, name := range flagNames {
		switch name {
		case "id":
			f.StringVar(&base.StringVar{
				Name:   "id",
				Target: &c.flagId,
				Usage:  "ID of the role to operate on",
			})
		case "name":
			f.StringVar(&base.StringVar{
				Name:   "name",
				Target: &c.flagName,
				Usage:  "Name to set on the role",
			})
		case "description":
			f.StringVar(&base.StringVar{
				Name:   "description",
				Target: &c.flagDescription,
				Usage:  "Description to set on the role",
			})
		case "grantscopeid":
			f.StringVar(&base.StringVar{
				Name:   "grant-scope-id",
				Target: &c.flagGrantScopeId,
				Usage:  "The scope ID for grants set on the role",
			})
		}
	}
}
