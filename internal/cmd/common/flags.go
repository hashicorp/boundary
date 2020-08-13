package common

import "github.com/hashicorp/boundary/internal/cmd/base"

func PopulateCommonFlags(c *base.Command, f *base.FlagSet, flagNames []string) {
	for _, name := range flagNames {
		switch name {
		case "id":
			f.StringVar(&base.StringVar{
				Name:   "id",
				Target: &c.FlagId,
				Usage:  "ID of the role to operate on",
			})
		case "name":
			f.StringVar(&base.StringVar{
				Name:   "name",
				Target: &c.FlagName,
				Usage:  "Name to set on the role",
			})
		case "description":
			f.StringVar(&base.StringVar{
				Name:   "description",
				Target: &c.FlagDescription,
				Usage:  "Description to set on the role",
			})
		case "version":
			f.IntVar(&base.IntVar{
				Name:   "version",
				Target: &c.FlagVersion,
				Usage:  "The version of the resource against which to perform an update operation. If not specified, the command will perform a check-and-set automatically.",
			})
		}
	}
}
