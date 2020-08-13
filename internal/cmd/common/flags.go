package common

import (
	"fmt"

	"github.com/hashicorp/boundary/internal/cmd/base"
	"github.com/hashicorp/boundary/internal/types/resource"
)

func PopulateCommonFlags(c *base.Command, f *base.FlagSet, resourceType resource.Type, flagNames []string) {
	for _, name := range flagNames {
		switch name {
		case "id":
			f.StringVar(&base.StringVar{
				Name:   "id",
				Target: &c.FlagId,
				Usage:  fmt.Sprintf("ID of the %s on which to operate", resourceType.String()),
			})
		case "name":
			f.StringVar(&base.StringVar{
				Name:   "name",
				Target: &c.FlagName,
				Usage:  fmt.Sprintf("Name to set on the %s", resourceType.String()),
			})
		case "description":
			f.StringVar(&base.StringVar{
				Name:   "description",
				Target: &c.FlagDescription,
				Usage:  fmt.Sprintf("Description to set on the %s", resourceType.String()),
			})
		case "version":
			f.IntVar(&base.IntVar{
				Name:   "version",
				Target: &c.FlagVersion,
				Usage:  fmt.Sprintf("The version of the %s against which to perform an update operation. If not specified, the command will perform a check-and-set automatically.", resourceType.String()),
			})
		}
	}
}
