package common

import (
	"fmt"

	"github.com/hashicorp/boundary/internal/cmd/base"
	"github.com/posener/complete"
)

func PopulateCommonFlags(c *base.Command, f *base.FlagSet, resourceType string, flagNames []string) {
	for _, name := range flagNames {
		switch name {
		case "scope-id":
			f.StringVar(&base.StringVar{
				Name:       "scope-id",
				Target:     &c.FlagScopeId,
				EnvVar:     "BOUNDARY_SCOPE_ID",
				Default:    "global",
				Completion: complete.PredictAnything,
				Usage:      `Scope in which to make the request`,
			})
		case "id":
			f.StringVar(&base.StringVar{
				Name:   "id",
				Target: &c.FlagId,
				Usage:  fmt.Sprintf("ID of the %s on which to operate", resourceType),
			})
		case "name":
			f.StringVar(&base.StringVar{
				Name:   "name",
				Target: &c.FlagName,
				Usage:  fmt.Sprintf("Name to set on the %s", resourceType),
			})
		case "description":
			f.StringVar(&base.StringVar{
				Name:   "description",
				Target: &c.FlagDescription,
				Usage:  fmt.Sprintf("Description to set on the %s", resourceType),
			})
		case "version":
			f.IntVar(&base.IntVar{
				Name:   "version",
				Target: &c.FlagVersion,
				Usage:  fmt.Sprintf("The version of the %s against which to perform an update operation. If not specified, the command will perform a check-and-set automatically.", resourceType),
			})
		case "auth-method-id":
			f.StringVar(&base.StringVar{
				Name:   "auth-method-id",
				EnvVar: "BOUNDARY_AUTH_METHOD_ID",
				Target: &c.FlagAuthMethodId,
				Usage:  "The auth-method resource to use for the operation",
			})
		case "host-catalog-id":
			f.StringVar(&base.StringVar{
				Name:   "host-catalog-id",
				EnvVar: "BOUNDARY_HOST_CATALOG_ID",
				Target: &c.FlagHostCatalogId,
				Usage:  "The host-catalog resource to use for the operation",
			})
		}
	}
}
