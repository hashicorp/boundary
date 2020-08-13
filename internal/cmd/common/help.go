package common

import (
	"fmt"
	"net/textproto"
	"strings"

	"github.com/hashicorp/boundary/internal/cmd/base"
	"github.com/hashicorp/boundary/internal/types/resource"
	"github.com/mitchellh/go-wordwrap"
)

func SynopsisFunc(inFunc, resourceType string) string {
	if inFunc == "" {
		return wordwrap.WrapString(fmt.Sprintf("Manage Boundary %ss", resourceType), base.TermWidth)
	}
	return wordwrap.WrapString(fmt.Sprintf("%s a %s within Boundary", textproto.CanonicalMIMEHeaderKey(inFunc), resourceType), base.TermWidth)
}

func HelpMap(resourceType resource.Type) map[string]func() string {
	prefixMap := map[string]string{
		resource.Scope.String(): "o",
		resource.Role.String():  "r",
		resource.Group.String(): "g",
		resource.User.String():  "u",
	}
	return map[string]func() string{
		"base": func() string {
			return base.WrapForHelpText(subType([]string{
				"Usage: boundary {{type}}s [sub command] [options] [args]",
				"",
				"  This command allows operations on Boundary {{type}}s. Examples",
				"",
				"    Create a {{type}}:",
				"",
				`      $ boundary {{type}}s create -name prodops -description "For ProdOps usage"`,
				"",
				"  Please see the {{type}}s subcommand help for detailed usage information.",
			}, resourceType, prefixMap))
		},

		"create": func() string {
			return base.WrapForHelpText(subType([]string{
				"Usage: boundary {{type}}s create [options] [args]",
				"",
				"  Create a {{type}}. Example:",
				"",
				`    $ boundary {{type}}s create -name prodops -description "{{uppertype}} for ProdOps"`,
				"",
				"",
			}, resourceType, prefixMap))
		},

		"update": func() string {
			return base.WrapForHelpText(subType([]string{
				"Usage: boundary {{type}}s update [options] [args]",
				"",
				"  Update a {{type}} given its ID. Example:",
				"",
				`    $ boundary {{type}}s update -id {{prefix}}_1234567890 -name "devops" -description "{{uppertype}} for DevOps"`,
			}, resourceType, prefixMap))
		},

		"read": func() string {
			return base.WrapForHelpText(subType([]string{
				"Usage: boundary {{type}}s read [options] [args]",
				"",
				"  Read a {{type}} given its ID. Example:",
				"",
				`    $ boundary {{type}}s read -id {{prefix}}_1234567890`,
			}, resourceType, prefixMap))
		},

		"delete": func() string {
			return base.WrapForHelpText(subType([]string{
				"Usage: boundary {{type}}s delete [options] [args]",
				"",
				"  Delete a {{type}} given its ID. Example:",
				"",
				`    $ boundary {{type}}s delete -id {{prefix}}_1234567890`,
			}, resourceType, prefixMap))
		},

		"list": func() string {
			return base.WrapForHelpText(subType([]string{
				"Usage: boundary {{type}}s list [options] [args]",
				"",
				"  List {{type}}s within an enclosing scope or resource. Example:",
				"",
				`    $ boundary {{type}}s list`,
			}, resourceType, prefixMap))
		},
	}
}

func subType(in []string, resType resource.Type, prefixMap map[string]string) []string {
	for i, v := range in {
		in[i] =
			strings.Replace(
				strings.Replace(
					strings.Replace(
						v, "{{type}}", resType.String(), -1),
					"{{uppertype}}", textproto.CanonicalMIMEHeaderKey(resType.String()), -1),
				"{{prefix}}", prefixMap[resType.String()], -1)
	}
	return in
}
