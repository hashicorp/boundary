package common

import (
	"fmt"
	"net/textproto"
	"strings"

	"github.com/hashicorp/boundary/internal/cmd/base"
	"github.com/hashicorp/boundary/internal/types/resource"
	"github.com/mitchellh/go-wordwrap"
)

func SynopsisFunc(inFunc, resType string) string {
	if inFunc == "" {
		return wordwrap.WrapString(fmt.Sprintf("Manage Boundary %ss", resType), base.TermWidth)
	}
	articleType := resType
	switch resType[0] {
	case 'a', 'e', 'i', 'o':
		articleType = fmt.Sprintf("an %s", articleType)
	default:
		articleType = fmt.Sprintf("a %s", articleType)
	}
	return wordwrap.WrapString(fmt.Sprintf("%s %s within Boundary", textproto.CanonicalMIMEHeaderKey(inFunc), articleType), base.TermWidth)
}

func HelpMap(resType string) map[string]func() string {
	prefixMap := map[string]string{
		resource.Scope.String():      "o",
		resource.AuthToken.String():  "at",
		resource.AuthMethod.String(): "am",
		resource.Role.String():       "r",
		resource.Group.String():      "g",
		resource.User.String():       "u",
	}
	return map[string]func() string{
		"base": func() string {
			return base.WrapForHelpText(subType([]string{
				"Usage: boundary {{type}}s [sub command] [options] [args]",
				"",
				"  This command allows operations on Boundary {{type}} resources. Examples",
				"",
				"    Create {{articletype}}:",
				"",
				`      $ boundary {{type}}s create -name prodops -description "For ProdOps usage"`,
				"",
				"  Please see the {{type}}s subcommand help for detailed usage information.",
			}, resType, prefixMap))
		},

		"create": func() string {
			return base.WrapForHelpText(subType([]string{
				"Usage: boundary {{type}}s create [options] [args]",
				"",
				"  Create {{articletype}}. Example:",
				"",
				`    $ boundary {{type}}s create -name prodops -description "{{uppertype}} for ProdOps"`,
				"",
				"",
			}, resType, prefixMap))
		},

		"update": func() string {
			return base.WrapForHelpText(subType([]string{
				"Usage: boundary {{type}}s update [options] [args]",
				"",
				"  Update {{articletype}} given its ID. Example:",
				"",
				`    $ boundary {{type}}s update -id {{prefix}}_1234567890 -name "devops" -description "{{uppertype}} for DevOps"`,
			}, resType, prefixMap))
		},

		"read": func() string {
			return base.WrapForHelpText(subType([]string{
				"Usage: boundary {{type}}s read [options] [args]",
				"",
				"  Read {{articletype}} given its ID. Example:",
				"",
				`    $ boundary {{type}}s read -id {{prefix}}_1234567890`,
			}, resType, prefixMap))
		},

		"delete": func() string {
			return base.WrapForHelpText(subType([]string{
				"Usage: boundary {{type}}s delete [options] [args]",
				"",
				"  Delete {{articletype}} given its ID. Example:",
				"",
				`    $ boundary {{type}}s delete -id {{prefix}}_1234567890`,
			}, resType, prefixMap))
		},

		"list": func() string {
			return base.WrapForHelpText(subType([]string{
				"Usage: boundary {{type}}s list [options] [args]",
				"",
				"  List {{type}}s within an enclosing scope or resource. Example:",
				"",
				`    $ boundary {{type}}s list`,
			}, resType, prefixMap))
		},
	}
}

func subType(in []string, resType string, prefixMap map[string]string) []string {
	articleType := resType
	switch resType[0] {
	case 'a', 'e', 'i', 'o':
		articleType = fmt.Sprintf("an %s", articleType)
	default:
		articleType = fmt.Sprintf("a %s", articleType)
	}
	for i, v := range in {
		in[i] =
			strings.Replace(
				strings.Replace(
					strings.Replace(
						strings.Replace(
							v, "{{type}}", resType, -1),
						"{{uppertype}}", textproto.CanonicalMIMEHeaderKey(resType), -1),
					"{{prefix}}", prefixMap[resType], -1),
				"{{articletype}}", articleType, -1)
	}
	return in
}
