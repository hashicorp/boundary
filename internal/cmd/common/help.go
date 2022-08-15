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
	return wordwrap.WrapString(fmt.Sprintf("%s %s", textproto.CanonicalMIMEHeaderKey(inFunc), articleType), base.TermWidth)
}

var prefixMap = map[string]string{
	resource.Scope.String():       "o",
	resource.AuthToken.String():   "at",
	resource.AuthMethod.String():  "am",
	resource.Account.String():     "a",
	resource.Role.String():        "r",
	resource.Group.String():       "g",
	resource.User.String():        "u",
	resource.HostCatalog.String(): "hc",
	resource.HostSet.String():     "hs",
	resource.Host.String():        "h",
	resource.Session.String():     "s",
	resource.Target.String():      "t",
	resource.Worker.String():      "w",
}

func HelpMap(resType string) map[string]func() string {
	return map[string]func() string{
		"base": func() string {
			return base.WrapForHelpText(subtype([]string{
				"Usage: boundary {{hyphentype}}s [sub command] [options] [args]",
				"",
				"  This command allows operations on Boundary {{type}} resources. Example:",
				"",
				"    Create {{articletype}}:",
				"",
				`      $ boundary {{hyphentype}}s create -name prodops -description "For ProdOps usage"`,
				"",
				"  Please see the {{hyphentype}}s subcommand help for detailed usage information.",
			}, resType, prefixMap))
		},

		"create": func() string {
			return base.WrapForHelpText(subtype([]string{
				"Usage: boundary {{hyphentype}}s create [options] [args]",
				"",
				"  Create {{articletype}}. Example:",
				"",
				`    $ boundary {{hyphentype}}s create -name prodops -description "{{uppertype}} for ProdOps"`,
				"",
				"",
			}, resType, prefixMap))
		},

		"update": func() string {
			return base.WrapForHelpText(subtype([]string{
				"Usage: boundary {{hyphentype}}s update [options] [args]",
				"",
				"  Update {{articletype}} given its ID. Example:",
				"",
				`    $ boundary {{hyphentype}}s update -id {{prefix}}_1234567890 -name "devops" -description "{{uppertype}} for DevOps"`,
				"",
				"",
			}, resType, prefixMap))
		},

		"read": func() string {
			return base.WrapForHelpText(subtype([]string{
				"Usage: boundary {{hyphentype}}s read [options] [args]",
				"",
				"  Read {{articletype}} given its ID. Example:",
				"",
				`    $ boundary {{hyphentype}}s read -id {{prefix}}_1234567890`,
				"",
				"",
			}, resType, prefixMap))
		},

		"delete": func() string {
			return base.WrapForHelpText(subtype([]string{
				"Usage: boundary {{hyphentype}}s delete [options] [args]",
				"",
				"  Delete {{articletype}} given its ID. Example:",
				"",
				`    $ boundary {{hyphentype}}s delete -id {{prefix}}_1234567890`,
				"",
				"",
			}, resType, prefixMap))
		},

		"list": func() string {
			return base.WrapForHelpText(subtype([]string{
				"Usage: boundary {{hyphentype}}s list [options] [args]",
				"",
				"  List {{type}}s within an enclosing scope or resource. Example:",
				"",
				`    $ boundary {{hyphentype}}s list`,
				"",
				"",
			}, resType, prefixMap))
		},
	}
}

func addSetRemoveActionText(fn, unit, textExample string) string {
	switch fn {
	case "add":
		return fmt.Sprintf("Add %ss %sto", unit, textExample)
	case "set":
		return fmt.Sprintf("Set the full contents of %ss %son", unit, textExample)
	case "remove":
		return fmt.Sprintf("Remove %ss %sfrom", unit, textExample)
	}
	return "Unknown"
}

func HelpAddSetRemoveMap(resType, unit, cmdExample, textExample string) map[string]func() string {
	ret := map[string]func() string{}
	for _, outerAction := range []string{"add", "set", "remove"} {
		action := outerAction // Bind it locally or it gets overwritten in the end
		ret[fmt.Sprintf("%s-%ss", action, unit)] = func() string {
			actionText := addSetRemoveActionText(action, unit, textExample)
			return base.WrapForHelpText(subtype([]string{
				fmt.Sprintf("Usage: boundary {{hyphentype}}s %s-%ss [options] [args]", action, unit),
				"",
				fmt.Sprintf(`  %s a %s given its ID. The "%s" flag can be specified multiple times. Example:`, actionText, resType, unit),
				"",
				fmt.Sprintf(`    $ boundary {{hyphentype}}s %s-%ss -id {{prefix}}_1234567890 -%s %s`, action, unit, unit, cmdExample),
				"",
				"",
			}, resType, prefixMap))
		}
	}
	return ret
}

func SynopsisAddSetRemoveFunc(resType, unit, textExample string) map[string]func() string {
	ret := map[string]func() string{}
	for _, outerAction := range []string{"add", "set", "remove"} {
		action := outerAction // Bind it locally or it gets overwritten in the end
		ret[fmt.Sprintf("%s-%ss", action, unit)] = func() string {
			actionText := addSetRemoveActionText(action, unit, textExample)
			return wordwrap.WrapString(fmt.Sprintf("%s a %s", actionText, resType), base.TermWidth)
		}
	}
	return ret
}

func subtype(in []string, resType string, prefixMap map[string]string) []string {
	hyphenType := strings.ReplaceAll(resType, " ", "-")
	articleType := resType
	switch resType[0] {
	case 'a', 'e', 'i', 'o':
		articleType = fmt.Sprintf("an %s", articleType)
	default:
		articleType = fmt.Sprintf("a %s", articleType)
	}
	for i, v := range in {
		in[i] = strings.Replace(
			strings.Replace(
				strings.Replace(
					strings.Replace(
						strings.Replace(
							v, "{{hyphentype}}", hyphenType, -1),
						"{{type}}", resType, -1),
					"{{uppertype}}", textproto.CanonicalMIMEHeaderKey(resType), -1),
				"{{prefix}}", prefixMap[resType], -1),
			"{{articletype}}", articleType, -1)
	}
	return in
}
