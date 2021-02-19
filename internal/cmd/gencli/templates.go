package main

import (
	"bytes"
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"
	"text/template"

	"github.com/hashicorp/boundary/sdk/strutil"
	"github.com/iancoleman/strcase"
)

func fillTemplates() {
	for pkg, structs := range inputStructs {
		for _, data := range structs {
			outBuf := new(bytes.Buffer)

			if err := cmdTemplate.Execute(outBuf, data); err != nil {
				fmt.Printf("error executing struct template for resource %s: %v\n", pkg, err)
				os.Exit(1)
			}

			fName := pkg
			if data.SubActionPrefix != "" {
				fName = fmt.Sprintf("%s_%s", data.SubActionPrefix, fName)
			}
			outFile, err := filepath.Abs(fmt.Sprintf("%s/%scmd/%s.gen.go", os.Getenv("CLI_GEN_BASEPATH"), pkg, fName))
			if err != nil {
				fmt.Printf("error opening file for package %s: %v\n", pkg, err)
				os.Exit(1)
			}
			outDir := filepath.Dir(outFile)
			if _, err := os.Stat(outDir); os.IsNotExist(err) {
				_ = os.Mkdir(outDir, os.ModePerm)
			}
			if err := ioutil.WriteFile(outFile, outBuf.Bytes(), 0o644); err != nil {
				fmt.Printf("error writing file %q: %v\n", outFile, err)
				os.Exit(1)
			}
		}
	}
}

func camelCase(in string) string {
	return strcase.ToCamel(in)
}

func envCase(in string) string {
	return strcase.ToScreamingSnake(in)
}

func snakeCase(in string) string {
	return strcase.ToSnake(in)
}

func kebabCase(in string) string {
	return strcase.ToKebab(in)
}

func lowerSpaceCase(in string) string {
	return strcase.ToDelimited(in, ' ')
}

func hasAction(in []string, action string) bool {
	return strutil.StrListContains(in, action)
}

var cmdTemplate = template.Must(template.New("").Funcs(
	template.FuncMap{
		"camelCase":      camelCase,
		"envCase":        envCase,
		"snakeCase":      snakeCase,
		"kebabCase":      kebabCase,
		"lowerSpaceCase": lowerSpaceCase,
		"hasAction":      hasAction,
	},
).Parse(`
{{ $input := . }}
package {{ .Pkg }}cmd

import (
	"fmt"
	"net/http"
	"os"

	"github.com/hashicorp/boundary/api"
	"github.com/hashicorp/boundary/api/{{ .Pkg }}"
	"github.com/hashicorp/boundary/internal/cmd/base"
	"github.com/hashicorp/boundary/internal/cmd/common"
	"github.com/hashicorp/boundary/internal/types/resource"
	"github.com/hashicorp/boundary/sdk/strutil"
	"github.com/mitchellh/cli"
	"github.com/posener/complete"
)

func init() {
	{{ if .HasCustomActionFlags }}
	for k, v := range extra{{ camelCase .SubActionPrefix }}ActionsFlagsMap {
		flags{{ camelCase .SubActionPrefix }}Map[k] = append(flags{{ camelCase .SubActionPrefix }}Map[k], v...)
	}
	{{ end }}
}

var (
	_ cli.Command             = (*{{ camelCase .SubActionPrefix }}Command)(nil)
	_ cli.CommandAutocomplete = (*{{ camelCase .SubActionPrefix }}Command)(nil)
)

type {{ camelCase .SubActionPrefix }}Command struct {
	*base.Command

	Func string

	// Used for delete operations
	existed bool
	// Used in some output
	plural string
	{{ if .HasExtraCommandVars }}
	extra{{ camelCase .SubActionPrefix }}CmdVars
	{{ end }}
}

func (c *{{ camelCase .SubActionPrefix }}Command) AutocompleteArgs() complete.Predictor {
	return complete.PredictAnything
}

func (c *{{ camelCase .SubActionPrefix }}Command) AutocompleteFlags() complete.Flags {
	return c.Flags().Completions()
}

func (c *{{ camelCase .SubActionPrefix }}Command) Synopsis() string {
	{{ if .HasExtraSynopsisFunc }}
	if extra := c.extra{{ camelCase .SubActionPrefix }}SynopsisFunc(); extra != "" {
		return extra
	} 
	{{ end }}
	return common.SynopsisFunc(c.Func, "{{ lowerSpaceCase .ResourceType }}")
}

func (c *{{ camelCase .SubActionPrefix }}Command) Help() string {
	var helpStr string
	helpMap := common.HelpMap("{{ lowerSpaceCase .ResourceType }}")

	switch c.Func {
	{{ if not .SkipNormalHelp }}
	{{ range $i, $action := .StdActions }}
	case "{{ $action }}":
		helpStr = helpMap[c.Func]() + c.Flags().Help()
	{{ end }}
	{{ end }}
	default:
	{{ if .HasExtraHelpFunc }}
		helpStr = c.extra{{ camelCase .SubActionPrefix }}HelpFunc(helpMap)
	{{ else }}
		helpStr = helpMap["base"]()
	{{ end }}
	}

	// Keep linter from complaining if we don't actually generate code using it
	_ = helpMap
	return helpStr
}

var flags{{ camelCase .SubActionPrefix }}Map = map[string][]string{
	{{ range $i, $action := .StdActions }}
	{{ if eq $action "create" }}
	"create": { "{{ kebabCase $input.Container }}-id", "name", "description" },
	{{ end }}
	{{ if eq $action "read" }}
	"read": {"id"},
	{{ end }}
	{{ if eq $action "update" }}
	"update": {"id", "name", "description" {{ if hasAction $input.VersionedActions "update" }}, "version" {{ end }} },
	{{ end }}
	{{ if eq $action "delete" }}
	"delete": {"id"},
	{{ end }}
	{{ if eq $action "list" }}
	"list": { "{{ kebabCase $input.Container }}-id" {{ if (eq $input.Container "Scope") }}, "recursive"{{ end }} },
	{{ end }}
	{{ end }}
}

func (c *{{ camelCase .SubActionPrefix }}Command) Flags() *base.FlagSets {
	if len(flags{{ camelCase .SubActionPrefix }}Map[c.Func]) == 0 {
		return c.FlagSet(base.FlagSetNone)
	}

	set := c.FlagSet(base.FlagSetHTTP | base.FlagSetClient | base.FlagSetOutputFormat)
	f := set.NewFlagSet("Command Options")
	common.PopulateCommonFlags(c.Command, f, "{{ if .SubActionPrefix }}{{ .SubActionPrefix }}-type {{ end }}{{ lowerSpaceCase .ResourceType }}", flags{{ camelCase .SubActionPrefix }}Map[c.Func])

	extra{{ camelCase .SubActionPrefix }}FlagsFunc(c, set, f)

	return set
}

func (c *{{ camelCase .SubActionPrefix }}Command) Run(args []string) int {
	{{ if .HasExampleCliOutput }}
	if os.Getenv("BOUNDARY_EXAMPLE_CLI_OUTPUT") != "" {
		c.UI.Output(exampleOutput())
		return 0
	}
	{{ end }}

	switch c.Func {
	case "":
		return cli.RunResultHelp
	{{ if .IsAbstractType }}
	case "create", "update":
		return cli.RunResultHelp
	{{ end }}
	}

	c.plural = "{{ if .SubActionPrefix }}{{ .SubActionPrefix }}-type {{ end }}{{ lowerSpaceCase .ResourceType }}"
	switch c.Func {
	case "list":
		c.plural = "{{ if .SubActionPrefix }}{{ .SubActionPrefix }}-type {{ end }}{{ lowerSpaceCase .ResourceType }}s"		
	}

	f := c.Flags()

	if err := f.Parse(args); err != nil {
		c.UI.Error(err.Error())
		return 1
	}

	{{ if .HasId }}
	if strutil.StrListContains(flags{{ camelCase .SubActionPrefix }}Map[c.Func], "id") && c.FlagId == "" {
			c.UI.Error("ID is required but not passed in via -id")
			return 1
	}
	{{ end }}

	var opts []{{ .Pkg }}.Option

	{{ if .Container }}
	if strutil.StrListContains(flags{{ camelCase .SubActionPrefix }}Map[c.Func], "{{ kebabCase .Container }}-id") {
		switch c.Func {
		{{ if hasAction .ContainerRequiredActions "create" }}
		case "create":
			if c.Flag{{ .Container }}Id == "" {
				c.UI.Error("{{ .Container }} ID must be passed in via -{{ kebabCase .Container }}-id or BOUNDARY_{{ envCase .Container }}_ID")
				return 1
			}
		{{ end }}
		{{ if hasAction .ContainerRequiredActions "list" }}
		case "list":
			if c.Flag{{ .Container }}Id == "" {
				c.UI.Error("{{ .Container }} ID must be passed in via -{{ kebabCase .Container }}-id or BOUNDARY_{{ envCase .Container }}_ID")
				return 1
			}
		{{ end }}
		}
	}
	{{ end }}

	client, err := c.Client()
	if err != nil {
		c.UI.Error(fmt.Sprintf("Error creating API client: %s", err.Error()))
		return 2
	}
	{{ .Pkg }}Client := {{ .Pkg }}.NewClient(client)

	{{ if .HasName }}
	switch c.FlagName {
	case "":
	case "null":
		opts = append(opts, {{ .Pkg }}.DefaultName())
	default:
		opts = append(opts, {{ .Pkg }}.WithName(c.FlagName))
	}
	{{ end }}

	{{ if .HasDescription }}
	switch c.FlagDescription {
	case "":
	case "null":
		opts = append(opts, {{ .Pkg }}.DefaultDescription())
	default:
		opts = append(opts, {{ .Pkg }}.WithDescription(c.FlagDescription))
	}
	{{ end }}

	{{ if (eq .Container "Scope") }}
	switch c.FlagRecursive {
	case true:
		opts = append(opts, {{ .Pkg }}.WithRecursive(true))
	}
	{{ end }}

	{{ if .HasScopeName }}
	switch c.FlagScopeName {
	case "":
	default:
		opts = append(opts, {{ .Pkg }}.WithScopeName(c.FlagScopeName))
	}
	{{ end }}

	{{ if .VersionedActions }}
	var version uint32
	switch c.Func {
	{{ range $i, $action := .VersionedActions }}
	case "{{ $action }}":
		switch c.FlagVersion {
		case 0:
			opts = append(opts, {{ $input.Pkg }}.WithAutomaticVersioning(true))
		default:
			version = uint32(c.FlagVersion)
		}
	{{ end }}
	}
	{{ end }}

	if ret := extra{{ camelCase .SubActionPrefix }}FlagsHandlingFunc(c, &opts); ret != 0 {
		return ret
	}

	c.existed = true
	var result api.GenericResult
	{{ if hasAction .StdActions "list" }}
	var listResult api.GenericListResult
	{{ end }}

	switch c.Func {
	{{ range $i, $action := $input.StdActions }}
	{{ if eq $action "create" }}
	case "create":
		result, err = {{ $input.Pkg }}Client.Create(c.Context, {{ if (and $input.SubActionPrefix $input.NeedsSubTypeInCreate) }}"{{ $input.SubActionPrefix }}",{{ end }} c.Flag{{ $input.Container }}Id, opts...)
	{{ end }}
	{{ if eq $action "read" }}
	case "read":
		result, err = {{ $input.Pkg }}Client.Read(c.Context, c.FlagId, opts...)
	{{ end }}
	{{ if eq $action "update" }}
	case "update":
		result, err = {{ $input.Pkg }}Client.Update(c.Context, c.FlagId, version, opts...)
	{{ end }}
	{{ if eq $action "delete" }}
	case "delete":
		_, err = {{ $input.Pkg}}Client.Delete(c.Context, c.FlagId, opts...)
		if apiErr := api.AsServerError(err); apiErr != nil && apiErr.ResponseStatus() == http.StatusNotFound {
			c.existed = false
			err = nil
		}
	{{ end }}
	{{ if eq $action "list" }}
	case "list":
		listResult, err = {{ $input.Pkg}}Client.List(c.Context, c.Flag{{ $input.Container }}Id, opts...)
	{{ end }}
	{{ end }}
	}

	{{ if .HasExtraActions }}
	result, err = c.executeExtraActions(result, err, {{ .Pkg }}Client, version, opts)
	{{ end }}

	if err != nil {
		if apiErr := api.AsServerError(err); apiErr != nil {
			c.UI.Error(fmt.Sprintf("Error from controller when performing %s on %s: %s", c.Func, c.plural, base.PrintApiError(apiErr)))
			return 1
		}
		c.UI.Error(fmt.Sprintf("Error trying to %s %s: %s", c.Func, c.plural, err.Error()))
		return 2
	}

	{{ if .HasExtraActionsOutput }}
	output, err := c.printCustomActionOutput()
	if err != nil {
		c.UI.Error(err.Error())
		return 1
	}
	if output {
		return 0
	}
	{{ end }}

	switch c.Func {
	{{ range $i, $action := .StdActions }}
	{{ if eq $action "delete" }}
	case "delete":
		switch base.Format(c.UI) {
		case "json":
			c.UI.Output(fmt.Sprintf("{ \"existed\": %t }", c.existed))

		case "table":
			output := "The delete operation completed successfully"
			switch c.existed {
			case true:
				output += "."
			default:
				output += ", however the resource did not exist at the time."
			}
			c.UI.Output(output)
		}

		return 0
	{{ end }}
	{{ if eq $action "list" }}
	case "list":
		listedItems := listResult.GetItems().([]*{{ $input.Pkg }}.{{ camelCase $input.ResourceType }})
		switch base.Format(c.UI) {
		case "json":
			switch {
			
			case len(listedItems) == 0:
				c.UI.Output("null")
			
			default:
				b, err := base.JsonFormatter{}.Format(listedItems)
				if err != nil {
					c.UI.Error(fmt.Errorf("Error formatting as JSON: %w", err).Error())
					return 1
				}
				c.UI.Output(string(b))
			}

		case "table":
			c.UI.Output(c.printListTable(listedItems))
		}

		return 0
	{{ end }}
	{{ end }}
	}

	item := result.GetItem().(*{{ .Pkg }}.{{ camelCase .ResourceType }})
	switch base.Format(c.UI) {
	case "table":
		c.UI.Output(printItemTable(item))

	case "json":
		b, err := base.JsonFormatter{}.Format(item)
		if err != nil {
			c.UI.Error(fmt.Errorf("Error formatting as JSON: %w", err).Error())
			return 1
		}
		c.UI.Output(string(b))
	}

	return 0
}

var (
	extra{{ camelCase .SubActionPrefix }}FlagsFunc = func(*{{ camelCase .SubActionPrefix }}Command, *base.FlagSets, *base.FlagSet) {}
	extra{{ camelCase .SubActionPrefix }}FlagsHandlingFunc = func(*{{ camelCase .SubActionPrefix }}Command, *[]{{ .Pkg }}.Option) int { return 0 }
)
`))
