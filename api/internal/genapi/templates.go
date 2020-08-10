package main

import (
	"bytes"
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"text/template"

	"github.com/iancoleman/strcase"
)

func toPath(segments []string, action string) string {
	// If it's just a collection name, don't do a fmt.Sprintf
	if len(segments) == 1 {
		ret := segments[0]
		if action != "" {
			ret = fmt.Sprintf("%s:%s", ret, action)
		}
		return fmt.Sprintf(`"%s"`, ret)
	}

	var printfString, printfArg []string
	for i, s := range segments {
		if i%2 == 0 {
			// The first (zero index) is always the resource name, the next will be the id.
			printfString = append(printfString, s)
		} else {
			printfString = append(printfString, "%s")
			printfArg = append(printfArg, s)
		}
	}
	if action != "" {
		action = fmt.Sprintf(":%s", action)
	}
	return fmt.Sprintf("fmt.Sprintf(\"%s%s\", %s)", strings.Join(printfString, "/"), action, strings.Join(printfArg, ", "))
}

func getArgsAndPaths(in []string, action string) (colArgs, resArgs []string, colPath, resPath string) {
	var argNames, pathSegment []string
	for _, s := range in {
		varName := fmt.Sprintf("%sId", strcase.ToLowerCamel(strings.ReplaceAll(s, "-", "_")))
		collectionName := fmt.Sprintf("%ss", s)

		argNames = append(argNames, varName)
		pathSegment = append(pathSegment, collectionName, varName)
	}

	colArgs, resArgs, colPath, resPath = argNames[:len(argNames)-1], argNames, toPath(pathSegment[:len(pathSegment)-1], action), toPath(pathSegment, action)

	// Scopes create and list operations always need scope ID
	if colPath == `"scopes"` {
		colArgs = append(colArgs, "scopeId")
	}
	return
}

type templateInput struct {
	ClientName             string
	Name                   string
	Package                string
	Fields                 []fieldInfo
	PathArgs               []string
	CollectionFunctionArgs []string
	ResourceFunctionArgs   []string
	CollectionPath         string
	ResourcePath           string
	SliceSubTypes          map[string]string
	VersionEnabled         bool
}

func fillTemplates() {
	optionsMap := map[string]map[string]fieldInfo{}
	for _, in := range inputStructs {
		outBuf := new(bytes.Buffer)
		input := templateInput{
			ClientName:     strings.ToLower(in.generatedStructure.name) + "s",
			Name:           in.generatedStructure.name,
			Package:        in.generatedStructure.pkg,
			Fields:         in.generatedStructure.fields,
			PathArgs:       in.pathArgs,
			VersionEnabled: in.versionEnabled,
		}

		if len(in.pathArgs) > 0 {
			input.CollectionFunctionArgs, input.ResourceFunctionArgs, input.CollectionPath, input.ResourcePath = getArgsAndPaths(in.pathArgs, "")
		}

		if err := structTemplate.Execute(outBuf, input); err != nil {
			fmt.Printf("error executing struct template for resource %s: %v\n", in.generatedStructure.name, err)
			os.Exit(1)
		}

		if len(in.sliceSubTypes) > 0 {
			input.SliceSubTypes = in.sliceSubTypes
			in.templates = append(in.templates, sliceSubTypeTemplate)
		}

		for _, t := range in.templates {
			if err := t.Execute(outBuf, input); err != nil {
				fmt.Printf("error executing function template for resource %s: %v\n", in.generatedStructure.name, err)
				os.Exit(1)
			}
		}

		// We want to generate options per-package, not per-struct, so we
		// collate them all here for writing later. The map argument of the
		// package map is to prevent duplicates since we may have multiple e.g.
		// Name or Description fields.
		if !in.outputOnly {
			pkgOptionMap := map[string]fieldInfo{}
			for _, val := range input.Fields {
				if val.GenerateSdkOption {
					val.SubtypeName = in.subtypeName
					pkgOptionMap[val.Name] = val
				}
			}
			optionMap := optionsMap[input.Package]
			if optionMap == nil {
				optionMap = map[string]fieldInfo{}
			}
			for name, val := range pkgOptionMap {
				optionMap[name] = val
			}
			optionsMap[input.Package] = optionMap
		}

		outFile, err := filepath.Abs(fmt.Sprintf("%s/%s", os.Getenv("API_GEN_BASEPATH"), in.outFile))
		if err != nil {
			fmt.Printf("error opening file %q: %v\n", in.outFile, err)
			os.Exit(1)
		}
		outDir := filepath.Dir(outFile)
		if _, err := os.Stat(outDir); os.IsNotExist(err) {
			_ = os.Mkdir(outDir, os.ModePerm)
		}
		if err := ioutil.WriteFile(outFile, outBuf.Bytes(), 0644); err != nil {
			fmt.Printf("error writing file %q: %v\n", outFile, err)
			os.Exit(1)
		}
	}

	// Now reconstruct options per package and write them out
	for pkg, options := range optionsMap {
		outBuf := new(bytes.Buffer)

		var fieldNames []string
		for _, v := range options {
			fieldNames = append(fieldNames, v.Name)
		}
		sort.Strings(fieldNames)

		var fields []fieldInfo
		for _, v := range fieldNames {
			fields = append(fields, options[v])
		}

		input := templateInput{
			Package: pkg,
			Fields:  fields,
		}

		if err := optionTemplate.Execute(outBuf, input); err != nil {
			fmt.Printf("error executing option template for package %s: %v\n", pkg, err)
			os.Exit(1)
		}

		outFile, err := filepath.Abs(fmt.Sprintf("%s/%s/%s", os.Getenv("API_GEN_BASEPATH"), pkg, "option.gen.go"))
		if err != nil {
			fmt.Printf("error opening file %q: %v\n", "option.gen.go", err)
			os.Exit(1)
		}
		outDir := filepath.Dir(outFile)
		if _, err := os.Stat(outDir); os.IsNotExist(err) {
			_ = os.Mkdir(outDir, os.ModePerm)
		}
		if err := ioutil.WriteFile(outFile, outBuf.Bytes(), 0644); err != nil {
			fmt.Printf("error writing file %q: %v\n", outFile, err)
			os.Exit(1)
		}
	}
}

var listTemplate = template.Must(template.New("").Parse(`
func (c *{{ .ClientName }}Client) List(ctx context.Context, {{ range .CollectionFunctionArgs }} {{ . }} string, {{ end }}opt... Option) ([]*{{ .Name }}, *api.Error, error) { {{ range .CollectionFunctionArgs }}
	if {{ . }} == "" {
		return nil, nil, fmt.Errorf("empty {{ . }} value passed into List request")
	}
	{{ end }}
	if c.client == nil {
		return nil, nil, fmt.Errorf("nil client")
	}

	_, apiOpts := getOpts(opt...)

	req, err := c.client.NewRequest(ctx, "GET", {{ .CollectionPath }}, nil, apiOpts...)
	if err != nil {
		return nil, nil, fmt.Errorf("error creating List request: %w", err)
	}
	{{ if ( eq .CollectionPath "\"scopes\"" ) }}
	q := url.Values{}
	q.Add("scope_id", scopeId)
	req.URL.RawQuery = q.Encode()
	{{ end }}

	resp, err := c.client.Do(req)
	if err != nil {
		return nil, nil, fmt.Errorf("error performing client request during List call: %w", err)
	}

	type listResponse struct {
		Items []*{{ .Name }}
	}
	target := &listResponse{}
	apiErr, err := resp.Decode(target)
	if err != nil {
		return nil, nil, fmt.Errorf("error decoding List response: %w", err)
	}

	return target.Items, apiErr, nil
}
`))

var readTemplate = template.Must(template.New("").Parse(`
func (c *{{ .ClientName }}Client) Read(ctx context.Context, {{ range .ResourceFunctionArgs }} {{ . }} string, {{ end }} opt... Option) (*{{ .Name }}, *api.Error, error) { {{ range .ResourceFunctionArgs }}
	if {{ . }} == "" {
		return nil, nil, fmt.Errorf("empty {{ . }} value passed into Read request")
	}
	{{ end }}
	if c.client == nil {
		return nil, nil, fmt.Errorf("nil client")
	}

	_, apiOpts := getOpts(opt...)

	req, err := c.client.NewRequest(ctx, "GET", {{ .ResourcePath }}, nil, apiOpts...)
	if err != nil {
		return nil, nil, fmt.Errorf("error creating Read request: %w", err)
	}

	resp, err := c.client.Do(req)
	if err != nil {
		return nil, nil, fmt.Errorf("error performing client request during Read call: %w", err)
	}

	target := new({{ .Name }})
	apiErr, err := resp.Decode(target)
	if err != nil {
		return nil, nil, fmt.Errorf("error decoding Read response: %w", err)
	}

	return target, apiErr, nil
}
`))

var deleteTemplate = template.Must(template.New("").Parse(`
func (c *{{ .ClientName }}Client) Delete(ctx context.Context, {{ range .ResourceFunctionArgs }} {{ . }} string, {{ end }} opt... Option) (bool, *api.Error, error) { {{ range .ResourceFunctionArgs }}
	if {{ . }} == "" {
		return false, nil, fmt.Errorf("empty {{ . }} value passed into Delete request")
	}
	{{ end }}
	if c.client == nil {
		return false, nil, fmt.Errorf("nil client")
	}
	
	_, apiOpts := getOpts(opt...)

	req, err := c.client.NewRequest(ctx, "DELETE", {{ .ResourcePath }}, nil, apiOpts...)
	if err != nil {
		return false, nil, fmt.Errorf("error creating Delete request: %w", err)
	}

	resp, err := c.client.Do(req)
	if err != nil {
		return false, nil, fmt.Errorf("error performing client request during Delete call: %w", err)
	}

	type deleteResponse struct {
		Existed bool
	}
	target := &deleteResponse{}
	apiErr, err := resp.Decode(target)
	if err != nil {
		return false, nil, fmt.Errorf("error decoding Delete response: %w", err)
	}

	return target.Existed, apiErr, nil
}
`))

var createTemplate = template.Must(template.New("").Parse(`
func (c *{{ .ClientName }}Client) Create(ctx context.Context, {{ range .CollectionFunctionArgs }} {{ . }} string, {{ end }} opt... Option) (*{{ .Name }}, *api.Error, error) { {{ range .CollectionFunctionArgs }}
	if {{ . }} == "" {
		return nil, nil, fmt.Errorf("empty {{ . }} value passed into Create request")
	}
	{{ end }}
	if c.client == nil {
		return nil, nil, fmt.Errorf("nil client")
	}

	opts, apiOpts := getOpts(opt...)

	req, err := c.client.NewRequest(ctx, "POST", {{ .CollectionPath }}, opts.valueMap, apiOpts...)
	if err != nil {
		return nil, nil, fmt.Errorf("error creating Create request: %w", err)
	}
	{{ if ( eq .CollectionPath "\"scopes\"" ) }}
	q := url.Values{}
	q.Add("scope_id", scopeId)
	req.URL.RawQuery = q.Encode()
	{{ end }}

	resp, err := c.client.Do(req)
	if err != nil {
		return nil, nil, fmt.Errorf("error performing client request during Create call: %w", err)
	}

	target := new({{ .Name }})
	apiErr, err := resp.Decode(target)
	if err != nil {
		return nil, nil, fmt.Errorf("error decoding Create response: %w", err)
	}

	return target, apiErr, nil
}
`))

var updateTemplate = template.Must(template.New("").Parse(`
func (c *{{ .ClientName }}Client) Update(ctx context.Context, {{ range .ResourceFunctionArgs }} {{ . }} string, {{ end }}version uint32, opt... Option) (*{{ .Name }}, *api.Error, error) { {{ range .ResourceFunctionArgs }}
	if {{ . }} == "" {
		return nil, nil, fmt.Errorf("empty {{ . }} value passed into Update request")
	}{{ end }}
	if c.client == nil {
		return nil, nil, fmt.Errorf("nil client")
	}

	opts, apiOpts := getOpts(opt...)

	{{ if .VersionEnabled }}
	if version == 0 {
		if !opts.withAutomaticVersioning {
			return nil, nil, errors.New("zero version number passed into Update request and automatic versioning not specified")
		}
		existingTarget, existingApiErr, existingErr := c.Read(ctx, {{ range .ResourceFunctionArgs }} {{ . }}, {{ end }} opt...)
		if existingErr != nil {
			return nil, nil, fmt.Errorf("error performing initial check-and-set read: %w", existingErr)
		}
		if existingApiErr != nil {
			return nil, nil, fmt.Errorf("error from controller when performing initial check-and-set read: %s", pretty.Sprint(existingApiErr))
		}
		if existingTarget == nil {
			return nil, nil, errors.New("nil resource found when performing initial check-and-set read")
		}
		version = existingTarget.Version
	}
	{{ end }}

	req, err := c.client.NewRequest(ctx, "PATCH", {{ .ResourcePath }}, opts.valueMap, apiOpts...)
	if err != nil {
		return nil, nil, fmt.Errorf("error creating Update request: %w", err)
	}

	q := url.Values{}
	q.Add("version", fmt.Sprintf("%d", version))
	req.URL.RawQuery = q.Encode()

	resp, err := c.client.Do(req)
	if err != nil {
		return nil, nil, fmt.Errorf("error performing client request during Update call: %w", err)
	}

	target := new({{ .Name }})
	apiErr, err := resp.Decode(target)
	if err != nil {
		return nil, nil, fmt.Errorf("error decoding Update response: %w", err)
	}

	return target, apiErr, nil
}
`))

var sliceSubTypeTemplate = template.Must(template.New("").Funcs(
	template.FuncMap{
		"makeSlice":         makeSlice,
		"snakeCase":         snakeCase,
		"kebabCase":         kebabCase,
		"getPathWithAction": getPathWithAction,
	},
).Parse(`
{{ $input := . }}
{{ range $index, $op := makeSlice "Add" "Set" "Remove" }}
{{ range $key, $value := $input.SliceSubTypes }}
{{ $fullName := print $op $key }}
{{ $actionName := kebabCase $fullName }}
{{ $resPath := getPathWithAction $input.PathArgs $actionName }}
func (c *{{ $input.ClientName }}Client) {{ $fullName }}(ctx context.Context, {{ range $input.ResourceFunctionArgs }} {{ . }} string, {{ end }}version uint32, {{ $value }} []string, opt... Option) (*{{ $input.Name }}, *api.Error, error) { {{ range $input.ResourceFunctionArgs }}
	if {{ . }} == "" {
		return nil, nil, fmt.Errorf("empty {{ . }} value passed into {{ $fullName }} request")
	}{{ end }}
	if c.client == nil {
		return nil, nil, fmt.Errorf("nil client")
	}

	opts, apiOpts := getOpts(opt...)

	{{ if $input.VersionEnabled }}
	if version == 0 {
		if !opts.withAutomaticVersioning {
			return nil, nil, errors.New("zero version number passed into {{ $fullName }} request")
		}
		existingTarget, existingApiErr, existingErr := c.Read(ctx, {{ range $input.ResourceFunctionArgs }} {{ . }}, {{ end }} opt...)
		if existingErr != nil {
			return nil, nil, fmt.Errorf("error performing initial check-and-set read: %w", existingErr)
		}
		if existingApiErr != nil {
			return nil, nil, fmt.Errorf("error from controller when performing initial check-and-set read: %s", pretty.Sprint(existingApiErr))
		}
		if existingTarget == nil {
			return nil, nil, errors.New("nil resource found when performing initial check-and-set read")
		}
		version = existingTarget.Version
	}
	{{ end }}

	if len({{ $value }}) > 0 {
		opts.valueMap["{{ snakeCase $value }}"] = {{ $value }}
	}{{ if ( eq $op "Set" ) }} else if {{ $value }} != nil {
			// In this function, a non-nil but empty list means clear out
			opts.valueMap["{{ snakeCase $value }}"] = nil
		}
	{{ end }}

	req, err := c.client.NewRequest(ctx, "POST", {{ $resPath }}, opts.valueMap, apiOpts...)
	if err != nil {
		return nil, nil, fmt.Errorf("error creating {{ $fullName }} request: %w", err)
	}

	q := url.Values{}
	q.Add("version", fmt.Sprintf("%d", version))
	req.URL.RawQuery = q.Encode()

	resp, err := c.client.Do(req)
	if err != nil {
		return nil, nil, fmt.Errorf("error performing client request during {{ $fullName }} call: %w", err)
	}

	target := new({{ $input.Name }})
	apiErr, err := resp.Decode(target)
	if err != nil {
		return nil, nil, fmt.Errorf("error decoding {{ $fullName }} response: %w", err)
	}

	return target, apiErr, nil
}
{{ end }}
{{ end }}
`))

var structTemplate = template.Must(template.New("").Parse(
	fmt.Sprint(`// Code generated by "make api"; DO NOT EDIT.
package {{ .Package }}

import (
	"context"
	"fmt"
	"time"

	"github.com/kr/pretty"

	"github.com/hashicorp/watchtower/api"
	"github.com/hashicorp/watchtower/api/scopes"
)

type {{ .Name }} struct { {{ range .Fields }}
{{ .Name }}  {{ .FieldType }} `, "`json:\"{{ .ProtoName }},omitempty\"`", `{{ end }}
}
`)))

var clientTemplate = template.Must(template.New("").Parse(`
type {{ .ClientName }}Client struct {
	client *api.Client
}

func New{{ .Name }}sClient(c *api.Client) *{{ .ClientName }}Client {
	return &{{ .ClientName }}Client{ client: c }
}
`))

var optionTemplate = template.Must(template.New("").Parse(`
package {{ .Package }}

import (
	"context"
	"fmt"
	"time"

	"github.com/hashicorp/watchtower/api"
)

// Option is a func that sets optional attributes for a call. This does not need
// to be used directly, but instead option arguments are built from the
// functions in this package. WithX options set a value to that given in the
// argument; DefaultX options indicate that the value should be set to its
// default. When an API call is made options are processed in ther order they
// appear in the function call, so for a given argument X, a succession of WithX
// or DefaultX calls will result in the last call taking effect.
type Option func(*options)

type options struct {
	valueMap map[string]interface{}
	withScopeId string
	withAutomaticVersioning bool
}

func getDefaultOptions() options {
	return options{
		valueMap: make(map[string]interface{}),
	}
}

func getOpts(opt ...Option) (options, []api.Option) {
	opts := getDefaultOptions()
	for _, o := range opt {
		o(&opts)
	}
	var apiOpts []api.Option
	if opts.withScopeId != "" {
		apiOpts = append(apiOpts, api.WithScopeId(opts.withScopeId))
	}
	return opts, apiOpts
}

func WithScopeId(id string) Option {
	return func(o *options) {
		o.withScopeId = id
	}
}

// If set, and if the version is zero during an update, the API will perform a
// fetch to get the current version of the resource and populate it during the
// update call. This is convenient but opens up the possibility for subtle
// order-of-modification issues, so use carefully.
func WithAutomaticVersioning() Option {
	return func(o *options) {
		o.withAutomaticVersioning = true
	}
}
{{ range .Fields }}
func With{{ .SubtypeName }}{{ .Name }}(in{{ .Name }} {{ .FieldType }}) Option {
	return func(o *options) {		{{ if ( not ( eq .SubtypeName "" ) ) }}
		raw, ok := o.valueMap["attributes"]
		if !ok {
			raw = interface{}(map[string]interface{}{})
		}
		val := raw.(map[string]interface{})
		val["{{ .ProtoName }}"] = in{{ .Name }}
		o.valueMap["attributes"] = val
		{{ else }}
		o.valueMap["{{ .ProtoName }}"] = in{{ .Name }}
		{{ end }}	}
}

func Default{{ .SubtypeName }}{{ .Name }}() Option {
	return func(o *options) {		{{ if ( not ( eq .SubtypeName "" ) ) }}
		raw, ok := o.valueMap["attributes"]
		if !ok {
			raw = interface{}(map[string]interface{}{})
		}
		val := raw.(map[string]interface{})
		val["{{ .ProtoName }}"] = nil
		o.valueMap["attributes"] = val
		{{ else }}
		o.valueMap["{{ .ProtoName }}"] = nil
		{{ end }}	}
}
{{ end }}
`))

func makeSlice(strs ...string) []string {
	return strs
}

func snakeCase(in string) string {
	return strcase.ToSnake(in)
}

func kebabCase(in string) string {
	return strcase.ToKebab(in)
}

func getPathWithAction(resArgs []string, action string) string {
	_, _, _, resPath := getArgsAndPaths(resArgs, action)
	return resPath
}
