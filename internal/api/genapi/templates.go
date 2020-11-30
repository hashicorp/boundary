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

func getArgsAndPaths(in []string, parentTypeName, action string) (colArg, resArg string, colPath, resPath string) {
	resArg = fmt.Sprintf("%sId", strcase.ToLowerCamel(strings.ReplaceAll(in[len(in)-1], "-", "_")))
	strToReplace := "scope"
	if len(in) == 1 {
		if parentTypeName != "" {
			strToReplace = parentTypeName
		}
	} else {
		strToReplace = in[len(in)-2]
	}
	colArg = fmt.Sprintf("%sId", strcase.ToLowerCamel(strings.ReplaceAll(strToReplace, "-", "_")))
	colPath = fmt.Sprintf("%ss", in[len(in)-1])

	if action != "" {
		action = fmt.Sprintf(":%s", action)
	}
	resPath = fmt.Sprintf("fmt.Sprintf(\"%s/%%s%s\", %s)", colPath, action, resArg)
	return
}

type templateInput struct {
	Name                  string
	Package               string
	Fields                []fieldInfo
	PathArgs              []string
	CollectionFunctionArg string
	ResourceFunctionArg   string
	CollectionPath        string
	ResourcePath          string
	ParentTypeName        string
	SliceSubTypes         map[string]string
	ExtraOptions          []fieldInfo
	VersionEnabled        bool
	TypeOnCreate          bool
	CreateResponseTypes   bool
}

func fillTemplates() {
	optionsMap := map[string]map[string]fieldInfo{}
	for _, in := range inputStructs {
		outBuf := new(bytes.Buffer)
		input := templateInput{
			Name:                in.generatedStructure.name,
			Package:             in.generatedStructure.pkg,
			Fields:              in.generatedStructure.fields,
			PathArgs:            in.pathArgs,
			ParentTypeName:      in.parentTypeName,
			ExtraOptions:        in.extraOptions,
			VersionEnabled:      in.versionEnabled,
			TypeOnCreate:        in.typeOnCreate,
			CreateResponseTypes: in.createResponseTypes,
		}

		if len(in.pathArgs) > 0 {
			input.CollectionFunctionArg, input.ResourceFunctionArg, input.CollectionPath, input.ResourcePath = getArgsAndPaths(in.pathArgs, in.parentTypeName, "")
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
		// Add in extra defined options
		if len(in.extraOptions) > 0 {
			optionMap := optionsMap[input.Package]
			if optionMap == nil {
				optionMap = map[string]fieldInfo{}
			}
			for _, val := range in.extraOptions {
				optionMap[val.Name] = val
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

var listTemplate = template.Must(template.New("").Funcs(
	template.FuncMap{
		"snakeCase": snakeCase,
	},
).Parse(`
func (c *Client) List(ctx context.Context, {{ .CollectionFunctionArg }} string, opt... Option) (*{{ .Name }}ListResult, error) {
	if {{ .CollectionFunctionArg }} == "" {
		return nil, fmt.Errorf("empty {{ .CollectionFunctionArg }} value passed into List request")
	}
	if c.client == nil {
		return nil, fmt.Errorf("nil client")
	}

	opts, apiOpts := getOpts(opt...)
	opts.queryMap["{{ snakeCase .CollectionFunctionArg }}"] = {{ .CollectionFunctionArg }}

	req, err := c.client.NewRequest(ctx, "GET", "{{ .CollectionPath }}", nil, apiOpts...)
	if err != nil {
		return nil, fmt.Errorf("error creating List request: %w", err)
	}
	{{ if ( eq .CollectionPath "\"scopes\"" ) }}
	opts.queryMap["scope_id"] = scopeId
	{{ end }}
	if len(opts.queryMap) > 0 {
		q := url.Values{}
		for k, v := range opts.queryMap {
			q.Add(k, v)
		}
		req.URL.RawQuery = q.Encode()
	}

	resp, err := c.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("error performing client request during List call: %w", err)
	}

	target := new({{ .Name }}ListResult)
	apiErr, err := resp.Decode(target)
	if err != nil {
		return nil, fmt.Errorf("error decoding List response: %w", err)
	}
	if apiErr != nil {
		return nil, apiErr
	}
	target.response = resp
	return target, nil
}
`))

var readTemplate = template.Must(template.New("").Parse(`
func (c *Client) Read(ctx context.Context, {{ .ResourceFunctionArg }} string, opt... Option) (*{{ .Name }}ReadResult, error) {
	if {{ .ResourceFunctionArg }} == "" {
		return nil, fmt.Errorf("empty {{ .ResourceFunctionArg }} value passed into Read request")
	}
	if c.client == nil {
		return nil, fmt.Errorf("nil client")
	}

	opts, apiOpts := getOpts(opt...)

	req, err := c.client.NewRequest(ctx, "GET", {{ .ResourcePath }}, nil, apiOpts...)
	if err != nil {
		return nil, fmt.Errorf("error creating Read request: %w", err)
	}

	if len(opts.queryMap) > 0 {
		q := url.Values{}
		for k, v := range opts.queryMap {
			q.Add(k, v)
		}
		req.URL.RawQuery = q.Encode()
	}

	resp, err := c.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("error performing client request during Read call: %w", err)
	}

	target := new({{ .Name }}ReadResult)
	target.Item = new({{ .Name }})
	apiErr, err := resp.Decode(target.Item)
	if err != nil {
		return nil, fmt.Errorf("error decoding Read response: %w", err)
	}
	if apiErr != nil {
		return nil, apiErr
	}
	target.response = resp
	return target, nil
}
`))

var deleteTemplate = template.Must(template.New("").Parse(`
func (c *Client) Delete(ctx context.Context, {{ .ResourceFunctionArg }} string, opt... Option) (*{{ .Name }}DeleteResult, error) { 
	if {{ .ResourceFunctionArg }} == "" {
		return nil, fmt.Errorf("empty {{ .ResourceFunctionArg }} value passed into Delete request")
	}
	if c.client == nil {
		return nil, fmt.Errorf("nil client")
	}
	
	opts, apiOpts := getOpts(opt...)

	req, err := c.client.NewRequest(ctx, "DELETE", {{ .ResourcePath }}, nil, apiOpts...)
	if err != nil {
		return nil, fmt.Errorf("error creating Delete request: %w", err)
	}

	if len(opts.queryMap) > 0 {
		q := url.Values{}
		for k, v := range opts.queryMap {
			q.Add(k, v)
		}
		req.URL.RawQuery = q.Encode()
	}

	resp, err := c.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("error performing client request during Delete call: %w", err)
	}

	apiErr, err := resp.Decode(nil)
	if err != nil {
		return nil, fmt.Errorf("error decoding Delete response: %w", err)
	}
	if apiErr != nil {
		return nil, apiErr
	}

	target := &{{ .Name }}DeleteResult{
		response: resp,
	}
	return target, nil
}
`))

var createTemplate = template.Must(template.New("").Funcs(
	template.FuncMap{
		"snakeCase": snakeCase,
	},
).Parse(`
func (c *Client) Create (ctx context.Context, {{ if .TypeOnCreate }} resourceType string, {{ end }} {{ .CollectionFunctionArg }} string, opt... Option) (*{{ .Name }}CreateResult, error) {
	if {{ .CollectionFunctionArg }} == "" {
		return nil, fmt.Errorf("empty {{ .CollectionFunctionArg }} value passed into Create request")
	}

	opts, apiOpts := getOpts(opt...)

	if c.client == nil {
		return nil, fmt.Errorf("nil client")
	}
	{{ if .TypeOnCreate }} if resourceType == "" {
		return nil, fmt.Errorf("empty resourceType value passed into Create request")
	} else {
		opts.postMap["type"] = resourceType
	}{{ end }}

	opts.postMap["{{ snakeCase .CollectionFunctionArg }}"] = {{ .CollectionFunctionArg }}

	req, err := c.client.NewRequest(ctx, "POST", "{{ .CollectionPath }}", opts.postMap, apiOpts...)
	if err != nil {
		return nil, fmt.Errorf("error creating Create request: %w", err)
	}
	{{ if ( eq .CollectionPath "\"scopes\"" ) }}
	opts.queryMap["scope_id"] = scopeId
	{{ end }}
	if len(opts.queryMap) > 0 {
		q := url.Values{}
		for k, v := range opts.queryMap {
			q.Add(k, v)
		}
		req.URL.RawQuery = q.Encode()
	}

	resp, err := c.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("error performing client request during Create call: %w", err)
	}

	target := new({{ .Name }}CreateResult)
	target.Item = new({{ .Name }})
	apiErr, err := resp.Decode(target.Item)
	if err != nil {
		return nil, fmt.Errorf("error decoding Create response: %w", err)
	}
	if apiErr != nil {
		return nil, apiErr
	}
	target.response = resp
	return target, nil
}
`))

var updateTemplate = template.Must(template.New("").Parse(`
func (c *Client) Update(ctx context.Context, {{ .ResourceFunctionArg }} string, version uint32, opt... Option) (*{{ .Name }}UpdateResult, error) {
	if {{ .ResourceFunctionArg }} == "" {
		return nil, fmt.Errorf("empty {{ .ResourceFunctionArg }} value passed into Update request")
	}
	if c.client == nil {
		return nil, fmt.Errorf("nil client")
	}

	opts, apiOpts := getOpts(opt...)

	{{ if .VersionEnabled }}
	if version == 0 {
		if !opts.withAutomaticVersioning {
			return nil, errors.New("zero version number passed into Update request and automatic versioning not specified")
		}
		existingTarget, existingErr := c.Read(ctx, {{ .ResourceFunctionArg }}, opt...)
		if existingErr != nil {
			if api.AsServerError(existingErr) != nil {
				return nil, fmt.Errorf("error from controller when performing initial check-and-set read: %w", existingErr)
			}
			return nil, fmt.Errorf("error performing initial check-and-set read: %w", existingErr)
		}
		if existingTarget == nil {
			return nil, errors.New("nil resource response found when performing initial check-and-set read")
		}
		if existingTarget.Item == nil {
			return nil, errors.New("nil resource found when performing initial check-and-set read")
		}
		version = existingTarget.Item.Version
	}
	{{ end }}

	opts.postMap["version"] = version

	req, err := c.client.NewRequest(ctx, "PATCH", {{ .ResourcePath }}, opts.postMap, apiOpts...)
	if err != nil {
		return nil, fmt.Errorf("error creating Update request: %w", err)
	}

	if len(opts.queryMap) > 0 {
		q := url.Values{}
		for k, v := range opts.queryMap {
			q.Add(k, v)
		}
		req.URL.RawQuery = q.Encode()
	}

	resp, err := c.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("error performing client request during Update call: %w", err)
	}

	target := new({{ .Name }}UpdateResult)
	target.Item = new({{ .Name }})
	apiErr, err := resp.Decode(target.Item)
	if err != nil {
		return nil, fmt.Errorf("error decoding Update response: %w", err)
	}
	if apiErr != nil {
		return nil, apiErr
	}
	target.response = resp
	return target, nil
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
{{ $resPath := getPathWithAction $input.PathArgs $input.ParentTypeName $actionName }}
func (c *Client) {{ $fullName }}(ctx context.Context, {{ $input.ResourceFunctionArg }} string, version uint32, {{ $value }} []string, opt... Option) (*{{ $input.Name }}UpdateResult, error) { 
	if {{ $input.ResourceFunctionArg }} == "" {
		return nil, fmt.Errorf("empty {{ $input.ResourceFunctionArg }} value passed into {{ $fullName }} request")
	}
	{{ if ( not ( eq $op "Set" ) ) }}if len({{ $value }}) == 0 {
		return nil, errors.New("empty {{ $value }} passed into {{ $fullName }} request")
	}{{ end }}
	if c.client == nil {
		return nil, errors.New("nil client")
	}

	opts, apiOpts := getOpts(opt...)

	{{ if $input.VersionEnabled }}
	if version == 0 {
		if !opts.withAutomaticVersioning {
			return nil, errors.New("zero version number passed into {{ $fullName }} request")
		}
		existingTarget, existingErr := c.Read(ctx, {{ $input.ResourceFunctionArg }}, opt...)
		if existingErr != nil {
			if api.AsServerError(existingErr) != nil {
				return nil, fmt.Errorf("error from controller when performing initial check-and-set read: %w", existingErr)
			}
			return nil, fmt.Errorf("error performing initial check-and-set read: %w", existingErr)
		}
		if existingTarget == nil {
			return nil, errors.New("nil resource response found when performing initial check-and-set read")
		}
		if existingTarget.Item == nil {
			return nil, errors.New("nil resource found when performing initial check-and-set read")
		}
		version = existingTarget.Item.Version
	}
	{{ end }}
	opts.postMap["version"] = version
	opts.postMap["{{ snakeCase $value }}"] = {{ $value }}

	req, err := c.client.NewRequest(ctx, "POST", {{ $resPath }}, opts.postMap, apiOpts...)
	if err != nil {
		return nil, fmt.Errorf("error creating {{ $fullName }} request: %w", err)
	}

	if len(opts.queryMap) > 0 {
		q := url.Values{}
		for k, v := range opts.queryMap {
			q.Add(k, v)
		}
		req.URL.RawQuery = q.Encode()
	}

	resp, err := c.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("error performing client request during {{ $fullName }} call: %w", err)
	}

	target := new({{ $input.Name }}UpdateResult)
	target.Item = new({{ $input.Name }})
	apiErr, err := resp.Decode(target.Item)
	if err != nil {
		return nil, fmt.Errorf("error decoding {{ $fullName }} response: %w", err)
	}
	if apiErr != nil {
		return nil, apiErr
	}
	target.response = resp
	return target, nil
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

	"github.com/hashicorp/boundary/api"
	"github.com/hashicorp/boundary/api/scopes"
)

type {{ .Name }} struct { {{ range .Fields }}
{{ .Name }}  {{ .FieldType }} `, "`json:\"{{ .ProtoName }},omitempty\"`", `{{ end }}
{{ if .CreateResponseTypes }}
	response *api.Response
{{ else if ( eq .Name "Error" ) }}
	response *Response
{{ end }}
}

{{ if ( or .CreateResponseTypes ( eq .Name "Error" ) ) }}
func (n {{ .Name }}) ResponseBody() *bytes.Buffer {
	return n.response.Body
}

func (n {{ .Name }}) ResponseMap() map[string]interface{} {
	return n.response.Map
}

func (n {{ .Name }}) ResponseStatus() int {
	return n.response.HttpResponse().StatusCode
}
{{ end }}

{{ if .CreateResponseTypes }}
type {{ .Name }}ReadResult struct {
	Item *{{ .Name }}
	response *api.Response
}

func (n {{ .Name }}ReadResult) GetItem() interface{} {
	return n.Item
}

func (n {{ .Name }}ReadResult) GetResponseBody() *bytes.Buffer {
	return n.response.Body
}

func (n {{ .Name }}ReadResult) GetResponseMap() map[string]interface{} {
	return n.response.Map
}

type {{ .Name }}CreateResult = {{ .Name }}ReadResult
type {{ .Name }}UpdateResult = {{ .Name }}ReadResult

type {{ .Name }}DeleteResult struct {
	response *api.Response
}

func (n {{ .Name }}DeleteResult) GetResponseBody() *bytes.Buffer {
	return n.response.Body
}

func (n {{ .Name }}DeleteResult) GetResponseMap() map[string]interface{} {
	return n.response.Map
}

type {{ .Name }}ListResult struct {
	Items []*{{ .Name }}
	response *api.Response
}

func (n {{ .Name }}ListResult) GetItems() interface{} {
	return n.Items
}

func (n {{ .Name }}ListResult) GetResponseBody() *bytes.Buffer {
	return n.response.Body
}

func (n {{ .Name }}ListResult) GetResponseMap() map[string]interface{} {
	return n.response.Map
}
{{ end }}
`)))

var clientTemplate = template.Must(template.New("").Parse(`
// Client is a client for this collection
type Client struct {
	client *api.Client
}

// Creates a new client for this collection. The submitted API client is cloned;
// modifications to it after generating this client will not have effect. If you
// need to make changes to the underlying API client, use ApiClient() to access
// it.
func NewClient(c *api.Client) *Client {
	return &Client{ client: c.Clone() }
}

// ApiClient returns the underlying API client
func (c *Client) ApiClient() *api.Client {
	return c.client
}
`))

var optionTemplate = template.Must(template.New("").Parse(`
package {{ .Package }}

import (
	"context"
	"fmt"
	"time"

	"github.com/hashicorp/boundary/api"
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
	postMap map[string]interface{}
	queryMap map[string]string
	withAutomaticVersioning bool
}

func getDefaultOptions() options {
	return options{
		postMap: make(map[string]interface{}),
		queryMap: make(map[string]string),
	}
}

func getOpts(opt ...Option) (options, []api.Option) {
	opts := getDefaultOptions()
	for _, o := range opt {
		o(&opts)
	}
	var apiOpts []api.Option
	return opts, apiOpts
}

// If set, and if the version is zero during an update, the API will perform a
// fetch to get the current version of the resource and populate it during the
// update call. This is convenient but opens up the possibility for subtle
// order-of-modification issues, so use carefully.
func WithAutomaticVersioning(enable bool) Option {
	return func(o *options) {
		o.withAutomaticVersioning = enable
	}
}
{{ range .Fields }}
func With{{ .SubtypeName }}{{ .Name }}(in{{ .Name }} {{ .FieldType }}) Option {
	return func(o *options) {		{{ if ( not ( eq .SubtypeName "" ) ) }}
		raw, ok := o.postMap["attributes"]
		if !ok {
			raw = interface{}(map[string]interface{}{})
		}
		val := raw.(map[string]interface{})
		val["{{ .ProtoName }}"] = in{{ .Name }}
		o.postMap["attributes"] = val
		{{ else if .Query }}
		o.queryMap["{{ .ProtoName }}"] = fmt.Sprintf("%v", in{{ .Name }})
		{{ else }}
		o.postMap["{{ .ProtoName }}"] = in{{ .Name }}
		{{ end }}	}
}
{{ if ( not .SkipDefault ) }}
func Default{{ .SubtypeName }}{{ .Name }}() Option {
	return func(o *options) {		{{ if ( not ( eq .SubtypeName "" ) ) }}
		raw, ok := o.postMap["attributes"]
		if !ok {
			raw = interface{}(map[string]interface{}{})
		}
		val := raw.(map[string]interface{})
		val["{{ .ProtoName }}"] = nil
		o.postMap["attributes"] = val
		{{ else }}
		o.postMap["{{ .ProtoName }}"] = nil
		{{ end }}	}
}
{{ end }}
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

func getPathWithAction(resArgs []string, parentTypeName, action string) string {
	_, _, _, resPath := getArgsAndPaths(resArgs, parentTypeName, action)
	return resPath
}
