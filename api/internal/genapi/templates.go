package main

import (
	"bytes"
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"
	"strings"
	"text/template"

	"github.com/iancoleman/strcase"
)

func toPath(segments []string) string {
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
	return fmt.Sprintf("fmt.Sprintf(\"%s\", %s)", strings.Join(printfString, "/"), strings.Join(printfArg, ", "))
}

func getArgsAndPaths(in []string) (colArgs, resArgs []string, colPath, resPath string) {
	var argNames, pathSegment []string
	for _, s := range in {
		varName := fmt.Sprintf("%sId", strcase.ToLowerCamel(strings.ReplaceAll(s, "-", "_")))
		collectionName := fmt.Sprintf("%ss", s)

		argNames = append(argNames, varName)
		pathSegment = append(pathSegment, collectionName, varName)
	}

	return argNames[:len(argNames)-1], argNames, toPath(pathSegment[:len(pathSegment)-1]), toPath(pathSegment)
}

type templateInput struct {
	ClientName             string
	Name                   string
	Package                string
	Fields                 []fieldInfo
	CollectionFunctionArgs []string
	ResourceFunctionArgs   []string
	CollectionPath         string
	ResourcePath           string
	SliceSubTypes          map[string]string
}

func fillTemplates() {
	optionsMap := map[string]map[string]fieldInfo{}
	for _, in := range inputStructs {
		outBuf := new(bytes.Buffer)
		input := templateInput{
			ClientName: strings.ToLower(in.generatedStructure.name),
			Name:       in.generatedStructure.name,
			Package:    in.generatedStructure.pkg,
			Fields:     in.generatedStructure.fields,
		}

		if len(in.pathArgs) > 0 {
			input.CollectionFunctionArgs, input.ResourceFunctionArgs, input.CollectionPath, input.ResourcePath = getArgsAndPaths(in.pathArgs)
		}

		structTemplate.Execute(outBuf, input)

		if len(in.sliceSubTypes) > 0 {
			input.SliceSubTypes = in.sliceSubTypes
			in.templates = append(in.templates, sliceSubTypeTemplate)
		}

		for _, t := range in.templates {
			t.Execute(outBuf, input)
		}

		// We want to generate options per-package, not per-struct, so we
		// collate them all here for writing later. The map argument of the
		// package map is to prevent duplicates since we may have multiple e.g.
		// Name or Description fields.
		if !in.outputOnly {
			pkgOptionMap := map[string]fieldInfo{}
			for _, val := range input.Fields {
				if val.Writable {
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
		var fields []fieldInfo
		for _, v := range options {
			fields = append(fields, v)
		}

		input := templateInput{
			Package: pkg,
			Fields:  fields,
		}

		optionTemplate.Execute(outBuf, input)

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
	if version == 0 {
		return nil, nil, errors.New("zero version number passed into Update request")
	}
	if c.client == nil {
		return nil, nil, fmt.Errorf("nil client")
	}

	opts, apiOpts := getOpts(opt...)

	req, err := c.client.NewRequest(ctx, "PATCH", {{ .ResourcePath }}, opts.valueMap, apiOpts...)
	if err != nil {
		return nil, nil, fmt.Errorf("error creating Update request: %w", err)
	}

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

var sliceSubTypeTemplate = template.Must(template.New("").Parse(`{{ $input := . }}{{ range $key, $value := .SliceSubTypes }}
func (c *{{ $input.ClientName }}Client) Add(ctx context.Context, {{ range .ResourceFunctionArgs }} {{ . }} string, {{ end }}version uint32, opt... Option) (*{{ .Name }}, *api.Error, error) { {{ range .ResourceFunctionArgs }}
	if {{ . }} == "" {
		return nil, nil, fmt.Errorf("empty {{ . }} value passed into Update request")
	}{{ end }}
	if version == 0 {
		return nil, nil, errors.New("zero version number passed into Update request")
	}
	if c.client == nil {
		return nil, nil, fmt.Errorf("nil client")
	}

	opts, apiOpts := getOpts(opt...)

	req, err := c.client.NewRequest(ctx, "PATCH", {{ .ResourcePath }}, opts.valueMap, apiOpts...)
	if err != nil {
		return nil, nil, fmt.Errorf("error creating Update request: %w", err)
	}

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
{{ end }}
`))

var structTemplate = template.Must(template.New("").Parse(
	fmt.Sprint(`// Code generated by "make api"; DO NOT EDIT.
package {{ .Package }}

import (
	"context"
	"fmt"
	"time"

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

func New{{ .Name }}Client(c *api.Client) *{{ .ClientName }}Client {
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

type Option func(*options)

type options struct {
	valueMap map[string]interface{}
	withScopeId string
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

func DefaultScopeId() Option {
	return func(o *options) {
		o.withScopeId = ""
	}
}

func WithScopeId(id string) Option {
	return func(o *options) {
		o.withScopeId = id
	}
}
{{ range .Fields }}
func With{{ .Name }}(in{{ .Name }} {{ .FieldType }}) Option {
	return func(o *options) {
		o.valueMap["{{ .ProtoName }}"] = in{{ .Name }}
	}
}

func Default{{ .Name }}() Option {
	return func(o *options) {
		o.valueMap["{{ .ProtoName }}"] = nil
	}
}
{{ end }}
`))
