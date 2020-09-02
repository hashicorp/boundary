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

func getArgsAndPathsNewStyle(in []string, action string) (colArg, resArg string, colPath, resPath string) {
	resArg = fmt.Sprintf("%sId", strcase.ToLowerCamel(strings.ReplaceAll(in[len(in)-1], "-", "_")))
	if len(in) == 1 {
		colArg = "scopeId"
	} else {
		colArg = fmt.Sprintf("%sId", strcase.ToLowerCamel(strings.ReplaceAll(in[len(in)-2], "-", "_")))
	}
	colPath = fmt.Sprintf("%ss", in[len(in)-1])

	if action != "" {
		action = fmt.Sprintf(":%s", action)
	}
	resPath = fmt.Sprintf("fmt.Sprintf(\"%s/%%s%s\", %s)", colPath, action, resArg)
	return
}

type templateInput struct {
	Name                   string
	Package                string
	Fields                 []fieldInfo
	PathArgs               []string
	CollectionFunctionArgs []string
	ResourceFunctionArgs   []string
	CollectionPath         string
	ResourcePath           string
	CollectionFunctionArg2 string
	ResourceFunctionArg2   string
	CollectionPath2        string
	ResourcePath2          string
	SliceSubTypes          map[string]string
	ExtraOptions           []fieldInfo
	VersionEnabled         bool
	TypeOnCreate           bool
}

func fillTemplates() {
	optionsMap := map[string]map[string]fieldInfo{}
	for _, in := range inputStructs {
		outBuf := new(bytes.Buffer)
		input := templateInput{
			Name:           in.generatedStructure.name,
			Package:        in.generatedStructure.pkg,
			Fields:         in.generatedStructure.fields,
			PathArgs:       in.pathArgs,
			ExtraOptions:   in.extraOptions,
			VersionEnabled: in.versionEnabled,
			TypeOnCreate:   in.typeOnCreate,
		}

		if len(in.pathArgs) > 0 {
			input.CollectionFunctionArgs, input.ResourceFunctionArgs, input.CollectionPath, input.ResourcePath = getArgsAndPaths(in.pathArgs, "")
			input.CollectionFunctionArg2, input.ResourceFunctionArg2, input.CollectionPath2, input.ResourcePath2 = getArgsAndPathsNewStyle(in.pathArgs, "")
		}

		if err := structTemplate.Execute(outBuf, input); err != nil {
			fmt.Printf("error executing struct template for resource %s: %v\n", in.generatedStructure.name, err)
			os.Exit(1)
		}

		if len(in.sliceSubTypes) > 0 {
			input.SliceSubTypes = in.sliceSubTypes
			if !in.disableOldStyle {
				in.templates = append(in.templates, sliceSubTypeTemplate)
			}
			if in.useNewStyle {
				in.templates = append(in.templates, sliceSubTypeTemplate2)
			}
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

var listTemplate2 = template.Must(template.New("").Funcs(
	template.FuncMap{
		"snakeCase": snakeCase,
	},
).Parse(`
func (c *Client) List2(ctx context.Context, {{ .CollectionFunctionArg2 }} string, opt... Option) ([]*{{ .Name }}, *api.Error, error) {
	if {{ .CollectionFunctionArg2 }} == "" {
		return nil, nil, fmt.Errorf("empty {{ .CollectionFunctionArg2 }} value passed into List request")
	}
	if c.client == nil {
		return nil, nil, fmt.Errorf("nil client")
	}

	opts, apiOpts := getOpts(opt...)
	apiOpts = append(apiOpts, api.WithNewStyle())
	opts.queryMap["{{ snakeCase .CollectionFunctionArg2 }}"] = {{ .CollectionFunctionArg2 }}

	req, err := c.client.NewRequest(ctx, "GET", "{{ .CollectionPath2 }}", nil, apiOpts...)
	if err != nil {
		return nil, nil, fmt.Errorf("error creating List request: %w", err)
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
	if apiErr != nil {
		return nil, apiErr, nil
	}
	return target.Items, apiErr, nil
}
`))

var listTemplate = template.Must(template.New("").Parse(`
func (c *Client) List(ctx context.Context, {{ range .CollectionFunctionArgs }} {{ . }} string, {{ end }}opt... Option) ([]*{{ .Name }}, *api.Error, error) { {{ range .CollectionFunctionArgs }}
	if {{ . }} == "" {
		return nil, nil, fmt.Errorf("empty {{ . }} value passed into List request")
	}
	{{ end }}
	if c.client == nil {
		return nil, nil, fmt.Errorf("nil client")
	}

	opts, apiOpts := getOpts(opt...)

	req, err := c.client.NewRequest(ctx, "GET", {{ .CollectionPath }}, nil, apiOpts...)
	if err != nil {
		return nil, nil, fmt.Errorf("error creating List request: %w", err)
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
	if apiErr != nil {
		return nil, apiErr, nil
	}
	return target.Items, apiErr, nil
}
`))

var readTemplate2 = template.Must(template.New("").Parse(`
func (c *Client) Read2(ctx context.Context, {{ .ResourceFunctionArg2 }} string, opt... Option) (*{{ .Name }}, *api.Error, error) {
	if {{ .ResourceFunctionArg2 }} == "" {
		return nil, nil, fmt.Errorf("empty  {{ .ResourceFunctionArg2 }} value passed into Read request")
	}
	if c.client == nil {
		return nil, nil, fmt.Errorf("nil client")
	}

	opts, apiOpts := getOpts(opt...)
	apiOpts = append(apiOpts, api.WithNewStyle())

	req, err := c.client.NewRequest(ctx, "GET", {{ .ResourcePath2 }}, nil, apiOpts...)
	if err != nil {
		return nil, nil, fmt.Errorf("error creating Read request: %w", err)
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
		return nil, nil, fmt.Errorf("error performing client request during Read call: %w", err)
	}

	target := new({{ .Name }})
	apiErr, err := resp.Decode(target)
	if err != nil {
		return nil, nil, fmt.Errorf("error decoding Read response: %w", err)
	}
	if apiErr != nil {
		return nil, apiErr, nil
	}
	return target, apiErr, nil
}
`))

var readTemplate = template.Must(template.New("").Parse(`
func (c *Client) Read(ctx context.Context, {{ range .ResourceFunctionArgs }} {{ . }} string, {{ end }} opt... Option) (*{{ .Name }}, *api.Error, error) { {{ range .ResourceFunctionArgs }}
	if {{ . }} == "" {
		return nil, nil, fmt.Errorf("empty {{ . }} value passed into Read request")
	}
	{{ end }}
	if c.client == nil {
		return nil, nil, fmt.Errorf("nil client")
	}

	opts, apiOpts := getOpts(opt...)

	req, err := c.client.NewRequest(ctx, "GET", {{ .ResourcePath }}, nil, apiOpts...)
	if err != nil {
		return nil, nil, fmt.Errorf("error creating Read request: %w", err)
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
		return nil, nil, fmt.Errorf("error performing client request during Read call: %w", err)
	}

	target := new({{ .Name }})
	apiErr, err := resp.Decode(target)
	if err != nil {
		return nil, nil, fmt.Errorf("error decoding Read response: %w", err)
	}
	if apiErr != nil {
		return nil, apiErr, nil
	}
	return target, apiErr, nil
}
`))

var deleteTemplate2 = template.Must(template.New("").Parse(`
func (c *Client) Delete2(ctx context.Context, {{ .ResourceFunctionArg2 }} string, opt... Option) (bool, *api.Error, error) { 
	if {{ .ResourceFunctionArg2 }} == "" {
		return false, nil, fmt.Errorf("empty {{ .ResourceFunctionArg2 }} value passed into Delete request")
	}
	if c.client == nil {
		return false, nil, fmt.Errorf("nil client")
	}
	
	opts, apiOpts := getOpts(opt...)
	apiOpts = append(apiOpts, api.WithNewStyle())

	req, err := c.client.NewRequest(ctx, "DELETE", {{ .ResourcePath2 }}, nil, apiOpts...)
	if err != nil {
		return false, nil, fmt.Errorf("error creating Delete request: %w", err)
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
	if apiErr != nil {
		return false, apiErr, nil
	}
	return target.Existed, apiErr, nil
}
`))

var deleteTemplate = template.Must(template.New("").Parse(`
func (c *Client) Delete(ctx context.Context, {{ range .ResourceFunctionArgs }} {{ . }} string, {{ end }} opt... Option) (bool, *api.Error, error) { {{ range .ResourceFunctionArgs }}
	if {{ . }} == "" {
		return false, nil, fmt.Errorf("empty {{ . }} value passed into Delete request")
	}
	{{ end }}
	if c.client == nil {
		return false, nil, fmt.Errorf("nil client")
	}
	
	opts, apiOpts := getOpts(opt...)

	req, err := c.client.NewRequest(ctx, "DELETE", {{ .ResourcePath }}, nil, apiOpts...)
	if err != nil {
		return false, nil, fmt.Errorf("error creating Delete request: %w", err)
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
	if apiErr != nil {
		return false, apiErr, nil
	}
	return target.Existed, apiErr, nil
}
`))

var createTemplate2 = template.Must(template.New("").Funcs(
	template.FuncMap{
		"snakeCase": snakeCase,
	},
).Parse(`
func (c *Client) Create2(ctx context.Context, {{ if .TypeOnCreate }} resourceType string, {{ end }} {{ .CollectionFunctionArg2 }} string, opt... Option) (*{{ .Name }}, *api.Error, error) {
	if {{ .CollectionFunctionArg2 }} == "" {
		return nil, nil, fmt.Errorf("empty {{ .CollectionFunctionArg2 }} value passed into Create request")
	}
	opts, apiOpts := getOpts(opt...)
	apiOpts = append(apiOpts, api.WithNewStyle())
	if c.client == nil {
		return nil, nil, fmt.Errorf("nil client")
	}
	{{ if .TypeOnCreate }} if resourceType == "" {
		return nil, nil, fmt.Errorf("empty resourceType value passed into Create request")
	} else {
		opts.postMap["type"] = resourceType
	}{{ end }}

	opts.postMap["{{ snakeCase .CollectionFunctionArg2 }}"] = {{ .CollectionFunctionArg2 }}

	req, err := c.client.NewRequest(ctx, "POST", "{{ .CollectionPath2 }}", opts.postMap, apiOpts...)
	if err != nil {
		return nil, nil, fmt.Errorf("error creating Create request: %w", err)
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
		return nil, nil, fmt.Errorf("error performing client request during Create call: %w", err)
	}

	target := new({{ .Name }})
	apiErr, err := resp.Decode(target)
	if err != nil {
		return nil, nil, fmt.Errorf("error decoding Create response: %w", err)
	}
	if apiErr != nil {
		return nil, apiErr, nil
	}
	return target, apiErr, nil
}
`))

var createTemplate = template.Must(template.New("").Parse(`
func (c *Client) Create(ctx context.Context, {{ if .TypeOnCreate }} resourceType string, {{ end }} {{ range .CollectionFunctionArgs }} {{ . }} string, {{ end }} opt... Option) (*{{ .Name }}, *api.Error, error) { {{ range .CollectionFunctionArgs }}
	if {{ . }} == "" {
		return nil, nil, fmt.Errorf("empty {{ . }} value passed into Create request")
	}
	{{ end }}opts, apiOpts := getOpts(opt...)
	if c.client == nil {
		return nil, nil, fmt.Errorf("nil client")
	}
	{{ if .TypeOnCreate }} if resourceType == "" {
		return nil, nil, fmt.Errorf("empty resourceType value passed into Create request")
	} else {
		opts.postMap["type"] = resourceType
	}{{ end }}

	req, err := c.client.NewRequest(ctx, "POST", {{ .CollectionPath }}, opts.postMap, apiOpts...)
	if err != nil {
		return nil, nil, fmt.Errorf("error creating Create request: %w", err)
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
		return nil, nil, fmt.Errorf("error performing client request during Create call: %w", err)
	}

	target := new({{ .Name }})
	apiErr, err := resp.Decode(target)
	if err != nil {
		return nil, nil, fmt.Errorf("error decoding Create response: %w", err)
	}
	if apiErr != nil {
		return nil, apiErr, nil
	}
	return target, apiErr, nil
}
`))

var updateTemplate2 = template.Must(template.New("").Parse(`
func (c *Client) Update2(ctx context.Context, {{ .ResourceFunctionArg2 }} string, version uint32, opt... Option) (*{{ .Name }}, *api.Error, error) {
	if {{ .ResourceFunctionArg2 }} == "" {
		return nil, nil, fmt.Errorf("empty {{ .ResourceFunctionArg2 }} value passed into Update request")
	}
	if c.client == nil {
		return nil, nil, fmt.Errorf("nil client")
	}

	opts, apiOpts := getOpts(opt...)
	apiOpts = append(apiOpts, api.WithNewStyle())

	{{ if .VersionEnabled }}
	if version == 0 {
		if !opts.withAutomaticVersioning {
			return nil, nil, errors.New("zero version number passed into Update request and automatic versioning not specified")
		}
		existingTarget, existingApiErr, existingErr := c.Read2(ctx, {{ .ResourceFunctionArg2 }}, opt...)
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

	opts.postMap["version"] = version

	req, err := c.client.NewRequest(ctx, "PATCH", {{ .ResourcePath2 }}, opts.postMap, apiOpts...)
	if err != nil {
		return nil, nil, fmt.Errorf("error creating Update request: %w", err)
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
		return nil, nil, fmt.Errorf("error performing client request during Update call: %w", err)
	}

	target := new({{ .Name }})
	apiErr, err := resp.Decode(target)
	if err != nil {
		return nil, nil, fmt.Errorf("error decoding Update response: %w", err)
	}
	if apiErr != nil {
		return nil, apiErr, nil
	}
	return target, apiErr, nil
}
`))

var updateTemplate = template.Must(template.New("").Parse(`
func (c *Client) Update(ctx context.Context, {{ range .ResourceFunctionArgs }} {{ . }} string, {{ end }}version uint32, opt... Option) (*{{ .Name }}, *api.Error, error) { {{ range .ResourceFunctionArgs }}
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

	opts.postMap["version"] = version

	req, err := c.client.NewRequest(ctx, "PATCH", {{ .ResourcePath }}, opts.postMap, apiOpts...)
	if err != nil {
		return nil, nil, fmt.Errorf("error creating Update request: %w", err)
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
		return nil, nil, fmt.Errorf("error performing client request during Update call: %w", err)
	}

	target := new({{ .Name }})
	apiErr, err := resp.Decode(target)
	if err != nil {
		return nil, nil, fmt.Errorf("error decoding Update response: %w", err)
	}
	if apiErr != nil {
		return nil, apiErr, nil
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
func (c *Client) {{ $fullName }}(ctx context.Context, {{ range $input.ResourceFunctionArgs }} {{ . }} string, {{ end }}version uint32, {{ $value }} []string, opt... Option) (*{{ $input.Name }}, *api.Error, error) { {{ range $input.ResourceFunctionArgs }}
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
	opts.postMap["version"] = version

	if len({{ $value }}) > 0 {
		opts.postMap["{{ snakeCase $value }}"] = {{ $value }}
	}{{ if ( eq $op "Set" ) }} else if {{ $value }} != nil {
			// In this function, a non-nil but empty list means clear out
			opts.postMap["{{ snakeCase $value }}"] = nil
		}
	{{ end }}

	req, err := c.client.NewRequest(ctx, "POST", {{ $resPath }}, opts.postMap, apiOpts...)
	if err != nil {
		return nil, nil, fmt.Errorf("error creating {{ $fullName }} request: %w", err)
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
		return nil, nil, fmt.Errorf("error performing client request during {{ $fullName }} call: %w", err)
	}

	target := new({{ $input.Name }})
	apiErr, err := resp.Decode(target)
	if err != nil {
		return nil, nil, fmt.Errorf("error decoding {{ $fullName }} response: %w", err)
	}
	if apiErr != nil {
		return nil, apiErr, nil
	}
	return target, apiErr, nil
}
{{ end }}
{{ end }}
`))

var sliceSubTypeTemplate2 = template.Must(template.New("").Funcs(
	template.FuncMap{
		"makeSlice":                 makeSlice,
		"snakeCase":                 snakeCase,
		"kebabCase":                 kebabCase,
		"getPathWithActionNewStyle": getPathWithActionNewStyle,
	},
).Parse(`
{{ $input := . }}
{{ range $index, $op := makeSlice "Add" "Set" "Remove" }}
{{ range $key, $value := $input.SliceSubTypes }}
{{ $fullName := print $op $key }}
{{ $actionName := kebabCase $fullName }}
{{ $resPath := getPathWithActionNewStyle $input.PathArgs $actionName }}
func (c *Client) {{ $fullName }}2(ctx context.Context, {{ $input.ResourceFunctionArg2 }} string, version uint32, {{ $value }} []string, opt... Option) (*{{ $input.Name }}, *api.Error, error) { 
	if {{ $input.ResourceFunctionArg2 }} == "" {
		return nil, nil, fmt.Errorf("empty {{ $input.ResourceFunctionArg2 }} value passed into {{ $fullName }} request")
	}
	if c.client == nil {
		return nil, nil, fmt.Errorf("nil client")
	}

	opts, apiOpts := getOpts(opt...)
	apiOpts = append(apiOpts, api.WithNewStyle())

	{{ if $input.VersionEnabled }}
	if version == 0 {
		if !opts.withAutomaticVersioning {
			return nil, nil, errors.New("zero version number passed into {{ $fullName }} request")
		}
		existingTarget, existingApiErr, existingErr := c.Read2(ctx, {{ $input.ResourceFunctionArg2 }}, opt...)
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
	opts.postMap["version"] = version

	if len({{ $value }}) > 0 {
		opts.postMap["{{ snakeCase $value }}"] = {{ $value }}
	}{{ if ( eq $op "Set" ) }} else if {{ $value }} != nil {
			// In this function, a non-nil but empty list means clear out
			opts.postMap["{{ snakeCase $value }}"] = nil
		}
	{{ end }}

	req, err := c.client.NewRequest(ctx, "POST", {{ $resPath }}, opts.postMap, apiOpts...)
	if err != nil {
		return nil, nil, fmt.Errorf("error creating {{ $fullName }} request: %w", err)
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
		return nil, nil, fmt.Errorf("error performing client request during {{ $fullName }} call: %w", err)
	}

	target := new({{ $input.Name }})
	apiErr, err := resp.Decode(target)
	if err != nil {
		return nil, nil, fmt.Errorf("error decoding {{ $fullName }} response: %w", err)
	}
	if apiErr != nil {
		return nil, apiErr, nil
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

	"github.com/hashicorp/boundary/api"
	"github.com/hashicorp/boundary/api/scopes"
)

type {{ .Name }} struct { {{ range .Fields }}
{{ .Name }}  {{ .FieldType }} `, "`json:\"{{ .ProtoName }},omitempty\"`", `{{ end }}
}
`)))

var clientTemplate = template.Must(template.New("").Parse(`
type Client struct {
	client *api.Client
}

func NewClient(c *api.Client) *Client {
	return &Client{ client: c }
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
	withScopeId string
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

func getPathWithActionNewStyle(resArgs []string, action string) string {
	_, _, _, resPath := getArgsAndPathsNewStyle(resArgs, action)
	return resPath
}
