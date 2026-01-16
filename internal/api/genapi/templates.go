// Copyright IBM Corp. 2020, 2025
// SPDX-License-Identifier: BUSL-1.1

package main

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"text/template"

	"github.com/hashicorp/go-secure-stdlib/strutil"
	"github.com/iancoleman/strcase"
)

func getArgsAndPaths(pluralResource, parentTypeName, action string) (colArg, colPath, resPath string) {
	strToReplace := "scope"
	if parentTypeName != "" {
		strToReplace = parentTypeName
	}

	colArg = fmt.Sprintf("%sId", strcase.ToLowerCamel(strings.ReplaceAll(strToReplace, "-", "_")))
	colPath = pluralResource
	// append s at the end only if it isn't already present
	if colPath[len(colPath)-1] != 's' {
		colPath = fmt.Sprintf("%ss", colPath)
	}

	if action != "" {
		action = fmt.Sprintf(":%s", action)
	}
	resPath = fmt.Sprintf("fmt.Sprintf(\"%s/%%s%s\", url.PathEscape(id))", colPath, action)
	return colArg, colPath, resPath
}

type templateInput struct {
	Name                  string
	Package               string
	Fields                []fieldInfo
	PluralResourceName    string
	CollectionFunctionArg string
	ResourceFunctionArg   string
	CollectionPath        string
	ResourcePath          string
	ParentTypeName        string
	SliceSubtypes         map[string]sliceSubtypeInfo
	ExtraFields           []fieldInfo
	VersionEnabled        bool
	NonPaginatedListing   bool
	CreateResponseTypes   []string
	SkipListFiltering     bool
	RecursiveListing      bool
	Subtype               string
}

func fillTemplates() {
	optionsMap := map[string]map[string]fieldInfo{}
	inputMap := map[string]*structInfo{}
	for _, in := range inputStructs {
		inputMap[in.generatedStructure.pkg] = in
		outBuf := new(bytes.Buffer)
		input := templateInput{
			Name:                in.generatedStructure.name,
			Package:             in.generatedStructure.pkg,
			Fields:              in.generatedStructure.fields,
			PluralResourceName:  in.pluralResourceName,
			ParentTypeName:      in.parentTypeName,
			ExtraFields:         in.extraFields,
			VersionEnabled:      in.versionEnabled,
			NonPaginatedListing: in.nonPaginatedListing,
			CreateResponseTypes: in.createResponseTypes,
			SkipListFiltering:   in.skipListFiltering,
			RecursiveListing:    in.recursiveListing,
			Subtype:             in.subtype,
		}
		if in.packageOverride != "" {
			input.Package = in.packageOverride
		}
		if in.nameOverride != "" {
			input.Name = in.nameOverride
		}

		if len(in.pluralResourceName) > 0 {
			input.CollectionFunctionArg, input.CollectionPath, input.ResourcePath = getArgsAndPaths(in.pluralResourceName, in.parentTypeName, "")
		}

		for _, override := range in.fieldOverrides {
			for i, field := range in.generatedStructure.fields {
				if field.Name == override.Name {
					if override.FieldType != "" {
						field.FieldType = override.FieldType
					}
					if len(override.JsonTags) != 0 {
						field.JsonTags = override.JsonTags
					}
					if override.AllowEmpty {
						field.AllowEmpty = true
					}
					in.generatedStructure.fields[i] = field
				}
			}
		}

		if err := structTemplate.Execute(outBuf, input); err != nil {
			fmt.Printf("error executing struct template for resource %s: %v\n", in.generatedStructure.name, err)
			os.Exit(1)
		}

		if len(in.sliceSubtypes) > 0 {
			input.SliceSubtypes = in.sliceSubtypes
			in.templates = append(in.templates, sliceSubtypeTemplate)
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
		if !in.skipOptions {
			pkgOptionMap := map[string]fieldInfo{}
			for _, val := range input.Fields {
				if val.GenerateSdkOption {
					val.SubtypeNames = append(val.SubtypeNames, in.subtypeName)
					pkgOptionMap[val.Name] = val
				}
			}
			optionMap := optionsMap[input.Package]
			if optionMap == nil {
				optionMap = map[string]fieldInfo{}
			}
			for name, val := range pkgOptionMap {
				val.SubtypeNames = append(val.SubtypeNames, optionMap[name].SubtypeNames...)
				optionMap[name] = val
			}
			optionsMap[input.Package] = optionMap
		}
		// Add in extra defined fields
		if len(in.extraFields) > 0 {
			optionMap := optionsMap[input.Package]
			if optionMap == nil {
				optionMap = map[string]fieldInfo{}
			}
			for _, val := range in.extraFields {
				optionMap[val.Name] = val
			}
			optionsMap[input.Package] = optionMap
		}
		// Override some defined options
		if len(in.fieldOverrides) > 0 {
			for _, override := range in.fieldOverrides {
				inOpts := optionsMap[input.Package]
				if inOpts != nil {
					if override.SkipDefault {
						fieldInfo := inOpts[override.Name]
						fieldInfo.SkipDefault = true
						inOpts[override.Name] = fieldInfo
					}
				}
			}
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
		if err := os.WriteFile(outFile, outBuf.Bytes(), 0o644); err != nil {
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
			Package:           pkg,
			Fields:            fields,
			SkipListFiltering: inputMap[pkg].skipListFiltering,
			RecursiveListing:  inputMap[pkg].recursiveListing,
			VersionEnabled:    inputMap[pkg].versionEnabled,
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
		if err := os.WriteFile(outFile, outBuf.Bytes(), 0o644); err != nil {
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

	requestPath := "{{ .CollectionPath }}"
	if opts.withResourcePathOverride != "" {
		requestPath = opts.withResourcePathOverride
	}

	req, err := c.client.NewRequest(ctx, "GET", requestPath, nil, apiOpts...)
	if err != nil {
		return nil, fmt.Errorf("error creating List request: %w", err)
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
	target.Response = resp
{{ if .NonPaginatedListing }}
	return target, nil
{{ end }}
{{ if ( not ( .NonPaginatedListing ) ) }}
	if target.ResponseType == "complete" || target.ResponseType == "" {
		return target, nil
	}

	// In case we shortcut out due to client directed pagination, ensure these
	// are set
{{ if .RecursiveListing }} 
	target.recursive = opts.withRecursive
{{ end }}
	target.pageSize = opts.withPageSize
	target.{{ .CollectionFunctionArg }} = {{ .CollectionFunctionArg }}
	target.allRemovedIds = target.RemovedIds
	if opts.withClientDirectedPagination {
		return target, nil
	}

	allItems := make([]*{{ .Name }}, 0, target.EstItemCount)
	allItems = append(allItems, target.Items...)

	// If there are more results, automatically fetch the rest of the results.
	// idToIndex keeps a map from the ID of an item to its index in target.Items.
	// This is used to update updated items in-place and remove deleted items
	// from the result after pagination is done.
	idToIndex := map[string]int{}
	for i, item := range allItems {
		idToIndex[item.Id] = i
	}

	// If we're here there are more pages and the client does not want to
	// paginate on their own; fetch them as this call returns all values.
	currentPage := target
	for {
		nextPage, err := c.ListNextPage(ctx, currentPage, opt...)
		if err != nil {
			return nil, fmt.Errorf("error getting next page in List call: %w", err)
		}

		for _, item := range nextPage.Items {
			if i, ok := idToIndex[item.Id]; ok {
				// Item has already been seen at index i, update in-place
				allItems[i] = item
			} else {
				allItems = append(allItems, item)
				idToIndex[item.Id] = len(allItems) - 1
			}
		}

		currentPage = nextPage

		if currentPage.ResponseType == "complete" {
			break
		}
	}

	// The current page here is the final page of the results, that is, the
	// response type is "complete"

	// Remove items that were deleted since the end of the last iteration.
	// If a {{ .Name }} has been updated and subsequently removed, we don't want
	// it to appear both in the Items and RemovedIds, so we remove it from the Items.
	for _, removedId := range currentPage.RemovedIds {
		if i, ok := idToIndex[removedId]; ok {
			// Remove the item at index i without preserving order
			// https://github.com/golang/go/wiki/SliceTricks#delete-without-preserving-order
			allItems[i] = allItems[len(allItems)-1]
			allItems = allItems[:len(allItems)-1]
			// Update the index of the previously last element
			idToIndex[allItems[i].Id] = i
		}
	}
	// Sort the results again since in-place updates and deletes
	// may have shuffled items. We sort by created time descending
	// (most recently created first), same as the API.
	slices.SortFunc(allItems, func(i, j *{{ .Name }}) int {
		return j.CreatedTime.Compare(i.CreatedTime)
	})
	// Since we paginated to the end, we can avoid confusion
	// for the user by setting the estimated item count to the
	// length of the items slice. If we don't set this here, it
	// will equal the value returned in the last response, which is
	// often much smaller than the total number returned.
	currentPage.EstItemCount = uint(len(allItems))
	// Set items to the full list we have collected here
	currentPage.Items = allItems
	// Set the returned value to the last page with calculated values
	target = currentPage
	// Finally, since we made at least 2 requests to the server to fulfill this
	// function call, resp.Body and resp.Map will only contain the most recent response.
	// Overwrite them with the true response.
	target.Response.Body.Reset()
	if err := json.NewEncoder(target.Response.Body).Encode(target); err != nil {
		return nil, fmt.Errorf("error encoding final JSON list response: %w", err)
	}
	if err := json.Unmarshal(target.Response.Body.Bytes(), &target.Response.Map); err != nil {
		return nil, fmt.Errorf("error encoding final map list response: %w", err)
	}
	// Note: the HTTP response body is consumed by resp.Decode in the loop,
	// so it doesn't need to be updated (it will always be, and has always been, empty).
	return target, nil
{{ end  }}
}

{{ if ( not ( .NonPaginatedListing ) ) }}
func (c *Client) ListNextPage(ctx context.Context, currentPage *{{ .Name }}ListResult, opt ...Option) (*{{ .Name }}ListResult, error) {
	if currentPage == nil {
		return nil, fmt.Errorf("empty currentPage value passed into ListNextPage request")
	}
	if currentPage.{{ .CollectionFunctionArg }} == "" {
		return nil, fmt.Errorf("empty {{ .CollectionFunctionArg }} value in currentPage passed into ListNextPage request")
	}
	if c.client == nil {
		return nil, fmt.Errorf("nil client")
	}
	if currentPage.ResponseType == "complete" || currentPage.ResponseType == "" {
		return nil, fmt.Errorf("no more pages available in ListNextPage request")
	}

	opts, apiOpts := getOpts(opt...)
	opts.queryMap["{{ snakeCase .CollectionFunctionArg }}"] = currentPage.{{ .CollectionFunctionArg }}

{{ if .RecursiveListing }} 
	// Don't require them to re-specify recursive
	if currentPage.recursive {
		opts.queryMap["recursive"] = "true"
	}
{{ end }}
	if currentPage.pageSize != 0 {
		opts.queryMap["page_size"] = strconv.FormatUint(uint64(currentPage.pageSize), 10)
	}

	requestPath := "{{ .CollectionPath }}"
	if opts.withResourcePathOverride != "" {
		requestPath = opts.withResourcePathOverride
	}

	req, err := c.client.NewRequest(ctx, "GET", requestPath, nil, apiOpts...)
	if err != nil {
		return nil, fmt.Errorf("error creating List request: %w", err)
	}

	opts.queryMap["list_token"] = currentPage.ListToken
	if len(opts.queryMap) > 0 {
		q := url.Values{}
		for k, v := range opts.queryMap {
			q.Add(k, v)
		}
		req.URL.RawQuery = q.Encode()
	}

	resp, err := c.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("error performing client request during List call during ListNextPage: %w", err)
	}

	nextPage := new({{ .Name }}ListResult)
	apiErr, err := resp.Decode(nextPage)
	if err != nil {
		return nil, fmt.Errorf("error decoding List response during ListNextPage: %w", err)
	}
	if apiErr != nil {
		return nil, apiErr
	}

	// Ensure values are carried forward to the next call
	nextPage.{{ .CollectionFunctionArg }} = currentPage.{{ .CollectionFunctionArg }}
{{ if .RecursiveListing }}
	nextPage.recursive = currentPage.recursive
{{ end }} 
	nextPage.pageSize = currentPage.pageSize
	// Cache the removed IDs from this page
	nextPage.allRemovedIds = append(currentPage.allRemovedIds, nextPage.RemovedIds...)
	// Set the response body to the current response
	nextPage.Response = resp
	// If we're done iterating, pull the full set of removed IDs into the last
	// response
	if nextPage.ResponseType == "complete" {
		// Collect up the last values
		nextPage.RemovedIds = nextPage.allRemovedIds
		// For now, removedIds will only be populated if this pagination cycle
		// was the result of a "refresh" operation (i.e., the caller provided a
		// list token option to this call).
		//
		// Sort to make response deterministic
		slices.Sort(nextPage.RemovedIds)
		// Remove any duplicates
		nextPage.RemovedIds = slices.Compact(nextPage.RemovedIds)
	}

	return nextPage, nil
}
{{ end }}
`))

var readTemplate = template.Must(template.New("").Parse(`
func (c *Client) Read(ctx context.Context, id string, opt... Option) (*{{ .Name }}ReadResult, error) {
	if id == "" {
		return nil, fmt.Errorf("empty id value passed into Read request")
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

	resp, err := c.client.Do(req, apiOpts...)
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
	target.Response = resp
	return target, nil
}
`))

var deleteTemplate = template.Must(template.New("").Parse(`
func (c *Client) Delete(ctx context.Context, id string, opt... Option) (*{{ .Name }}DeleteResult, error) { 
	if id == "" {
		return nil, fmt.Errorf("empty id value passed into Delete request")
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
		Response: resp,
	}
	return target, nil
}
`))

const createTemplateStr = `
func (c *Client) {{ funcName }} (ctx context.Context, {{ range extraRequiredParams }} {{ .Name }} {{ .Typ }}, {{ end }} {{ .CollectionFunctionArg }} string, opt... Option) (*{{ .Name }}CreateResult, error) {
	if {{ .CollectionFunctionArg }} == "" {
		return nil, fmt.Errorf("empty {{ .CollectionFunctionArg }} value passed into {{ funcName }} request")
	}

	opts, apiOpts := getOpts(opt...)

	if c.client == nil {
		return nil, fmt.Errorf("nil client")
	}{{ range extraRequiredParams }}
	if {{ .Name }} == "" {
		return nil, fmt.Errorf("empty {{ .Name }} value passed into {{ funcName }} request")
	} else {
		opts.postMap["{{ .PostType }}"] = {{ .Name }}
	}{{ end }}

	opts.postMap["{{ snakeCase .CollectionFunctionArg }}"] = {{ .CollectionFunctionArg }}

	req, err := c.client.NewRequest(ctx, "POST", "{{ .CollectionPath }}{{ apiAction }}", opts.postMap, apiOpts...)
	if err != nil {
		return nil, fmt.Errorf("error creating {{ funcName }} request: %w", err)
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
		return nil, fmt.Errorf("error performing client request during {{ funcName }} call: %w", err)
	}

	target := new({{ .Name }}CreateResult)
	target.Item = new({{ .Name }})
	apiErr, err := resp.Decode(target.Item)
	if err != nil {
		return nil, fmt.Errorf("error decoding {{ funcName }} response: %w", err)
	}
	if apiErr != nil {
		return nil, apiErr
	}
	target.Response = resp
	return target, nil
}
`

var commonCreateTemplate = template.Must(template.New("").Funcs(
	template.FuncMap{
		"snakeCase": snakeCase,
		"funcName": func() string {
			return "Create"
		},
		"apiAction": func() string {
			return ""
		},
		"extraRequiredParams": func() []requiredParam {
			return nil
		},
	},
).Parse(createTemplateStr))

var updateTemplate = template.Must(template.New("").Parse(`
func (c *Client) Update(ctx context.Context, id string, version uint32, opt... Option) (*{{ .Name }}UpdateResult, error) {
	if id == "" {
		return nil, fmt.Errorf("empty id value passed into Update request")
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
		existingTarget, existingErr := c.Read(ctx, id, append([]Option{WithSkipCurlOutput(true)}, opt...)...)
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
	target.Response = resp
	return target, nil
}
`))

var sliceSubtypeTemplate = template.Must(template.New("").Funcs(
	template.FuncMap{
		"makeSlice":         makeSlice,
		"snakeCase":         snakeCase,
		"kebabCase":         kebabCase,
		"getPathWithAction": getPathWithAction,
	},
).Parse(`
{{ $input := . }}
{{ range $index, $op := makeSlice "Add" "Set" "Remove" }}
{{ range $key, $value := $input.SliceSubtypes }}
{{ $fullName := print $op $key }}
{{ $actionName := kebabCase $fullName }}
{{ $resPath := getPathWithAction $input.PluralResourceName $input.ParentTypeName $actionName }}
func (c *Client) {{ $fullName }}(ctx context.Context, id string, version uint32, {{ if ( not ( eq $value.VarName "" ) ) }}{{ $value.VarName }} {{ $value.SliceType }},{{ end }} opt... Option) (*{{ $input.Name }}UpdateResult, error) {
	if id == "" {
		return nil, fmt.Errorf("empty id value passed into {{ $fullName }} request")
	}
	{{ if ( not ( eq $op "Set" ) ) }}
	  {{ if ( not ( eq $value.VarName "" ) ) }}
		if len({{ $value.VarName }}) == 0 {
			return nil, errors.New("empty {{ $value.VarName }} passed into {{ $fullName }} request")
		}
	  {{ end }}
	{{ end }}
	if c.client == nil {
		return nil, errors.New("nil client")
	}

	opts, apiOpts := getOpts(opt...)

	{{ if $input.VersionEnabled }}
	if version == 0 {
		if !opts.withAutomaticVersioning {
			return nil, errors.New("zero version number passed into {{ $fullName }} request")
		}
		existingTarget, existingErr := c.Read(ctx, id, append([]Option{WithSkipCurlOutput(true)}, opt...)...)
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
	{{ if ( not ( eq $value.VarName "" ) ) }}
	opts.postMap["{{ snakeCase $value.VarName }}"] = {{ $value.VarName }}
	{{ end }}

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
	target.Response = resp
	return target, nil
}
{{ end }}
{{ end }}
`))

func hasResponseType(types []string, typ string) bool {
	return strutil.StrListContains(types, typ)
}

var structTemplate = template.Must(template.New("").Funcs(
	template.FuncMap{
		"hasResponseType": hasResponseType,
		"stringsjoin":     strings.Join,
	},
).Parse(
	fmt.Sprint(`// Code generated by "make api"; DO NOT EDIT.
// Copyright IBM Corp. 2020, 2025
// SPDX-License-Identifier: MPL-2.0

package {{ .Package }}

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/url"
	"slices"
	"time"

	"github.com/hashicorp/boundary/api"
	"github.com/hashicorp/boundary/api/scopes"
)

type {{ .Name }} struct { {{ range .Fields }}
{{ .Name }}  {{ .FieldType }} `, "`json:\"{{ .ProtoName }}{{ if ( ne ( len ( .JsonTags ) ) 0 ) }},{{ stringsjoin .JsonTags \",\" }}{{ end }}{{ if ( not .AllowEmpty ) }},omitempty{{ end }}\"`", `{{ end }}
{{ if ( eq .Name "Error" ) }}
	response *Response
{{ end }}
}

{{ if ( hasResponseType .CreateResponseTypes "read" ) }}
type {{ .Name }}ReadResult struct {
	Item *{{ .Name }}
	Response *api.Response
}

func (n {{ .Name }}ReadResult) GetItem() *{{ .Name }} {
	return n.Item
}

func (n {{ .Name }}ReadResult) GetResponse() *api.Response {
	return n.Response
}
{{ end }}
{{ if ( hasResponseType .CreateResponseTypes "create" ) }} type {{ .Name }}CreateResult = {{ .Name }}ReadResult {{ end }}
{{ if ( hasResponseType .CreateResponseTypes "update" ) }} type {{ .Name }}UpdateResult = {{ .Name }}ReadResult {{ end }}

{{ if ( hasResponseType .CreateResponseTypes "delete" ) }}
type {{ .Name }}DeleteResult struct {
	Response *api.Response
}

// GetItem will always be nil for {{ .Name }}DeleteResult
func (n {{ .Name }}DeleteResult) GetItem() any {
	return nil
}

func (n {{ .Name }}DeleteResult) GetResponse() *api.Response {
	return n.Response
}
{{ end }}
{{ if ( hasResponseType .CreateResponseTypes "list" ) }}
type {{ .Name }}ListResult struct {
	Items        []*{{ .Name }} `, "`json:\"items,omitempty\"`", `
	EstItemCount uint           `, "`json:\"est_item_count,omitempty\"`", `
	RemovedIds   []string       `, "`json:\"removed_ids,omitempty\"`", `
	ListToken string            `, "`json:\"list_token,omitempty\"`", `
	ResponseType string         `, "`json:\"response_type,omitempty\"`", `
	Response *api.Response


	// The following fields are used for cached information when client-directed
	// pagination is used.
	recursive bool
	pageSize uint32
	{{ .CollectionFunctionArg }} string
	allRemovedIds []string
}

func (n {{ .Name }}ListResult) GetItems() []*{{ .Name }} {
	return n.Items
}

func (n {{ .Name }}ListResult) GetEstItemCount() uint {
	return n.EstItemCount
}

func (n {{ .Name }}ListResult) GetRemovedIds() []string {
	return n.RemovedIds
}

func (n {{ .Name }}ListResult) GetListToken() string {
	return n.ListToken
}

func (n {{ .Name }}ListResult) GetResponseType() string {
	return n.ResponseType
}

func (n {{ .Name }}ListResult) GetResponse() *api.Response {
	return n.Response
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

var optionTemplate = template.Must(template.New("").Funcs(
	template.FuncMap{
		"makeSlice":  makeSlice,
		"removeDups": removeDups,
	},
).Parse(`// Code generated by "make api"; DO NOT EDIT.
// Copyright IBM Corp. 2020, 2025
// SPDX-License-Identifier: MPL-2.0

package {{ .Package }}

import (
	"strconv"

	"github.com/hashicorp/boundary/api"
)

// Option is a func that sets optional attributes for a call. This does not need
// to be used directly, but instead option arguments are built from the
// functions in this package. WithX options set a value to that given in the
// argument; DefaultX options indicate that the value should be set to its
// default. When an API call is made options are processed in the order they
// appear in the function call, so for a given argument X, a succession of WithX
// or DefaultX calls will result in the last call taking effect.
type Option func(*options)

type options struct {
	postMap map[string]any
	queryMap map[string]string
	withAutomaticVersioning bool
	withSkipCurlOutput bool
	withFilter string
	withListToken string
	withClientDirectedPagination bool
	withPageSize uint32
    withResourcePathOverride string
	{{ if .RecursiveListing }} withRecursive bool {{ end }}
}

func getDefaultOptions() options {
	return options{
		postMap: make(map[string]any),
		queryMap: make(map[string]string),
	}
}

func getOpts(opt ...Option) (options, []api.Option) {
	opts := getDefaultOptions()
	for _, o := range opt {
		if o != nil {
			o(&opts)
		}
	}
	var apiOpts []api.Option
	if opts.withSkipCurlOutput {
		apiOpts = append(apiOpts, api.WithSkipCurlOutput(true))
	}
	if opts.withFilter != "" {
		opts.queryMap["filter"] = opts.withFilter
	}
	if opts.withListToken != "" {
		opts.queryMap["list_token"] = opts.withListToken
	}{{ if .RecursiveListing }}
	if opts.withRecursive {
		opts.queryMap["recursive"] = strconv.FormatBool(opts.withRecursive)
	} {{ end }}
	if opts.withPageSize != 0 {
		opts.queryMap["page_size"] = strconv.FormatUint(uint64(opts.withPageSize), 10)
	}
	return opts, apiOpts
}

{{ if .VersionEnabled }}
// If set, and if the version is zero during an update, the API will perform a
// fetch to get the current version of the resource and populate it during the
// update call. This is convenient but opens up the possibility for subtle
// order-of-modification issues, so use carefully.
func WithAutomaticVersioning(enable bool) Option {
	return func(o *options) {
		o.withAutomaticVersioning = enable
	}
}
{{ end }}

// WithSkipCurlOutput tells the API to not use the current call for cURL output.
// Useful for when we need to look up versions.
func WithSkipCurlOutput(skip bool) Option {
	return func(o *options) {
		o.withSkipCurlOutput = skip
	}
}

// WithListToken tells the API to use the provided list token
// for listing operations on this resource.
func WithListToken(listToken string) Option {
	return func(o *options) {
		o.withListToken = listToken
	}
}

{{ if not .SkipListFiltering }}
// WithFilter tells the API to filter the items returned using the provided
// filter term.  The filter should be in a format supported by
// hashicorp/go-bexpr.
func WithFilter(filter string) Option {
	return func(o *options) {
		o.withFilter = strings.TrimSpace(filter)
	}
}
{{ end }}
// WithClientDirectedPagination tells the List function to return only the first
// page, if more pages are available
func WithClientDirectedPagination(with bool) Option {
	return func(o *options) {
			o.withClientDirectedPagination = with
	}
}

// WithPageSize controls the size of pages used during List
func WithPageSize(with uint32) Option {
	return func(o *options) {
		o.withPageSize = with
	}
}

// WithResourcePathOverride tells the API to use the provided resource path
func WithResourcePathOverride(path string) Option {
	return func(o *options) {
		o.withResourcePathOverride = path
	}
}
{{ if .RecursiveListing }}
// WithRecursive tells the API to use recursion for listing operations on this
// resource
func WithRecursive(recurse bool) Option {
	return func(o *options) {
		o.withRecursive = recurse
	}
}
{{ end }}
{{ range $fieldIndex, $field := .Fields }}
{{ $subtypes := (removeDups $field.SubtypeNames ) }}
{{ if ( eq ( len ( $subtypes ) ) 0 )}}
{{ $subtypes = ( makeSlice "" ) }}
{{ end }}
{{ range $subtypeIndex, $subtypeName := $subtypes }}
func With{{ $subtypeName }}{{ $field.Name }}(in{{ $field.Name }} {{ $field.FieldType }}) Option {
	return func(o *options) {		{{ if ( not ( eq $subtypeName "" ) ) }}
		raw, ok := o.postMap["attributes"]
		if !ok {
			raw = any(map[string]any{})
		}
		val := raw.(map[string]any)
		val["{{ $field.ProtoName }}"] = in{{ $field.Name }}
		o.postMap["attributes"] = val
		{{ else if $field.Query }}
		o.queryMap["{{ $field.ProtoName }}"] = fmt.Sprintf("%v", in{{ $field.Name }})
		{{ else }}
		o.postMap["{{ $field.ProtoName }}"] = in{{ $field.Name }}
		{{ end }}	}
}
{{ if ( not $field.SkipDefault ) }}
func Default{{ $subtypeName }}{{ $field.Name }}() Option {
	return func(o *options) {		{{ if ( not ( eq $subtypeName "" ) ) }}
		raw, ok := o.postMap["attributes"]
		if !ok {
			raw = any(map[string]any{})
		}
		val := raw.(map[string]any)
		val["{{ $field.ProtoName }}"] = nil
		o.postMap["attributes"] = val
		{{ else }}
		o.postMap["{{ $field.ProtoName }}"] = nil
		{{ end }}	}
}
{{ end }}
{{ end }}
{{ end }}
`))

var mapstructureConversionTemplate = template.Must(template.New("").Funcs(
	template.FuncMap{
		"typeFromSubtype": typeFromSubtype,
		"kebabCase":       kebabCase,
	},
).Parse(`
func AttributesMapTo{{ .Name }}(in map[string]any) (*{{ .Name }}, error) {
	if in == nil {
		return nil, fmt.Errorf("nil input map")
	}
	var out {{ .Name }}
	dec, err := mapstructure.NewDecoder(&mapstructure.DecoderConfig{
		Result: &out,
		TagName: "json",
	})
	if err != nil {
		return nil, fmt.Errorf("error creating mapstructure decoder: %w", err)
	}
	if err := dec.Decode(in); err != nil {
		return nil, fmt.Errorf("error decoding: %w", err)
	}
	return &out, nil
}

func (pt *{{ .ParentTypeName }}) Get{{ .Name }}() (*{{ .Name }}, error) {
	if pt.Type != "{{ typeFromSubtype .Subtype .Name .ParentTypeName "Attributes"}}" {
		return nil, fmt.Errorf("asked to fetch %s-type attributes but {{ kebabCase .ParentTypeName }} is of type %s", "{{ typeFromSubtype .Subtype .Name .ParentTypeName "Attributes"}}", pt.Type)
	}
	return AttributesMapTo{{ .Name }}(pt.Attributes)
}
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

func getPathWithAction(plResName, parentTypeName, action string) string {
	_, _, resPath := getArgsAndPaths(plResName, parentTypeName, action)
	return resPath
}

func removeDups(in []string) []string {
	if in == nil {
		return nil
	}
	if len(in) == 0 {
		return []string{}
	}
	vals := make(map[string]struct{}, len(in))
	for _, val := range in {
		vals[val] = struct{}{}
	}
	ret := make([]string, 0, len(vals))
	for val := range vals {
		ret = append(ret, val)
	}

	sort.Strings(ret)

	return ret
}

func typeFromSubtype(subtype, in, parent, extraSuffix string) string {
	if subtype != "" {
		return subtype
	}
	return strings.ToLower(strings.TrimSuffix(strings.TrimSuffix(in, extraSuffix), parent))
}
