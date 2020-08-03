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
	Name                   string
	Package                string
	Fields                 []fieldInfo
	CollectionFunctionArgs []string
	ResourceFunctionArgs   []string
	CollectionPath         string
	ResourcePath           string
}

func fillTemplates() {
	for _, in := range inputStructs {
		outBuf := new(bytes.Buffer)
		input := templateInput{
			Name:    in.generatedStructure.name,
			Package: in.generatedStructure.pkg,
			Fields:  in.generatedStructure.fields,
		}

		if len(in.pathArgs) > 0 {
			input.CollectionFunctionArgs, input.ResourceFunctionArgs, input.CollectionPath, input.ResourcePath = getArgsAndPaths(in.pathArgs)
		}

		structTemplate.Execute(outBuf, input)

		for _, t := range in.templates {
			t.Execute(outBuf, input)
		}

		outFile, err := filepath.Abs(fmt.Sprintf("%s/%s", os.Getenv("GEN_BASEPATH"), in.outFile))
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
}

var listTemplate = template.Must(template.New("").Parse(`
func (s *{{ .Name }}Client) List(ctx context.Context, {{ range .CollectionFunctionArgs }} {{ . }} string, {{ end }}opts... api.Option) ([]{{ .Name }}, *api.Error, error) {
	{{ range .CollectionFunctionArgs }}
		if {{ . }} == "" {
			return nil, nil, fmt.Errorf("empty {{ . }} value passed into List request")
		}
	{{ end }}
	if s.client == nil {
		return nil, nil, fmt.Errorf("nil client")
	}

	req, err := s.client.NewRequest(ctx, "GET", {{ .CollectionPath }}, nil, opts...)
	if err != nil {
		return nil, nil, fmt.Errorf("error creating List request: %w", err)
	}

	resp, err := s.client.Do(req)
	if err != nil {
		return nil, nil, fmt.Errorf("error performing client request during List call: %w", err)
	}

	type listResponse struct {
		Items []{{ .Name }}
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
func (s *{{ .Name }}Client) Read(ctx context.Context, {{ range .ResourceFunctionArgs }} {{ . }} string, {{ end }} opts... api.Option) (*{{ .Name }}, *api.Error, error) {
	{{ range .ResourceFunctionArgs }}
	if {{ . }} == "" {
		return nil, nil, fmt.Errorf("empty {{ . }} value passed into List request")
	}
	{{ end }}
	if s.client == nil {
		return nil, nil, fmt.Errorf("nil client")
	}

	req, err := s.client.NewRequest(ctx, "GET", {{ .ResourcePath }}, nil, opts...)
	if err != nil {
		return nil, nil, fmt.Errorf("error creating Read request: %w", err)
	}

	resp, err := s.client.Do(req)
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
func (s *{{ .Name }}Client) Delete(ctx context.Context, {{ range .ResourceFunctionArgs }} {{ . }} string, {{ end }} opts... api.Option) (bool, *api.Error, error) {
	{{ range .ResourceFunctionArgs }}
	if {{ . }} == "" {
		return false, nil, fmt.Errorf("empty {{ . }} value passed into List request")
	}
	{{ end }}
	if s.client == nil {
		return false, nil, fmt.Errorf("nil client")
	}

	req, err := s.client.NewRequest(ctx, "DELETE", {{ .ResourcePath }}, nil, opts...)
	if err != nil {
		return false, nil, fmt.Errorf("error creating Delete request: %w", err)
	}

	resp, err := s.client.Do(req)
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
func (s *{{ .Name }}Client) Create(ctx context.Context, {{ range .CollectionFunctionArgs }} . string, {{ end }} opts... api.Option) (*{{ .Name }}, *api.Error, error) {
	{{ range .CollectionFunctionArgs }}
	if . == "" {
		return nil, nil, fmt.Errorf("empty {{ . }} value passed into List request")
	}
	{{ end }}
	if s.client == nil {
		return nil, nil, fmt.Errorf("nil client")
	}
	r := {{ .Name }}{}
	req, err := s.client.NewRequest(ctx, "POST", {{ .CollectionPath }}, r, opts...)
	if err != nil {
		return nil, nil, fmt.Errorf("error creating Create request: %w", err)
	}

	resp, err := s.client.Do(req)
	if err != nil {
		return nil, nil, fmt.Errorf("error performing client request during Read call: %w", err)
	}

	target := new({{ .Name }})
	apiErr, err := resp.Decode(target)
	if err != nil {
		return nil, nil, fmt.Errorf("error decoding Create response: %w", err)
	}

	return target, apiErr, nil
}
`))

var structTemplate = template.Must(template.New("").Parse(
	fmt.Sprint(`// Code generated by "make api"; DO NOT EDIT.
package {{ .Package }}

import (
	"context"
	"encoding/json"
	"strings"

	"github.com/fatih/structs"

	"github.com/hashicorp/watchtower/api"
)

type {{ .Name }} struct {
{{ range .Fields }} {{ .Name }}  {{ .FieldType }} `, "`json:\"{{ .ProtoName }},omitempty\"`", `
{{ end }}
}
`)))

var clientTemplate = template.Must(template.New("").Parse(`
type {{ .Name }}Client struct {
	client *api.Client
}

func New(c *api.Client) *{{ .Name }}Client {
	return &{{ .Name }}Client{ client: c }
}
`))
