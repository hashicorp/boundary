package main

import (
	"bytes"
	"fmt"
	"io/ioutil"
	"os"
	"strings"
	"text/template"
)

type updateInfo struct {
	baseType   string
	targetType string
	path       string
}

var updateFuncs = map[string][]*updateInfo{
	"scopes": {
		{
			baseType:   "Organization",
			targetType: "Project",
			path:       "projects",
		},
		{
			baseType:   "Project",
			targetType: "hosts.HostCatalog",
			path:       "host-catalogs",
		},
	},
}

func writeUpdateFuncs() {
	for outPkg, funcs := range updateFuncs {
		outFile := os.Getenv("GEN_BASEPATH") + fmt.Sprintf("/api/%s/update.gen.go", outPkg)
		outBuf := bytes.NewBuffer([]byte(fmt.Sprintf(
			`// Code generated by "make api"; DO NOT EDIT.
package %s
`, outPkg)))
		for _, updateInfo := range funcs {
			updateFuncTemplate.Execute(outBuf, struct {
				BaseType   string
				TargetType string
				TargetName string
				Path       string
			}{
				BaseType:   updateInfo.baseType,
				TargetType: updateInfo.targetType,
				TargetName: strings.Split(updateInfo.targetType, ".")[strings.Count(updateInfo.targetType, ".")],
				Path:       updateInfo.path,
			})
		}
		if err := ioutil.WriteFile(outFile, outBuf.Bytes(), 0644); err != nil {
			fmt.Printf("error writing file %q: %v\n", outFile, err)
			os.Exit(1)
		}
	}
}

var updateFuncTemplate = template.Must(template.New("").Parse(
	`
func (s {{ .BaseType }}) Update{{ .TargetName }}(ctx context.Context, r *{{ .TargetType }}) (*{{ .TargetType }}, *api.Error, error) {
	if s.Client == nil {
		return nil, nil, fmt.Errorf("nil client in Create{{ .TargetName }} request")
	}
	if s.Id == "" {
		{{ if (eq .BaseType "Organization") }}
		// Assume the client has been configured with organization already and
		// move on
		{{ else if (eq .BaseType "Project") }}
		// Assume the client has been configured with project already and move
		// on
		{{ else }}
		return nil, nil, fmt.Errorf("missing {{ .BaseType}} ID in Create{{ .TargetName }} request")
		{{ end }}
	} else {
		// If it's explicitly set here, override anything that might be in the
		// client
		{{ if (eq .BaseType "Organization") }}
		ctx = context.WithValue(ctx, "org", s.Id)
		{{ else if (eq .BaseType "Project") }}
		ctx = context.WithValue(ctx, "project", s.Id)
		{{ end }}
	}

	id := r.Id
	r.Id = ""

	req, err := s.Client.NewRequest(ctx, "PATCH", fmt.Sprintf("%s/%s", "{{ .Path }}", id), r)
	if err != nil {
		return nil, nil, fmt.Errorf("error creating Create{{ .TargetName }} request: %w", err)
	}

	resp, err := s.Client.Do(req)
	if err != nil {
		return nil, nil, fmt.Errorf("error performing client request during Update{{ .TargetName }} call: %w", err)
	}

	target := new({{ .TargetType }})
	apiErr, err := resp.Decode(target)
	if err != nil {
		return nil, nil, fmt.Errorf("error decoding Update{{ .TargetName }} repsonse: %w", err)
	}

	{{ if (eq .TargetType "Organization") }}
	target.Client = s.Client.Clone()
	target.Client.SetOrgnization(target.Id)
	{{ else if (eq .TargetType "Project") }}
	target.Client = s.Client.Clone()
	target.Client.SetProject(target.Id)
	{{ else }}
	target.Client = s.Client
	{{ end }}

	return target, apiErr, nil
}
`))
