package main

import (
	"bytes"
	"fmt"
	"io/ioutil"
	"os"
	"strings"
	"text/template"
)

type listInfo struct {
	baseType   string
	targetType string
	path       string
}

var listFuncs = map[string][]*listInfo{
	"scopes": {
		{
			baseType:   "Org",
			targetType: "Project",
			path:       "projects",
		},
		{
			baseType:   "Org",
			targetType: "groups.Group",
			path:       "groups",
		},
		{
			baseType:   "Org",
			targetType: "roles.Role",
			path:       "roles",
		},
		{
			baseType:   "Org",
			targetType: "users.User",
			path:       "users",
		},
		{
			baseType:   "Project",
			targetType: "groups.Group",
			path:       "groups",
		},
		{
			baseType:   "Project",
			targetType: "roles.Role",
			path:       "roles",
		},
	},
}

func writeListFuncs() {
	for outPkg, funcs := range listFuncs {
		outFile := os.Getenv("GEN_BASEPATH") + fmt.Sprintf("/api/%s/list.gen.go", outPkg)
		outBuf := bytes.NewBuffer([]byte(fmt.Sprintf(
			`// Code generated by "make api"; DO NOT EDIT.
package %s
`, outPkg)))
		for _, listInfo := range funcs {
			listFuncTemplate.Execute(outBuf, struct {
				BaseType   string
				TargetType string
				TargetName string
				Path       string
			}{
				BaseType:   listInfo.baseType,
				TargetType: listInfo.targetType,
				TargetName: strings.Split(listInfo.targetType, ".")[strings.Count(listInfo.targetType, ".")],
				Path:       listInfo.path,
			})
		}
		if err := ioutil.WriteFile(outFile, outBuf.Bytes(), 0644); err != nil {
			fmt.Printf("error writing file %q: %v\n", outFile, err)
			os.Exit(1)
		}
	}
}

var listFuncTemplate = template.Must(template.New("").Parse(
	`
func (s {{ .BaseType }}) List{{ .TargetName }}s(ctx context.Context) ([]*{{ .TargetType }}, *api.Error, error) {
	if s.Client == nil {
		return nil, nil, fmt.Errorf("nil client in List{{ .TargetName }} request")
	}
	if s.Id == "" {
		{{ if (eq .BaseType "Org") }}
		// Assume the client has been configured with org already and
		// move on
		{{ else if (eq .BaseType "Project") }}
		// Assume the client has been configured with project already and move
		// on
		{{ else }}
		return nil, nil, fmt.Errorf("missing {{ .BaseType }} ID in List{{ .TargetType }}s request")
		{{ end }}
	} else {
		// If it's explicitly set here, override anything that might be in the
		// client
		{{ if (eq .BaseType "Org") }}
		ctx = context.WithValue(ctx, "org", s.Id)
		{{ else if (eq .BaseType "Project") }}
		ctx = context.WithValue(ctx, "project", s.Id)
		{{ end }}
	}

	req, err := s.Client.NewRequest(ctx, "GET", "{{ .Path }}", nil)
	if err != nil {
		return nil, nil, fmt.Errorf("error creating List{{ .TargetName }}s request: %w", err)
	}

	resp, err := s.Client.Do(req)
	if err != nil {
		return nil, nil, fmt.Errorf("error performing client request during List{{ .TargetName }}s call: %w", err)
	}

	type listResponse struct {
		Items []*{{ .TargetType }}
	}
	target := &listResponse{}

	apiErr, err := resp.Decode(target)
	if err != nil {
		return nil, nil, fmt.Errorf("error decoding List{{ .TargetName }}s response: %w", err)
	}

	for _, t := range target.Items {
	{{ if (eq .TargetType "Org") }}
	t.Client = s.Client.Clone()
	t.Client.SetOrgnization(t.Id)
	{{ else if (eq .TargetType "Project") }}
	t.Client = s.Client.Clone()
	t.Client.SetProject(t.Id)
	{{ else }}
	t.Client = s.Client
	{{ end }}
	}

	return target.Items, apiErr, nil
}
`))
