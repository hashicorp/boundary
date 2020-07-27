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
			baseType:   "Scope",
			targetType: "Scope",
			path:       "scopes",
		},
	},
	"authtokens": {
		{
			baseType:   "AuthToken",
			targetType: "AuthToken",
			path:       "auth-tokens",
		},
	},
	"groups": {
		{
			baseType:   "Group",
			targetType: "Group",
			path:       "groups",
		},
	},
	"users": {
		{
			baseType:   "User",
			targetType: "User",
			path:       "users",
		},
	},
	"roles": {
		{
			baseType:   "Role",
			targetType: "Role",
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

	var opts []api.Option
	if s.Scope.Id != "" {
		// If it's explicitly set here, override anything that might be in the
		// client
		opts = append(opts, api.WithScopeId(s.Scope.Id))
	}

	req, err := s.Client.NewRequest(ctx, "GET", "{{ .Path }}", nil, opts...)
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
	{{ if (eq .TargetType "Scope") }}
	t.Client = s.Client.Clone()
	t.Client.SetScopeId(t.Id)
	{{ else }}
	t.Client = s.Client
	{{ end }}
	}

	return target.Items, apiErr, nil
}
`))
