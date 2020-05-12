package main

import (
	"bytes"
	"fmt"
	"io/ioutil"
	"os"
	"strings"
	"text/template"
)

type readInfo struct {
	baseType   string
	targetType string
	verb       string
	path       string
}

var readFuncs = map[string][]*readInfo{
	"scopes": {
		{
			"Organization",
			"Project",
			"GET",
			"projects/%s",
		},
	},
}

func writeReadFuncs() {
	for outPkg, funcs := range readFuncs {
		outFile := os.Getenv("GEN_BASEPATH") + fmt.Sprintf("/api/%s/read.gen.go", outPkg)
		outBuf := bytes.NewBuffer([]byte(fmt.Sprintf(
			`// Code generated by "make api"; DO NOT EDIT.
package %s
`, outPkg)))
		for _, readInfo := range funcs {
			readFuncTemplate.Execute(outBuf, struct {
				BaseType        string
				TargetType      string
				LowerTargetType string
				Verb            string
				Path            string
			}{
				BaseType:        readInfo.baseType,
				TargetType:      readInfo.targetType,
				LowerTargetType: strings.ToLower(readInfo.targetType),
				Verb:            readInfo.verb,
				Path:            readInfo.path,
			})
		}
		if err := ioutil.WriteFile(outFile, outBuf.Bytes(), 0644); err != nil {
			fmt.Printf("error writing file %q: %v\n", outFile, err)
			os.Exit(1)
		}
	}
}

var readFuncTemplate = template.Must(template.New("").Parse(
	`
func (s {{ .BaseType }}) Read{{ .TargetType }}(ctx context.Context, {{ .LowerTargetType }} *{{ .TargetType }}) (*{{ .TargetType }}, *api.Error, error) {
	if s.Client == nil {
		return nil, nil, fmt.Errorf("nil client in Read{{ .TargetType }} request")
	}
	if s.Id == "" {
		{{ if (eq .BaseType "Organization") }}
		// Assume the client has been configured with organization already and
		// move on
		{{ else if (eq .BaseType "Project") }}
		// Assume the client has been configured with project already and move
		// on
		{{ else }}
		return nil, nil, fmt.Errorf("missing {{ .BaseType }} ID in Read{{ .TargetType }} request")
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
	if {{ .LowerTargetType }}.Id == "" {
		return nil, nil, fmt.Errorf("empty {{ .LowerTargetType }} ID field in Read{{ .TargetType }} request")
	}

	req, err := s.Client.NewRequest(ctx, "{{ .Verb }}", fmt.Sprintf("{{ .Path }}", {{ .LowerTargetType }}.Id), {{ .LowerTargetType }})
	if err != nil {
		return nil, nil, fmt.Errorf("error creating Read{{ .TargetType }} request: %w", err)
	}

	resp, err := s.Client.Do(req)
	if err != nil {
		return nil, nil, fmt.Errorf("error performing client request during Read{{ .TargetType }} call: %w", err)
	}

	target := new({{ .TargetType }})
	apiErr, err := resp.Decode(target)
	if err != nil {
		return nil, nil, fmt.Errorf("error decoding Read{{ .TargetType }} repsonse: %w", err)
	}

	return target, apiErr, nil
}
`))
