package main

import (
	"bytes"
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"
	"text/template"
)

type templateType int

const (
	templateTypeResource templateType = iota
	templateTypeDetail
)

func writeStructTemplates() {
	for _, inputStruct := range inputStructs {
		outBuf := new(bytes.Buffer)
		switch inputStruct.templateType {
		case templateTypeResource:
			structTemplate.Execute(outBuf, struct {
				Name         string
				Package      string
				StructFields string
			}{
				Name:         inputStruct.outName,
				Package:      inputStruct.outPkg,
				StructFields: inputStruct.structFields,
			})

		case templateTypeDetail:
			detailTemplate.Execute(outBuf, struct {
				Package      string
				StructFields string
				ParentName   string
				DetailName   string
			}{
				Package:      inputStruct.outPkg,
				StructFields: inputStruct.structFields,
				ParentName:   inputStruct.parentName,
				DetailName:   inputStruct.detailName,
			})

		}

		outFile, err := filepath.Abs(inputStruct.outFile)
		if err != nil {
			fmt.Printf("error opening file %q: %v\n", inputStruct.outFile, err)
			os.Exit(1)
		}
		if err := ioutil.WriteFile(outFile, outBuf.Bytes(), 0644); err != nil {
			fmt.Printf("error writing file %q: %v\n", outFile, err)
			os.Exit(1)
		}
	}
}

// TODO: Add documentation around SetDefault and how it behaves when the field corresponding to the provided key is already set.
var structTemplate = template.Must(template.New("").Parse(
	`// Code generated by "make api"; DO NOT EDIT.
package {{ .Package }} 

import (
	"context"
	"encoding/json"

	"github.com/fatih/structs"

	"github.com/hashicorp/watchtower/api"
	"github.com/hashicorp/watchtower/api/internal/strutil"
)

type {{ .Name }} struct {
	{{ if (not (eq .Package "api")) }}
	Client *api.Client ` + "`json:\"-\"`" + `
	{{ end }}

	{{ .StructFields }}
}

func (s *{{ .Name }}) SetDefault(key string) {
	s.defaultFields = strutil.AppendIfMissing(s.defaultFields, key)
}

func (s *{{ .Name }}) UnsetDefault(key string) {
	s.defaultFields = strutil.StrListDelete(s.defaultFields, key)
}

func (s {{ .Name }}) MarshalJSON() ([]byte, error) {
	m := structs.Map(s)
	if m == nil {
		m = make(map[string]interface{})
	}
	for _, k := range s.defaultFields {
		m[k] = nil
	}
	return json.Marshal(m)
}
`))

var detailTemplate = template.Must(template.New("").Parse(
	`// Code generated by "make api"; DO NOT EDIT.
package {{ .Package }}

import (
	"fmt"

	"github.com/mitchellh/mapstructure"

	"github.com/hashicorp/watchtower/api"
)

type {{ .DetailName }} struct {
	*{{ .ParentName }}

	{{ .StructFields }}
}

func (s {{ .ParentName }}) As{{ .DetailName }}() (*{{ .DetailName }}, error) {
	out := &{{ .DetailName }}{
		{{ .ParentName }}: &s,
	}
	decoder, err := mapstructure.NewDecoder(&mapstructure.DecoderConfig{
		Result: out,
		TagName: "json",
	})
	if err != nil {
		return nil, fmt.Errorf("error creating map decoder: %w", err)
	}
	
	if err := decoder.Decode(s.Attributes); err != nil {
		return nil, fmt.Errorf("error decoding attributes map: %w", err)
	}

	return out, nil
}
`))
