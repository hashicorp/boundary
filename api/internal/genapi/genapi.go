package main

// +build genapi

import (
	"bufio"
	"bytes"
	"fmt"
	"go/ast"
	"go/format"
	"go/parser"
	"go/token"
	"io/ioutil"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"text/template"
	"time"
)

type templateType int

const (
	templateTypeResource templateType = iota
	templateTypeDetail
)

type generateInfo struct {
	inFile       string
	inName       string
	outFile      string
	outName      string
	outPkg       string
	structFields string
	parentName   string
	detailName   string
	templateType templateType
}

var (
	regex = regexp.MustCompile(`(json:".*")`)

	inputStructs = []*generateInfo{
		{
			os.Getenv("APIGEN_BASEPATH") + "/internal/gen/controller/api/error.pb.go",
			"Error",
			os.Getenv("APIGEN_BASEPATH") + "/api/error.go",
			"Error",
			"api",
			"",
			"",
			"",
			templateTypeResource,
		},
		{
			os.Getenv("APIGEN_BASEPATH") + "/internal/gen/controller/api/error.pb.go",
			"ErrorDetails",
			os.Getenv("APIGEN_BASEPATH") + "/api/error_details.go",
			"ErrorDetails",
			"api",
			"",
			"",
			"",
			templateTypeResource,
		},
		{
			os.Getenv("APIGEN_BASEPATH") + "/internal/gen/controller/api/resources/hosts/host.pb.go",
			"Host",
			os.Getenv("APIGEN_BASEPATH") + "/api/hosts/host.go",
			"Host",
			"hosts",
			"",
			"",
			"",
			templateTypeResource,
		},
		{
			os.Getenv("APIGEN_BASEPATH") + "/internal/gen/controller/api/resources/hosts/host_set.pb.go",
			"HostSet",
			os.Getenv("APIGEN_BASEPATH") + "/api/hosts/host_set.go",
			"HostSet",
			"hosts",
			"",
			"",
			"",
			templateTypeResource,
		},
		{
			os.Getenv("APIGEN_BASEPATH") + "/internal/gen/controller/api/resources/hosts/host_catalog.pb.go",
			"HostCatalog",
			os.Getenv("APIGEN_BASEPATH") + "/api/hosts/host_catalog.go",
			"HostCatalog",
			"hosts",
			"",
			"",
			"",
			templateTypeResource,
		},
		{
			os.Getenv("APIGEN_BASEPATH") + "/internal/gen/controller/api/resources/hosts/host_catalog.pb.go",
			"StaticHostCatalogDetails",
			os.Getenv("APIGEN_BASEPATH") + "/api/hosts/static_host_catalog.go",
			"StaticHostCatalogDetails",
			"hosts",
			"",
			"HostCatalog",
			"StaticHostCatalog",
			templateTypeDetail,
		},
		{
			os.Getenv("APIGEN_BASEPATH") + "/internal/gen/controller/api/resources/hosts/host_catalog.pb.go",
			"AwsEc2HostCatalogDetails",
			os.Getenv("APIGEN_BASEPATH") + "/api/hosts/awsec2_host_catalog.go",
			"AwsEc2HostCatalogDetails",
			"hosts",
			"",
			"HostCatalog",
			"AwsEc2HostCatalog",
			templateTypeDetail,
		},
	}
)

type visitFn func(node ast.Node)

func (fn visitFn) Visit(node ast.Node) ast.Visitor {
	fn(node)
	return fn
}

func main() {
	createStructs()
	createUtilFuncs()
}

func createStructs() {
	for _, inputStruct := range inputStructs {
		inFile, err := filepath.Abs(inputStruct.inFile)
		if err != nil {
			fmt.Printf("error opening file %q: %v\n", inputStruct.inFile, err)
			os.Exit(1)
		}

		fset := token.NewFileSet()
		inAst, err := parser.ParseFile(fset, inFile, nil, parser.ParseComments)
		if err != nil {
			fmt.Printf("error parsing %s: %v\n", inFile, err)
			os.Exit(1)
		}

		ast.Walk(visitFn(func(n ast.Node) {
			spec, ok := n.(*ast.TypeSpec)
			if !ok {
				return
			}
			if spec.Name == nil {
				return
			}
			if spec.Name.Name != inputStruct.inName {
				return
			}

			spec.Name.Name = inputStruct.outName
			st, ok := spec.Type.(*ast.StructType)
			if !ok {
				fmt.Printf("expected struct type for identifier, got %t\n", spec.Type)
				os.Exit(1)
				return
			}

			if st.Fields.List == nil {
				fmt.Printf("no fields found in %q\n", inputStruct.inName)
				os.Exit(1)
				return
			}

			// Tee up unexported field deletion
			var elideList []int
			{
				defer func() {
					var cutCount int
					// Remove unexported proto stuff
					for _, val := range elideList {
						loc := val - cutCount
						st.Fields.List = append(st.Fields.List[:loc], st.Fields.List[loc+1:]...)
						cutCount++
					}

					// Add default fields if a base resource
					if inputStruct.templateType == templateTypeResource {
						st.Fields.List = append([]*ast.Field{{
							Names: []*ast.Ident{
								{
									Name: "defaultFields",
									Obj: &ast.Object{
										Kind: ast.Var,
										Name: "defaultFields",
									},
								},
							},
							Type: &ast.ArrayType{
								Elt: &ast.Ident{
									Name: "string",
								},
							},
						}}, st.Fields.List...)
					}
				}()
			}

			for i, field := range st.Fields.List {
				if !field.Names[0].IsExported() {
					elideList = append(elideList, i)
					continue
				}

				// Anything that isn't a basic type we expect to be a star
				// expression with a selector; that is, a wrapper value, timestamp
				// value, etc.
				//
				// TODO: this isn't necessarily a good assumption, which means we
				// might get failures with other types. This is an internal tools
				// only; we can revisit as needed!
				var selectorExpr *ast.SelectorExpr
				switch typ := field.Type.(type) {
				case *ast.Ident:
					typ.Name = "*" + typ.Name
					goto TAGMODIFY
				case *ast.ArrayType:
					goto TAGMODIFY
				case *ast.StarExpr:
					switch nextTyp := typ.X.(type) {
					case *ast.Ident:
						// Already a pointer, don't do anything
						goto TAGMODIFY
					case *ast.SelectorExpr:
						selectorExpr = nextTyp
					}
				case *ast.SelectorExpr:
					selectorExpr = typ
				}

				switch {
				case selectorExpr != nil:
					xident, ok := selectorExpr.X.(*ast.Ident)
					if !ok {
						fmt.Printf("unexpected non-ident type in selector\n")
						os.Exit(1)
					}

					switch xident.Name {
					case "wrappers":
						switch selectorExpr.Sel.Name {
						case "StringValue":
							st.Fields.List[i] = &ast.Field{
								Names: field.Names,
								Type: &ast.Ident{
									Name: "*string",
								},
								Tag: field.Tag,
							}
						case "BoolValue":
							st.Fields.List[i] = &ast.Field{
								Names: field.Names,
								Type: &ast.Ident{
									Name: "*bool",
								},
								Tag: field.Tag,
							}
						case "Int64Value":
							st.Fields.List[i] = &ast.Field{
								Names: field.Names,
								Type: &ast.Ident{
									Name: "*int64",
								},
								Tag: field.Tag,
							}
						default:
							fmt.Printf("unhandled wrappers selector sel name %q\n", selectorExpr.Sel.Name)
							os.Exit(1)
						}

					case "timestamp":
						switch selectorExpr.Sel.Name {
						case "Timestamp":
							st.Fields.List[i] = &ast.Field{
								Names: field.Names,
								Type: &ast.Ident{
									Name: "time.Time",
								},
								Tag: field.Tag,
							}

						default:
							fmt.Printf("unhandled timestamp selector sel name %q\n", selectorExpr.Sel.Name)
							os.Exit(1)
						}

					case "_struct":
						switch selectorExpr.Sel.Name {
						case "Struct":
							st.Fields.List[i] = &ast.Field{
								Names: field.Names,
								Type: &ast.MapType{
									Key: &ast.Ident{
										Name: "string",
									},
									Value: &ast.InterfaceType{
										Methods: &ast.FieldList{},
									},
								},
								Tag: field.Tag,
							}

						default:
							fmt.Printf("unhandled timestamp selector sel name %q\n", selectorExpr.Sel.Name)
							os.Exit(1)
						}

					default:
						fmt.Printf("unhandled xident name %q\n", xident.Name)
						os.Exit(1)
					}

				default:
					fmt.Println("unhandled non-ident, non-selector case")
					os.Exit(1)
				}

			TAGMODIFY:
				st.Fields.List[i].Tag.Value = "`" + regex.FindString(st.Fields.List[i].Tag.Value) + "`"
			}
		}), inAst)

		buf := new(bytes.Buffer)
		if err := format.Node(buf, fset, inAst); err != nil {
			fmt.Printf("error formatting new code: %v\n", err)
			os.Exit(1)
		}

		// We have to manually cut out the lines we don't want because comments
		// won't be preserved otherwise. See the note about lossy comments in
		// https://arslan.io/2017/09/14/the-ultimate-guide-to-writing-a-go-tool/
		scanner := bufio.NewScanner(bytes.NewBufferString(buf.String()))
		var inType bool
		var outBuf []string
		for scanner.Scan() {
			if !inType {
				if strings.HasPrefix(scanner.Text(), "type "+inputStruct.outName+" struct") {
					inType = true
					// Don't add this line, we'll do it in the template
					continue
				}
			} else {
				if scanner.Text() == "}" {
					// We've reached the end of the type
					break
				}
			}

			if inType {
				outBuf = append(outBuf, scanner.Text())
			}
		}

		inputStruct.structFields = strings.Join(outBuf, "\n")
	}
}

func createUtilFuncs() {
	for _, inputStruct := range inputStructs {
		outBuf := new(bytes.Buffer)
		switch inputStruct.templateType {
		case templateTypeResource:
			utilFuncsTemplate.Execute(outBuf, struct {
				Timestamp    time.Time
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
				Timestamp    time.Time
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

var utilFuncsTemplate = template.Must(template.New("").Parse(`// Code generated by go generate; DO NOT EDIT.
package {{ .Package }} 

import (
	"encoding/json"

	"github.com/fatih/structs"
	"github.com/hashicorp/watchtower/api/internal/strutil"
)

type {{ .Name }} struct {
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

// TODO: Figure out the right way to write out the specific fields
var detailTemplate = template.Must(template.New("").Parse(`// Code generated by go generate; DO NOT EDIT.
package {{ .Package }}

import (
	"fmt"

	"github.com/mitchellh/mapstructure"
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
