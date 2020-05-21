package main

import (
	"bufio"
	"bytes"
	"fmt"
	"go/ast"
	"go/format"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"regexp"
	"strings"
)

var regex = regexp.MustCompile(`(json:".*")`)

type visitFn func(node ast.Node)

func (fn visitFn) Visit(node ast.Node) ast.Visitor {
	fn(node)
	return fn
}

func parsePBs() {
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
					// Id values are immutable and should always exist, so
					// don't make it a pointer
					if field.Names[0].Name != "Id" {
						typ.Name = "*" + typ.Name
					}
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
				// TraceId needs to be handled differently because it's a specific value used by OpenTelemetry
				st.Fields.List[i].Tag.Value = "`" + strings.Replace(regex.FindString(st.Fields.List[i].Tag.Value), "trace_id", "TraceId", 1) + "`"
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
