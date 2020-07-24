package main

import (
	"os"
	"text/template"

	"github.com/hashicorp/watchtower/internal/gen/controller/api"
	"github.com/hashicorp/watchtower/internal/gen/controller/api/resources/users"
	"google.golang.org/protobuf/proto"
)

type structureInfo struct {
	pkg    string
	name   string
	fields []fieldInfo
}

type fieldInfo struct {
	Name      string
	ProtoName string
	FieldType string
}

type structInfo struct {
	inProto            proto.Message
	outFile            string
	generatedStructure structureInfo
	templates          []*template.Template
	outputOnly         bool
}

var inputStructs = []*structInfo{
	{
		inProto: &api.Error{},
		outFile: os.Getenv("GEN_BASEPATH") + "/api2/error.gen.go",
	},
	{
		inProto: &api.ErrorDetails{},
		outFile: os.Getenv("GEN_BASEPATH") + "/api2/error_details.gen.go",
	},
	{
		inProto: &api.FieldError{},
		outFile: os.Getenv("GEN_BASEPATH") + "/api2/field_error.gen.go",
	},
	{
		inProto:   &users.User{},
		outFile:   os.Getenv("GEN_BASEPATH") + "/api2/users/user.gen.go",
		templates: []*template.Template{clientTemplate, readTemplate("users"), createTemplate("users")},
	},
}
