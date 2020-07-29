package main

import (
	"os"
	"text/template"

	"github.com/hashicorp/watchtower/internal/gen/controller/api"
	"github.com/hashicorp/watchtower/internal/gen/controller/api/resources/groups"
	"github.com/hashicorp/watchtower/internal/gen/controller/api/resources/roles"
	"github.com/hashicorp/watchtower/internal/gen/controller/api/resources/scopes"
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
	// The parameters passed into the path.  These should be non-pluralized resource names.
	// The templates will convert '-' to '_' and append an _id to them in the SDK param
	// and append an 's' to it when building the path.
	// The final value should be the path name of the resource since for single resource
	// operations all values are used for the function argument.
	// For collection based operations the last value is ignored for generating function argument.
	pathArgs []string
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
	// Scope related resources
	{
		inProto: &scopes.ScopeInfo{},
		outFile: os.Getenv("GEN_BASEPATH") + "/api2/scopes/scope_info.gen.go",
	},
	{
		inProto: &scopes.Scope{},
		outFile: os.Getenv("GEN_BASEPATH") + "/api2/scopes/scope.gen.go",
		templates: []*template.Template{
			clientTemplate, readTemplate, listTemplate, createTemplate, deleteTemplate},
		pathArgs: []string{"scope"},
	},
	// User related resources
	{
		inProto: &users.User{},
		outFile: os.Getenv("GEN_BASEPATH") + "/api2/users/user.gen.go",
		templates: []*template.Template{
			clientTemplate, readTemplate, listTemplate, createTemplate, deleteTemplate},
		pathArgs: []string{"user"},
	},
	// Group related resources
	{
		inProto: &groups.Member{},
		outFile: os.Getenv("GEN_BASEPATH") + "/api2/groups/member.gen.go",
	},
	{
		inProto: &groups.Group{},
		outFile: os.Getenv("GEN_BASEPATH") + "/api2/groups/group.gen.go",
		templates: []*template.Template{
			clientTemplate,
			readTemplate,
			listTemplate,
			createTemplate,
			deleteTemplate,
		},
		pathArgs: []string{"group"},
	},
	// Role related resources
	{
		inProto: &roles.Grant{},
		outFile: os.Getenv("GEN_BASEPATH") + "/api2/roles/grant.gen.go",
	},
	{
		inProto: &roles.Principal{},
		outFile: os.Getenv("GEN_BASEPATH") + "/api2/roles/principal.gen.go",
	},
	{
		inProto: &roles.GrantJson{},
		outFile: os.Getenv("GEN_BASEPATH") + "/api2/roles/grant_json.gen.go",
	},
	{
		inProto: &roles.Role{},
		outFile: os.Getenv("GEN_BASEPATH") + "/api2/roles/role.gen.go",
		templates: []*template.Template{
			clientTemplate,
			readTemplate,
			listTemplate,
			createTemplate,
			deleteTemplate,
		},
		pathArgs: []string{"role"},
	},
	// Account related resources
	{
		inProto: &users.User{},
		outFile: os.Getenv("GEN_BASEPATH") + "/api2/users/user.gen.go",
		templates: []*template.Template{
			clientTemplate, readTemplate, listTemplate, createTemplate, deleteTemplate},
		pathArgs: []string{"user"},
	},
}
