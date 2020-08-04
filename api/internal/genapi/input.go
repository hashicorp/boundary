package main

import (
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

	// outputOnly indicates that we shouldn't create options for setting members
	// for this struct
	outputOnly bool

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
		outFile: "error.gen.go",
	},
	{
		inProto: &api.ErrorDetails{},
		outFile: "error_details.gen.go",
	},
	{
		inProto: &api.FieldError{},
		outFile: "field_error.gen.go",
	},
	// Scope related resources
	{
		inProto:    &scopes.ScopeInfo{},
		outFile:    "scopes/scope_info.gen.go",
		outputOnly: true,
	},
	{
		inProto: &scopes.Scope{},
		outFile: "scopes/scope.gen.go",
		templates: []*template.Template{
			clientTemplate,
			readTemplate,
			listTemplate,
			createTemplate,
			deleteTemplate,
		},
		pathArgs: []string{"scope"},
	},
	// User related resources
	{
		inProto: &users.User{},
		outFile: "users/user.gen.go",
		templates: []*template.Template{
			clientTemplate,
			readTemplate,
			listTemplate,
			createTemplate,
			deleteTemplate,
		},
		pathArgs: []string{"user"},
	},
	// Group related resources
	{
		inProto:    &groups.Member{},
		outFile:    "groups/member.gen.go",
		outputOnly: true,
	},
	{
		inProto: &groups.Group{},
		outFile: "groups/group.gen.go",
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
		inProto:    &roles.Grant{},
		outFile:    "roles/grant.gen.go",
		outputOnly: true,
	},
	{
		inProto:    &roles.Principal{},
		outFile:    "roles/principal.gen.go",
		outputOnly: true,
	},
	{
		inProto:    &roles.GrantJson{},
		outFile:    "roles/grant_json.gen.go",
		outputOnly: true,
	},
	{
		inProto: &roles.Role{},
		outFile: "roles/role.gen.go",
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
		outFile: "users/user.gen.go",
		templates: []*template.Template{
			clientTemplate,
			readTemplate,
			listTemplate,
			createTemplate,
			deleteTemplate,
		},
		pathArgs: []string{"user"},
	},
}
