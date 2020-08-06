package main

import (
	"text/template"

	"github.com/hashicorp/watchtower/internal/gen/controller/api"
	"github.com/hashicorp/watchtower/internal/gen/controller/api/resources/authtokens"
	"github.com/hashicorp/watchtower/internal/gen/controller/api/resources/groups"
	"github.com/hashicorp/watchtower/internal/gen/controller/api/resources/hosts"
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
	Name              string
	ProtoName         string
	FieldType         string
	GenerateSdkOption bool
}

type structInfo struct {
	inProto            proto.Message
	outFile            string
	generatedStructure structureInfo
	templates          []*template.Template

	// mappings of names of resources and param names for sub slice types, e.g.
	// role principals and group members
	sliceSubTypes map[string]string

	// outputOnly indicates that we shouldn't create options for setting members
	// for this struct
	outputOnly bool

	// versionEnabled indicates that we should build a Version handler in
	// update. Eventually everything should support this and this param can go
	// away.
	versionEnabled bool

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
		inProto:    &api.Error{},
		outFile:    "error.gen.go",
		outputOnly: true,
	},
	{
		inProto:    &api.ErrorDetails{},
		outFile:    "error_details.gen.go",
		outputOnly: true,
	},
	{
		inProto:    &api.FieldError{},
		outFile:    "field_error.gen.go",
		outputOnly: true,
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
			createTemplate,
			readTemplate,
			updateTemplate,
			deleteTemplate,
			listTemplate,
		},
		pathArgs: []string{"scope"},
	},
	// User related resources
	{
		inProto: &users.User{},
		outFile: "users/user.gen.go",
		templates: []*template.Template{
			clientTemplate,
			createTemplate,
			readTemplate,
			updateTemplate,
			deleteTemplate,
			listTemplate,
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
			createTemplate,
			readTemplate,
			updateTemplate,
			deleteTemplate,
			listTemplate,
		},
		sliceSubTypes: map[string]string{
			"Members": "memberIds",
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
			createTemplate,
			readTemplate,
			updateTemplate,
			deleteTemplate,
			listTemplate,
		},
		sliceSubTypes: map[string]string{
			"Principals": "principalIds",
			"Grants":     "grantStrings",
		},
		pathArgs:       []string{"role"},
		versionEnabled: true,
	},
	// Account related resources
	{
		inProto: &users.User{},
		outFile: "users/user.gen.go",
		templates: []*template.Template{
			clientTemplate,
			createTemplate,
			readTemplate,
			updateTemplate,
			deleteTemplate,
			listTemplate,
		},
		pathArgs: []string{"user"},
	},
	// Auth Tokens
	{
		inProto: &authtokens.AuthToken{},
		outFile: "authtokens/authtokens.gen.go",
		templates: []*template.Template{
			clientTemplate,
			readTemplate,
			deleteTemplate,
			listTemplate,
		},
		pathArgs: []string{"auth-token"},
	},
	// Host related resources
	{
		inProto: &hosts.HostCatalog{},
		outFile: "hosts/host_catalog.gen.go",
		templates: []*template.Template{
			clientTemplate,
			createTemplate,
			readTemplate,
			updateTemplate,
			deleteTemplate,
			listTemplate,
		},
		pathArgs: []string{"host-catalog"},
	},
	{
		inProto: &hosts.Host{},
		outFile: "hosts/host.gen.go",
		templates: []*template.Template{
			clientTemplate,
			createTemplate,
			readTemplate,
			updateTemplate,
			deleteTemplate,
			listTemplate,
		},
		pathArgs: []string{"host-catalog", "host"},
	},
}
