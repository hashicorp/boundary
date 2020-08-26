package main

import (
	"text/template"

	"github.com/hashicorp/boundary/internal/gen/controller/api"
	"github.com/hashicorp/boundary/internal/gen/controller/api/resources/authmethods"
	"github.com/hashicorp/boundary/internal/gen/controller/api/resources/authtokens"
	"github.com/hashicorp/boundary/internal/gen/controller/api/resources/groups"
	"github.com/hashicorp/boundary/internal/gen/controller/api/resources/hosts"
	"github.com/hashicorp/boundary/internal/gen/controller/api/resources/roles"
	"github.com/hashicorp/boundary/internal/gen/controller/api/resources/scopes"
	"github.com/hashicorp/boundary/internal/gen/controller/api/resources/users"
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
	SubtypeName       string
}

type structInfo struct {
	inProto            proto.Message
	outFile            string
	generatedStructure structureInfo
	templates          []*template.Template

	// Subtype name for types implementing an abstract resource type. This is
	// used as text to insert into With/Default function calls to separate out
	// implementations of the same abstract type. This way e.g. a WithLoginName
	// option turns into WithPasswordAccountLoginName which is wordy but
	// unambiguous. It also switches the behavior of the functions to work on
	// the attributes map.
	subtypeName string

	// mappings of names of resources and param names for sub slice types, e.g.
	// role principals and group members
	sliceSubTypes map[string]string

	// outputOnly indicates that we shouldn't create options for setting members
	// for this struct
	outputOnly bool

	// versionEnabled indicates that we should build a Version handler in
	// update. Some structs are embedded in others and shouldn't have version
	// fields.
	versionEnabled bool

	// The parameters passed into the path.  These should be non-pluralized resource names.
	// The templates will convert '-' to '_' and append an _id to them in the SDK param
	// and append an 's' to it when building the path.
	// The final value should be the path name of the resource since for single resource
	// operations all values are used for the function argument.
	// For collection based operations the last value is ignored for generating function argument.
	pathArgs []string

	// typeOnCreate indicates that create will be creating a concrete
	// implementation of an abstract type and thus a type field is necessary
	typeOnCreate bool

	// extraOptions allows specifying extra options that will be created for a
	// given type, e.g. arguments only valid for one call or purpose and not
	// conveyed within the item itself
	extraOptions []fieldInfo
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
		extraOptions: []fieldInfo{
			{
				Name:      "SkipRoleCreation",
				ProtoName: "skip_role_creation",
				FieldType: "bool",
			},
		},
		versionEnabled: true,
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
		pathArgs:       []string{"user"},
		versionEnabled: true,
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
		pathArgs:       []string{"group"},
		versionEnabled: true,
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
	// Auth Methods related resources
	{
		inProto: &authmethods.AuthMethod{},
		outFile: "authmethods/authmethods.gen.go",
		templates: []*template.Template{
			clientTemplate,
			createTemplate,
			readTemplate,
			updateTemplate,
			deleteTemplate,
			listTemplate,
		},
		pathArgs:       []string{"auth-method"},
		typeOnCreate:   true,
		versionEnabled: true,
	},
	{
		inProto:     &authmethods.PasswordAuthMethodAttributes{},
		outFile:     "authmethods/password_auth_method_attributes.gen.go",
		subtypeName: "PasswordAuthMethod",
	},
	{
		inProto: &authmethods.Account{},
		outFile: "authmethods/account.gen.go",
		templates: []*template.Template{
			clientTemplate,
			createTemplate,
			readTemplate,
			updateTemplate,
			deleteTemplate,
			listTemplate,
		},
		pathArgs:       []string{"auth-method", "account"},
		versionEnabled: true,
	},
	{
		inProto:     &authmethods.PasswordAccountAttributes{},
		outFile:     "authmethods/password_account_attributes.gen.go",
		subtypeName: "PasswordAccount",
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
		pathArgs:       []string{"host-catalog"},
		typeOnCreate:   true,
		versionEnabled: true,
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
		pathArgs:       []string{"host-catalog", "host"},
		versionEnabled: true,
	},
	{
		inProto:     &hosts.StaticHostAttributes{},
		outFile:     "hosts/static_host_attributes.gen.go",
		subtypeName: "StaticHost",
	},
	{
		inProto: &hosts.HostSet{},
		outFile: "hosts/host_set.gen.go",
		templates: []*template.Template{
			clientTemplate,
			createTemplate,
			readTemplate,
			updateTemplate,
			deleteTemplate,
			listTemplate,
		},
		pathArgs: []string{"host-catalog", "host-set"},
		sliceSubTypes: map[string]string{
			"Hosts": "hostIds",
		},
		versionEnabled: true,
	},
}
