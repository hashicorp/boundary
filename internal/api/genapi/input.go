package main

import (
	"text/template"

	"github.com/hashicorp/boundary/internal/gen/controller/api"
	"github.com/hashicorp/boundary/internal/gen/controller/api/resources/accounts"
	"github.com/hashicorp/boundary/internal/gen/controller/api/resources/authmethods"
	"github.com/hashicorp/boundary/internal/gen/controller/api/resources/authtokens"
	"github.com/hashicorp/boundary/internal/gen/controller/api/resources/credentiallibraries"
	"github.com/hashicorp/boundary/internal/gen/controller/api/resources/credentialstores"
	"github.com/hashicorp/boundary/internal/gen/controller/api/resources/groups"
	"github.com/hashicorp/boundary/internal/gen/controller/api/resources/hostcatalogs"
	"github.com/hashicorp/boundary/internal/gen/controller/api/resources/hosts"
	"github.com/hashicorp/boundary/internal/gen/controller/api/resources/hostsets"
	"github.com/hashicorp/boundary/internal/gen/controller/api/resources/managedgroups"
	"github.com/hashicorp/boundary/internal/gen/controller/api/resources/roles"
	"github.com/hashicorp/boundary/internal/gen/controller/api/resources/scopes"
	"github.com/hashicorp/boundary/internal/gen/controller/api/resources/sessions"
	"github.com/hashicorp/boundary/internal/gen/controller/api/resources/targets"
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
	Query             bool
	SkipDefault       bool
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

	// For non-top-level collections, this can be used to indicate the name of
	// the argument that should be used
	parentTypeName string

	// mappings of names of resources and param names for sub slice types, e.g.
	// role principals and group members
	sliceSubtypes map[string]string

	// outputOnly indicates that we shouldn't create options for setting members
	// for mapping src field struct
	outputOnly bool

	// versionEnabled indicates that we should build a Version handler in
	// update. Some structs are embedded in others and shouldn't have version
	// fields.
	versionEnabled bool

	// This is used for building the api path.
	pluralResourceName string

	// typeOnCreate indicates that create will be creating a concrete
	// implementation of an abstract type and thus a type field is necessary
	typeOnCreate bool

	// recursiveListing indicates that the collection supports recursion when
	// listing
	recursiveListing bool

	// extraOptions allows specifying extra options that will be created for a
	// given type, e.g. arguments only valid for one call or purpose and not
	// conveyed within the item itself
	extraOptions []fieldInfo

	// fieldOverrides allows overriding some field behavior without making them
	// "new" fields like with extraOptions
	fieldOverrides []fieldInfo

	// createResponseTypes controls for which structs response types are created
	createResponseTypes bool

	// fieldFilter is a set of field names that will not result in generated API
	// fields
	fieldFilter []string
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
		inProto:    &api.WrappedError{},
		outFile:    "wrapped_error.gen.go",
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
		pluralResourceName: "scopes",
		extraOptions: []fieldInfo{
			{
				Name:      "SkipAdminRoleCreation",
				ProtoName: "skip_admin_role_creation",
				FieldType: "bool",
				Query:     true,
			},
			{
				Name:      "SkipDefaultRoleCreation",
				ProtoName: "skip_default_role_creation",
				FieldType: "bool",
				Query:     true,
			},
		},
		versionEnabled:      true,
		createResponseTypes: true,
		recursiveListing:    true,
	},
	// User related resources
	{
		inProto:    &users.Account{},
		outFile:    "users/account.gen.go",
		outputOnly: true,
	},
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
		sliceSubtypes: map[string]string{
			"Accounts": "accountIds",
		},
		pluralResourceName:  "users",
		versionEnabled:      true,
		createResponseTypes: true,
		recursiveListing:    true,
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
		sliceSubtypes: map[string]string{
			"Members": "memberIds",
		},
		pluralResourceName:  "groups",
		versionEnabled:      true,
		createResponseTypes: true,
		recursiveListing:    true,
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
		sliceSubtypes: map[string]string{
			"Principals": "principalIds",
			"Grants":     "grantStrings",
		},
		pluralResourceName:  "roles",
		versionEnabled:      true,
		createResponseTypes: true,
		recursiveListing:    true,
	},
	// Auth Methods related resources
	{
		inProto:     &authmethods.PasswordAuthMethodAttributes{},
		outFile:     "authmethods/password_auth_method_attributes.gen.go",
		subtypeName: "PasswordAuthMethod",
	},
	{
		inProto:     &authmethods.OidcAuthMethodAttributes{},
		outFile:     "authmethods/oidc_auth_method_attributes.gen.go",
		subtypeName: "OidcAuthMethod",
	},
	{
		inProto:     &authmethods.OidcAuthMethodAuthenticateStartResponse{},
		outFile:     "authmethods/oidc_auth_method_authenticate_start_response.gen.go",
		subtypeName: "OidcAuthMethod",
	},
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
		pluralResourceName:  "auth-methods",
		typeOnCreate:        true,
		versionEnabled:      true,
		createResponseTypes: true,
		recursiveListing:    true,
	},
	// Accounts
	{
		inProto:     &accounts.PasswordAccountAttributes{},
		outFile:     "accounts/password_account_attributes.gen.go",
		subtypeName: "PasswordAccount",
	},
	{
		inProto:     &accounts.OidcAccountAttributes{},
		outFile:     "accounts/oidc_account_attributes.gen.go",
		subtypeName: "OidcAccount",
	},
	{
		inProto: &accounts.Account{},
		outFile: "accounts/account.gen.go",
		templates: []*template.Template{
			clientTemplate,
			createTemplate,
			readTemplate,
			updateTemplate,
			deleteTemplate,
			listTemplate,
		},
		pluralResourceName:  "accounts",
		parentTypeName:      "auth-method",
		versionEnabled:      true,
		createResponseTypes: true,
	},
	// Managed Groups
	{
		inProto:     &managedgroups.OidcManagedGroupAttributes{},
		outFile:     "managedgroups/oidc_managed_group_attributes.gen.go",
		subtypeName: "OidcManagedGroup",
		fieldOverrides: []fieldInfo{
			{
				Name:        "Filter",
				SkipDefault: true,
			},
		},
	},
	{
		inProto: &managedgroups.ManagedGroup{},
		outFile: "managedgroups/managedgroups.gen.go",
		templates: []*template.Template{
			clientTemplate,
			createTemplate,
			readTemplate,
			updateTemplate,
			deleteTemplate,
			listTemplate,
		},
		pluralResourceName:  "managed-groups",
		parentTypeName:      "auth-method",
		versionEnabled:      true,
		createResponseTypes: true,
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
		pluralResourceName:  "auth-tokens",
		createResponseTypes: true,
		recursiveListing:    true,
	},
	// Credentials
	{
		inProto:     &credentialstores.VaultCredentialStoreAttributes{},
		outFile:     "credentialstores/vault_credential_store_attributes.gen.go",
		subtypeName: "VaultCredentialStore",
	},
	{
		inProto: &credentialstores.CredentialStore{},
		outFile: "credentialstores/credential_store.gen.go",
		templates: []*template.Template{
			clientTemplate,
			createTemplate,
			readTemplate,
			updateTemplate,
			deleteTemplate,
			listTemplate,
		},
		pluralResourceName:  "credential-stores",
		parentTypeName:      "scope",
		typeOnCreate:        true,
		versionEnabled:      true,
		createResponseTypes: true,
		recursiveListing:    true,
		fieldOverrides: []fieldInfo{
			{
				Name:        "Address",
				SkipDefault: true,
			},
			{
				Name:        "Token",
				SkipDefault: true,
			},
		},
	},
	{
		inProto:     &credentiallibraries.VaultCredentialLibraryAttributes{},
		outFile:     "credentiallibraries/vault_credential_library_attributes.gen.go",
		subtypeName: "VaultCredentialLibrary",
		fieldOverrides: []fieldInfo{
			{
				Name:        "Path",
				SkipDefault: true,
			},
		},
	},
	{
		inProto: &credentiallibraries.CredentialLibrary{},
		outFile: "credentiallibraries/credential_library.gen.go",
		templates: []*template.Template{
			clientTemplate,
			createTemplate,
			readTemplate,
			updateTemplate,
			deleteTemplate,
			listTemplate,
		},
		pluralResourceName:  "credential-libraries",
		parentTypeName:      "credential-store",
		versionEnabled:      true,
		createResponseTypes: true,
	},
	// Host related resources
	{
		inProto: &hostcatalogs.HostCatalog{},
		outFile: "hostcatalogs/host_catalog.gen.go",
		templates: []*template.Template{
			clientTemplate,
			createTemplate,
			readTemplate,
			updateTemplate,
			deleteTemplate,
			listTemplate,
		},
		pluralResourceName:  "host-catalogs",
		typeOnCreate:        true,
		versionEnabled:      true,
		createResponseTypes: true,
		recursiveListing:    true,
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
		pluralResourceName:  "hosts",
		parentTypeName:      "host-catalog",
		versionEnabled:      true,
		createResponseTypes: true,
	},
	{
		inProto:     &hosts.StaticHostAttributes{},
		outFile:     "hosts/static_host_attributes.gen.go",
		subtypeName: "StaticHost",
	},
	{
		inProto: &hostsets.HostSet{},
		outFile: "hostsets/host_set.gen.go",
		templates: []*template.Template{
			clientTemplate,
			createTemplate,
			readTemplate,
			updateTemplate,
			deleteTemplate,
			listTemplate,
		},
		pluralResourceName: "host-sets",
		parentTypeName:     "host-catalog",
		sliceSubtypes: map[string]string{
			"Hosts": "hostIds",
		},
		versionEnabled:      true,
		createResponseTypes: true,
	},
	{
		inProto: &targets.HostSet{},
		outFile: "targets/host_set.gen.go",
	},
	{
		inProto: &targets.CredentialLibrary{},
		outFile: "targets/credential_library.gen.go",
	},
	{
		inProto: &targets.SessionCredential{},
		outFile: "targets/session_credential.gen.go",
	},
	{
		inProto:     &targets.SessionAuthorization{},
		outFile:     "targets/session_authorization.gen.go",
		subtypeName: "SessionAuthorization",
	},
	{
		inProto:     &targets.WorkerInfo{},
		outFile:     "targets/worker_info.gen.go",
		subtypeName: "WorkerInfo",
	},
	{
		inProto:     &targets.TcpTargetAttributes{},
		outFile:     "targets/tcp_target_attributes.gen.go",
		subtypeName: "TcpTarget",
	},
	{
		inProto: &targets.Target{},
		outFile: "targets/target.gen.go",
		templates: []*template.Template{
			clientTemplate,
			createTemplate,
			readTemplate,
			updateTemplate,
			deleteTemplate,
			listTemplate,
		},
		pluralResourceName: "targets",
		sliceSubtypes: map[string]string{
			"HostSets":            "hostSetIds",
			"CredentialLibraries": "credentialLibraryIds",
		},
		extraOptions: []fieldInfo{
			{
				Name:        "HostId",
				ProtoName:   "host_id",
				FieldType:   "string",
				SkipDefault: true,
			},
			{
				Name:        "ScopeId",
				ProtoName:   "scope_id",
				FieldType:   "string",
				SkipDefault: true,
			},
			{
				Name:        "ScopeName",
				ProtoName:   "scope_name",
				FieldType:   "string",
				SkipDefault: true,
			},
		},
		versionEnabled:      true,
		typeOnCreate:        true,
		createResponseTypes: true,
		recursiveListing:    true,
	},
	{
		inProto: &sessions.SessionState{},
		outFile: "sessions/state.gen.go",
	},
	{
		inProto: &sessions.WorkerInfo{},
		outFile: "sessions/workers.gen.go",
	},
	{
		inProto: &sessions.Session{},
		outFile: "sessions/session.gen.go",
		templates: []*template.Template{
			clientTemplate,
			readTemplate,
			listTemplate,
		},
		pluralResourceName:  "sessions",
		createResponseTypes: true,
		fieldFilter:         []string{"private_key"},
		recursiveListing:    true,
	},
}
