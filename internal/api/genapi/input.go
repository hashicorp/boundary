package main

import (
	"text/template"

	"github.com/hashicorp/boundary/internal/gen/controller/api"
	"github.com/hashicorp/boundary/sdk/pbs/controller/api/resources/accounts"
	"github.com/hashicorp/boundary/sdk/pbs/controller/api/resources/authmethods"
	"github.com/hashicorp/boundary/sdk/pbs/controller/api/resources/authtokens"
	"github.com/hashicorp/boundary/sdk/pbs/controller/api/resources/credentiallibraries"
	"github.com/hashicorp/boundary/sdk/pbs/controller/api/resources/credentials"
	"github.com/hashicorp/boundary/sdk/pbs/controller/api/resources/credentialstores"
	"github.com/hashicorp/boundary/sdk/pbs/controller/api/resources/groups"
	"github.com/hashicorp/boundary/sdk/pbs/controller/api/resources/hostcatalogs"
	"github.com/hashicorp/boundary/sdk/pbs/controller/api/resources/hosts"
	"github.com/hashicorp/boundary/sdk/pbs/controller/api/resources/hostsets"
	"github.com/hashicorp/boundary/sdk/pbs/controller/api/resources/managedgroups"
	"github.com/hashicorp/boundary/sdk/pbs/controller/api/resources/plugins"
	"github.com/hashicorp/boundary/sdk/pbs/controller/api/resources/roles"
	"github.com/hashicorp/boundary/sdk/pbs/controller/api/resources/scopes"
	"github.com/hashicorp/boundary/sdk/pbs/controller/api/resources/sessions"
	"github.com/hashicorp/boundary/sdk/pbs/controller/api/resources/targets"
	"github.com/hashicorp/boundary/sdk/pbs/controller/api/resources/users"
	"github.com/hashicorp/boundary/sdk/pbs/controller/api/resources/workers"
	"google.golang.org/protobuf/proto"
)

const (
	ReadResponseType   = "read"
	UpdateResponseType = "update"
	CreateResponseType = "create"
	ListResponseType   = "list"
	DeleteResponseType = "delete"
)

type sliceSubtypeInfo struct {
	SliceType string
	VarName   string
}

type structureInfo struct {
	pkg    string
	name   string
	fields []fieldInfo
}

type requiredParam struct {
	Name     string
	Typ      string
	PostType string
}

type fieldInfo struct {
	Name              string
	ProtoName         string
	FieldType         string
	GenerateSdkOption bool
	SubtypeNames      []string
	Query             bool
	SkipDefault       bool
	JsonTags          []string // Appended to a field's `json` tag (comma separated)
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
	// role principals and group members. If sliceSubtypeInfo is blank for a
	// key, the function is created but no required parameter is produced.
	sliceSubtypes map[string]sliceSubtypeInfo

	// skipOptions indicates that we shouldn't create options for setting
	// members for mapping src field struct
	skipOptions bool

	// versionEnabled indicates that we should build a Version handler in
	// update. Some structs are embedded in others and shouldn't have version
	// fields.
	versionEnabled bool

	// This is used for building the api path.
	pluralResourceName string

	// packageOverride can be used when sourcing a package from a different
	// place as the target, e.g. for sourcing services structs
	packageOverride string

	// nameOverride can be used to override the name coming from the proto,
	// useful to avoid collisions
	nameOverride string

	// recursiveListing indicates that the collection supports recursion when
	// listing
	recursiveListing bool

	// extraFields allows specifying extra options that will be created for a
	// given type, e.g. arguments only valid for one call or purpose and not
	// conveyed within the item itself
	extraFields []fieldInfo

	// fieldOverrides allows overriding some field behavior without making them
	// "new" fields like with extraFields
	fieldOverrides []fieldInfo

	// createResponseTypes controls for which structs response types are created
	createResponseTypes []string

	// fieldFilter is a set of field names that will not result in generated API
	// fields
	fieldFilter []string
}

var inputStructs = []*structInfo{
	{
		inProto:     &api.Error{},
		outFile:     "error.gen.go",
		skipOptions: true,
	},
	{
		inProto:     &api.ErrorDetails{},
		outFile:     "error_details.gen.go",
		skipOptions: true,
	},
	{
		inProto:     &api.WrappedError{},
		outFile:     "wrapped_error.gen.go",
		skipOptions: true,
	},
	{
		inProto:     &api.FieldError{},
		outFile:     "field_error.gen.go",
		skipOptions: true,
	},
	// Scope related resources
	{
		inProto:     &scopes.ScopeInfo{},
		outFile:     "scopes/scope_info.gen.go",
		skipOptions: true,
	},
	{
		inProto:     &plugins.PluginInfo{},
		outFile:     "plugins/plugin_info.gen.go",
		skipOptions: true,
	},
	{
		inProto:     &scopes.Key{},
		outFile:     "scopes/key.gen.go",
		skipOptions: true,
	},
	{
		inProto:     &scopes.KeyVersion{},
		outFile:     "scopes/key_version.gen.go",
		skipOptions: true,
	},
	{
		inProto:     &scopes.KeyVersionDestructionJob{},
		outFile:     "scopes/key_version_destruction_job.gen.go",
		skipOptions: true,
		fieldOverrides: []fieldInfo{
			// int64 fields get marshalled by protobuf as strings, so we have
			// to tell the json parser that their json representation is a
			// string but they go into Go int64 types.
			{Name: "CompletedCount", JsonTags: []string{"string"}},
			{Name: "TotalCount", JsonTags: []string{"string"}},
		},
	},
	{
		inProto: &scopes.Scope{},
		outFile: "scopes/scope.gen.go",
		templates: []*template.Template{
			clientTemplate,
			commonCreateTemplate,
			readTemplate,
			updateTemplate,
			deleteTemplate,
			listTemplate,
		},
		pluralResourceName: "scopes",
		extraFields: []fieldInfo{
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
		createResponseTypes: []string{CreateResponseType, ReadResponseType, UpdateResponseType, DeleteResponseType, ListResponseType},
		recursiveListing:    true,
	},
	// User related resources
	{
		inProto:     &users.Account{},
		outFile:     "users/account.gen.go",
		skipOptions: true,
	},
	{
		inProto: &users.User{},
		outFile: "users/user.gen.go",
		templates: []*template.Template{
			clientTemplate,
			commonCreateTemplate,
			readTemplate,
			updateTemplate,
			deleteTemplate,
			listTemplate,
		},
		sliceSubtypes: map[string]sliceSubtypeInfo{
			"Accounts": {
				SliceType: "[]string",
				VarName:   "accountIds",
			},
		},
		pluralResourceName:  "users",
		versionEnabled:      true,
		createResponseTypes: []string{CreateResponseType, ReadResponseType, UpdateResponseType, DeleteResponseType, ListResponseType},
		recursiveListing:    true,
	},
	// Group related resources
	{
		inProto:     &groups.Member{},
		outFile:     "groups/member.gen.go",
		skipOptions: true,
	},
	{
		inProto: &groups.Group{},
		outFile: "groups/group.gen.go",
		templates: []*template.Template{
			clientTemplate,
			commonCreateTemplate,
			readTemplate,
			updateTemplate,
			deleteTemplate,
			listTemplate,
		},
		sliceSubtypes: map[string]sliceSubtypeInfo{
			"Members": {
				SliceType: "[]string",
				VarName:   "memberIds",
			},
		},
		pluralResourceName:  "groups",
		versionEnabled:      true,
		createResponseTypes: []string{CreateResponseType, ReadResponseType, UpdateResponseType, DeleteResponseType, ListResponseType},
		recursiveListing:    true,
	},
	// Role related resources
	{
		inProto:     &roles.Grant{},
		outFile:     "roles/grant.gen.go",
		skipOptions: true,
	},
	{
		inProto:     &roles.Principal{},
		outFile:     "roles/principal.gen.go",
		skipOptions: true,
	},
	{
		inProto:     &roles.GrantJson{},
		outFile:     "roles/grant_json.gen.go",
		skipOptions: true,
	},
	{
		inProto: &roles.Role{},
		outFile: "roles/role.gen.go",
		templates: []*template.Template{
			clientTemplate,
			commonCreateTemplate,
			readTemplate,
			updateTemplate,
			deleteTemplate,
			listTemplate,
		},
		sliceSubtypes: map[string]sliceSubtypeInfo{
			"Principals": {
				SliceType: "[]string",
				VarName:   "principalIds",
			},
			"Grants": {
				SliceType: "[]string",
				VarName:   "grantStrings",
			},
		},
		pluralResourceName:  "roles",
		versionEnabled:      true,
		createResponseTypes: []string{CreateResponseType, ReadResponseType, UpdateResponseType, DeleteResponseType, ListResponseType},
		recursiveListing:    true,
	},
	// Auth Methods related resources
	{
		inProto:        &authmethods.PasswordAuthMethodAttributes{},
		outFile:        "authmethods/password_auth_method_attributes.gen.go",
		subtypeName:    "PasswordAuthMethod",
		parentTypeName: "AuthMethod",
		templates: []*template.Template{
			mapstructureConversionTemplate,
		},
	},
	{
		inProto:        &authmethods.OidcAuthMethodAttributes{},
		outFile:        "authmethods/oidc_auth_method_attributes.gen.go",
		subtypeName:    "OidcAuthMethod",
		parentTypeName: "AuthMethod",
		templates: []*template.Template{
			mapstructureConversionTemplate,
		},
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
			template.Must(template.New("").Funcs(
				template.FuncMap{
					"snakeCase": snakeCase,
					"funcName": func() string {
						return "Create"
					},
					"apiAction": func() string {
						return ""
					},
					"extraRequiredParams": func() []requiredParam {
						return []requiredParam{
							{
								Name:     "resourceType",
								Typ:      "string",
								PostType: "type",
							},
						}
					},
				},
			).Parse(createTemplateStr)),
			readTemplate,
			updateTemplate,
			deleteTemplate,
			listTemplate,
		},
		pluralResourceName:  "auth-methods",
		versionEnabled:      true,
		createResponseTypes: []string{CreateResponseType, ReadResponseType, UpdateResponseType, DeleteResponseType, ListResponseType},
		recursiveListing:    true,
	},
	// Accounts
	{
		inProto:        &accounts.PasswordAccountAttributes{},
		outFile:        "accounts/password_account_attributes.gen.go",
		subtypeName:    "PasswordAccount",
		parentTypeName: "Account",
		templates: []*template.Template{
			mapstructureConversionTemplate,
		},
	},
	{
		inProto:        &accounts.OidcAccountAttributes{},
		outFile:        "accounts/oidc_account_attributes.gen.go",
		subtypeName:    "OidcAccount",
		parentTypeName: "Account",
		templates: []*template.Template{
			mapstructureConversionTemplate,
		},
	},
	{
		inProto: &accounts.Account{},
		outFile: "accounts/account.gen.go",
		templates: []*template.Template{
			clientTemplate,
			commonCreateTemplate,
			readTemplate,
			updateTemplate,
			deleteTemplate,
			listTemplate,
		},
		pluralResourceName:  "accounts",
		parentTypeName:      "auth-method",
		versionEnabled:      true,
		createResponseTypes: []string{CreateResponseType, ReadResponseType, UpdateResponseType, DeleteResponseType, ListResponseType},
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
		parentTypeName: "ManagedGroup",
		templates: []*template.Template{
			mapstructureConversionTemplate,
		},
	},
	{
		inProto: &managedgroups.ManagedGroup{},
		outFile: "managedgroups/managedgroups.gen.go",
		templates: []*template.Template{
			clientTemplate,
			commonCreateTemplate,
			readTemplate,
			updateTemplate,
			deleteTemplate,
			listTemplate,
		},
		pluralResourceName:  "managed-groups",
		parentTypeName:      "auth-method",
		versionEnabled:      true,
		createResponseTypes: []string{CreateResponseType, ReadResponseType, UpdateResponseType, DeleteResponseType, ListResponseType},
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
		createResponseTypes: []string{CreateResponseType, ReadResponseType, UpdateResponseType, DeleteResponseType, ListResponseType},
		recursiveListing:    true,
	},
	// Credentials
	{
		inProto:        &credentialstores.VaultCredentialStoreAttributes{},
		outFile:        "credentialstores/vault_credential_store_attributes.gen.go",
		subtypeName:    "VaultCredentialStore",
		parentTypeName: "CredentialStore",
		templates: []*template.Template{
			mapstructureConversionTemplate,
		},
	},
	{
		inProto: &credentialstores.CredentialStore{},
		outFile: "credentialstores/credential_store.gen.go",
		templates: []*template.Template{
			clientTemplate,
			template.Must(template.New("").Funcs(
				template.FuncMap{
					"snakeCase": snakeCase,
					"funcName": func() string {
						return "Create"
					},
					"apiAction": func() string {
						return ""
					},
					"extraRequiredParams": func() []requiredParam {
						return []requiredParam{
							{
								Name:     "resourceType",
								Typ:      "string",
								PostType: "type",
							},
						}
					},
				},
			).Parse(createTemplateStr)),
			readTemplate,
			updateTemplate,
			deleteTemplate,
			listTemplate,
		},
		pluralResourceName:  "credential-stores",
		parentTypeName:      "scope",
		versionEnabled:      true,
		createResponseTypes: []string{CreateResponseType, ReadResponseType, UpdateResponseType, DeleteResponseType, ListResponseType},
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
		parentTypeName: "CredentialLibrary",
		templates: []*template.Template{
			mapstructureConversionTemplate,
		},
	},
	{
		inProto: &credentiallibraries.CredentialLibrary{},
		outFile: "credentiallibraries/credential_library.gen.go",
		templates: []*template.Template{
			clientTemplate,
			commonCreateTemplate,
			readTemplate,
			updateTemplate,
			deleteTemplate,
			listTemplate,
		},
		pluralResourceName:  "credential-libraries",
		parentTypeName:      "credential-store",
		versionEnabled:      true,
		createResponseTypes: []string{CreateResponseType, ReadResponseType, UpdateResponseType, DeleteResponseType, ListResponseType},
	},
	{
		inProto:     &credentials.UsernamePasswordAttributes{},
		outFile:     "credentials/username_password_attributes.gen.go",
		subtypeName: "UsernamePasswordCredential",
		fieldOverrides: []fieldInfo{
			{
				Name:        "Username",
				SkipDefault: true,
			},
			{
				Name:        "Password",
				SkipDefault: true,
			},
		},
		parentTypeName: "Credential",
		templates: []*template.Template{
			mapstructureConversionTemplate,
		},
	},
	{
		inProto:     &credentials.SshPrivateKeyAttributes{},
		outFile:     "credentials/ssh_private_key_attributes.gen.go",
		subtypeName: "SshPrivateKeyCredential",
		fieldOverrides: []fieldInfo{
			{
				Name:        "Username",
				SkipDefault: true,
			},
			{
				Name:        "PrivateKey",
				SkipDefault: true,
			},
		},
		parentTypeName: "Credential",
		templates: []*template.Template{
			mapstructureConversionTemplate,
		},
	},
	{
		inProto:     &credentials.JsonAttributes{},
		outFile:     "credentials/json_attributes.gen.go",
		subtypeName: "JsonCredential",
		fieldOverrides: []fieldInfo{
			{
				Name:        "Object",
				SkipDefault: true,
			},
		},
		parentTypeName: "Credential",
		templates: []*template.Template{
			mapstructureConversionTemplate,
		},
	},
	{
		inProto: &credentials.Credential{},
		outFile: "credentials/credential.gen.go",
		templates: []*template.Template{
			clientTemplate,
			template.Must(template.New("").Funcs(
				template.FuncMap{
					"snakeCase": snakeCase,
					"funcName": func() string {
						return "Create"
					},
					"apiAction": func() string {
						return ""
					},
					"extraRequiredParams": func() []requiredParam {
						return []requiredParam{
							{
								Name:     "resourceType",
								Typ:      "string",
								PostType: "type",
							},
						}
					},
				},
			).Parse(createTemplateStr)),
			readTemplate,
			updateTemplate,
			deleteTemplate,
			listTemplate,
		},
		pluralResourceName:  "credentials",
		parentTypeName:      "credential-store",
		versionEnabled:      true,
		createResponseTypes: []string{CreateResponseType, ReadResponseType, UpdateResponseType, DeleteResponseType, ListResponseType},
	},

	// Host related resources
	{
		inProto: &hostcatalogs.HostCatalog{},
		outFile: "hostcatalogs/host_catalog.gen.go",
		templates: []*template.Template{
			clientTemplate,
			template.Must(template.New("").Funcs(
				template.FuncMap{
					"snakeCase": snakeCase,
					"funcName": func() string {
						return "Create"
					},
					"apiAction": func() string {
						return ""
					},
					"extraRequiredParams": func() []requiredParam {
						return []requiredParam{
							{
								Name:     "resourceType",
								Typ:      "string",
								PostType: "type",
							},
						}
					},
				},
			).Parse(createTemplateStr)),
			readTemplate,
			updateTemplate,
			deleteTemplate,
			listTemplate,
		},
		extraFields: []fieldInfo{
			{
				Name:        "PluginName",
				ProtoName:   "plugin_name",
				FieldType:   "string",
				SkipDefault: true,
				Query:       true,
			},
		},
		fieldOverrides: []fieldInfo{
			{
				Name:        "PluginId",
				SkipDefault: true,
			},
		},
		pluralResourceName:  "host-catalogs",
		versionEnabled:      true,
		createResponseTypes: []string{CreateResponseType, ReadResponseType, UpdateResponseType, DeleteResponseType, ListResponseType},
		recursiveListing:    true,
	},
	{
		inProto: &hosts.Host{},
		outFile: "hosts/host.gen.go",
		templates: []*template.Template{
			clientTemplate,
			commonCreateTemplate,
			readTemplate,
			updateTemplate,
			deleteTemplate,
			listTemplate,
		},
		pluralResourceName:  "hosts",
		parentTypeName:      "host-catalog",
		versionEnabled:      true,
		createResponseTypes: []string{CreateResponseType, ReadResponseType, UpdateResponseType, DeleteResponseType, ListResponseType},
	},
	{
		inProto:        &hosts.StaticHostAttributes{},
		outFile:        "hosts/static_host_attributes.gen.go",
		subtypeName:    "StaticHost",
		parentTypeName: "Host",
		templates: []*template.Template{
			mapstructureConversionTemplate,
		},
	},
	{
		inProto: &hostsets.HostSet{},
		outFile: "hostsets/host_set.gen.go",
		templates: []*template.Template{
			clientTemplate,
			commonCreateTemplate,
			readTemplate,
			updateTemplate,
			deleteTemplate,
			listTemplate,
		},
		pluralResourceName: "host-sets",
		parentTypeName:     "host-catalog",
		sliceSubtypes: map[string]sliceSubtypeInfo{
			"Hosts": {
				SliceType: "[]string",
				VarName:   "hostIds",
			},
		},
		versionEnabled:      true,
		createResponseTypes: []string{CreateResponseType, ReadResponseType, UpdateResponseType, DeleteResponseType, ListResponseType},
	},
	{
		inProto: &targets.HostSource{},
		outFile: "targets/host_source.gen.go",
	},
	{
		inProto: &targets.CredentialSource{},
		outFile: "targets/credential_source.gen.go",
	},
	{
		inProto: &targets.SessionSecret{},
		outFile: "targets/session_secret.gen.go",
		fieldOverrides: []fieldInfo{
			{
				Name:      "Raw",
				FieldType: "json.RawMessage",
			},
		},
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
		inProto:        &targets.TcpTargetAttributes{},
		outFile:        "targets/tcp_target_attributes.gen.go",
		subtypeName:    "TcpTarget",
		parentTypeName: "Target",
		templates: []*template.Template{
			mapstructureConversionTemplate,
		},
	},
	{
		inProto:        &targets.SshTargetAttributes{},
		outFile:        "targets/ssh_target_attributes.gen.go",
		subtypeName:    "SshTarget",
		parentTypeName: "Target",
		templates: []*template.Template{
			mapstructureConversionTemplate,
		},
	},
	{
		inProto: &targets.Target{},
		outFile: "targets/target.gen.go",
		templates: []*template.Template{
			clientTemplate,
			template.Must(template.New("").Funcs(
				template.FuncMap{
					"snakeCase": snakeCase,
					"funcName": func() string {
						return "Create"
					},
					"apiAction": func() string {
						return ""
					},
					"extraRequiredParams": func() []requiredParam {
						return []requiredParam{
							{
								Name:     "resourceType",
								Typ:      "string",
								PostType: "type",
							},
						}
					},
				},
			).Parse(createTemplateStr)),
			readTemplate,
			updateTemplate,
			deleteTemplate,
			listTemplate,
		},
		pluralResourceName: "targets",
		sliceSubtypes: map[string]sliceSubtypeInfo{
			"HostSources": {
				SliceType: "[]string",
				VarName:   "hostSourceIds",
			},
			"CredentialSources": {},
		},
		extraFields: []fieldInfo{
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
			{
				Name:      "ApplicationCredentialSourceIds",
				ProtoName: "application_credential_source_ids",
				FieldType: "[]string",
			},
			{
				Name:      "BrokeredCredentialSourceIds",
				ProtoName: "brokered_credential_source_ids",
				FieldType: "[]string",
			},
			{
				Name:      "InjectedApplicationCredentialSourceIds",
				ProtoName: "injected_application_credential_source_ids",
				FieldType: "[]string",
			},
		},
		versionEnabled:      true,
		createResponseTypes: []string{CreateResponseType, ReadResponseType, UpdateResponseType, DeleteResponseType, ListResponseType},
		recursiveListing:    true,
	},
	{
		inProto: &sessions.SessionState{},
		outFile: "sessions/state.gen.go",
	},
	{
		inProto: &sessions.Connection{},
		outFile: "sessions/connection.gen.go",
		fieldOverrides: []fieldInfo{
			// uint64 fields get marshalled by protobuf as strings, so we have
			// to tell the json parser that their json representation is a
			// string but they go into Go uint64 types.
			{Name: "BytesUp", JsonTags: []string{"string"}},
			{Name: "BytesDown", JsonTags: []string{"string"}},
		},
	},
	{
		inProto: &sessions.Session{},
		outFile: "sessions/session.gen.go",
		templates: []*template.Template{
			clientTemplate,
			readTemplate,
			listTemplate,
		},
		extraFields: []fieldInfo{
			{
				Name:      "IncludeTerminated",
				ProtoName: "include_terminated",
				FieldType: "bool",
				Query:     true,
			},
		},
		pluralResourceName:  "sessions",
		createResponseTypes: []string{CreateResponseType, ReadResponseType, UpdateResponseType, DeleteResponseType, ListResponseType},
		fieldFilter:         []string{"private_key"},
		recursiveListing:    true,
	},
	{
		inProto: &workers.Certificate{},
		outFile: "workers/certificate.gen.go",
	},
	{
		inProto:             &workers.CertificateAuthority{},
		outFile:             "workers/certificate_authority.gen.go",
		createResponseTypes: []string{ReadResponseType},
	},
	{
		inProto: &workers.Worker{},
		outFile: "workers/worker.gen.go",
		templates: []*template.Template{
			clientTemplate,
			template.Must(template.New("").Funcs(
				template.FuncMap{
					"snakeCase": snakeCase,
					"funcName": func() string {
						return "CreateWorkerLed"
					},
					"apiAction": func() string {
						return ":create:worker-led"
					},
					"extraRequiredParams": func() []requiredParam {
						return []requiredParam{
							{
								Name:     "workerGeneratedAuthToken",
								Typ:      "string",
								PostType: "worker_generated_auth_token",
							},
						}
					},
				},
			).Parse(createTemplateStr)),
			template.Must(template.New("").Funcs(
				template.FuncMap{
					"snakeCase": snakeCase,
					"funcName": func() string {
						return "CreateControllerLed"
					},
					"apiAction": func() string {
						return ":create:controller-led"
					},
					"extraRequiredParams": func() []requiredParam {
						return nil
					},
				},
			).Parse(createTemplateStr)),
			readTemplate,
			updateTemplate,
			deleteTemplate,
			listTemplate,
		},
		pluralResourceName: "workers",
		sliceSubtypes: map[string]sliceSubtypeInfo{
			"WorkerTags": {
				SliceType: "map[string][]string",
				VarName:   "apiTags",
			},
		},
		createResponseTypes: []string{CreateResponseType, ReadResponseType, UpdateResponseType, DeleteResponseType, ListResponseType},
		recursiveListing:    true,
		versionEnabled:      true,
	},
}
