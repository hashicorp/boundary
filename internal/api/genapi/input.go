// Copyright IBM Corp. 2020, 2025
// SPDX-License-Identifier: BUSL-1.1

package main

import (
	"text/template"

	"github.com/hashicorp/boundary/internal/gen/controller/api"
	"github.com/hashicorp/boundary/sdk/pbs/controller/api/resources/accounts"
	"github.com/hashicorp/boundary/sdk/pbs/controller/api/resources/aliases"
	"github.com/hashicorp/boundary/sdk/pbs/controller/api/resources/authmethods"
	"github.com/hashicorp/boundary/sdk/pbs/controller/api/resources/authtokens"
	"github.com/hashicorp/boundary/sdk/pbs/controller/api/resources/billing"
	"github.com/hashicorp/boundary/sdk/pbs/controller/api/resources/credentiallibraries"
	"github.com/hashicorp/boundary/sdk/pbs/controller/api/resources/credentials"
	"github.com/hashicorp/boundary/sdk/pbs/controller/api/resources/credentialstores"
	"github.com/hashicorp/boundary/sdk/pbs/controller/api/resources/groups"
	"github.com/hashicorp/boundary/sdk/pbs/controller/api/resources/hostcatalogs"
	"github.com/hashicorp/boundary/sdk/pbs/controller/api/resources/hosts"
	"github.com/hashicorp/boundary/sdk/pbs/controller/api/resources/hostsets"
	"github.com/hashicorp/boundary/sdk/pbs/controller/api/resources/managedgroups"
	"github.com/hashicorp/boundary/sdk/pbs/controller/api/resources/plugins"
	"github.com/hashicorp/boundary/sdk/pbs/controller/api/resources/policies"
	"github.com/hashicorp/boundary/sdk/pbs/controller/api/resources/roles"
	"github.com/hashicorp/boundary/sdk/pbs/controller/api/resources/scopes"
	"github.com/hashicorp/boundary/sdk/pbs/controller/api/resources/session_recordings"
	"github.com/hashicorp/boundary/sdk/pbs/controller/api/resources/sessions"
	"github.com/hashicorp/boundary/sdk/pbs/controller/api/resources/storagebuckets"
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
	AllowEmpty        bool
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

	// subtype specifies exactly the value expected in the resource's "type"
	// Field.  This is used when checking if the attributes returned can be
	// marshaled into a specific generated attributes struct.
	subtype string

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

	// skipListFiltering indicates that the collection doesn't support
	// filtering when listing
	skipListFiltering bool

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

	// nonPaginatedListing indicates a collection that does not support
	// pagination
	nonPaginatedListing bool

	allowEmpty bool
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
	{
		inProto: &billing.ActiveUsers{},
		outFile: "billing/active_users.gen.go",
		templates: []*template.Template{
			clientTemplate,
		},
		fieldOverrides: []fieldInfo{
			{
				Name:       "Count",
				ProtoName:  "count",
				FieldType:  "uint32",
				AllowEmpty: true,
			},
		},
		extraFields: []fieldInfo{
			{
				Name:        "StartTime",
				ProtoName:   "start_time",
				FieldType:   "string",
				SkipDefault: true,
				Query:       true,
			},
			{
				Name:        "EndTime",
				ProtoName:   "end_time",
				FieldType:   "string",
				SkipDefault: true,
				Query:       true,
			},
		},
		pluralResourceName: "billing",
		versionEnabled:     true,
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
			"GrantScopes": {
				SliceType: "[]string",
				VarName:   "grantScopeIds",
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
		inProto:        &authmethods.LdapAuthMethodAttributes{},
		outFile:        "authmethods/ldap_auth_method_attributes.gen.go",
		subtypeName:    "LdapAuthMethod",
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
		inProto:        &accounts.LdapAccountAttributes{},
		outFile:        "accounts/ldap_account_attributes.gen.go",
		subtypeName:    "LdapAccount",
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
		inProto:     &managedgroups.LdapManagedGroupAttributes{},
		outFile:     "managedgroups/ldap_managed_group_attributes.gen.go",
		subtypeName: "LdapManagedGroup",
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
		createResponseTypes: []string{ReadResponseType, UpdateResponseType, DeleteResponseType, ListResponseType},
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
		subtype:     "vault-generic",
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
		inProto:     &credentiallibraries.VaultSSHCertificateCredentialLibraryAttributes{},
		outFile:     "credentiallibraries/vault_ssh_certificate_credential_library_attributes.gen.go",
		subtypeName: "VaultSSHCertificateCredentialLibrary",
		subtype:     "vault-ssh-certificate",
		fieldOverrides: []fieldInfo{
			{
				Name:        "Path",
				SkipDefault: true,
			},
			{
				Name:        "Username",
				SkipDefault: true,
			},
			{
				Name:      "CriticalOptions",
				FieldType: "map[string]string",
			},
			{
				Name:      "Extensions",
				FieldType: "map[string]string",
			},
		},
		parentTypeName: "CredentialLibrary",
		templates: []*template.Template{
			mapstructureConversionTemplate,
		},
	},
	{
		inProto:     &credentiallibraries.VaultLdapCredentialLibraryAttributes{},
		outFile:     "credentiallibraries/vault_ldap_credential_library_attributes.gen.go",
		subtypeName: "VaultLdapCredentialLibrary",
		subtype:     "vault-ldap",
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
		pluralResourceName:  "credential-libraries",
		parentTypeName:      "credential-store",
		versionEnabled:      true,
		createResponseTypes: []string{CreateResponseType, ReadResponseType, UpdateResponseType, DeleteResponseType, ListResponseType},
	},
	{
		inProto:     &credentials.PasswordAttributes{},
		outFile:     "credentials/password_attributes.gen.go",
		subtypeName: "PasswordCredential",
		subtype:     "password",
		fieldOverrides: []fieldInfo{
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
		inProto:     &credentials.UsernamePasswordAttributes{},
		outFile:     "credentials/username_password_attributes.gen.go",
		subtypeName: "UsernamePasswordCredential",
		subtype:     "username_password",
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
		inProto:     &credentials.UsernamePasswordDomainAttributes{},
		outFile:     "credentials/username_password_domain_attributes.gen.go",
		subtypeName: "UsernamePasswordDomainCredential",
		subtype:     "username_password_domain",
		fieldOverrides: []fieldInfo{
			{
				Name:        "Username",
				SkipDefault: true,
			},
			{
				Name:        "Password",
				SkipDefault: true,
			},
			{
				Name:        "Domain",
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
		subtype:     "ssh_private_key",
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

	// Alias related resources
	{
		inProto:        &aliases.TargetAliasAttributes{},
		outFile:        "aliases/target_alias_attributes.gen.go",
		subtypeName:    "target",
		parentTypeName: "Alias",
		templates: []*template.Template{
			mapstructureConversionTemplate,
		},
	},
	{
		inProto:     &aliases.AuthorizeSessionArguments{},
		outFile:     "aliases/authorize_session_arguments.gen.go",
		skipOptions: true,
	},
	{
		inProto: &aliases.Alias{},
		outFile: "aliases/alias.gen.go",
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
		pluralResourceName:  "aliases",
		versionEnabled:      true,
		createResponseTypes: []string{CreateResponseType, ReadResponseType, UpdateResponseType, DeleteResponseType, ListResponseType},
		recursiveListing:    true,
	},

	// Storage related resources
	{
		inProto: &storagebuckets.StorageBucket{},
		outFile: "storagebuckets/storage_bucket.gen.go",
		templates: []*template.Template{
			clientTemplate,
			commonCreateTemplate,
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
		pluralResourceName:  "storage-buckets",
		versionEnabled:      true,
		createResponseTypes: []string{CreateResponseType, ReadResponseType, UpdateResponseType, DeleteResponseType, ListResponseType},
		recursiveListing:    true,
	},

	// Policy-related resources.
	{
		inProto: &policies.StoragePolicyDeleteAfter{},
		outFile: "policies/storage_policy_delete_after.gen.go",
	},
	{
		inProto: &policies.StoragePolicyRetainFor{},
		outFile: "policies/storage_policy_retain_for.gen.go",
	},
	{
		inProto:        &policies.StoragePolicyAttributes{},
		outFile:        "policies/storage_policy_attributes.gen.go",
		parentTypeName: "Policy",
		subtypeName:    "StoragePolicy",
		subtype:        "storage",
		templates:      []*template.Template{mapstructureConversionTemplate},
	},
	{
		inProto: &policies.Policy{},
		outFile: "policies/policy.gen.go",
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
		pluralResourceName:  "policies",
		createResponseTypes: []string{CreateResponseType, ReadResponseType, UpdateResponseType, DeleteResponseType, ListResponseType},
		versionEnabled:      true,
		recursiveListing:    true,
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
		inProto:        &hosts.StaticHostAttributes{},
		outFile:        "hosts/static_host_attributes.gen.go",
		subtypeName:    "StaticHost",
		parentTypeName: "Host",
		templates: []*template.Template{
			mapstructureConversionTemplate,
		},
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
		inProto: &targets.Alias{},
		outFile: "targets/alias.gen.go",
	},
	{
		inProto: &targets.TargetAliasAttributes{},
		outFile: "targets/target_alias_attributes.gen.go",
	},
	{
		inProto: &targets.AuthorizeSessionArguments{},
		outFile: "targets/authorize_session_arguments.gen.go",
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
		inProto:     &targets.SessionAuthorizationData{},
		outFile:     "targets/session_authorization_data.gen.go",
		subtypeName: "SessionAuthorizationData",
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
		fieldOverrides: []fieldInfo{
			{
				Name:        "EnableSessionRecording",
				SkipDefault: true,
			},
		},
	},
	{
		inProto:        &targets.RdpTargetAttributes{},
		outFile:        "targets/rdp_target_attributes.gen.go",
		subtypeName:    "RdpTarget",
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
				Name:      "BrokeredCredentialSourceIds",
				ProtoName: "brokered_credential_source_ids",
				FieldType: "[]string",
			},
			{
				Name:      "InjectedApplicationCredentialSourceIds",
				ProtoName: "injected_application_credential_source_ids",
				FieldType: "[]string",
			},
			// with_aliases is used when creating a target with alaises.
			{
				Name:        "Aliases",
				ProtoName:   "with_aliases",
				FieldType:   "[]Alias",
				SkipDefault: true,
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
			// int64 fields get marshalled by protobuf as strings, so we have
			// to tell the json parser that their json representation is a
			// string but they go into Go int64 types.
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
		versionEnabled:      true,
		recursiveListing:    true,
	},
	{
		inProto: &session_recordings.User{},
		outFile: "sessionrecordings/user.gen.go",
	},
	{
		inProto: &session_recordings.Target{},
		outFile: "sessionrecordings/target.gen.go",
	},
	{
		inProto:        &session_recordings.SshTargetAttributes{},
		outFile:        "sessionrecordings/ssh_target_attributes.gen.go",
		subtypeName:    "Ssh",
		parentTypeName: "Target",
		templates: []*template.Template{
			mapstructureConversionTemplate,
		},
	},
	{
		inProto: &session_recordings.Host{},
		outFile: "sessionrecordings/host.gen.go",
	},
	{
		inProto:        &session_recordings.StaticHostAttributes{},
		outFile:        "sessionrecordings/static_host_attributes.gen.go",
		subtypeName:    "Static",
		parentTypeName: "Host",
		templates: []*template.Template{
			mapstructureConversionTemplate,
		},
	},
	{
		inProto: &session_recordings.HostCatalog{},
		outFile: "sessionrecordings/host_catalog.gen.go",
	},
	{
		inProto: &session_recordings.Credential{},
		outFile: "sessionrecordings/credential.gen.go",
	},
	{
		inProto:        &session_recordings.PasswordCredentialAttributes{},
		outFile:        "sessionrecordings/password_credential_attributes.gen.go",
		subtype:        "password",
		parentTypeName: "Credential",
		templates: []*template.Template{
			mapstructureConversionTemplate,
		},
	},
	{
		inProto:        &session_recordings.UsernamePasswordCredentialAttributes{},
		outFile:        "sessionrecordings/username_password_credential_attributes.gen.go",
		subtype:        "username_password",
		parentTypeName: "Credential",
		templates: []*template.Template{
			mapstructureConversionTemplate,
		},
	},
	{
		inProto:        &session_recordings.JsonCredentialAttributes{},
		outFile:        "sessionrecordings/json_credential_attributes.gen.go",
		subtype:        "json",
		parentTypeName: "Credential",
		templates: []*template.Template{
			mapstructureConversionTemplate,
		},
	},
	{
		inProto:        &session_recordings.SshPrivateKeyCredentialAttributes{},
		outFile:        "sessionrecordings/ssh_private_key_credential_attributes.gen.go",
		subtype:        "ssh_private_key",
		parentTypeName: "Credential",
		templates: []*template.Template{
			mapstructureConversionTemplate,
		},
	},
	{
		inProto: &session_recordings.CredentialLibrary{},
		outFile: "sessionrecordings/credential_library.gen.go",
	},
	{
		inProto:        &session_recordings.VaultCredentialLibraryAttributes{},
		outFile:        "sessionrecordings/vault_credential_library_attributes.gen.go",
		subtype:        "vault-generic",
		parentTypeName: "CredentialLibrary",
		templates: []*template.Template{
			mapstructureConversionTemplate,
		},
	},
	{
		inProto:        &session_recordings.VaultSSHCertificateCredentialLibraryAttributes{},
		outFile:        "sessionrecordings/vault_ssh_certificate_credential_library_attributes.gen.go",
		subtype:        "vault-ssh-certificate",
		parentTypeName: "CredentialLibrary",
		fieldOverrides: []fieldInfo{
			{
				Name:      "CriticalOptions",
				FieldType: "map[string]string",
			},
			{
				Name:      "Extensions",
				FieldType: "map[string]string",
			},
		},
		templates: []*template.Template{
			mapstructureConversionTemplate,
		},
	},
	{
		inProto: &session_recordings.CredentialStore{},
		outFile: "sessionrecordings/credential_store.gen.go",
	},
	{
		inProto:        &session_recordings.VaultCredentialStoreAttributes{},
		outFile:        "sessionrecordings/vault_credential_store_attributes.gen.go",
		subtype:        "vault",
		parentTypeName: "CredentialStore",
		templates: []*template.Template{
			mapstructureConversionTemplate,
		},
	},
	{
		inProto: &session_recordings.ValuesAtTime{},
		outFile: "sessionrecordings/values_at_time.gen.go",
	},
	{
		inProto: &session_recordings.ConnectionRecording{},
		outFile: "sessionrecordings/connection_recording.gen.go",
		fieldOverrides: []fieldInfo{
			// int64 fields get marshalled by protobuf as strings, so we have
			// to tell the json parser that their json representation is a
			// string but they go into Go int64 types.
			{Name: "BytesUp", JsonTags: []string{"string"}},
			{Name: "BytesDown", JsonTags: []string{"string"}},
		},
	},
	{
		inProto: &session_recordings.ChannelRecording{},
		outFile: "sessionrecordings/channel_recording.gen.go",
		fieldOverrides: []fieldInfo{
			// int64 fields get marshalled by protobuf as strings, so we have
			// to tell the json parser that their json representation is a
			// string but they go into Go int64 types.
			{Name: "BytesUp", JsonTags: []string{"string"}},
			{Name: "BytesDown", JsonTags: []string{"string"}},
		},
	},
	{
		// this must be the last block of session recording blocks, otherwise
		// the bits beyond inProto and outFile will get overwritten by
		// subsequent session recording blocks
		inProto: &session_recordings.SessionRecording{},
		outFile: "sessionrecordings/session_recording.gen.go",
		templates: []*template.Template{
			clientTemplate,
			readTemplate,
			deleteTemplate,
			listTemplate,
		},
		pluralResourceName:  "session-recordings",
		createResponseTypes: []string{ReadResponseType, DeleteResponseType, ListResponseType},
		recursiveListing:    true,
		skipListFiltering:   true,
		versionEnabled:      false,
		fieldOverrides: []fieldInfo{
			// int64 fields get marshalled by protobuf as strings, so we have
			// to tell the json parser that their json representation is a
			// string but they go into Go int64 types.
			{Name: "BytesUp", JsonTags: []string{"string"}},
			{Name: "BytesDown", JsonTags: []string{"string"}},
		},
	},
	{
		inProto: &workers.Certificate{},
		outFile: "workers/certificate.gen.go",
	},
	{
		inProto: &workers.RemoteStorageState{},
		outFile: "workers/remote_storage_state.gen.go",
	},
	{
		inProto: &workers.RemoteStoragePermissions{},
		outFile: "workers/remote_storage_permissions.gen.go",
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
		fieldOverrides: []fieldInfo{
			{
				Name:      "RemoteStorageState",
				ProtoName: "remote_storage_state",
				FieldType: "map[string]RemoteStorageState",
			},
		},
		createResponseTypes: []string{CreateResponseType, ReadResponseType, UpdateResponseType, DeleteResponseType, ListResponseType},
		recursiveListing:    true,
		versionEnabled:      true,
		nonPaginatedListing: true,
	},
}
