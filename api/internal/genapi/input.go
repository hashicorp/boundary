package main

import "os"

type structInfo struct {
	inFile       string
	inName       string
	outFile      string
	outName      string
	outPkg       string
	structFields string
	parentName   string
	detailName   string
	outputOnly   bool
	templateType templateType
	nameJsonMap  map[string]string
}

var inputStructs = []*structInfo{
	{
		inFile:     os.Getenv("GEN_BASEPATH") + "/internal/gen/controller/api/error.pb.go",
		inName:     "Error",
		outFile:    os.Getenv("GEN_BASEPATH") + "/api/error.gen.go",
		outName:    "Error",
		outPkg:     "api",
		outputOnly: true,
	},
	{
		inFile:     os.Getenv("GEN_BASEPATH") + "/internal/gen/controller/api/error.pb.go",
		inName:     "ErrorDetails",
		outFile:    os.Getenv("GEN_BASEPATH") + "/api/error_details.gen.go",
		outName:    "ErrorDetails",
		outPkg:     "api",
		outputOnly: true,
	},
	{
		inFile:     os.Getenv("GEN_BASEPATH") + "/internal/gen/controller/api/error.pb.go",
		inName:     "FieldError",
		outFile:    os.Getenv("GEN_BASEPATH") + "/api/field_error.gen.go",
		outName:    "FieldError",
		outPkg:     "api",
		outputOnly: true,
	},
	{
		inFile:  os.Getenv("GEN_BASEPATH") + "/internal/gen/controller/api/resources/hosts/host.pb.go",
		inName:  "Host",
		outFile: os.Getenv("GEN_BASEPATH") + "/api/hosts/host.gen.go",
		outName: "Host",
		outPkg:  "hosts",
	},
	{
		inFile:  os.Getenv("GEN_BASEPATH") + "/internal/gen/controller/api/resources/hosts/host_set.pb.go",
		inName:  "HostSet",
		outFile: os.Getenv("GEN_BASEPATH") + "/api/hosts/host_set.gen.go",
		outName: "HostSet",
		outPkg:  "hosts",
	},
	{
		inFile:  os.Getenv("GEN_BASEPATH") + "/internal/gen/controller/api/resources/hosts/host_catalog.pb.go",
		inName:  "HostCatalog",
		outFile: os.Getenv("GEN_BASEPATH") + "/api/hosts/host_catalog.gen.go",
		outName: "HostCatalog",
		outPkg:  "hosts",
	},
	{
		inFile:  os.Getenv("GEN_BASEPATH") + "/internal/gen/controller/api/resources/authtokens/authtoken.pb.go",
		inName:  "AuthToken",
		outFile: os.Getenv("GEN_BASEPATH") + "/api/authtokens/authtoken.gen.go",
		outName: "AuthToken",
		outPkg:  "authtokens",
	},
	{
		inFile:  os.Getenv("GEN_BASEPATH") + "/internal/gen/controller/api/resources/scopes/scope.pb.go",
		inName:  "Scope",
		outFile: os.Getenv("GEN_BASEPATH") + "/api/scopes/scope.gen.go",
		outName: "Scope",
		outPkg:  "scopes",
	},

	{
		inFile:     os.Getenv("GEN_BASEPATH") + "/internal/gen/controller/api/resources/scopes/scope.pb.go",
		inName:     "ScopeInfo",
		outFile:    os.Getenv("GEN_BASEPATH") + "/api/info/scope.gen.go",
		outName:    "Scope",
		outPkg:     "info",
		outputOnly: true,
	},
	{
		inFile:  os.Getenv("GEN_BASEPATH") + "/internal/gen/controller/api/resources/users/user.pb.go",
		inName:  "User",
		outFile: os.Getenv("GEN_BASEPATH") + "/api/users/user.gen.go",
		outName: "User",
		outPkg:  "users",
	},
	{
		inFile:  os.Getenv("GEN_BASEPATH") + "/internal/gen/controller/api/resources/groups/group.pb.go",
		inName:  "Group",
		outFile: os.Getenv("GEN_BASEPATH") + "/api/groups/group.gen.go",
		outName: "Group",
		outPkg:  "groups",
	},
	{
		inFile:     os.Getenv("GEN_BASEPATH") + "/internal/gen/controller/api/resources/groups/group.pb.go",
		inName:     "Member",
		outFile:    os.Getenv("GEN_BASEPATH") + "/api/groups/member.gen.go",
		outName:    "Member",
		outPkg:     "groups",
		outputOnly: true,
	},
	{
		inFile:  os.Getenv("GEN_BASEPATH") + "/internal/gen/controller/api/resources/roles/role.pb.go",
		inName:  "Role",
		outFile: os.Getenv("GEN_BASEPATH") + "/api/roles/role.gen.go",
		outName: "Role",
		outPkg:  "roles",
	},
	{
		inFile:     os.Getenv("GEN_BASEPATH") + "/internal/gen/controller/api/resources/roles/role.pb.go",
		inName:     "Principal",
		outFile:    os.Getenv("GEN_BASEPATH") + "/api/roles/principal.gen.go",
		outName:    "Principal",
		outPkg:     "roles",
		outputOnly: true,
	},
	{
		inFile:     os.Getenv("GEN_BASEPATH") + "/internal/gen/controller/api/resources/roles/role.pb.go",
		inName:     "Grant",
		outFile:    os.Getenv("GEN_BASEPATH") + "/api/roles/grant.gen.go",
		outName:    "Grant",
		outPkg:     "roles",
		outputOnly: true,
	},
	{
		inFile:     os.Getenv("GEN_BASEPATH") + "/internal/gen/controller/api/resources/roles/role.pb.go",
		inName:     "GrantJson",
		outFile:    os.Getenv("GEN_BASEPATH") + "/api/roles/grant_json.gen.go",
		outName:    "GrantJson",
		outPkg:     "roles",
		outputOnly: true,
	},
	{
		inFile:       os.Getenv("GEN_BASEPATH") + "/internal/gen/controller/api/resources/hosts/host_catalog.pb.go",
		inName:       "StaticHostCatalogDetails",
		outFile:      os.Getenv("GEN_BASEPATH") + "/api/hosts/static_host_catalog.gen.go",
		outName:      "StaticHostCatalogDetails",
		outPkg:       "hosts",
		parentName:   "HostCatalog",
		detailName:   "StaticHostCatalog",
		templateType: templateTypeDetail,
	},
	{
		inFile:       os.Getenv("GEN_BASEPATH") + "/internal/gen/controller/api/resources/hosts/host_catalog.pb.go",
		inName:       "AwsEc2HostCatalogDetails",
		outFile:      os.Getenv("GEN_BASEPATH") + "/api/hosts/awsec2_host_catalog.gen.go",
		outName:      "AwsEc2HostCatalogDetails",
		outPkg:       "hosts",
		parentName:   "HostCatalog",
		detailName:   "AwsEc2HostCatalog",
		templateType: templateTypeDetail,
	},
}
