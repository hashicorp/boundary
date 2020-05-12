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
	templateType templateType
}

var inputStructs = []*structInfo{
	{
		os.Getenv("GEN_BASEPATH") + "/internal/gen/controller/api/error.pb.go",
		"Error",
		os.Getenv("GEN_BASEPATH") + "/api/error.gen.go",
		"Error",
		"api",
		"",
		"",
		"",
		templateTypeResource,
	},
	{
		os.Getenv("GEN_BASEPATH") + "/internal/gen/controller/api/error.pb.go",
		"ErrorDetails",
		os.Getenv("GEN_BASEPATH") + "/api/error_details.gen.go",
		"ErrorDetails",
		"api",
		"",
		"",
		"",
		templateTypeResource,
	},
	{
		os.Getenv("GEN_BASEPATH") + "/internal/gen/controller/api/resources/hosts/host.pb.go",
		"Host",
		os.Getenv("GEN_BASEPATH") + "/api/hosts/host.gen.go",
		"Host",
		"hosts",
		"",
		"",
		"",
		templateTypeResource,
	},
	{
		os.Getenv("GEN_BASEPATH") + "/internal/gen/controller/api/resources/hosts/host_set.pb.go",
		"HostSet",
		os.Getenv("GEN_BASEPATH") + "/api/hosts/host_set.gen.go",
		"HostSet",
		"hosts",
		"",
		"",
		"",
		templateTypeResource,
	},
	{
		os.Getenv("GEN_BASEPATH") + "/internal/gen/controller/api/resources/hosts/host_catalog.pb.go",
		"HostCatalog",
		os.Getenv("GEN_BASEPATH") + "/api/hosts/host_catalog.gen.go",
		"HostCatalog",
		"hosts",
		"",
		"",
		"",
		templateTypeResource,
	},
	{
		os.Getenv("GEN_BASEPATH") + "/internal/gen/controller/api/resources/scopes/organization.pb.go",
		"Organization",
		os.Getenv("GEN_BASEPATH") + "/api/scopes/organization.gen.go",
		"Organization",
		"scopes",
		"",
		"",
		"",
		templateTypeResource,
	},
	{
		os.Getenv("GEN_BASEPATH") + "/internal/gen/controller/api/resources/scopes/project.pb.go",
		"Project",
		os.Getenv("GEN_BASEPATH") + "/api/scopes/project.gen.go",
		"Project",
		"scopes",
		"",
		"",
		"",
		templateTypeResource,
	},
	{
		os.Getenv("GEN_BASEPATH") + "/internal/gen/controller/api/resources/hosts/host_catalog.pb.go",
		"StaticHostCatalogDetails",
		os.Getenv("GEN_BASEPATH") + "/api/hosts/static_host_catalog.gen.go",
		"StaticHostCatalogDetails",
		"hosts",
		"",
		"HostCatalog",
		"StaticHostCatalog",
		templateTypeDetail,
	},
	{
		os.Getenv("GEN_BASEPATH") + "/internal/gen/controller/api/resources/hosts/host_catalog.pb.go",
		"AwsEc2HostCatalogDetails",
		os.Getenv("GEN_BASEPATH") + "/api/hosts/awsec2_host_catalog.gen.go",
		"AwsEc2HostCatalogDetails",
		"hosts",
		"",
		"HostCatalog",
		"AwsEc2HostCatalog",
		templateTypeDetail,
	},
}
