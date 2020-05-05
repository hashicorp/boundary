// +build genapi

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
		os.Getenv("APIGEN_BASEPATH") + "/internal/gen/controller/api/error.pb.go",
		"Error",
		os.Getenv("APIGEN_BASEPATH") + "/api/error.go",
		"Error",
		"api",
		"",
		"",
		"",
		templateTypeResource,
	},
	{
		os.Getenv("APIGEN_BASEPATH") + "/internal/gen/controller/api/error.pb.go",
		"ErrorDetails",
		os.Getenv("APIGEN_BASEPATH") + "/api/error_details.go",
		"ErrorDetails",
		"api",
		"",
		"",
		"",
		templateTypeResource,
	},
	{
		os.Getenv("APIGEN_BASEPATH") + "/internal/gen/controller/api/resources/hosts/host.pb.go",
		"Host",
		os.Getenv("APIGEN_BASEPATH") + "/api/hosts/host.go",
		"Host",
		"hosts",
		"",
		"",
		"",
		templateTypeResource,
	},
	{
		os.Getenv("APIGEN_BASEPATH") + "/internal/gen/controller/api/resources/hosts/host_set.pb.go",
		"HostSet",
		os.Getenv("APIGEN_BASEPATH") + "/api/hosts/host_set.go",
		"HostSet",
		"hosts",
		"",
		"",
		"",
		templateTypeResource,
	},
	{
		os.Getenv("APIGEN_BASEPATH") + "/internal/gen/controller/api/resources/hosts/host_catalog.pb.go",
		"HostCatalog",
		os.Getenv("APIGEN_BASEPATH") + "/api/hosts/host_catalog.go",
		"HostCatalog",
		"hosts",
		"",
		"",
		"",
		templateTypeResource,
	},
	{
		os.Getenv("APIGEN_BASEPATH") + "/internal/gen/controller/api/resources/hosts/host_catalog.pb.go",
		"StaticHostCatalogDetails",
		os.Getenv("APIGEN_BASEPATH") + "/api/hosts/static_host_catalog.go",
		"StaticHostCatalogDetails",
		"hosts",
		"",
		"HostCatalog",
		"StaticHostCatalog",
		templateTypeDetail,
	},
	{
		os.Getenv("APIGEN_BASEPATH") + "/internal/gen/controller/api/resources/hosts/host_catalog.pb.go",
		"AwsEc2HostCatalogDetails",
		os.Getenv("APIGEN_BASEPATH") + "/api/hosts/awsec2_host_catalog.go",
		"AwsEc2HostCatalogDetails",
		"hosts",
		"",
		"HostCatalog",
		"AwsEc2HostCatalog",
		templateTypeDetail,
	},
}
