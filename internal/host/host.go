// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package host

import "github.com/hashicorp/boundary/internal/boundary"

// Domain defines the domain for the host package
const Domain = "host"

// Catalog contains the common methods across all the different types of host
// catalogs.
type Catalog interface {
	boundary.Resource
	GetProjectId() string
}

// Set contains the common methods across all the different types of host sets.
type Set interface {
	boundary.Resource
	GetCatalogId() string
}

// Host contains the common methods across all the different types of hosts.
type Host interface {
	boundary.Resource
	GetCatalogId() string
	GetAddress() string
	GetIpAddresses() []string
	GetDnsNames() []string
	GetSetIds() []string
}
