package host

import "github.com/hashicorp/boundary/internal/boundary"

// Catalog contains the common methods across all the different types of host
// catalogs.
type Catalog interface {
	boundary.Resource
	GetScopeId() string
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
