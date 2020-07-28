package servers

import "github.com/hashicorp/watchtower/internal/types/resource"

type Resource interface {
	// GetPublicId is the resource ID used to access the resource via an API
	GetPublicId() string

	// GetName is the optional friendly name used to
	// access the resource via an API
	GetName() string

	// GetDescription is the optional description of the resource
	GetDescription() string

	// Type of Resource (Target, Policy, User, Group, etc)
	ResourceType() resource.Type
}

type Clonable interface {
	Clone() interface{}
}
