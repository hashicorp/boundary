package iam

import (
	"context"

	"github.com/hashicorp/watchtower/internal/iam/store"
)

// Resource declares the shared behavior of IAM Resources
type Resource interface {
	// GetPublicId is the resource ID used to access the resource via an API
	GetPublicId() string

	// GetFriendlyName is the optional friendly name used to
	// access the resource via an API
	GetFriendlyName() string

	// GetPrimaryScope is the Scope that owns the Resource
	GetPrimaryScope(ctx context.Context, r Reader) (*Scope, error)

	// GetAssignableScopes specifies the scopes that this resource is available in.
	// Public Ids are the keys to the map of Scopes returned
	GetAssignableScopes(ctx context.Context, r Reader) (map[string]*AssignableScope, error)

	// GetOwner is the owner of the resource, that has
	// full access to the resource including the right to delegate access
	// to others
	GetOwner(ctx context.Context, r Reader) (*User, error)

	// Type of Resource (Target, Policy, User, Group, etc)
	ResourceType() ResourceType

	// Actions that can be assigned permissions for
	// the Resource in Policies. Action String() is key for
	// the map of Actions returned.
	Actions() map[string]Action

	// CreateTime is the time the resource was created
	GetCreateTime() *store.Timestamp

	// UpdateTime is the time the resource was last updated
	GetUpdateTime() *store.Timestamp
}

// ResourceType defines the types of resources in the system
type ResourceType int

const (
	ResourceTypeUnknown = iota
	ResourceTypeScope
	ResourceTypeAssignableScope
	ResourceTypeUser
	ResourceTypeUserAlias
	ResourceTypeGroup
	ResourceTypeRole
)
