package iam

import (
	"context"
	"errors"
	"fmt"

	"github.com/hashicorp/watchtower/internal/db"
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
	GetPrimaryScope(ctx context.Context, r db.Reader) (*Scope, error)

	// GetOwner is the owner of the resource, that has
	// full access to the resource including the right to delegate access
	// to others
	GetOwner(ctx context.Context, r db.Reader) (*User, error)

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
	ResourceTypeUnknown      ResourceType = 0
	ResourceTypeScope        ResourceType = 1
	ResourceTypeUser         ResourceType = 2
	ResourceTypeUserAlias    ResourceType = 3
	ResourceTypeGroup        ResourceType = 4
	ResourceTypeRole         ResourceType = 5
	ResourceTypeOrganization ResourceType = 6
)

type ResourceWithOwner interface {
	GetId() uint32
	GetOwnerId() uint32
}

func LookupOwner(ctx context.Context, reader db.Reader, resource ResourceWithOwner) (*User, error) {
	if reader == nil {
		return nil, errors.New("error reader is nil for LookupOwner")
	}
	if resource == nil {
		return nil, errors.New("error resource is nil for LookupOwner")
	}
	if resource.GetId() == 0 {
		return nil, errors.New("error id is 0 for LookupOwner")
	}
	if resource.GetOwnerId() == 0 {
		return nil, nil
	}
	owner := User{}
	if err := reader.LookupBy(ctx, &owner, "id = ?", resource.GetOwnerId()); err != nil {
		return nil, fmt.Errorf("error getting Owner %w for LookupOwner", err)
	}
	return &owner, nil
}

type ResourceWithPrimaryScope interface {
	GetId() uint32
	GetPrimaryScopeId() uint32
}

func LookupPrimaryScope(ctx context.Context, reader db.Reader, resource ResourceWithPrimaryScope) (*Scope, error) {
	if reader == nil {
		return nil, errors.New("error reader is nil for LookupPrimaryScope")
	}
	if resource == nil {
		return nil, errors.New("error resource is nil for LookupPrimaryScope")
	}
	if resource.GetPrimaryScopeId() == 0 {
		return nil, errors.New("error primary scope is unset for LookupPrimaryScope")
	}
	var p Scope
	if err := reader.LookupBy(ctx, &p, "id = ?", resource.GetPrimaryScopeId()); err != nil {
		return nil, fmt.Errorf("error getting PrimaryScope %w for LookupPrimaryScope", err)
	}
	return &p, nil
}
