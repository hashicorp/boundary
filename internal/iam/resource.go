package iam

import (
	"context"
	"errors"
	"fmt"

	"github.com/hashicorp/watchtower/internal/db"
)

// Resource declares the shared behavior of IAM Resources
type Resource interface {
	// GetPublicId is the resource ID used to access the resource via an API
	GetPublicId() string

	// GetName is the optional friendly name used to
	// access the resource via an API
	GetName() string

	// GetDescription is the optional description of the resource
	GetDescription() string

	// GetScope is the Scope that owns the Resource
	GetScope(ctx context.Context, r db.Reader) (*Scope, error)

	// Type of Resource (Target, Policy, User, Group, etc)
	ResourceType() ResourceType

	// Actions that can be assigned permissions for
	// the Resource in Policies. Action String() is key for
	// the map of Actions returned.
	Actions() map[string]Action
}

// ResourceType defines the types of resources in the system
type ResourceType int

const (
	ResourceTypeUnknown           ResourceType = 0
	ResourceTypeScope             ResourceType = 1
	ResourceTypeUser              ResourceType = 2
	ResourceTypeGroup             ResourceType = 3
	ResourceTypeRole              ResourceType = 4
	ResourceTypeOrganization      ResourceType = 5
	ResourceTypeGroupMember       ResourceType = 6
	ResourceTypeGroupUserMember   ResourceType = 7
	ResourceTypeAssignedRole      ResourceType = 8
	ResourceTypeAssignedUserRole  ResourceType = 9
	ResourceTypeAssignedGroupRole ResourceType = 10
	ResourceTypeRoleGrant         ResourceType = 11
	ResourceTypeAuthMethod        ResourceType = 12
	ResourceTypeProject           ResourceType = 13
)

func (r ResourceType) String() string {
	return [...]string{
		"unknown",
		"scope",
		"user",
		"group",
		"role",
		"organization",
		"group member",
		"group user member",
		"assigned role",
		"assigned user role",
		"assigned group role",
		"role grant",
		"auth method",
		"project",
	}[r]
}

type ClonableResource interface {
	Clone() Resource
}

// ResourceWithScope defines an interface for Resources that have a scope
type ResourceWithScope interface {
	GetPublicId() string
	GetScopeId() string
}

// LookupScope looks up the resource's  scope
func LookupScope(ctx context.Context, reader db.Reader, resource ResourceWithScope) (*Scope, error) {
	if reader == nil {
		return nil, errors.New("error reader is nil for LookupScope")
	}
	if resource == nil {
		return nil, errors.New("error resource is nil for LookupScope")
	}
	if resource.GetScopeId() == "" {
		return nil, errors.New("error scope is unset for LookupScope")
	}
	var p Scope
	if err := reader.LookupWhere(ctx, &p, "public_id = ?", resource.GetScopeId()); err != nil {
		return nil, fmt.Errorf("error getting scope for LookupScope: %w", err)
	}
	return &p, nil
}
