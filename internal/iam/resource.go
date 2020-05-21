package iam

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/lib/pq"

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

type Clonable interface {
	Clone() interface{}
}

// ResourceWithScope defines an interface for Resources that have a scope
type ResourceWithScope interface {
	GetPublicId() string
	GetScopeId() string
	validScopeTypes() []ScopeType
}

// LookupScope looks up the resource's  scope
func LookupScope(ctx context.Context, reader db.Reader, resource ResourceWithScope) (*Scope, error) {
	if reader == nil {
		return nil, errors.New("error reader is nil for LookupScope")
	}
	if resource == nil {
		return nil, errors.New("error resource is nil for LookupScope")
	}
	if resource.GetPublicId() == "" {
		return nil, errors.New("error resource has an unset public id")
	}
	if resource.GetScopeId() == "" {
		// try to retrieve it from db with it's scope id
		if err := reader.LookupByPublicId(ctx, resource); err != nil {
			return nil, fmt.Errorf("unable to get resource by public id: %w", err)
		}
		// if it's still not set after getting it from the db...
		if resource.GetScopeId() == "" {
			return nil, errors.New("error scope is unset for LookupScope")
		}
	}
	var p Scope
	if err := reader.LookupWhere(ctx, &p, "public_id = ?", resource.GetScopeId()); err != nil {
		return nil, err
	}
	return &p, nil
}

// validateScopeForWrite will validate that the scope is okay for db write operations
func validateScopeForWrite(ctx context.Context, r db.Reader, resource ResourceWithScope, opType db.OpType, opt ...db.Option) error {
	opts := db.GetOpts(opt...)

	if opType == db.CreateOp {
		if resource.GetScopeId() == "" {
			return errors.New("error scope id not set for user write")
		}
		ps, err := LookupScope(ctx, r, resource)
		if err != nil {
			if errors.Is(err, db.ErrRecordNotFound) {
				return errors.New("scope is not found")
			}
			return err
		}
		validScopeType := false
		for _, t := range resource.validScopeTypes() {
			if ps.Type == t.String() {
				validScopeType = true
			}
		}
		if !validScopeType {
			return fmt.Errorf("%s not a valid scope type for this resource", ps.Type)
		}

	}
	if opType == db.UpdateOp && resource.GetScopeId() != "" {
		switch len(opts.WithFieldMaskPaths) {
		case 0:
			return errors.New("not allowed to change a resource's scope")
		default:
			for _, mask := range opts.WithFieldMaskPaths {
				if strings.EqualFold(mask, "ScopeId") {
					return errors.New("not allowed to change a resource's scope")
				}
			}
		}
	}
	return nil
}

func uniqueError(err error) bool {
	var e *pq.Error
	if errors.As(err, &e) {
		if e.Code.Name() == "unique_violation" {
			return true
		}
	}
	return false
}
