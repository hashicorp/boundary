package iam

import (
	"context"
	"fmt"

	"github.com/hashicorp/boundary/internal/db"
	"github.com/hashicorp/boundary/internal/errors"
	"github.com/hashicorp/boundary/internal/types/action"
	"github.com/hashicorp/boundary/internal/types/resource"
	"github.com/hashicorp/boundary/internal/types/scope"
)

// IamRepoFactory is a factory function that returns a repository and any error
type IamRepoFactory func() (*Repository, error)

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
	ResourceType() resource.Type

	// Actions that can be assigned permissions for
	// the Resource in Policies. Action String() is key for
	// the map of Actions returned.
	Actions() map[string]action.Type
}

type Cloneable interface {
	Clone() interface{}
}

// ResourceWithScope defines an interface for Resources that have a scope
type ResourceWithScope interface {
	GetPublicId() string
	GetScopeId() string
	validScopeTypes() []scope.Type
}

// LookupScope looks up the resource's  scope
func LookupScope(ctx context.Context, reader db.Reader, resource ResourceWithScope) (*Scope, error) {
	const op = "iam.LookupScope"
	if reader == nil {
		return nil, errors.New(ctx, errors.InvalidParameter, op, "nil reader")
	}
	if resource == nil {
		return nil, errors.New(ctx, errors.InvalidParameter, op, "missing resource")
	}
	if resource.GetPublicId() == "" {
		return nil, errors.New(ctx, errors.InvalidParameter, op, "missing public id")
	}
	if resource.GetScopeId() == "" {
		// try to retrieve it from db with it's scope id
		if err := reader.LookupById(ctx, resource); err != nil {
			return nil, errors.Wrap(ctx, err, op)
		}
		// if it's still not set after getting it from the db...
		if resource.GetScopeId() == "" {
			return nil, errors.New(ctx, errors.InvalidParameter, op, "missing scope id")
		}
	}
	var p Scope
	if err := reader.LookupWhere(ctx, &p, "public_id = ?", []interface{}{resource.GetScopeId()}); err != nil {
		return nil, errors.Wrap(ctx, err, op)
	}
	return &p, nil
}

// validateScopeForWrite will validate that the scope is okay for db write operations
func validateScopeForWrite(ctx context.Context, r db.Reader, resource ResourceWithScope, opType db.OpType, opt ...db.Option) error {
	const op = "iam.validateScopeForWrite"
	opts := db.GetOpts(opt...)

	if opType == db.CreateOp {
		if resource.GetScopeId() == "" {
			return errors.New(ctx, errors.InvalidParameter, op, "error scope id not set for user write")
		}
		ps, err := LookupScope(ctx, r, resource)
		if err != nil {
			if errors.IsNotFoundError(err) {
				return errors.New(ctx, errors.RecordNotFound, op, "scope is not found")
			}
			return errors.Wrap(ctx, err, op)
		}
		validScopeType := false
		for _, t := range resource.validScopeTypes() {
			if ps.Type == t.String() {
				validScopeType = true
			}
		}
		if !validScopeType {
			return errors.New(ctx, errors.InvalidParameter, op, fmt.Sprintf("%s not a valid scope type for this resource", ps.Type))
		}

	}
	if opType == db.UpdateOp && resource.GetScopeId() != "" {
		if contains(opts.WithFieldMaskPaths, "ScopeId") || contains(opts.WithNullPaths, "ScopeId") {
			return errors.New(ctx, errors.InvalidParameter, op, "not allowed to change a resource's scope")
		}
	}
	return nil
}
