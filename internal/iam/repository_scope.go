package iam

import (
	"context"
	"errors"
)

// CreateScope will create a scope in the repository and return the written scope
func (r *Repository) CreateScope(ctx context.Context, scope *Scope, opt ...Option) (*Scope, error) {
	if scope == nil {
		return nil, errors.New("error scope is nil for create")
	}
	resource, err := r.create(ctx, scope)
	return resource.(*Scope), err
}

// UpdateScope will update a scope in the repository and return the written scope
func (r *Repository) UpdateScope(ctx context.Context, scope *Scope, fieldMaskPaths []string, opt ...Option) (*Scope, error) {
	if scope == nil {
		return nil, errors.New("error scope is nil for update")
	}
	resource, err := r.update(ctx, scope, fieldMaskPaths)
	return resource.(*Scope), err
}

// LookupScope will look up a scope in the respository
func (r *Repository) LookupScope(ctx context.Context, opt ...Option) (*Scope, error) {
	opts := getOpts(opt...)
	withPublicId := opts.withPublicId
	withName := opts.withName

	if withPublicId != "" {
		scope := allocScope()
		scope.PublicId = withPublicId
		if err := r.reader.LookupByPublicId(ctx, &scope); err != nil {
			return nil, err
		}
		return &scope, nil
	}
	if withName != "" {
		scope := allocScope()
		scope.Name = withName
		if err := r.reader.LookupByName(ctx, &scope); err != nil {
			s := allocScope()
			return &s, err
		}
		return &scope, nil
	}
	return nil, errors.New("you must look up scopes by id or name")
}
