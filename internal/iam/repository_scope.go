package iam

import (
	"context"
	"errors"
)

func (r *dbRepository) CreateScope(ctx context.Context, scope *Scope, opt ...Option) (*Scope, error) {
	if scope == nil {
		return nil, errors.New("error scope is nil for create")
	}
	resource, err := r.create(context.Background(), scope)
	return resource.(*Scope), err
}
func (r *dbRepository) UpdateScope(ctx context.Context, scope *Scope, fieldMaskPaths []string, opt ...Option) (*Scope, error) {
	if scope == nil {
		return nil, errors.New("error scope is nil for update")
	}
	resource, err := r.update(context.Background(), scope, fieldMaskPaths)
	return resource.(*Scope), err
}
func (r *dbRepository) LookupScope(ctx context.Context, opt ...Option) (Scope, error) {
	opts := getOpts(opt...)
	withPublicId := opts.withPublicId
	withName := opts.withName

	scope := allocScope()

	if withPublicId != "" {
		scope.PublicId = withPublicId
		if err := r.reader.LookupByPublicId(ctx, &scope); err != nil {
			return allocScope(), err
		}
		return scope, nil
	}
	if withName != "" {
		scope.Name = withName
		if err := r.reader.LookupByName(ctx, &scope); err != nil {
			return allocScope(), err
		}
		return scope, nil
	}
	return allocScope(), errors.New("you must loop up scopes by id or friendly name")
}
