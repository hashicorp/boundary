package iam

import (
	"context"
	"errors"
	"fmt"

	"github.com/hashicorp/watchtower/internal/db"
)

// CreateScope will create a scope in the repository and return the written scope
func (r *Repository) CreateScope(ctx context.Context, scope *Scope, opt ...Option) (*Scope, error) {
	if scope == nil {
		return nil, errors.New("error scope is nil for create")
	}
	resource, err := r.create(ctx, scope)
	if err != nil {
		return nil, fmt.Errorf("failed to create scope: %w", err)
	}
	return resource.(*Scope), nil
}

// UpdateScope will update a scope in the repository and return the written scope
func (r *Repository) UpdateScope(ctx context.Context, scope *Scope, fieldMaskPaths []string, opt ...Option) (*Scope, int, error) {
	if scope == nil {
		return nil, db.NoRowsAffected, errors.New("error scope is nil for update")
	}
	if scope.PublicId == "" {
		return nil, db.NoRowsAffected, errors.New("error scope public id is unset for update")
	}
	resource, rowsUpdated, err := r.update(ctx, scope, fieldMaskPaths)
	if err != nil {
		return nil, db.NoRowsAffected, fmt.Errorf("failed to update scope: %w", err)
	}
	return resource.(*Scope), rowsUpdated, err
}

// LookupScope will look up a scope in the repository.  If the scope is not
// found, it will return nil, nil.
func (r *Repository) LookupScope(ctx context.Context, withPublicId string, opt ...Option) (*Scope, error) {
	if withPublicId == "" {
		return nil, errors.New("you cannot lookup a scope with an empty public id")
	}
	scope := allocScope()
	scope.PublicId = withPublicId
	if err := r.reader.LookupByPublicId(ctx, &scope); err != nil {
		if err == db.ErrRecordNotFound {
			return nil, nil
		}
		return nil, fmt.Errorf("unable to lookup scope by public id %s: %w", withPublicId, err)
	}
	return &scope, nil
}

// DeleteScope will delete a scope from the repository
func (r *Repository) DeleteScope(ctx context.Context, withPublicId string, opt ...Option) (int, error) {
	if withPublicId == "" {
		return db.NoRowsAffected, errors.New("you cannot delete a scope with an empty public id")
	}
	scope := allocScope()
	scope.PublicId = withPublicId
	rowsDeleted, err := r.writer.Delete(ctx, &scope)
	if err != nil {
		return db.NoRowsAffected, fmt.Errorf("unable to delete scope with public id %s: %w", withPublicId, err)
	}
	return rowsDeleted, nil
}
