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
func (r *Repository) LookupScope(ctx context.Context, opt ...Option) (*Scope, error) {
	opts := getOpts(opt...)
	withPublicId := opts.withPublicId
	withName := opts.withName
	withParentId := opts.withParentId

	if withPublicId != "" && withName != "" {
		return nil, errors.New("you cannot lookup a scope using both its public id and name")
	}

	if withPublicId != "" {
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
	if withName != "" {
		var scopes []*Scope
		var where string
		args := []interface{}{withName}
		switch withParentId {
		case nil:
			where = "name = ? and parent_id is null"
		default:
			args = append(args, *withParentId)
			where = "name = ? and parent_id = ?"
		}
		if err := r.reader.SearchWhere(ctx, &scopes, where, args...); err != nil {
			if err == db.ErrRecordNotFound {
				return nil, nil
			}
			return nil, fmt.Errorf("unable to lookup scope by name: %w", err)
		}
		if len(scopes) == 0 {
			return nil, nil
		}
		if len(scopes) > 1 {
			return nil, fmt.Errorf("unable to lookup scope by name, since there are %d scopes with a name of %s", len(scopes), withName)
		}
		return scopes[0], nil
	}
	return nil, errors.New("you must look up scopes by id or name")
}

// DeleteScope will delete a scope from the repository
func (r *Repository) DeleteScope(ctx context.Context, opt ...Option) (int, error) {
	opts := getOpts(opt...)
	withPublicId := opts.withPublicId
	withName := opts.withName
	withParentId := opts.withParentId

	if withPublicId != "" && withName != "" {
		return db.NoRowsAffected, errors.New("you cannot delete a scope using both its public id and name")
	}
	if withPublicId != "" {
		scope := allocScope()
		scope.PublicId = withPublicId
		rowsDeleted, err := r.writer.Delete(ctx, &scope)
		if err != nil {
			return db.NoRowsAffected, fmt.Errorf("unable to delete scope by public id: %w", err)
		}
		return rowsDeleted, nil
	}
	if withName != "" {
		var scopes []*Scope
		var where string
		args := []interface{}{withName}
		switch withParentId {
		case nil:
			where = "name = ? and parent_id is null"
		default:
			args = append(args, *withParentId)
			where = "name = ? and parent_id = ?"
		}
		if err := r.reader.SearchWhere(ctx, &scopes, where, args...); err != nil {
			if err == db.ErrRecordNotFound {
				return db.NoRowsAffected, nil
			}
			return db.NoRowsAffected, fmt.Errorf("unable to find scope by name for delete: %w", err)
		}
		if len(scopes) == 0 {
			return db.NoRowsAffected, nil
		}
		if len(scopes) > 1 {
			// the db schema should prevent this from ever happening, but just
			// in case there are multiple matches for this name
			return db.NoRowsAffected, fmt.Errorf("unable to delete scope with name %s, since there are multiple scopes with that name", withName)
		}
		s := allocScope()
		s.PublicId = scopes[0].PublicId
		rowsDeleted, err := r.writer.Delete(ctx, &s)
		if err != nil {
			return db.NoRowsAffected, fmt.Errorf("unable to delete scope by name: %w", err)
		}
		return rowsDeleted, nil
	}
	return db.NoRowsAffected, errors.New("you must delete scopes by id or name")
}
