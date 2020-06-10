package iam

import (
	"context"
	"fmt"
	"strings"

	"github.com/hashicorp/watchtower/internal/db"
)

// CreateGroup will create a group in the repository and return the written group.
func (r *Repository) CreateGroup(ctx context.Context, group *Group, opt ...Option) (*Group, error) {
	if group == nil {
		return nil, fmt.Errorf("create group: missing group %w", db.ErrNilParameter)
	}
	if group.Group == nil {
		return nil, fmt.Errorf("create group: missing group store %w", db.ErrNilParameter)
	}
	id, err := newGroupId()
	if err != nil {
		return nil, fmt.Errorf("create group: %w", err)
	}
	g := group.Clone().(*Group)
	g.PublicId = id
	resource, err := r.create(ctx, g)
	if err != nil {
		if db.IsUniqueError(err) {
			return nil, fmt.Errorf("create group: group %s already exists in scope %s: %w", group.Name, group.ScopeId, err)
		}
		return nil, fmt.Errorf("create group: %w for %s", err, g.PublicId)
	}
	return resource.(*Group), err
}

// UpdateGroup will update a group in the repository and return the written
// group. fieldMaskPaths provides field_mask.proto paths for fields that should
// be updated.  Fields will be set to NULL if the field is a zero value and
// included in fieldMask. Name and Description are the only updatable fields,
// If no updatable fields are included in the fieldMaskPaths, then an error is returned.
func (r *Repository) UpdateGroup(ctx context.Context, group *Group, fieldMaskPaths []string, opt ...Option) (*Group, int, error) {
	if group == nil {
		return nil, db.NoRowsAffected, fmt.Errorf("update group: missing group %w", db.ErrNilParameter)
	}
	if group.PublicId == "" {
		return nil, db.NoRowsAffected, fmt.Errorf("update group: missing group public id %w", db.ErrInvalidParameter)
	}
	for _, f := range fieldMaskPaths {
		switch {
		case strings.EqualFold("name", f):
		case strings.EqualFold("description", f):
		default:
			return nil, db.NoRowsAffected, fmt.Errorf("update group: field: %s: %w", f, db.ErrInvalidFieldMask)
		}
	}
	var dbMask, nullFields []string
	dbMask, nullFields = buildUpdatePaths(
		map[string]interface{}{
			"name":        group.Name,
			"description": group.Description,
		},
		fieldMaskPaths,
	)
	if len(dbMask) == 0 && len(nullFields) == 0 {
		return nil, db.NoRowsAffected, fmt.Errorf("update group: %w", db.ErrEmptyFieldMask)
	}
	g := group.Clone().(*Group)
	resource, rowsUpdated, err := r.update(ctx, g, dbMask, nullFields)
	if err != nil {
		if db.IsUniqueError(err) {
			return nil, db.NoRowsAffected, fmt.Errorf("update group: group %s already exists in organization %s: %w", group.Name, group.ScopeId, db.ErrNotUnique)
		}
		return nil, db.NoRowsAffected, fmt.Errorf("update group: %w for %s", err, group.PublicId)
	}
	return resource.(*Group), rowsUpdated, err
}

// LookupGroup will look up a group in the repository.  If the group is not
// found, it will return nil, nil.
func (r *Repository) LookupGroup(ctx context.Context, withPublicId string, opt ...Option) (*Group, error) {
	if withPublicId == "" {
		return nil, fmt.Errorf("lookup group: missing public id %w", db.ErrNilParameter)
	}
	g := allocGroup()
	g.PublicId = withPublicId
	if err := r.reader.LookupByPublicId(ctx, &g); err != nil {
		return nil, fmt.Errorf("lookup group: failed %w for %s", err, withPublicId)
	}
	return &g, nil
}

// DeleteGroup will delete a group from the repository.
func (r *Repository) DeleteGroup(ctx context.Context, withPublicId string, opt ...Option) (int, error) {
	if withPublicId == "" {
		return db.NoRowsAffected, fmt.Errorf("delete group: missing public id %w", db.ErrNilParameter)
	}
	g := allocGroup()
	g.PublicId = withPublicId
	if err := r.reader.LookupByPublicId(ctx, &g); err != nil {
		return db.NoRowsAffected, fmt.Errorf("delete group: failed %w for %s", err, withPublicId)
	}
	rowsDeleted, err := r.writer.Delete(ctx, &g)
	if err != nil {
		return db.NoRowsAffected, fmt.Errorf("delete group: failed %w for %s", err, withPublicId)
	}
	return rowsDeleted, nil
}
