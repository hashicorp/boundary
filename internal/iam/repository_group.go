package iam

import (
	"context"
	"errors"
	"fmt"

	"github.com/hashicorp/watchtower/internal/db"
)

// CreateGroup will create a group in the repository and return the written group
func (r *Repository) CreateGroup(ctx context.Context, group *Group, opt ...Option) (*Group, error) {
	if group == nil {
		return nil, errors.New("error group is nil for create")
	}
	id, err := newGroupId()
	if err != nil {
		return nil, fmt.Errorf("create group: %w", err)
	}
	group.PublicId = id
	resource, err := r.create(ctx, group)
	if err != nil {
		return nil, fmt.Errorf("failed to create group: %w", err)
	}
	return resource.(*Group), err
}

// UpdateGroup will update a group in the repository and return the written group
func (r *Repository) UpdateGroup(ctx context.Context, group *Group, fieldMaskPaths []string, opt ...Option) (*Group, int, error) {
	if group == nil {
		return nil, db.NoRowsAffected, errors.New("error group is nil for update")
	}
	resource, rowsUpdated, err := r.update(ctx, group, fieldMaskPaths, nil)
	if err != nil {
		return nil, db.NoRowsAffected, fmt.Errorf("failed to update group: %w", err)
	}
	return resource.(*Group), rowsUpdated, err
}

// LookupGroup will look up a group in the repository.  If the group is not
// found, it will return nil, nil.
func (r *Repository) LookupGroup(ctx context.Context, withPublicId string, opt ...Option) (*Group, error) {
	if withPublicId == "" {
		return nil, errors.New("you cannot lookup a group with an empty public id")
	}

	g := allocGroup()
	g.PublicId = withPublicId
	if err := r.reader.LookupByPublicId(ctx, &g); err != nil {
		return nil, err
	}
	return &g, nil
}

// DeleteGroup will delete a group from the repository
func (r *Repository) DeleteGroup(ctx context.Context, withPublicId string, opt ...Option) (int, error) {
	if withPublicId == "" {
		return db.NoRowsAffected, errors.New("you cannot delete a group with an empty public id")
	}
	g := allocGroup()
	g.PublicId = withPublicId
	rowsDeleted, err := r.writer.Delete(ctx, &g)
	if err != nil {
		return db.NoRowsAffected, fmt.Errorf("unable to delete group by public id: %w", err)
	}
	return rowsDeleted, nil
}
