package iam

import (
	"context"
	"fmt"
	"strings"

	"github.com/hashicorp/watchtower/internal/db"
)

// CreateUser will create a user in the repository and return the written user
func (r *Repository) CreateUser(ctx context.Context, user *User, opt ...Option) (*User, error) {
	if user == nil {
		return nil, fmt.Errorf("create user: missing user %w", db.ErrNilParameter)
	}
	if user.PublicId != "" {
		return nil, fmt.Errorf("create user: public id is not empty %w", db.ErrInvalidParameter)
	}
	id, err := newUserId()
	if err != nil {
		return nil, fmt.Errorf("create user: %w", err)
	}
	u := user.Clone()
	u.(*User).PublicId = id
	resource, err := r.create(ctx, u.(*User))
	if err != nil {
		if db.IsUniqueError(err) {
			return nil, fmt.Errorf("create user: user %s already exists in organization %s", user.Name, user.ScopeId)
		}
		return nil, fmt.Errorf("create user: %w for %s", err, u.(*User).PublicId)
	}
	return resource.(*User), err
}

// UpdateUser will update a user in the repository and return the written user.
// fieldMaskPaths provides field_mask.proto paths for fields that should
// be updated.  Fields will be set to NULL if the field is a zero value and
// included in fieldMask. Name and Description are the only updatable fields,
// If no updatable fields are included in the fieldMaskPaths, then an error is returned.
func (r *Repository) UpdateUser(ctx context.Context, user *User, fieldMaskPaths []string, opt ...Option) (*User, int, error) {
	if user == nil {
		return nil, db.NoRowsAffected, fmt.Errorf("update user: missing user %w", db.ErrNilParameter)
	}
	if user.PublicId == "" {
		return nil, db.NoRowsAffected, fmt.Errorf("update user: missing user public id %w", db.ErrInvalidParameter)
	}
	for _, f := range fieldMaskPaths {
		switch {
		case strings.EqualFold("name", f):
		case strings.EqualFold("description", f):
		default:
			return nil, db.NoRowsAffected, fmt.Errorf("update user: field: %s: %w", f, db.ErrInvalidFieldMask)
		}
	}
	var dbMask, nullFields []string
	dbMask, nullFields = buildUpdatePaths(
		map[string]interface{}{
			"name":        user.Name,
			"description": user.Description,
		},
		fieldMaskPaths,
	)
	if len(dbMask) == 0 && len(nullFields) == 0 {
		return nil, db.NoRowsAffected, fmt.Errorf("update user: %w", db.ErrEmptyFieldMask)
	}
	u := user.Clone()
	resource, rowsUpdated, err := r.update(ctx, u.(*User), dbMask, nullFields)
	if err != nil {
		if db.IsUniqueError(err) {
			return nil, db.NoRowsAffected, fmt.Errorf("update user: user %s already exists in organization %s", user.Name, user.ScopeId)
		}
		return nil, db.NoRowsAffected, fmt.Errorf("update user: %w for %s", err, user.PublicId)
	}
	return resource.(*User), rowsUpdated, err
}

// LookupUser will look up a user in the repository.  If the user is not
// found, it will return nil, nil.
func (r *Repository) LookupUser(ctx context.Context, withPublicId string, opt ...Option) (*User, error) {
	if withPublicId == "" {
		return nil, fmt.Errorf("lookup user: missing public id %w", db.ErrNilParameter)
	}

	user := allocUser()
	user.PublicId = withPublicId
	if err := r.reader.LookupByPublicId(ctx, &user); err != nil {
		return nil, fmt.Errorf("lookup user: failed %w for %s", err, withPublicId)
	}
	return &user, nil
}

// DeleteUser will delete a user from the repository
func (r *Repository) DeleteUser(ctx context.Context, withPublicId string, opt ...Option) (int, error) {
	if withPublicId == "" {
		return db.NoRowsAffected, fmt.Errorf("delete user: missing public id %w", db.ErrNilParameter)
	}
	user := allocUser()
	user.PublicId = withPublicId
	rowsDeleted, err := r.writer.Delete(ctx, &user)
	if err != nil {
		return db.NoRowsAffected, fmt.Errorf("delete user: failed %w for %s", err, withPublicId)
	}
	return rowsDeleted, nil
}
