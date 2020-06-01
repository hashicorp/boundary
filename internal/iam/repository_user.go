package iam

import (
	"context"
	"fmt"

	"github.com/hashicorp/watchtower/internal/db"
)

// CreateUser will create a user in the repository and return the written user
func (r *Repository) CreateUser(ctx context.Context, user *User, opt ...Option) (*User, error) {
	if user == nil {
		return nil, fmt.Errorf("create user: missing user %w", db.ErrNilParameter)
	}
	resource, err := r.create(ctx, user)
	if err != nil {
		if uniqueError(err) {
			return nil, fmt.Errorf("create user: user %s already exists in organization %s", user.Name, user.ScopeId)
		}
		return nil, fmt.Errorf("create user: %w for %s", err, user.PublicId)
	}
	return resource.(*User), err
}

// UpdateUser will update a user in the repository and return the written user.
// If fieldMaskPaths is unset, the updatable fields will be updated(Name,
// Description and Disabled).
func (r *Repository) UpdateUser(ctx context.Context, user *User, fieldMaskPaths []string, opt ...Option) (*User, int, error) {
	if user == nil {
		return nil, db.NoRowsAffected, fmt.Errorf("update user: missing user %w", db.ErrNilParameter)
	}
	if user.PublicId == "" {
		return nil, db.NoRowsAffected, fmt.Errorf("update user: missing user public id %w", db.ErrNilParameter)
	}
	if len(fieldMaskPaths) == 0 {
		fieldMaskPaths = []string{
			"Name",
			"Description",
			"Disabled",
		}
	}
	resource, rowsUpdated, err := r.update(ctx, user, fieldMaskPaths, nil)
	if err != nil {
		if uniqueError(err) {
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
