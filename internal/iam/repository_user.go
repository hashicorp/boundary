package iam

import (
	"context"
	"errors"
	"fmt"

	"github.com/hashicorp/watchtower/internal/db"
)

// CreateUser will create a user in the repository and return the written user
func (r *Repository) CreateUser(ctx context.Context, user *User, opt ...Option) (*User, error) {
	if user == nil {
		return nil, errors.New("error user is nil for create")
	}
	resource, err := r.create(context.Background(), user)
	if err != nil {
		return nil, fmt.Errorf("failed to create user: %w", err)
	}
	return resource.(*User), err
}

// UpdateUser will update a user in the repository and return the written user
func (r *Repository) UpdateUser(ctx context.Context, user *User, fieldMaskPaths []string, opt ...Option) (*User, int, error) {
	if user == nil {
		return nil, db.NoRowsAffected, errors.New("error user is nil for update")
	}
	resource, rowsUpdated, err := r.update(context.Background(), user, fieldMaskPaths)
	if err != nil {
		return nil, db.NoRowsAffected, fmt.Errorf("failed to update user: %w", err)
	}
	return resource.(*User), rowsUpdated, err
}

// LookupUser will look up a user in the repository.  If the user is not
// found, it will return nil, nil.
func (r *Repository) LookupUser(ctx context.Context, withPublicId string, opt ...Option) (*User, error) {
	if withPublicId == "" {
		return nil, errors.New("you cannot lookup a user with an empty public id")
	}

	user := allocUser()
	user.PublicId = withPublicId
	if err := r.reader.LookupByPublicId(ctx, &user); err != nil {
		return nil, err
	}
	return &user, nil

	return nil, errors.New("you must loop up users by id or friendly name")
}

// DeleteUser will delete a user from the repository
func (r *Repository) DeleteUser(ctx context.Context, withPublicId string, opt ...Option) (int, error) {
	if withPublicId == "" {
		return db.NoRowsAffected, errors.New("you cannot delete a user with an empty public id")
	}
	user := allocUser()
	user.PublicId = withPublicId
	rowsDeleted, err := r.writer.Delete(ctx, &user)
	if err != nil {
		return db.NoRowsAffected, fmt.Errorf("unable to delete user by public id: %w", err)
	}
	return rowsDeleted, nil
}
