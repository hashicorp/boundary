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
func (r *Repository) UpdateUser(ctx context.Context, user *User, fieldMaskPaths []string, opt ...Option) (*User, error) {
	if user == nil {
		return nil, errors.New("error user is nil for update")
	}
	resource, err := r.update(context.Background(), user, fieldMaskPaths)
	if err != nil {
		return nil, fmt.Errorf("failed to update user: %w", err)
	}
	return resource.(*User), err
}

// LookupUser will look up a user in the repository.  If the user is not
// found, it will return nil, nil.
func (r *Repository) LookupUser(ctx context.Context, opt ...Option) (*User, error) {
	opts := getOpts(opt...)
	withPublicId := opts.withPublicId
	withName := opts.withName

	if withPublicId != "" {
		user := allocUser()
		user.PublicId = withPublicId
		if err := r.reader.LookupByPublicId(ctx, &user); err != nil {
			return nil, err
		}
		return &user, nil
	}
	if withName != "" {
		user := allocUser()
		user.Name = withName
		if err := r.reader.LookupByName(ctx, &user); err != nil {
			return nil, err
		}
		return &user, nil
	}
	return nil, errors.New("you must loop up users by id or friendly name")
}

// DeleteUser will delete a user from the repository
func (r *Repository) DeleteUser(ctx context.Context, opt ...Option) error {
	opts := getOpts(opt...)
	withPublicId := opts.withPublicId
	withName := opts.withName

	if withPublicId != "" {
		user := allocUser()
		user.PublicId = withPublicId
		if err := r.writer.Delete(ctx, &user); err != nil {
			return fmt.Errorf("unable to delete user by public id: %w", err)
		}
		return nil
	}
	if withName != "" {
		user := allocUser()
		user.Name = withName
		if err := r.reader.LookupByName(ctx, &user); err != nil {
			if err == db.ErrRecordNotFound {
				return nil
			}
			return fmt.Errorf("unable to find user by name for delete: %w", err)
		}
		if user.PublicId == "" {
			return fmt.Errorf("unable to delete user with unset public id")
		}
		if err := r.writer.Delete(ctx, &user); err != nil {
			return fmt.Errorf("unable to delete user by name: %w", err)
		}
		return nil
	}
	return errors.New("you must delete users by id or name")
}
