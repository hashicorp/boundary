package iam

import (
	"context"
	"errors"
	"fmt"
)

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
