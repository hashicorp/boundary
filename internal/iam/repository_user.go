package iam

import (
	"context"
	"errors"
)

func (r *dbRepository) CreateUser(ctx context.Context, user *User, opt ...Option) (*User, error) {
	resource, err := r.create(context.Background(), user)
	return resource.(*User), err
}
func (r *dbRepository) UpdateUser(ctx context.Context, user *User, fieldMaskPaths []string, opt ...Option) (*User, error) {
	resource, err := r.update(context.Background(), user, fieldMaskPaths)
	return resource.(*User), err
}

func (r *dbRepository) LookupUser(ctx context.Context, opt ...Option) (User, error) {
	opts := getOpts(opt...)
	withPublicId := opts.withPublicId
	withName := opts.withName

	user := allocUser()

	if withPublicId != "" {
		user.PublicId = withPublicId
		if err := r.reader.LookupByPublicId(ctx, &user); err != nil {
			return allocUser(), err
		}
		return user, nil
	}
	if withName != "" {
		user.Name = withName
		if err := r.reader.LookupByName(ctx, &user); err != nil {
			return allocUser(), err
		}
		return user, nil
	}
	return allocUser(), errors.New("you must loop up users by id or friendly name")
}
