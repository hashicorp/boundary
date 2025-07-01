// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package dbw

import (
	"context"
	"fmt"

	"gorm.io/gorm"
)

// LookupBy will lookup a resource by it's primary keys, which must be
// unique. If the resource implements either ResourcePublicIder or
// ResourcePrivateIder interface, then they are used as the resource's
// primary key for lookup.  Otherwise, the resource tags are used to
// determine it's primary key(s) for lookup.  The WithDebug and WithTable
// options are supported.
func (rw *RW) LookupBy(ctx context.Context, resourceWithIder interface{}, opt ...Option) error {
	const op = "dbw.LookupById"
	if rw.underlying == nil {
		return fmt.Errorf("%s: missing underlying db: %w", op, ErrInvalidParameter)
	}
	if err := raiseErrorOnHooks(resourceWithIder); err != nil {
		return fmt.Errorf("%s: %w", op, err)
	}
	if err := validateResourcesInterface(resourceWithIder); err != nil {
		return fmt.Errorf("%s: %w", op, err)
	}
	where, keys, err := rw.primaryKeysWhere(ctx, resourceWithIder)
	if err != nil {
		return fmt.Errorf("%s: %w", op, err)
	}
	opts := GetOpts(opt...)
	db := rw.underlying.wrapped.WithContext(ctx)
	if opts.WithTable != "" {
		db = db.Table(opts.WithTable)
	}
	if opts.WithDebug {
		db = db.Debug()
	}
	rw.clearDefaultNullResourceFields(ctx, resourceWithIder)
	if err := db.Where(where, keys...).First(resourceWithIder).Error; err != nil {
		if err == gorm.ErrRecordNotFound {
			return fmt.Errorf("%s: %w", op, ErrRecordNotFound)
		}
		return fmt.Errorf("%s: %w", op, err)
	}
	return nil
}

// LookupByPublicId will lookup resource by its public_id, which must be unique.
// The WithTable option is supported.
func (rw *RW) LookupByPublicId(ctx context.Context, resource ResourcePublicIder, opt ...Option) error {
	return rw.LookupBy(ctx, resource, opt...)
}

func (rw *RW) lookupAfterWrite(ctx context.Context, i interface{}, opt ...Option) error {
	const op = "dbw.lookupAfterWrite"
	opts := GetOpts(opt...)
	withLookup := opts.WithLookup
	if err := raiseErrorOnHooks(i); err != nil {
		return fmt.Errorf("%s: %w", op, err)
	}
	if !withLookup {
		return nil
	}
	if err := rw.LookupBy(ctx, i, opt...); err != nil {
		return fmt.Errorf("%s: %w", op, err)
	}
	return nil
}
