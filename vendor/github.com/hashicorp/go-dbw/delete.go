// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package dbw

import (
	"context"
	"fmt"
	"reflect"
)

// Delete a resource in the db with options: WithWhere, WithDebug, WithTable,
// and WithVersion. WithWhere and WithVersion allows specifying a additional
// constraints on the operation in addition to the PKs. Delete returns the
// number of rows deleted and any errors.
func (rw *RW) Delete(ctx context.Context, i interface{}, opt ...Option) (int, error) {
	const op = "dbw.Delete"
	if rw.underlying == nil {
		return noRowsAffected, fmt.Errorf("%s: missing underlying db: %w", op, ErrInvalidParameter)
	}
	if isNil(i) {
		return noRowsAffected, fmt.Errorf("%s: missing interface: %w", op, ErrInvalidParameter)
	}
	if err := raiseErrorOnHooks(i); err != nil {
		return noRowsAffected, fmt.Errorf("%s: %w", op, err)
	}
	opts := GetOpts(opt...)

	mDb := rw.underlying.wrapped.Model(i)
	err := mDb.Statement.Parse(i)
	if err == nil && mDb.Statement.Schema == nil {
		return noRowsAffected, fmt.Errorf("%s: (internal error) unable to parse stmt: %w", op, ErrUnknown)
	}
	reflectValue := reflect.Indirect(reflect.ValueOf(i))
	for _, pf := range mDb.Statement.Schema.PrimaryFields {
		if _, isZero := pf.ValueOf(ctx, reflectValue); isZero {
			return noRowsAffected, fmt.Errorf("%s: primary key %s is not set: %w", op, pf.Name, ErrInvalidParameter)
		}
	}
	if opts.WithBeforeWrite != nil {
		if err := opts.WithBeforeWrite(i); err != nil {
			return noRowsAffected, fmt.Errorf("%s: error before write: %w", op, err)
		}
	}
	db := rw.underlying.wrapped.WithContext(ctx)
	if opts.WithVersion != nil || opts.WithWhereClause != "" {
		where, args, err := rw.whereClausesFromOpts(ctx, i, opts)
		if err != nil {
			return noRowsAffected, fmt.Errorf("%s: %w", op, err)
		}
		db = db.Where(where, args...)
	}
	if opts.WithDebug {
		db = db.Debug()
	}
	if opts.WithTable != "" {
		db = db.Table(opts.WithTable)
	}
	db = db.Delete(i)
	if db.Error != nil {
		return noRowsAffected, fmt.Errorf("%s: %w", op, db.Error)
	}
	rowsDeleted := int(db.RowsAffected)
	if rowsDeleted > 0 && opts.WithAfterWrite != nil {
		if err := opts.WithAfterWrite(i, rowsDeleted); err != nil {
			return rowsDeleted, fmt.Errorf("%s: error after write: %w", op, err)
		}
	}
	return rowsDeleted, nil
}

// DeleteItems will delete multiple items of the same type. Options supported:
// WithWhereClause, WithDebug, WithTable
func (rw *RW) DeleteItems(ctx context.Context, deleteItems interface{}, opt ...Option) (int, error) {
	const op = "dbw.DeleteItems"
	switch {
	case rw.underlying == nil:
		return noRowsAffected, fmt.Errorf("%s: missing underlying db: %w", op, ErrInvalidParameter)
	case isNil(deleteItems):
		return noRowsAffected, fmt.Errorf("%s: no interfaces to delete: %w", op, ErrInvalidParameter)
	}
	valDeleteItems := reflect.ValueOf(deleteItems)
	switch {
	case valDeleteItems.Kind() != reflect.Slice:
		return noRowsAffected, fmt.Errorf("%s: not a slice: %w", op, ErrInvalidParameter)
	case valDeleteItems.Len() == 0:
		return noRowsAffected, fmt.Errorf("%s: missing items: %w", op, ErrInvalidParameter)

	}
	if err := raiseErrorOnHooks(deleteItems); err != nil {
		return noRowsAffected, fmt.Errorf("%s: %w", op, err)
	}

	opts := GetOpts(opt...)
	switch {
	case opts.WithLookup:
		return noRowsAffected, fmt.Errorf("%s: with lookup not a supported option: %w", op, ErrInvalidParameter)
	case opts.WithVersion != nil:
		return noRowsAffected, fmt.Errorf("%s: with version is not a supported option: %w", op, ErrInvalidParameter)
	}

	// we need to dig out the stmt so in just a sec we can make sure the PKs are
	// set for all the items, so we'll just use the first item to do so.
	mDb := rw.underlying.wrapped.Model(valDeleteItems.Index(0).Interface())
	err := mDb.Statement.Parse(valDeleteItems.Index(0).Interface())
	switch {
	case err != nil:
		return noRowsAffected, fmt.Errorf("%s: (internal error) error parsing stmt: %w", op, err)
	case err == nil && mDb.Statement.Schema == nil:
		return noRowsAffected, fmt.Errorf("%s: (internal error) unable to parse stmt: %w", op, ErrUnknown)
	}

	// verify that deleteItems are all the same type, among a myriad of
	// other things on the set of items
	var foundType reflect.Type

	for i := 0; i < valDeleteItems.Len(); i++ {
		if i == 0 {
			foundType = reflect.TypeOf(valDeleteItems.Index(i).Interface())
		}
		currentType := reflect.TypeOf(valDeleteItems.Index(i).Interface())
		switch {
		case isNil(valDeleteItems.Index(i).Interface()) || currentType == nil:
			return noRowsAffected, fmt.Errorf("%s: unable to determine type of item %d: %w", op, i, ErrInvalidParameter)
		case foundType != currentType:
			return noRowsAffected, fmt.Errorf("%s: items contain disparate types.  item %d is not a %s: %w", op, i, foundType.Name(), ErrInvalidParameter)
		}
		if opts.WithWhereClause == "" {
			// make sure the PK is set for the current item
			reflectValue := reflect.Indirect(reflect.ValueOf(valDeleteItems.Index(i).Interface()))
			for _, pf := range mDb.Statement.Schema.PrimaryFields {
				if _, isZero := pf.ValueOf(ctx, reflectValue); isZero {
					return noRowsAffected, fmt.Errorf("%s: primary key %s is not set: %w", op, pf.Name, ErrInvalidParameter)
				}
			}
		}
	}

	if opts.WithBeforeWrite != nil {
		if err := opts.WithBeforeWrite(deleteItems); err != nil {
			return noRowsAffected, fmt.Errorf("%s: error before write: %w", op, err)
		}
	}

	db := rw.underlying.wrapped.WithContext(ctx)
	if opts.WithDebug {
		db = db.Debug()
	}

	if opts.WithWhereClause != "" {
		where, args, err := rw.whereClausesFromOpts(ctx, valDeleteItems.Index(0).Interface(), opts)
		if err != nil {
			return noRowsAffected, fmt.Errorf("%s: %w", op, err)
		}
		db = db.Where(where, args...)
	}

	switch {
	case opts.WithTable != "":
		db = db.Table(opts.WithTable)
	default:
		tabler, ok := valDeleteItems.Index(0).Interface().(tableNamer)
		if ok {
			db = db.Table(tabler.TableName())
		}
	}

	db = db.Delete(deleteItems)
	if db.Error != nil {
		return noRowsAffected, fmt.Errorf("%s: %w", op, db.Error)
	}
	rowsDeleted := int(db.RowsAffected)
	if rowsDeleted > 0 && opts.WithAfterWrite != nil {
		if err := opts.WithAfterWrite(deleteItems, int(rowsDeleted)); err != nil {
			return rowsDeleted, fmt.Errorf("%s: error after write: %w", op, err)
		}
	}
	return rowsDeleted, nil
}

type tableNamer interface {
	TableName() string
}
