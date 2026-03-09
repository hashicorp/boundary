// Copyright IBM Corp. 2020, 2025
// SPDX-License-Identifier: BUSL-1.1

package iam

import (
	"context"
	"fmt"
	"strings"

	"github.com/hashicorp/boundary/internal/db"
	"github.com/hashicorp/boundary/internal/errors"
	"github.com/hashicorp/boundary/internal/kms"
	"github.com/hashicorp/boundary/internal/oplog"
	"github.com/hashicorp/boundary/internal/types/scope"
	"github.com/hashicorp/boundary/internal/util"
)

var ErrMetadataScopeNotFound = errors.New(context.Background(), errors.RecordNotFound, "iam", "scope not found for metadata", errors.WithoutEvent())

// Repository is the iam database repository
type Repository struct {
	reader db.Reader
	writer db.Writer
	kms    *kms.Kms

	// defaultLimit provides a default for limiting the number of results returned from the repo
	defaultLimit int
}

// NewRepository creates a new iam Repository. Supports the options: WithLimit
// which sets a default limit on results returned by repo operations.
func NewRepository(ctx context.Context, r db.Reader, w db.Writer, kms *kms.Kms, opt ...Option) (*Repository, error) {
	const op = "iam.NewRepository"
	if r == nil {
		return nil, errors.New(ctx, errors.InvalidParameter, op, "nil reader")
	}
	if w == nil {
		return nil, errors.New(ctx, errors.InvalidParameter, op, "nil writer")
	}
	if kms == nil {
		return nil, errors.New(ctx, errors.InvalidParameter, op, "nil kms")
	}
	opts := getOpts(opt...)
	if opts.withLimit == 0 {
		// zero signals the boundary defaults should be used.
		opts.withLimit = db.DefaultLimit
	}
	return &Repository{
		reader:       r,
		writer:       w,
		kms:          kms,
		defaultLimit: opts.withLimit,
	}, nil
}

// list will return a listing of resources and honor the WithLimit option or the
// repo defaultLimit
//
// Supported options: WithLimit, WithReaderWriter
func (r *Repository) list(ctx context.Context, resources any, where string, args []any, opt ...Option) error {
	opts := getOpts(opt...)
	limit := r.defaultLimit
	if opts.withLimit != 0 {
		// non-zero signals an override of the default limit for the repo.
		limit = opts.withLimit
	}
	reader := r.reader
	if !util.IsNil(opts.withReader) {
		reader = opts.withReader
	}
	return reader.SearchWhere(ctx, resources, where, args, db.WithLimit(limit))
}

// create will create a new iam resource in the db repository with an oplog entry
//
// Supported options: WithReaderWriter
func (r *Repository) create(ctx context.Context, resource Resource, opt ...Option) (Resource, error) {
	const op = "iam.(Repository).create"
	if resource == nil {
		return nil, errors.New(ctx, errors.InvalidParameter, op, "missing resource")
	}
	resourceCloner, ok := resource.(Cloneable)
	if !ok {
		return nil, errors.New(ctx, errors.InvalidParameter, op, "resource is not Cloneable")
	}
	metadata, err := r.stdMetadata(ctx, resource)
	if err != nil {
		return nil, errors.Wrap(ctx, err, op, errors.WithMsg("error getting metadata"))
	}
	metadata["op-type"] = []string{oplog.OpType_OP_TYPE_CREATE.String()}

	scope, err := resource.GetScope(ctx, r.reader)
	if err != nil {
		return nil, errors.Wrap(ctx, err, op, errors.WithMsg("unable to get scope"))
	}
	oplogWrapper, err := r.kms.GetWrapper(ctx, scope.GetPublicId(), kms.KeyPurposeOplog)
	if err != nil {
		return nil, errors.Wrap(ctx, err, op, errors.WithMsg("unable to get oplog wrapper"))
	}

	returnedResource := resourceCloner.Clone()
	opts := getOpts(opt...)
	if opts.withWriter != nil {
		err = opts.withWriter.Create(ctx, returnedResource, db.WithOplog(oplogWrapper, metadata))
	} else {
		_, err = r.writer.DoTx(
			ctx,
			db.StdRetryCnt,
			db.ExpBackoff{},
			func(_ db.Reader, w db.Writer) error {
				return w.Create(ctx, returnedResource, db.WithOplog(oplogWrapper, metadata))
			},
		)
	}
	if err != nil {
		return nil, errors.Wrap(ctx, err, op)
	}
	return returnedResource.(Resource), nil
}

// update will update an iam resource in the db repository with an oplog entry
//
// Supported options: WithReaderWriter
func (r *Repository) update(ctx context.Context, resource Resource, version uint32, fieldMaskPaths []string, setToNullPaths []string, opt ...Option) (Resource, int, error) {
	const op = "iam.(Repository).update"
	if version == 0 {
		return nil, db.NoRowsAffected, errors.New(ctx, errors.InvalidParameter, op, "missing version")
	}
	if resource == nil {
		return nil, db.NoRowsAffected, errors.New(ctx, errors.InvalidParameter, op, "missing resource")
	}
	resourceCloner, ok := resource.(Cloneable)
	if !ok {
		return nil, db.NoRowsAffected, errors.New(ctx, errors.InvalidParameter, op, "resource is not Cloneable")
	}
	metadata, err := r.stdMetadata(ctx, resource)
	if err != nil {
		return nil, db.NoRowsAffected, errors.Wrap(ctx, err, op, errors.WithMsg("error getting metadata"))
	}
	metadata["op-type"] = []string{oplog.OpType_OP_TYPE_UPDATE.String()}

	dbOpts := []db.Option{
		db.WithVersion(&version),
	}
	opts := getOpts(opt...)
	if opts.withSkipVetForWrite {
		dbOpts = append(dbOpts, db.WithSkipVetForWrite(true))
	}

	reader := r.reader
	writer := r.writer
	needFreshReaderWriter := true
	if !util.IsNil(opts.withReader) && !util.IsNil(opts.withWriter) {
		reader = opts.withReader
		writer = opts.withWriter
		if !writer.IsTx(ctx) {
			return nil, db.NoRowsAffected, errors.New(ctx, errors.Internal, op, "writer is not in transaction")
		}
		needFreshReaderWriter = false
	}

	var scope *Scope
	switch t := resource.(type) {
	case *Scope:
		scope = t
	default:
		scope, err = resource.GetScope(ctx, r.reader)
		if err != nil {
			return nil, db.NoRowsAffected, errors.Wrap(ctx, err, op, errors.WithMsg("unable to get scope"))
		}
	}
	oplogWrapper, err := r.kms.GetWrapper(ctx, scope.GetPublicId(), kms.KeyPurposeOplog)
	if err != nil {
		return nil, db.NoRowsAffected, errors.Wrap(ctx, err, op, errors.WithMsg("unable to get oplog wrapper"))
	}
	dbOpts = append(dbOpts, db.WithOplog(oplogWrapper, metadata))

	var rowsUpdated int
	var returnedResource any
	txFunc := func(rdr db.Reader, wtr db.Writer) error {
		returnedResource = resourceCloner.Clone()
		rowsUpdated, err = wtr.Update(
			ctx,
			returnedResource,
			fieldMaskPaths,
			setToNullPaths,
			dbOpts...,
		)
		if err != nil {
			return errors.Wrap(ctx, err, op)
		}
		if rowsUpdated > 1 {
			// return err, which will result in a rollback of the update
			return errors.New(ctx, errors.MultipleRecords, op, "more than 1 resource would have been updated")
		}
		return nil
	}

	if !needFreshReaderWriter {
		err = txFunc(reader, writer)
	} else {
		_, err = r.writer.DoTx(
			ctx,
			db.StdRetryCnt,
			db.ExpBackoff{},
			txFunc,
		)
	}
	if err != nil {
		return nil, db.NoRowsAffected, errors.Wrap(ctx, err, op)
	}
	return returnedResource.(Resource), rowsUpdated, nil
}

// delete will delete an iam resource in the db repository with an oplog entry
func (r *Repository) delete(ctx context.Context, resource Resource, _ ...Option) (int, error) {
	const op = "iam.(Repository).delete"
	if resource == nil {
		return db.NoRowsAffected, errors.New(ctx, errors.InvalidParameter, op, "missing resource")
	}
	resourceCloner, ok := resource.(Cloneable)
	if !ok {
		return db.NoRowsAffected, errors.New(ctx, errors.InvalidParameter, op, "resource is not Cloneable")
	}
	metadata, err := r.stdMetadata(ctx, resource)
	if err != nil {
		return db.NoRowsAffected, errors.Wrap(ctx, err, op, errors.WithMsg("error getting metadata"))
	}
	metadata["op-type"] = []string{oplog.OpType_OP_TYPE_DELETE.String()}

	scope, err := resource.GetScope(ctx, r.reader)
	if err != nil {
		return db.NoRowsAffected, errors.Wrap(ctx, err, op, errors.WithMsg("unable to get scope"))
	}
	oplogWrapper, err := r.kms.GetWrapper(ctx, scope.GetPublicId(), kms.KeyPurposeOplog)
	if err != nil {
		return db.NoRowsAffected, errors.Wrap(ctx, err, op, errors.WithMsg("unable to get oplog wrapper"))
	}

	var rowsDeleted int
	var deleteResource any
	_, err = r.writer.DoTx(
		ctx,
		db.StdRetryCnt,
		db.ExpBackoff{},
		func(_ db.Reader, w db.Writer) error {
			deleteResource = resourceCloner.Clone()
			rowsDeleted, err = w.Delete(
				ctx,
				deleteResource,
				db.WithOplog(oplogWrapper, metadata),
			)
			if err != nil {
				return errors.Wrap(ctx, err, op)
			}
			if rowsDeleted > 1 {
				// return err, which will result in a rollback of the delete
				return errors.New(ctx, errors.MultipleRecords, op, "more than 1 resource would have been deleted")
			}
			return nil
		},
	)
	if err != nil {
		return db.NoRowsAffected, errors.Wrap(ctx, err, op)
	}
	return rowsDeleted, nil
}

func (r *Repository) stdMetadata(ctx context.Context, resource Resource) (oplog.Metadata, error) {
	const op = "iam.(Repository).stdMetadata"
	if s, ok := resource.(*Scope); ok {
		newScope := AllocScope()
		newScope.PublicId = s.PublicId
		newScope.Type = s.Type
		if newScope.Type == "" {
			if err := r.reader.LookupByPublicId(ctx, &newScope); err != nil {
				return nil, errors.Wrap(ctx, ErrMetadataScopeNotFound, op)
			}
		}
		switch newScope.Type {
		case scope.Global.String(), scope.Org.String():
			return oplog.Metadata{
				"resource-public-id": []string{resource.GetPublicId()},
				"scope-id":           []string{newScope.PublicId},
				"scope-type":         []string{newScope.Type},
				"resource-type":      []string{resource.GetResourceType().String()},
			}, nil
		case scope.Project.String():
			return oplog.Metadata{
				"resource-public-id": []string{resource.GetPublicId()},
				"scope-id":           []string{newScope.ParentId},
				"scope-type":         []string{newScope.Type},
				"resource-type":      []string{resource.GetResourceType().String()},
			}, nil
		default:
			return nil, errors.New(ctx, errors.InvalidParameter, op, fmt.Sprintf("not a supported scope for metadata: %s", s.Type))
		}
	}

	scope, err := resource.GetScope(ctx, r.reader)
	if err != nil {
		return nil, errors.Wrap(ctx, err, op, errors.WithMsg("unable to get scope"))
	}
	if scope == nil {
		return nil, errors.E(ctx, errors.WithOp(op), errors.WithMsg("nil scope"))
	}
	return oplog.Metadata{
		"resource-public-id": []string{resource.GetPublicId()},
		"scope-id":           []string{scope.PublicId},
		"scope-type":         []string{scope.Type},
		"resource-type":      []string{resource.GetResourceType().String()},
	}, nil
}

func contains(ss []string, t string) bool {
	for _, s := range ss {
		if strings.EqualFold(s, t) {
			return true
		}
	}
	return false
}
