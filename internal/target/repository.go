package target

import (
	"context"
	"fmt"
	"strings"

	"github.com/hashicorp/boundary/internal/db"
	"github.com/hashicorp/boundary/internal/errors"
	"github.com/hashicorp/boundary/internal/kms"
	"github.com/hashicorp/boundary/internal/oplog"
)

// Cloneable provides a cloning interface
type Cloneable interface {
	Clone() interface{}
}

// Repository is the target database repository
type Repository struct {
	reader db.Reader
	writer db.Writer
	kms    *kms.Kms

	// defaultLimit provides a default for limiting the number of results returned from the repo
	defaultLimit int
}

// NewRepository creates a new target Repository. Supports the options: WithLimit
// which sets a default limit on results returned by repo operations.
func NewRepository(r db.Reader, w db.Writer, kms *kms.Kms, opt ...Option) (*Repository, error) {
	const op = "target.NewRepository"
	if r == nil {
		return nil, errors.NewDeprecated(errors.InvalidParameter, op, "nil reader")
	}
	if w == nil {
		return nil, errors.NewDeprecated(errors.InvalidParameter, op, "nil writer")
	}
	if kms == nil {
		return nil, errors.NewDeprecated(errors.InvalidParameter, op, "nil kms")
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

// LookupTarget will look up a target in the repository and return the target
// with its host source ids and credential source ids.  If the target is not
// found, it will return nil, nil, nil, nil. No options are currently supported.
func (r *Repository) LookupTarget(ctx context.Context, publicIdOrName string, opt ...Option) (Target, []HostSource, []CredentialSource, error) {
	const op = "target.(Repository).LookupTarget"
	opts := getOpts(opt...)

	if publicIdOrName == "" {
		return nil, nil, nil, errors.New(ctx, errors.InvalidParameter, op, "missing public id")
	}

	var where []string
	var whereArgs []interface{}
	nameEmpty := opts.withName == ""
	scopeIdEmpty := opts.withScopeId == ""
	scopeNameEmpty := opts.withScopeName == ""
	if !nameEmpty {
		if opts.withName != publicIdOrName {
			return nil, nil, nil, errors.New(ctx, errors.InvalidParameter, op, "name passed in but does not match publicId")
		}
		where, whereArgs = append(where, "lower(name) = lower(?)"), append(whereArgs, opts.withName)
		switch {
		case scopeIdEmpty && scopeNameEmpty:
			return nil, nil, nil, errors.New(ctx, errors.InvalidParameter, op, "using name but both scope ID and scope name are empty")
		case !scopeIdEmpty && !scopeNameEmpty:
			return nil, nil, nil, errors.New(ctx, errors.InvalidParameter, op, "using name but both scope ID and scope name are set")
		case !scopeIdEmpty:
			where, whereArgs = append(where, "scope_id = ?"), append(whereArgs, opts.withScopeId)
		case !scopeNameEmpty:
			where, whereArgs = append(where, "scope_id = (select public_id from iam_scope where lower(name) = lower(?))"), append(whereArgs, opts.withScopeName)
		default:
			return nil, nil, nil, errors.New(ctx, errors.InvalidParameter, op, "unknown combination of parameters")
		}
	} else {
		switch {
		case !scopeIdEmpty:
			return nil, nil, nil, errors.New(ctx, errors.InvalidParameter, op, "passed in scope ID when using target ID for lookup")
		case !scopeNameEmpty:
			return nil, nil, nil, errors.New(ctx, errors.InvalidParameter, op, "passed in scope name when using target ID for lookup")
		}
	}

	target := allocTargetView()
	target.PublicId = publicIdOrName
	var hostSources []HostSource
	var credSources []CredentialSource
	_, err := r.writer.DoTx(
		ctx,
		db.StdRetryCnt,
		db.ExpBackoff{},
		func(read db.Reader, w db.Writer) error {
			var lookupErr error
			switch where {
			case nil:
				lookupErr = read.LookupById(ctx, &target)
			default:
				target.PublicId = ""
				lookupErr = read.LookupWhere(ctx, &target, strings.Join(where, " and "), whereArgs...)
			}
			if lookupErr != nil {
				return errors.Wrap(ctx, lookupErr, op, errors.WithMsg(fmt.Sprintf("failed for %s", publicIdOrName)))
			}
			var err error
			if hostSources, err = fetchHostSources(ctx, read, target.PublicId); err != nil {
				return errors.Wrap(ctx, err, op)
			}
			if credSources, err = fetchCredentialSources(ctx, read, target.PublicId); err != nil {
				return errors.Wrap(ctx, err, op)
			}
			return nil
		},
	)
	if err != nil {
		if errors.IsNotFoundError(err) {
			return nil, nil, nil, nil
		}
		return nil, nil, nil, errors.Wrap(ctx, err, op)
	}
	subtype, err := target.targetSubtype()
	if err != nil {
		return nil, nil, nil, errors.Wrap(ctx, err, op)
	}
	return subtype, hostSources, credSources, nil
}

// ListTargets in targets in a scope.  Supports the WithScopeId, WithLimit, WithTargetType options.
func (r *Repository) ListTargets(ctx context.Context, opt ...Option) ([]Target, error) {
	const op = "target.(Repository).ListTargets"
	opts := getOpts(opt...)
	if len(opts.withScopeIds) == 0 && opts.withUserId == "" {
		return nil, errors.New(ctx, errors.InvalidParameter, op, "must specify either scope id or user id")
	}
	// TODO (jimlambrt 8/2020) - implement WithUserId() optional filtering.
	var where []string
	var args []interface{}
	if len(opts.withScopeIds) != 0 {
		where, args = append(where, "scope_id in (?)"), append(args, opts.withScopeIds)
	}
	if opts.withTargetType != nil {
		where, args = append(where, "type = ?"), append(args, opts.withTargetType.String())
	}

	var foundTargets []*targetView
	err := r.list(ctx, &foundTargets, strings.Join(where, " and "), args, opt...)
	if err != nil {
		return nil, errors.Wrap(ctx, err, op)
	}

	targets := make([]Target, 0, len(foundTargets))

	for _, t := range foundTargets {
		subtype, err := t.targetSubtype()
		if err != nil {
			return nil, errors.Wrap(ctx, err, op)
		}
		targets = append(targets, subtype)
	}
	return targets, nil
}

// list will return a listing of resources and honor the WithLimit option or the
// repo defaultLimit
func (r *Repository) list(ctx context.Context, resources interface{}, where string, args []interface{}, opt ...Option) error {
	const op = "target.(Repository).list"
	opts := getOpts(opt...)
	limit := r.defaultLimit
	var dbOpts []db.Option
	if opts.withLimit != 0 {
		// non-zero signals an override of the default limit for the repo.
		limit = opts.withLimit
	}
	dbOpts = append(dbOpts, db.WithLimit(limit))
	if err := r.reader.SearchWhere(ctx, resources, where, args, dbOpts...); err != nil {
		return errors.Wrap(ctx, err, op)
	}
	return nil
}

// DeleteTarget will delete a target from the repository.
func (r *Repository) DeleteTarget(ctx context.Context, publicId string, _ ...Option) (int, error) {
	const op = "target.(Repository).DeleteTarget"
	if publicId == "" {
		return db.NoRowsAffected, errors.New(ctx, errors.InvalidParameter, op, "missing public id")
	}
	t := allocTargetView()
	t.PublicId = publicId
	if err := r.reader.LookupByPublicId(ctx, &t); err != nil {
		return db.NoRowsAffected, errors.Wrap(ctx, err, op, errors.WithMsg(fmt.Sprintf("failed for %s", publicId)))
	}
	var metadata oplog.Metadata
	var deleteTarget interface{}
	switch t.Type {
	case TcpTargetType.String():
		tcpT := allocTcpTarget()
		tcpT.PublicId = publicId
		deleteTarget = &tcpT
		metadata = tcpT.oplog(oplog.OpType_OP_TYPE_DELETE)
	default:
		return db.NoRowsAffected, errors.New(ctx, errors.InvalidParameter, op, fmt.Sprintf("%s is an unsupported target type %s", publicId, t.Type))
	}

	oplogWrapper, err := r.kms.GetWrapper(ctx, t.ScopeId, kms.KeyPurposeOplog)
	if err != nil {
		return db.NoRowsAffected, errors.Wrap(ctx, err, op, errors.WithMsg("unable to get oplog wrapper"))
	}

	var rowsDeleted int
	var deleteResource interface{}
	_, err = r.writer.DoTx(
		ctx,
		db.StdRetryCnt,
		db.ExpBackoff{},
		func(_ db.Reader, w db.Writer) error {
			deleteResource = deleteTarget.(Cloneable).Clone()
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

// update a target in the db repository with an oplog entry.
// It currently supports no options.
func (r *Repository) update(ctx context.Context, target Target, version uint32, fieldMaskPaths []string, setToNullPaths []string, _ ...Option) (Target, []HostSource, []CredentialSource, int, error) {
	const op = "target.(Repository).update"
	if version == 0 {
		return nil, nil, nil, db.NoRowsAffected, errors.New(ctx, errors.InvalidParameter, op, "missing version")
	}
	if target == nil {
		return nil, nil, nil, db.NoRowsAffected, errors.New(ctx, errors.InvalidParameter, op, "nil target")
	}
	cloner, ok := target.(Cloneable)
	if !ok {
		return nil, nil, nil, db.NoRowsAffected, errors.New(ctx, errors.InvalidParameter, op, "target is not cloneable")
	}
	dbOpts := []db.Option{
		db.WithVersion(&version),
	}
	scopeId := target.GetScopeId()
	if scopeId == "" {
		t := allocTargetView()
		t.PublicId = target.GetPublicId()
		if err := r.reader.LookupByPublicId(ctx, &t); err != nil {
			return nil, nil, nil, db.NoRowsAffected, errors.Wrap(ctx, err, op, errors.WithMsg(fmt.Sprintf("lookup failed for %s", t.PublicId)))
		}
		scopeId = t.ScopeId
	}
	oplogWrapper, err := r.kms.GetWrapper(ctx, scopeId, kms.KeyPurposeOplog)
	if err != nil {
		return nil, nil, nil, db.NoRowsAffected, errors.Wrap(ctx, err, op, errors.WithMsg("unable to get oplog wrapper"))
	}
	metadata := target.oplog(oplog.OpType_OP_TYPE_UPDATE)
	dbOpts = append(dbOpts, db.WithOplog(oplogWrapper, metadata))

	var rowsUpdated int
	var returnedTarget interface{}
	var hostSources []HostSource
	var credSources []CredentialSource
	_, err = r.writer.DoTx(
		ctx,
		db.StdRetryCnt,
		db.ExpBackoff{},
		func(reader db.Reader, w db.Writer) error {
			returnedTarget = cloner.Clone()
			rowsUpdated, err = w.Update(
				ctx,
				returnedTarget,
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

			if hostSources, err = fetchHostSources(ctx, reader, target.GetPublicId()); err != nil {
				return errors.Wrap(ctx, err, op)
			}

			if credSources, err = fetchCredentialSources(ctx, reader, target.GetPublicId()); err != nil {
				return errors.Wrap(ctx, err, op)
			}
			return nil
		},
	)
	if err != nil {
		return nil, nil, nil, db.NoRowsAffected, errors.Wrap(ctx, err, op)
	}
	return returnedTarget.(Target), hostSources, credSources, rowsUpdated, nil
}
