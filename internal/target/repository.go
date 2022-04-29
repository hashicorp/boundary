package target

import (
	"context"
	"database/sql"
	"fmt"
	"strings"

	"github.com/hashicorp/boundary/internal/boundary"
	"github.com/hashicorp/boundary/internal/db"
	dbcommon "github.com/hashicorp/boundary/internal/db/common"
	"github.com/hashicorp/boundary/internal/errors"
	"github.com/hashicorp/boundary/internal/kms"
	"github.com/hashicorp/boundary/internal/oplog"
	"github.com/hashicorp/boundary/internal/types/scope"
)

// Cloneable provides a cloning interface
type Cloneable interface {
	Clone() Target
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
	opts := GetOpts(opt...)
	if opts.WithLimit == 0 {
		// zero signals the boundary defaults should be used.
		opts.WithLimit = db.DefaultLimit
	}
	return &Repository{
		reader:       r,
		writer:       w,
		kms:          kms,
		defaultLimit: opts.WithLimit,
	}, nil
}

// LookupTarget will look up a target in the repository and return the target
// with its host source ids and credential source ids.  If the target is not
// found, it will return nil, nil, nil, nil. No options are currently supported.
func (r *Repository) LookupTarget(ctx context.Context, publicIdOrName string, opt ...Option) (Target, []HostSource, []CredentialSource, error) {
	const op = "target.(Repository).LookupTarget"
	opts := GetOpts(opt...)

	if publicIdOrName == "" {
		return nil, nil, nil, errors.New(ctx, errors.InvalidParameter, op, "missing public id")
	}

	var where []string
	var whereArgs []interface{}
	nameEmpty := opts.WithName == ""
	scopeIdEmpty := opts.WithScopeId == ""
	scopeNameEmpty := opts.WithScopeName == ""
	if !nameEmpty {
		if opts.WithName != publicIdOrName {
			return nil, nil, nil, errors.New(ctx, errors.InvalidParameter, op, "name passed in but does not match publicId")
		}
		where, whereArgs = append(where, "lower(name) = lower(?)"), append(whereArgs, opts.WithName)
		switch {
		case scopeIdEmpty && scopeNameEmpty:
			return nil, nil, nil, errors.New(ctx, errors.InvalidParameter, op, "using name but both scope ID and scope name are empty")
		case !scopeIdEmpty && !scopeNameEmpty:
			return nil, nil, nil, errors.New(ctx, errors.InvalidParameter, op, "using name but both scope ID and scope name are set")
		case !scopeIdEmpty:
			where, whereArgs = append(where, "scope_id = ?"), append(whereArgs, opts.WithScopeId)
		case !scopeNameEmpty:
			where, whereArgs = append(where, "scope_id = (select public_id from iam_scope where lower(name) = lower(?))"), append(whereArgs, opts.WithScopeName)
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
				lookupErr = read.LookupWhere(ctx, &target, strings.Join(where, " and "), whereArgs)
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
	subtype, err := target.targetSubtype(ctx)
	if err != nil {
		return nil, nil, nil, errors.Wrap(ctx, err, op)
	}
	return subtype, hostSources, credSources, nil
}

// FetchAuthzProtectedEntitiesByScope implements boundary.AuthzProtectedEntityProvider
func (r *Repository) FetchAuthzProtectedEntitiesByScope(ctx context.Context, scopeIds []string) (map[string][]boundary.AuthzProtectedEntity, error) {
	const op = "target.(Repository).FetchAuthzProtectedEntitiesByScope"

	var where string
	var args []interface{}

	inClauseCnt := 0

	switch len(scopeIds) {
	case 0:
		return nil, errors.New(ctx, errors.InvalidParameter, op, "no scopes given")
	case 1:
		if scopeIds[0] != scope.Global.String() {
			inClauseCnt += 1
			where, args = fmt.Sprintf("where scope_id = @%d", inClauseCnt), append(args, sql.Named(fmt.Sprintf("%d", inClauseCnt), scopeIds[0]))
		}
	default:
		idsInClause := make([]string, 0, len(scopeIds))
		for _, id := range scopeIds {
			inClauseCnt += 1
			idsInClause, args = append(idsInClause, fmt.Sprintf("@%d", inClauseCnt)), append(args, sql.Named(fmt.Sprintf("%d", inClauseCnt), id))
		}
		where = fmt.Sprintf("where scope_id in (%s)", strings.Join(idsInClause, ","))
	}

	q := targetPublicIdList
	query := fmt.Sprintf(q, where)

	rows, err := r.reader.Query(ctx, query, args)
	if err != nil {
		return nil, errors.Wrap(ctx, err, op)
	}
	defer rows.Close()

	targetsMap := map[string][]boundary.AuthzProtectedEntity{}
	for rows.Next() {
		var tv targetView
		if err := r.reader.ScanRows(ctx, rows, &tv); err != nil {
			return nil, errors.Wrap(ctx, err, op, errors.WithMsg("scan row failed"))
		}
		targetsMap[tv.GetScopeId()] = append(targetsMap[tv.GetScopeId()], tv)
	}

	return targetsMap, nil
}

// ListTargets in targets in a scope.  Supports the WithScopeId, WithLimit, WithType options.
func (r *Repository) ListTargets(ctx context.Context, opt ...Option) ([]Target, error) {
	const op = "target.(Repository).ListTargets"
	opts := GetOpts(opt...)
	if len(opts.WithScopeIds) == 0 && opts.WithUserId == "" && len(opts.WithTargetIds) == 0 {
		return nil, errors.New(ctx, errors.InvalidParameter, op, "must specify either scope ids, target ids, or user id")
	}
	// TODO (jimlambrt 8/2020) - implement WithUserId() optional filtering.
	var where []string
	var args []interface{}
	inClauseCnt := 0

	switch len(opts.WithScopeIds) {
	case 0:
	case 1:
		inClauseCnt += 1
		where, args = append(where, fmt.Sprintf("scope_id = @%d", inClauseCnt)), append(args, sql.Named(fmt.Sprintf("%d", inClauseCnt), opts.WithScopeIds[0]))
	default:
		idsInClause := make([]string, 0, len(opts.WithScopeIds))
		for _, id := range opts.WithScopeIds {
			inClauseCnt += 1
			idsInClause, args = append(idsInClause, fmt.Sprintf("@%d", inClauseCnt)), append(args, sql.Named(fmt.Sprintf("%d", inClauseCnt), id))
		}
		where = append(where, fmt.Sprintf("scope_id in (%s)", strings.Join(idsInClause, ",")))
	}

	switch len(opts.WithTargetIds) {
	case 0:
	case 1:
		inClauseCnt += 1
		where, args = append(where, fmt.Sprintf("public_id = @%d", inClauseCnt)), append(args, sql.Named(fmt.Sprintf("%d", inClauseCnt), opts.WithTargetIds[0]))
	default:
		idsInClause := make([]string, 0, len(opts.WithTargetIds))
		for _, id := range opts.WithTargetIds {
			inClauseCnt += 1
			idsInClause, args = append(idsInClause, fmt.Sprintf("@%d", inClauseCnt)), append(args, sql.Named(fmt.Sprintf("%d", inClauseCnt), id))
		}
		where = append(where, fmt.Sprintf("public_id in (%s)", strings.Join(idsInClause, ",")))
	}

	if opts.WithType != "" {
		inClauseCnt += 1
		where, args = append(where, fmt.Sprintf("type = @%d", inClauseCnt)), append(args, sql.Named(fmt.Sprintf("%d", inClauseCnt), opts.WithType.String()))
	}

	var foundTargets []*targetView
	err := r.list(ctx, &foundTargets, strings.Join(where, " and "), args, opt...)
	if err != nil {
		return nil, errors.Wrap(ctx, err, op)
	}

	targets := make([]Target, 0, len(foundTargets))

	for _, t := range foundTargets {
		subtype, err := t.targetSubtype(ctx)
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
	opts := GetOpts(opt...)
	limit := r.defaultLimit
	var dbOpts []db.Option
	if opts.WithLimit != 0 {
		// non-zero signals an override of the default limit for the repo.
		limit = opts.WithLimit
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
	var deleteTarget Target
	alloc, ok := subtypeRegistry.allocFunc(t.Subtype())
	if !ok {
		return db.NoRowsAffected, errors.New(ctx, errors.InvalidParameter, op, fmt.Sprintf("%s is an unsupported target type %s", publicId, t.Type))
	}

	deleteTarget = alloc()
	deleteTarget.SetPublicId(ctx, publicId)
	metadata = deleteTarget.Oplog(oplog.OpType_OP_TYPE_DELETE)

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
	metadata := target.Oplog(oplog.OpType_OP_TYPE_UPDATE)
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

// CreateTarget inserts into the repository and returns the new Target with
// its list of host sets and credential libraries.
// WithPublicId is the only supported option.
func (r *Repository) CreateTarget(ctx context.Context, target Target, opt ...Option) (Target, []HostSource, []CredentialSource, error) {
	const op = "target.(Repository).CreateTarget"
	opts := GetOpts(opt...)
	if target == nil {
		return nil, nil, nil, errors.New(ctx, errors.InvalidParameter, op, "missing target")
	}

	vet, ok := subtypeRegistry.vetFunc(target.GetType())
	if !ok {
		return nil, nil, nil, errors.New(ctx, errors.InvalidParameter, op, fmt.Sprintf("unsupported target type %s", target.GetType()))
	}
	if err := vet(ctx, target); err != nil {
		return nil, nil, nil, err
	}
	if target.GetScopeId() == "" {
		return nil, nil, nil, errors.New(ctx, errors.InvalidParameter, op, "missing scope id")
	}
	if target.GetName() == "" {
		return nil, nil, nil, errors.New(ctx, errors.InvalidParameter, op, "missing name")
	}
	if target.GetPublicId() != "" {
		return nil, nil, nil, errors.New(ctx, errors.InvalidParameter, op, "public id not empty")
	}

	t := target.Clone()

	if opts.WithPublicId != "" {
		if err := t.SetPublicId(ctx, opts.WithPublicId); err != nil {
			return nil, nil, nil, err
		}
	} else {
		prefix, ok := subtypeRegistry.idPrefix(target.GetType())
		if !ok {
			return nil, nil, nil, errors.New(ctx, errors.InvalidParameter, op, fmt.Sprintf("unsupported target type %s", target.GetType()))
		}
		id, err := db.NewPublicId(prefix)
		if err != nil {
			return nil, nil, nil, errors.Wrap(ctx, err, op)
		}
		t.SetPublicId(ctx, id)
	}

	oplogWrapper, err := r.kms.GetWrapper(ctx, target.GetScopeId(), kms.KeyPurposeOplog)
	if err != nil {
		return nil, nil, nil, errors.Wrap(ctx, err, op, errors.WithMsg("unable to get oplog wrapper"))
	}

	metadata := t.Oplog(oplog.OpType_OP_TYPE_CREATE)
	var returnedTarget interface{}
	var returnedHostSources []HostSource
	var returnedCredSources []CredentialSource
	_, err = r.writer.DoTx(
		ctx,
		db.StdRetryCnt,
		db.ExpBackoff{},
		func(read db.Reader, w db.Writer) error {
			targetTicket, err := w.GetTicket(ctx, t)
			if err != nil {
				return errors.Wrap(ctx, err, op, errors.WithMsg("unable to get ticket"))
			}
			msgs := make([]*oplog.Message, 0, 2)
			var targetOplogMsg oplog.Message
			returnedTarget = t.Clone()
			if err := w.Create(ctx, returnedTarget, db.NewOplogMsg(&targetOplogMsg)); err != nil {
				return errors.Wrap(ctx, err, op, errors.WithMsg("unable to create target"))
			}
			msgs = append(msgs, &targetOplogMsg)
			if err := w.WriteOplogEntryWith(ctx, oplogWrapper, targetTicket, metadata, msgs); err != nil {
				return errors.Wrap(ctx, err, op, errors.WithMsg("unable to write oplog"))
			}

			return nil
		},
	)
	if err != nil {
		return nil, nil, nil, errors.Wrap(ctx, err, op, errors.WithMsg(fmt.Sprintf("failed for %s target id", t.GetPublicId())))
	}
	return returnedTarget.(Target), returnedHostSources, returnedCredSources, nil
}

// UpdateTarget will update a target in the repository and return the written
// target. fieldMaskPaths provides field_mask.proto paths for fields that should
// be updated.  Fields will be set to NULL if the field is a zero value and
// included in fieldMask. Name, Description, and WorkerFilter are the only
// updatable fields. If no updatable fields are included in the fieldMaskPaths,
// then an error is returned.
func (r *Repository) UpdateTarget(ctx context.Context, target Target, version uint32, fieldMaskPaths []string, _ ...Option) (Target, []HostSource, []CredentialSource, int, error) {
	const op = "target.(Repository).UpdateTarget"
	if target == nil {
		return nil, nil, nil, db.NoRowsAffected, errors.New(ctx, errors.InvalidParameter, op, "missing target")
	}
	vet, ok := subtypeRegistry.vetFunc(target.GetType())
	if !ok {
		return nil, nil, nil, db.NoRowsAffected, errors.New(ctx, errors.InvalidParameter, op, fmt.Sprintf("unsupported target type %s", target.GetType()))
	}
	if err := vet(ctx, target); err != nil {
		return nil, nil, nil, db.NoRowsAffected, err
	}

	if target.GetPublicId() == "" {
		return nil, nil, nil, db.NoRowsAffected, errors.New(ctx, errors.InvalidParameter, op, "missing target public id")
	}

	for _, f := range fieldMaskPaths {
		switch {
		case strings.EqualFold("name", f):
		case strings.EqualFold("description", f):
		case strings.EqualFold("defaultport", f):
		case strings.EqualFold("sessionmaxseconds", f):
		case strings.EqualFold("sessionconnectionlimit", f):
		case strings.EqualFold("workerfilter", f):
		default:
			return nil, nil, nil, db.NoRowsAffected, errors.New(ctx, errors.InvalidFieldMask, op, fmt.Sprintf("invalid field mask: %s", f))
		}
	}
	var dbMask, nullFields []string
	dbMask, nullFields = dbcommon.BuildUpdatePaths(
		map[string]interface{}{
			"Name":                   target.GetName(),
			"Description":            target.GetDescription(),
			"DefaultPort":            target.GetDefaultPort(),
			"SessionMaxSeconds":      target.GetSessionMaxSeconds(),
			"SessionConnectionLimit": target.GetSessionConnectionLimit(),
			"WorkerFilter":           target.GetWorkerFilter(),
		},
		fieldMaskPaths,
		[]string{"SessionMaxSeconds", "SessionConnectionLimit"},
	)
	if len(dbMask) == 0 && len(nullFields) == 0 {
		return nil, nil, nil, db.NoRowsAffected, errors.New(ctx, errors.EmptyFieldMask, op, "empty field mask")
	}
	var returnedTarget Target
	var rowsUpdated int
	var hostSources []HostSource
	var credSources []CredentialSource
	_, err := r.writer.DoTx(
		ctx,
		db.StdRetryCnt,
		db.ExpBackoff{},
		func(read db.Reader, w db.Writer) error {
			var err error
			t := target.Clone()
			returnedTarget, hostSources, credSources, rowsUpdated, err = r.update(ctx, t, version, dbMask, nullFields)
			if err != nil {
				return errors.Wrap(ctx, err, op)
			}
			return nil
		},
	)
	if err != nil {
		if errors.IsUniqueError(err) {
			return nil, nil, nil, db.NoRowsAffected, errors.New(ctx, errors.NotUnique, op, fmt.Sprintf("target %s already exists in scope %s", target.GetName(), target.GetScopeId()))
		}
		return nil, nil, nil, db.NoRowsAffected, errors.Wrap(ctx, err, op, errors.WithMsg(fmt.Sprintf("failed for %s", target.GetPublicId())))
	}
	return returnedTarget, hostSources, credSources, rowsUpdated, nil
}
