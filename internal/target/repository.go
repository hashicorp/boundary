package target

import (
	"context"
	"database/sql"
	"fmt"
	"strings"

	"github.com/hashicorp/boundary/internal/boundary"
	"github.com/hashicorp/boundary/internal/db"
	"github.com/hashicorp/boundary/internal/errors"
	"github.com/hashicorp/boundary/internal/kms"
	"github.com/hashicorp/boundary/internal/oplog"
	"github.com/hashicorp/boundary/internal/perms"
	"github.com/hashicorp/boundary/internal/types/action"
	"github.com/hashicorp/boundary/internal/types/resource"
	"github.com/hashicorp/boundary/internal/types/scope"
	"github.com/hashicorp/go-dbw"
)

// RepositoryFactory enables `target.Repository` object instantiation,
// and is used by the various service packages/controller object to do so.
type RepositoryFactory func(...Option) (*Repository, error)

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

	// permissions provides a set of user permissions - these directly correlate to what the user
	// has access to in terms of actions and resources and we use it to build queries.
	// These are passed in on the repository constructor using `WithPermissions`, meaning the
	// `Repository` object is contextualized to whatever the request context is.
	permissions []perms.Permission
}

// NewRepository creates a new target Repository.
// Supports the following options:
// - WithLimit: sets a limit on the number of results returned by various repo operations.
// - WithPermissions: defines the permissions the user has to perform different
// actions and access resources within the created repo object.
func NewRepository(ctx context.Context, r db.Reader, w db.Writer, kms *kms.Kms, opt ...Option) (*Repository, error) {
	const op = "target.NewRepository"
	if r == nil {
		return nil, errors.New(ctx, errors.InvalidParameter, op, "nil reader")
	}
	if w == nil {
		return nil, errors.New(ctx, errors.InvalidParameter, op, "nil writer")
	}
	if kms == nil {
		return nil, errors.New(ctx, errors.InvalidParameter, op, "nil kms")
	}

	opts := GetOpts(opt...)
	if opts.WithLimit == 0 {
		// zero signals the boundary defaults should be used.
		opts.WithLimit = db.DefaultLimit
	}

	for _, p := range opts.WithPermissions {
		if p.Resource != resource.Target {
			return nil, errors.New(ctx, errors.InvalidParameter, op, "permission for incorrect resource found")
		}
	}

	return &Repository{
		reader:       r,
		writer:       w,
		kms:          kms,
		defaultLimit: opts.WithLimit,
		permissions:  opts.WithPermissions,
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
	projectIdEmpty := opts.WithProjectId == ""
	projectNameEmpty := opts.WithProjectName == ""
	if !nameEmpty {
		if opts.WithName != publicIdOrName {
			return nil, nil, nil, errors.New(ctx, errors.InvalidParameter, op, "name passed in but does not match publicId")
		}
		where, whereArgs = append(where, "lower(name) = lower(?)"), append(whereArgs, opts.WithName)
		switch {
		case projectIdEmpty && projectNameEmpty:
			return nil, nil, nil, errors.New(ctx, errors.InvalidParameter, op, "using name but both project ID and project name are empty")
		case !projectIdEmpty && !projectNameEmpty:
			return nil, nil, nil, errors.New(ctx, errors.InvalidParameter, op, "using name but both project ID and project name are set")
		case !projectIdEmpty:
			where, whereArgs = append(where, "project_id = ?"), append(whereArgs, opts.WithProjectId)
		case !projectNameEmpty:
			where, whereArgs = append(where, "project_id = (select public_id from iam_scope where lower(name) = lower(?))"), append(whereArgs, opts.WithProjectName)
		default:
			return nil, nil, nil, errors.New(ctx, errors.InvalidParameter, op, "unknown combination of parameters")
		}
	} else {
		switch {
		case !projectIdEmpty:
			return nil, nil, nil, errors.New(ctx, errors.InvalidParameter, op, "passed in project ID when using target ID for lookup")
		case !projectNameEmpty:
			return nil, nil, nil, errors.New(ctx, errors.InvalidParameter, op, "passed in project name when using target ID for lookup")
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
func (r *Repository) FetchAuthzProtectedEntitiesByScope(ctx context.Context, projectIds []string) (map[string][]boundary.AuthzProtectedEntity, error) {
	const op = "target.(Repository).FetchAuthzProtectedEntitiesByScope"

	var where string
	var args []interface{}

	inClauseCnt := 0

	switch len(projectIds) {
	case 0:
		return nil, errors.New(ctx, errors.InvalidParameter, op, "no projects given")
	case 1:
		if projectIds[0] != scope.Global.String() {
			inClauseCnt += 1
			where, args = fmt.Sprintf("where project_id = @%d", inClauseCnt), append(args, sql.Named(fmt.Sprintf("%d", inClauseCnt), projectIds[0]))
		}
	default:
		idsInClause := make([]string, 0, len(projectIds))
		for _, id := range projectIds {
			inClauseCnt += 1
			idsInClause, args = append(idsInClause, fmt.Sprintf("@%d", inClauseCnt)), append(args, sql.Named(fmt.Sprintf("%d", inClauseCnt), id))
		}
		where = fmt.Sprintf("where project_id in (%s)", strings.Join(idsInClause, ","))
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
		targetsMap[tv.GetProjectId()] = append(targetsMap[tv.GetProjectId()], tv)
	}

	return targetsMap, nil
}

// ListTargets lists targets in a project based on the data in the WithPermissions option
// provided to the Repository constructor. If no permissions are available, this function
// is a no-op.
// Supports WithLimit which overrides the limit set in the Repository object.
func (r *Repository) ListTargets(ctx context.Context, opt ...Option) ([]Target, error) {
	const op = "target.(Repository).ListTargets"

	if len(r.permissions) == 0 {
		return []Target{}, nil
	}
	where, args := r.listPermissionWhereClauses()

	opts := GetOpts(opt...)
	limit := r.defaultLimit
	if opts.WithLimit != 0 {
		limit = opts.WithLimit
	}

	var foundTargets []*targetView
	err := r.reader.SearchWhere(ctx, &foundTargets, strings.Join(where, " or "), args,
		db.WithLimit(limit))
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

func (r *Repository) listPermissionWhereClauses() ([]string, []interface{}) {
	var where []string
	var args []interface{}

	inClauseCnt := 0
	for _, p := range r.permissions {
		if p.Action != action.List {
			continue
		}
		inClauseCnt++

		var clauses []string
		clauses = append(clauses, fmt.Sprintf("project_id = @project_id_%d", inClauseCnt))
		args = append(args, sql.Named(fmt.Sprintf("project_id_%d", inClauseCnt), p.ScopeId))

		if len(p.ResourceIds) > 0 {
			clauses = append(clauses, fmt.Sprintf("public_id = any(@public_id_%d)", inClauseCnt))
			args = append(args, sql.Named(fmt.Sprintf("public_id_%d", inClauseCnt), "{"+strings.Join(p.ResourceIds, ",")+"}"))
		}

		where = append(where, fmt.Sprintf("(%s)", strings.Join(clauses, " and ")))
	}

	return where, args
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

	oplogWrapper, err := r.kms.GetWrapper(ctx, t.ProjectId, kms.KeyPurposeOplog)
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
	projectId := target.GetProjectId()
	if projectId == "" {
		t := allocTargetView()
		t.PublicId = target.GetPublicId()
		if err := r.reader.LookupByPublicId(ctx, &t); err != nil {
			return nil, nil, nil, db.NoRowsAffected, errors.Wrap(ctx, err, op, errors.WithMsg(fmt.Sprintf("lookup failed for %s", t.PublicId)))
		}
		projectId = t.ProjectId
	}
	oplogWrapper, err := r.kms.GetWrapper(ctx, projectId, kms.KeyPurposeOplog)
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
	if target.GetProjectId() == "" {
		return nil, nil, nil, errors.New(ctx, errors.InvalidParameter, op, "missing project id")
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

	oplogWrapper, err := r.kms.GetWrapper(ctx, target.GetProjectId(), kms.KeyPurposeOplog)
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
	vet, ok := subtypeRegistry.vetForUpdateFunc(target.GetType())
	if !ok {
		return nil, nil, nil, db.NoRowsAffected, errors.New(ctx, errors.InvalidParameter, op, fmt.Sprintf("unsupported target type %s", target.GetType()))
	}
	if err := vet(ctx, target, fieldMaskPaths); err != nil {
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
	dbMask, nullFields = dbw.BuildUpdatePaths(
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
			return nil, nil, nil, db.NoRowsAffected, errors.New(ctx, errors.NotUnique, op, fmt.Sprintf("target %s already exists in project %s", target.GetName(), target.GetProjectId()))
		}
		return nil, nil, nil, db.NoRowsAffected, errors.Wrap(ctx, err, op, errors.WithMsg(fmt.Sprintf("failed for %s", target.GetPublicId())))
	}
	return returnedTarget, hostSources, credSources, rowsUpdated, nil
}
