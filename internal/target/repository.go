// Copyright IBM Corp. 2020, 2025
// SPDX-License-Identifier: BUSL-1.1

package target

import (
	"context"
	"database/sql"
	"fmt"
	"io"
	"strings"
	"time"

	"github.com/hashicorp/boundary/globals"
	talias "github.com/hashicorp/boundary/internal/alias/target"
	"github.com/hashicorp/boundary/internal/boundary"
	"github.com/hashicorp/boundary/internal/db"
	"github.com/hashicorp/boundary/internal/db/timestamp"
	"github.com/hashicorp/boundary/internal/errors"
	"github.com/hashicorp/boundary/internal/kms"
	"github.com/hashicorp/boundary/internal/oplog"
	"github.com/hashicorp/boundary/internal/perms"
	"github.com/hashicorp/boundary/internal/types/action"
	"github.com/hashicorp/boundary/internal/types/resource"
	"github.com/hashicorp/boundary/internal/types/scope"
	"github.com/hashicorp/boundary/internal/util"
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
	permissions  []perms.Permission
	randomReader io.Reader
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
		randomReader: opts.withRandomReader,
	}, nil
}

// LookupTargetForSessionAuthorization will look up a target in the repository and return the target
// with its host source ids, credential source ids, and server certificate, if applicable.  If the target is not
// found, it will return nil, nil.
// Supported option: WithAlias if the session authorization uses a target alias
func (r *Repository) LookupTargetForSessionAuthorization(ctx context.Context, publicId string, projectId string, opt ...Option) (Target, error) {
	const op = "target.(Repository).LookupTargetForSessionAuthorization"
	opts := GetOpts(opt...)
	switch {
	case publicId == "":
		return nil, errors.New(ctx, errors.InvalidParameter, op, "missing public id")
	case projectId == "":
		return nil, errors.New(ctx, errors.InvalidParameter, op, "missing project id")
	}

	databaseWrapper, err := r.kms.GetWrapper(ctx, projectId, kms.KeyPurposeDatabase)
	if err != nil {
		return nil, errors.Wrap(ctx, err, op, errors.WithMsg("unable to get database wrapper"))
	}

	target := allocTargetView()
	target.PublicId = publicId
	var address string
	var hostSources []HostSource
	var credSources []CredentialSource
	var cert *ServerCertificate
	_, err = r.writer.DoTx(
		ctx,
		db.StdRetryCnt,
		db.ExpBackoff{},
		func(read db.Reader, w db.Writer) error {
			lookupErr := read.LookupById(ctx, &target)
			if lookupErr != nil {
				return errors.Wrap(ctx, lookupErr, op, errors.WithMsg(fmt.Sprintf("failed for %s", publicId)))
			}

			var err error
			if hostSources, err = fetchHostSources(ctx, read, target.PublicId); err != nil {
				return errors.Wrap(ctx, err, op)
			}
			if credSources, err = fetchCredentialSources(ctx, read, target.PublicId); err != nil {
				return errors.Wrap(ctx, err, op)
			}

			targetAddress, err := fetchAddress(ctx, read, target.PublicId)
			if err != nil && !errors.IsNotFoundError(err) {
				return errors.Wrap(ctx, err, op)
			}
			if targetAddress != nil {
				address = targetAddress.GetAddress()
			}

			if opts.WithAlias != nil {
				cert, err = fetchTargetAliasProxyServerCertificate(ctx, read, w, target.PublicId, target.ProjectId, opts.WithAlias, databaseWrapper, target.GetSessionMaxSeconds(), WithRandomReader(r.randomReader))
				if err != nil && !errors.IsNotFoundError(err) {
					return errors.Wrap(ctx, err, op)
				}
			} else {
				cert, err = fetchTargetProxyServerCertificate(ctx, read, w, target.PublicId, target.ProjectId, databaseWrapper, target.GetSessionMaxSeconds())
				if err != nil && !errors.IsNotFoundError(err) {
					return errors.Wrap(ctx, err, op)
				}
			}
			return nil
		},
	)
	if err != nil {
		if errors.IsNotFoundError(err) {
			return nil, nil
		}
		return nil, errors.Wrap(ctx, err, op)
	}
	subtype, err := target.targetSubtype(ctx, address)
	if err != nil {
		return nil, errors.Wrap(ctx, err, op)
	}
	subtype.SetHostSources(hostSources)
	subtype.SetCredentialSources(credSources)
	subtype.SetProxyServerCertificate(cert)

	return subtype, nil
}

// LookupTarget will look up a target in the repository and return the target
// with its host source ids and credential source ids.  If the target is not
// found, it will return nil, nil.
// Supported options: WithName, WithProjectId, and WithProjectName
func (r *Repository) LookupTarget(ctx context.Context, publicIdOrName string, opt ...Option) (Target, error) {
	const op = "target.(Repository).LookupTarget"
	opts := GetOpts(opt...)

	if publicIdOrName == "" {
		return nil, errors.New(ctx, errors.InvalidParameter, op, "missing public id")
	}

	var where []string
	var whereArgs []any
	nameEmpty := opts.WithName == ""
	projectIdEmpty := opts.WithProjectId == ""
	projectNameEmpty := opts.WithProjectName == ""
	if !nameEmpty {
		if opts.WithName != publicIdOrName {
			return nil, errors.New(ctx, errors.InvalidParameter, op, "name passed in but does not match publicId")
		}
		where, whereArgs = append(where, "lower(name) = lower(?)"), append(whereArgs, opts.WithName)
		switch {
		case projectIdEmpty && projectNameEmpty:
			return nil, errors.New(ctx, errors.InvalidParameter, op, "using name but both project ID and project name are empty")
		case !projectIdEmpty && !projectNameEmpty:
			return nil, errors.New(ctx, errors.InvalidParameter, op, "using name but both project ID and project name are set")
		case !projectIdEmpty:
			where, whereArgs = append(where, "project_id = ?"), append(whereArgs, opts.WithProjectId)
		case !projectNameEmpty:
			where, whereArgs = append(where, "project_id = (select public_id from iam_scope where lower(name) = lower(?))"), append(whereArgs, opts.WithProjectName)
		default:
			return nil, errors.New(ctx, errors.InvalidParameter, op, "unknown combination of parameters")
		}
	} else {
		switch {
		case !projectIdEmpty:
			return nil, errors.New(ctx, errors.InvalidParameter, op, "passed in project ID when using target ID for lookup")
		case !projectNameEmpty:
			return nil, errors.New(ctx, errors.InvalidParameter, op, "passed in project name when using target ID for lookup")
		}
	}

	target := allocTargetView()
	target.PublicId = publicIdOrName
	var address string
	var hostSources []HostSource
	var credSources []CredentialSource
	var aliases []*talias.Alias
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
			if aliases, err = fetchTargetAliases(ctx, read, target.PublicId); err != nil {
				return errors.Wrap(ctx, err, op)
			}
			targetAddress, err := fetchAddress(ctx, read, target.PublicId)
			if err != nil && !errors.IsNotFoundError(err) {
				return errors.Wrap(ctx, err, op)
			}
			if targetAddress != nil {
				address = targetAddress.GetAddress()
			}
			return nil
		},
	)
	if err != nil {
		if errors.IsNotFoundError(err) {
			return nil, nil
		}
		return nil, errors.Wrap(ctx, err, op)
	}
	subtype, err := target.targetSubtype(ctx, address)
	if err != nil {
		return nil, errors.Wrap(ctx, err, op)
	}
	subtype.SetHostSources(hostSources)
	subtype.SetCredentialSources(credSources)
	subtype.SetAliases(aliases)

	return subtype, nil
}

// FetchAuthzProtectedEntitiesByScope implements boundary.AuthzProtectedEntityProvider
func (r *Repository) FetchAuthzProtectedEntitiesByScope(ctx context.Context, projectIds []string) (map[string][]boundary.AuthzProtectedEntity, error) {
	const op = "target.(Repository).FetchAuthzProtectedEntitiesByScope"

	var where string
	var args []any

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
	if err := rows.Err(); err != nil {
		return nil, errors.Wrap(ctx, err, op, errors.WithMsg("next rows error"))
	}

	return targetsMap, nil
}

// listTargets lists targets based on the data in the WithPermissions option
// provided to the Repository constructor. If no permissions are available, this function
// is a no-op.
// Supported options:
//   - WithLimit which overrides the limit set in the Repository object
//   - WithStartPageAfterItem which sets where to start listing from
func (r *Repository) listTargets(ctx context.Context, opt ...Option) ([]Target, time.Time, error) {
	if len(r.permissions) == 0 {
		return []Target{}, time.Time{}, nil
	}
	where, args := r.listPermissionWhereClauses()
	permissionWhereClause := "(" + strings.Join(where, " or ") + ")"

	opts := GetOpts(opt...)
	limit := r.defaultLimit
	if opts.WithLimit != 0 {
		limit = opts.WithLimit
	}

	query := fmt.Sprintf(listTargetsTemplate, permissionWhereClause, limit)
	if opts.WithStartPageAfterItem != nil {
		query = fmt.Sprintf(listTargetsPageTemplate, permissionWhereClause, limit)
		args = append(args,
			sql.Named("last_item_create_time", opts.WithStartPageAfterItem.GetCreateTime()),
			sql.Named("last_item_id", opts.WithStartPageAfterItem.GetPublicId()),
		)
	}

	return r.queryTargets(ctx, query, args, limit)
}

// listTargetsRefresh lists targets based on the data in the WithPermissions option
// provided to the Repository constructor. If no permissions are available, this function
// is a no-op.
// Supported options:
//   - WithLimit which overrides the limit set in the Repository object
//   - WithStartPageAfterItem which sets where to start listing from
func (r *Repository) listTargetsRefresh(ctx context.Context, updatedAfter time.Time, opt ...Option) ([]Target, time.Time, error) {
	const op = "target.(Repository).listTargetsRefresh"

	if updatedAfter.IsZero() {
		return nil, time.Time{}, errors.New(ctx, errors.InvalidParameter, op, "missing updated after time")
	}
	if len(r.permissions) == 0 {
		return []Target{}, time.Time{}, nil
	}
	where, args := r.listPermissionWhereClauses()
	permissionWhereClause := "(" + strings.Join(where, " or ") + ")"

	opts := GetOpts(opt...)
	limit := r.defaultLimit
	if opts.WithLimit != 0 {
		limit = opts.WithLimit
	}

	query := fmt.Sprintf(refreshTargetsTemplate, permissionWhereClause, limit)
	args = append(args,
		sql.Named("updated_after_time", timestamp.New(updatedAfter)),
	)
	if opts.WithStartPageAfterItem != nil {
		query = fmt.Sprintf(refreshTargetsPageTemplate, permissionWhereClause, limit)
		args = append(args,
			sql.Named("last_item_update_time", opts.WithStartPageAfterItem.GetUpdateTime()),
			sql.Named("last_item_id", opts.WithStartPageAfterItem.GetPublicId()),
		)
	}

	return r.queryTargets(ctx, query, args, limit)
}

func (r *Repository) queryTargets(ctx context.Context, query string, args []any, limit int) ([]Target, time.Time, error) {
	const op = "target.(Repository).queryTargets"

	var targets []Target
	var transactionTimestamp time.Time
	if _, err := r.writer.DoTx(ctx, db.StdRetryCnt, db.ExpBackoff{}, func(r db.Reader, w db.Writer) error {
		rows, err := r.Query(ctx, query, args)
		if err != nil {
			return err
		}
		defer rows.Close()
		var foundTargets []*targetView
		for rows.Next() {
			if err := r.ScanRows(ctx, rows, &foundTargets); err != nil {
				return err
			}
		}
		if err := rows.Err(); err != nil {
			return err
		}
		var targetIds []string
		for _, t := range foundTargets {
			targetIds = append(targetIds, t.GetPublicId())
		}

		var foundAddresses []*Address
		if err := r.SearchWhere(ctx,
			&foundAddresses,
			"target_id in (?)",
			[]any{targetIds},
			db.WithLimit(limit),
		); err != nil {
			return err
		}
		addresses := make(map[string]string)
		for _, addr := range foundAddresses {
			addresses[addr.TargetId()] = addr.Address()
		}

		for _, t := range foundTargets {
			var address string
			if v, ok := addresses[t.GetPublicId()]; ok {
				address = v
			}
			subtype, err := t.targetSubtype(ctx, address)
			if errors.Is(err, errTargetSubtypeNotFound) {
				// In cases where we have mixed target types and the controller
				// doesn't support all of them, we want to ignore if we can't find
				// the target subtype and continue listing the others we do support.
				continue
			}
			if err != nil {
				return err
			}
			targets = append(targets, subtype)
		}
		transactionTimestamp, err = r.Now(ctx)
		return err
	}); err != nil {
		return nil, time.Time{}, errors.Wrap(ctx, err, op)
	}

	return targets, transactionTimestamp, nil
}

func (r *Repository) listPermissionWhereClauses() ([]string, []any) {
	var where []string
	var args []any

	inClauseCnt := 0
	for _, p := range r.permissions {
		if p.Action != action.List {
			continue
		}
		inClauseCnt++

		var clauses []string
		clauses = append(clauses, fmt.Sprintf("project_id = @project_id_%d", inClauseCnt))
		args = append(args, sql.Named(fmt.Sprintf("project_id_%d", inClauseCnt), p.GrantScopeId))

		if len(p.ResourceIds) > 0 && !p.All {
			clauses = append(clauses, fmt.Sprintf("public_id = any(@public_id_%d)", inClauseCnt))
			args = append(args, sql.Named(fmt.Sprintf("public_id_%d", inClauseCnt), "{"+strings.Join(p.ResourceIds, ",")+"}"))
		}

		where = append(where, fmt.Sprintf("(%s)", strings.Join(clauses, " and ")))
	}

	return where, args
}

// listDeletedIds lists the public IDs of any targets deleted since the timestamp provided,
// and the timestamp of the transaction within which the targets were listed.
func (r *Repository) listDeletedIds(ctx context.Context, since time.Time) ([]string, time.Time, error) {
	const op = "target.(Repository).listDeletedIds"
	var deleteTargets []*deletedTarget
	var transactionTimestamp time.Time

	if _, err := r.writer.DoTx(ctx, db.StdRetryCnt, db.ExpBackoff{}, func(r db.Reader, _ db.Writer) error {
		if err := r.SearchWhere(ctx, &deleteTargets, "delete_time >= ?", []any{since}); err != nil {
			return errors.Wrap(ctx, err, op, errors.WithMsg("failed to query deleted targets"))
		}
		var err error
		transactionTimestamp, err = r.Now(ctx)
		if err != nil {
			return errors.Wrap(ctx, err, op, errors.WithMsg("failed to get transaction timestamp"))
		}
		return nil
	}); err != nil {
		return nil, time.Time{}, err
	}
	var targetIds []string
	for _, t := range deleteTargets {
		targetIds = append(targetIds, t.PublicId)
	}
	return targetIds, transactionTimestamp, nil
}

// estimatedCount returns an estimate of the total number of items across all targets.
func (r *Repository) estimatedCount(ctx context.Context) (int, error) {
	const op = "target.(Repository).estimatedCount"
	rows, err := r.reader.Query(ctx, estimateCountTargets, nil)
	if err != nil {
		return 0, errors.Wrap(ctx, err, op, errors.WithMsg("failed to query total targets"))
	}
	var count int
	for rows.Next() {
		if err := r.reader.ScanRows(ctx, rows, &count); err != nil {
			return 0, errors.Wrap(ctx, err, op, errors.WithMsg("failed to query total targets"))
		}
	}
	if err := rows.Err(); err != nil {
		return 0, errors.Wrap(ctx, err, op, errors.WithMsg("failed to query total targets"))
	}
	return count, nil
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
	var deleteResource any
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

// CreateTarget inserts into the repository and returns the new Target with
// its list of host sets and credential libraries.
// WithPublicId and WithAliases are supported options.
func (r *Repository) CreateTarget(ctx context.Context, target Target, opt ...Option) (Target, error) {
	const op = "target.(Repository).CreateTarget"
	opts := GetOpts(opt...)
	if target == nil {
		return nil, errors.New(ctx, errors.InvalidParameter, op, "missing target")
	}

	targetType := target.GetType()
	vet, ok := subtypeRegistry.vetFunc(targetType)
	if !ok {
		return nil, errors.New(ctx, errors.InvalidParameter, op, fmt.Sprintf("unsupported target type %s", targetType))
	}
	if err := vet(ctx, target); err != nil {
		return nil, err
	}
	if target.GetProjectId() == "" {
		return nil, errors.New(ctx, errors.InvalidParameter, op, "missing project id")
	}
	if target.GetName() == "" {
		return nil, errors.New(ctx, errors.InvalidParameter, op, "missing name")
	}
	if target.GetPublicId() != "" {
		return nil, errors.New(ctx, errors.InvalidParameter, op, "public id not empty")
	}

	t := target.Clone()

	if opts.WithPublicId != "" {
		if err := t.SetPublicId(ctx, opts.WithPublicId); err != nil {
			return nil, err
		}
	} else {
		prefix, ok := subtypeRegistry.idPrefix(targetType)
		if !ok {
			return nil, errors.New(ctx, errors.InvalidParameter, op, fmt.Sprintf("unsupported target type %s", targetType))
		}
		id, err := db.NewPublicId(ctx, prefix)
		if err != nil {
			return nil, errors.Wrap(ctx, err, op)
		}
		t.SetPublicId(ctx, id)
	}

	var address *Address
	var err error
	if t.GetAddress() != "" {
		host, err := util.ParseAddress(ctx, t.GetAddress())
		if err != nil {
			return nil, errors.Wrap(ctx, err, op, errors.WithCode(errors.InvalidAddress), errors.WithMsg("invalid address"))
		}
		t.SetAddress(host)
		address, err = NewAddress(ctx, t.GetPublicId(), t.GetAddress())
		if err != nil {
			return nil, errors.Wrap(ctx, err, op)
		}
	}

	serverCert := t.GetProxyServerCertificate()

	oplogWrapper, err := r.kms.GetWrapper(ctx, target.GetProjectId(), kms.KeyPurposeOplog)
	if err != nil {
		return nil, errors.Wrap(ctx, err, op, errors.WithMsg("unable to get oplog wrapper"))
	}

	databaseWrapper, err := r.kms.GetWrapper(ctx, target.GetProjectId(), kms.KeyPurposeDatabase)
	if err != nil {
		return nil, errors.Wrap(ctx, err, op, errors.WithMsg("unable to get database wrapper"))
	}

	metadata := t.Oplog(oplog.OpType_OP_TYPE_CREATE)
	var createdAliases []*talias.Alias
	var returnedTarget Target
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

			if address != nil {
				var targetAddressOplogMsg oplog.Message
				if err := w.Create(ctx, address, db.NewOplogMsg(&targetAddressOplogMsg)); err != nil {
					return errors.Wrap(ctx, err, op, errors.WithMsg("unable to create target address"))
				}
				msgs = append(msgs, &targetAddressOplogMsg)
			}

			createdAliases = make([]*talias.Alias, 0, len(opts.withAliases))
			for _, a := range opts.withAliases {
				a = a.Clone()
				aliasId, err := db.NewPublicId(ctx, globals.TargetAliasPrefix)
				if err != nil {
					return errors.Wrap(ctx, err, op)
				}
				a.PublicId = aliasId

				a.DestinationId = t.GetPublicId()
				var targetAliasOplogMsg oplog.Message
				if err := w.Create(ctx, a, db.NewOplogMsg(&targetAliasOplogMsg)); err != nil {
					return errors.Wrap(ctx, err, op, errors.WithMsg("unable to create target alias"))
				}
				createdAliases = append(createdAliases, a)
				msgs = append(msgs, &targetAliasOplogMsg)
			}

			if serverCert != nil {
				proxyCert := allocTargetProxyCertificate()
				err = proxyCert.fromServerCertificate(ctx, serverCert)
				if err != nil {
					return errors.Wrap(ctx, err, op, errors.WithMsg("unable to convert server certificate to target proxy certificate"))
				}
				proxyCert.TargetId = t.GetPublicId()
				id, err := db.NewPublicId(ctx, globals.ProxyServerCertificatePrefix)
				if err != nil {
					return errors.Wrap(ctx, err, op)
				}
				proxyCert.PublicId = id
				if err := proxyCert.Encrypt(ctx, databaseWrapper); err != nil {
					return errors.Wrap(ctx, err, op, errors.WithMsg("error encrypting target proxy certificate"))
				}

				var targetProxyCertOplogMsg oplog.Message
				if err := w.Create(ctx, proxyCert, db.NewOplogMsg(&targetProxyCertOplogMsg)); err != nil {
					return errors.Wrap(ctx, err, op, errors.WithMsg("unable to create target proxy certificate"))
				}
				msgs = append(msgs, &targetProxyCertOplogMsg)
			}

			if err := w.WriteOplogEntryWith(ctx, oplogWrapper, targetTicket, metadata, msgs); err != nil {
				return errors.Wrap(ctx, err, op, errors.WithMsg("unable to write oplog"))
			}

			return nil
		},
	)
	if err != nil {
		return nil, errors.Wrap(ctx, err, op, errors.WithMsg(fmt.Sprintf("failed for %s target id", t.GetPublicId())))
	}
	returnedTarget.SetAliases(createdAliases)
	return returnedTarget, nil
}

// UpdateTarget will update a target in the repository and return the written
// target. fieldMaskPaths provides field_mask.proto paths for fields that should
// be updated.  Fields will be set to NULL if the field is a zero value and
// included in fieldMask. Name, Description, and WorkerFilter are the only
// updatable fields. If no updatable fields are included in the fieldMaskPaths,
// then an error is returned.
func (r *Repository) UpdateTarget(ctx context.Context, target Target, version uint32, fieldMaskPaths []string, _ ...Option) (Target, int, error) {
	const op = "target.(Repository).UpdateTarget"
	if target == nil {
		return nil, db.NoRowsAffected, errors.New(ctx, errors.InvalidParameter, op, "missing target")
	}
	if target.GetPublicId() == "" {
		return nil, db.NoRowsAffected, errors.New(ctx, errors.InvalidParameter, op, "missing target public id")
	}
	if target.GetProjectId() == "" {
		return nil, db.NoRowsAffected, errors.New(ctx, errors.InvalidParameter, op, "missing project id")
	}
	if version == 0 {
		return nil, db.NoRowsAffected, errors.New(ctx, errors.InvalidParameter, op, "missing version")
	}
	vet, ok := subtypeRegistry.vetForUpdateFunc(target.GetType())
	if !ok {
		return nil, db.NoRowsAffected, errors.New(ctx, errors.InvalidParameter, op, fmt.Sprintf("unsupported target type %s", target.GetType()))
	}
	if err := vet(ctx, target, fieldMaskPaths); err != nil {
		return nil, db.NoRowsAffected, err
	}

	for _, f := range fieldMaskPaths {
		switch {
		case strings.EqualFold("name", f):
		case strings.EqualFold("description", f):
		case strings.EqualFold("defaultport", f):
		case strings.EqualFold("defaultclientport", f):
		case strings.EqualFold("sessionmaxseconds", f):
		case strings.EqualFold("sessionconnectionlimit", f):
		case strings.EqualFold("workerfilter", f):
		case strings.EqualFold("egressworkerfilter", f):
		case strings.EqualFold("ingressworkerfilter", f):
		case strings.EqualFold("address", f):
		case strings.EqualFold("storagebucketid", f):
		case strings.EqualFold("enablesessionrecording", f):
		default:
			return nil, db.NoRowsAffected, errors.New(ctx, errors.InvalidFieldMask, op, fmt.Sprintf("invalid field mask: %s", f))
		}
	}

	var dbMask, nullFields []string
	dbMask, nullFields = dbw.BuildUpdatePaths(
		map[string]any{
			"Name":                   target.GetName(),
			"Description":            target.GetDescription(),
			"DefaultPort":            target.GetDefaultPort(),
			"DefaultClientPort":      target.GetDefaultClientPort(),
			"SessionMaxSeconds":      target.GetSessionMaxSeconds(),
			"SessionConnectionLimit": target.GetSessionConnectionLimit(),
			"WorkerFilter":           target.GetWorkerFilter(),
			"EgressWorkerFilter":     target.GetEgressWorkerFilter(),
			"IngressWorkerFilter":    target.GetIngressWorkerFilter(),
			"Address":                target.GetAddress(),
			"StorageBucketId":        target.GetStorageBucketId(),
			"EnableSessionRecording": target.GetEnableSessionRecording(),
		},
		fieldMaskPaths,
		[]string{"SessionMaxSeconds", "SessionConnectionLimit", "EnableSessionRecording"},
	)
	if len(dbMask) == 0 && len(nullFields) == 0 {
		return nil, db.NoRowsAffected, errors.New(ctx, errors.EmptyFieldMask, op, "empty field mask")
	}

	// The Address field is not a part of the target schema in the database. It
	// is a part of a different table called target_address, which is why the
	// Address field must be filtered out of the dbMask & nullFields slices.
	var addressEndpoint string
	var updateAddress, deleteAddress bool
	var filteredDbMask, filteredNullFields []string
	for _, f := range dbMask {
		switch {
		case strings.EqualFold("Address", f):
			updateAddress = true
			address, err := util.ParseAddress(ctx, target.GetAddress())
			if err != nil {
				return nil, db.NoRowsAffected, errors.Wrap(ctx, err, op, errors.WithCode(errors.InvalidAddress), errors.WithMsg("invalid address"))
			}
			target.SetAddress(address)
			addressEndpoint = target.GetAddress()
		default:
			filteredDbMask = append(filteredDbMask, f)
		}
	}
	for _, f := range nullFields {
		switch {
		case strings.EqualFold("Address", f):
			deleteAddress = true
		default:
			filteredNullFields = append(filteredNullFields, f)
		}
	}

	// If the Address field is the only present change, then we must still
	// update the target's version because a target address is a child object
	// of the target.
	if (len(filteredDbMask) == 0 && len(filteredNullFields) == 0) && (updateAddress || deleteAddress) {
		target.SetVersion(version + 1)
		filteredDbMask = append(filteredDbMask, "Version")
	}

	oplogWrapper, err := r.kms.GetWrapper(ctx, target.GetProjectId(), kms.KeyPurposeOplog)
	if err != nil {
		return nil, db.NoRowsAffected, errors.Wrap(ctx, err, op, errors.WithMsg("unable to get oplog wrapper"))
	}

	var rowsUpdated int
	var returnedTarget Target
	var hostSources []HostSource
	var credSources []CredentialSource
	_, err = r.writer.DoTx(
		ctx,
		db.StdRetryCnt,
		db.ExpBackoff{},
		func(read db.Reader, w db.Writer) error {
			t := target.Clone()
			rowsUpdated, err = w.Update(ctx, t, filteredDbMask, filteredNullFields,
				db.WithOplog(oplogWrapper, t.Oplog(oplog.OpType_OP_TYPE_UPDATE)),
				db.WithVersion(&version),
			)
			if err != nil {
				return errors.Wrap(ctx, err, op)
			}
			if rowsUpdated > 1 {
				return errors.New(ctx, errors.MultipleRecords, op, "more than 1 target resource would have been updated")
			}

			if hostSources, err = fetchHostSources(ctx, read, t.GetPublicId()); err != nil {
				return errors.Wrap(ctx, err, op)
			}
			if credSources, err = fetchCredentialSources(ctx, read, t.GetPublicId()); err != nil {
				return errors.Wrap(ctx, err, op)
			}

			var address *Address
			switch {
			case updateAddress:
				if len(hostSources) > 0 {
					return errors.New(ctx, errors.Conflict, op, "unable to set address because one or more host sources is assigned to the given target")
				}
				address, err = NewAddress(ctx, t.GetPublicId(), addressEndpoint)
				if err != nil {
					return errors.Wrap(ctx, err, op)
				}
				if err := w.Create(ctx, address,
					db.WithOplog(oplogWrapper, address.oplog(oplog.OpType_OP_TYPE_UPDATE)),
					db.WithOnConflict(&db.OnConflict{
						Target: db.Columns{"target_id"},
						Action: db.UpdateAll(true),
					})); err != nil {
					return errors.Wrap(ctx, err, op, errors.WithMsg("unable to create target address"))
				}
			case deleteAddress:
				var err error
				address = allocTargetAddress()
				address.TargetAddress.TargetId = t.GetPublicId()
				rowsDeleted, err := w.Delete(ctx, address, db.WithOplog(oplogWrapper, address.oplog(oplog.OpType_OP_TYPE_DELETE)))
				if err != nil {
					return errors.Wrap(ctx, err, op, errors.WithMsg("unable to delete target address"))
				}
				if rowsDeleted > 1 {
					return errors.New(ctx, errors.MultipleRecords, op, "more than 1 target resource would have been deleted")
				}
				// If the only update was deleting an address, consider this as one "row" being updated.
				if rowsUpdated == 0 && rowsDeleted == 1 {
					rowsUpdated = 1
				}
			default:
				address, err = fetchAddress(ctx, read, t.GetPublicId())
				if err != nil && !errors.IsNotFoundError(err) {
					return errors.Wrap(ctx, err, op, errors.WithMsg("unable to fetch target address"))
				}
			}
			if address != nil {
				t.SetAddress(address.GetAddress())
			}
			returnedTarget = t.Clone()

			return nil
		},
	)
	if err != nil {
		if errors.IsUniqueError(err) {
			return nil, db.NoRowsAffected, errors.New(ctx, errors.NotUnique, op, fmt.Sprintf("target %s already exists in project %s", target.GetName(), target.GetProjectId()))
		}
		return nil, db.NoRowsAffected, errors.Wrap(ctx, err, op, errors.WithMsg(fmt.Sprintf("failed for %s", target.GetPublicId())))
	}

	returnedTarget.SetHostSources(hostSources)
	returnedTarget.SetCredentialSources(credSources)

	return returnedTarget, rowsUpdated, nil
}
