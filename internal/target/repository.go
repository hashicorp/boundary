package target

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/hashicorp/boundary/internal/db"
	"github.com/hashicorp/boundary/internal/kms"
	"github.com/hashicorp/boundary/internal/oplog"
)

var (
	ErrMetadataScopeNotFound = errors.New("scope not found for metadata")
)

// Clonable provides a cloning interface
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
	if r == nil {
		return nil, errors.New("error creating db repository with nil reader")
	}
	if w == nil {
		return nil, errors.New("error creating db repository with nil writer")
	}
	if kms == nil {
		return nil, errors.New("error creating db repository with nil kms")
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
// with its host set ids.  If the target is not found, it will return nil, nil, nil.
// No options are currently supported.
func (r *Repository) LookupTarget(ctx context.Context, publicId string, opt ...Option) (Target, []string, error) {
	if publicId == "" {
		return nil, nil, fmt.Errorf("lookup target: missing private id: %w", db.ErrNilParameter)
	}
	target := allocTargetView()
	target.PublicId = publicId
	var hostSets []string
	_, err := r.writer.DoTx(
		ctx,
		db.StdRetryCnt,
		db.ExpBackoff{},
		func(read db.Reader, w db.Writer) error {
			if err := read.LookupById(ctx, &target); err != nil {
				return fmt.Errorf("lookup target: failed %w for %s", err, publicId)
			}
			var err error
			if hostSets, err = fetchHostSets(ctx, read, target.PublicId); err != nil {
				return err
			}
			return nil
		},
	)
	if err != nil {
		return nil, nil, fmt.Errorf("lookup target: %w", err)
	}
	subType, err := target.TargetSubType()
	if err != nil {
		return nil, nil, fmt.Errorf("lookup target: %w", err)
	}
	return subType, hostSets, nil
}

func fetchHostSets(ctx context.Context, r db.Reader, targetId string) ([]string, error) {
	var hostSets []*TargetHostSet
	if err := r.SearchWhere(ctx, &hostSets, "target_id = ?", []interface{}{targetId}); err != nil {
		return nil, fmt.Errorf("fetch host sets: %w", err)
	}
	if len(hostSets) == 0 {
		return nil, nil
	}
	hs := make([]string, 0, len(hostSets))
	for _, h := range hostSets {
		hs = append(hs, h.HostSetId)
	}
	return hs, nil
}

// ListTargets in targets in a scope.  Supports the WithScopeId, WithLimit, WithTargetType options.
func (r *Repository) ListTargets(ctx context.Context, opt ...Option) ([]Target, error) {
	opts := getOpts(opt...)
	if opts.withScopeId == "" && opts.withUserId == "" {
		return nil, fmt.Errorf("list targets: must specify either a scope id or user id: %w", db.ErrInvalidParameter)
	}
	// TODO (jimlambrt) - implement WithUserId() optional filtering.
	var where []string
	var args []interface{}
	if opts.withScopeId != "" {
		where, args = append(where, "scope_id = ?"), append(args, opts.withScopeId)
	}
	if opts.withTargetType != nil {
		where, args = append(where, "type = ?"), append(args, opts.withTargetType.String())
	}

	var foundTargets []*targetView
	err := r.list(ctx, &foundTargets, strings.Join(where, " and "), args, opt...)
	if err != nil {
		return nil, fmt.Errorf("list targets: %w", err)
	}

	targets := make([]Target, 0, len(foundTargets))

	for _, t := range foundTargets {
		subType, err := t.TargetSubType()
		if err != nil {
			return nil, fmt.Errorf("list targets: %w", err)
		}
		targets = append(targets, subType)
	}
	return targets, nil
}

// list will return a listing of resources and honor the WithLimit option or the
// repo defaultLimit
func (r *Repository) list(ctx context.Context, resources interface{}, where string, args []interface{}, opt ...Option) error {
	opts := getOpts(opt...)
	limit := r.defaultLimit
	var dbOpts []db.Option
	if opts.withLimit != 0 {
		// non-zero signals an override of the default limit for the repo.
		limit = opts.withLimit
	}
	dbOpts = append(dbOpts, db.WithLimit(limit))
	return r.reader.SearchWhere(ctx, resources, where, args, dbOpts...)
}

// DeleteTarget will delete a target from the repository.
func (r *Repository) DeleteTarget(ctx context.Context, publicId string, opt ...Option) (int, error) {
	if publicId == "" {
		return db.NoRowsAffected, fmt.Errorf("delete target: missing public id %w", db.ErrNilParameter)
	}
	t := allocTargetView()
	t.PublicId = publicId
	if err := r.reader.LookupByPublicId(ctx, &t); err != nil {
		return db.NoRowsAffected, fmt.Errorf("delete target: failed %w for %s", err, publicId)
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
		return db.NoRowsAffected, fmt.Errorf("delete target: %s is an unsupported target type %s", publicId, t.Type)
	}

	oplogWrapper, err := r.kms.GetWrapper(ctx, t.ScopeId, kms.KeyPurposeOplog)
	if err != nil {
		return db.NoRowsAffected, fmt.Errorf("delete target: unable to get oplog wrapper: %w", err)
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
			if err == nil && rowsDeleted > 1 {
				// return err, which will result in a rollback of the delete
				return errors.New("error more than 1 target would have been deleted ")
			}
			return err
		},
	)
	return rowsDeleted, err
}

// AddTargeHostSets provides the ability to add host sets (hostSetIds) to a
// target (targetId).  The target's current db version must match the
// targetVersion or an error will be returned.   The target and a list of
// current host set ids will be returned on success. Zero is not a valid value
// for the WithVersion option and will return an error.
func (r *Repository) AddTargeHostSets(ctx context.Context, targetId string, targetVersion uint32, hostSetIds []string, opt ...Option) (Target, []string, error) {
	if targetId == "" {
		return nil, nil, fmt.Errorf("add target host sets: missing target id: %w", db.ErrInvalidParameter)
	}
	if targetVersion == 0 {
		return nil, nil, fmt.Errorf("add target host sets: version cannot be zero: %w", db.ErrInvalidParameter)
	}
	if len(hostSetIds) == 0 {
		return nil, nil, fmt.Errorf("add target host sets: missing host set ids: %w", db.ErrInvalidParameter)
	}
	newHostSets := make([]interface{}, 0, len(hostSetIds))
	for _, id := range hostSetIds {
		ths, err := NewTargetHostSet(targetId, id)
		if err != nil {
			return nil, nil, fmt.Errorf("add target host sets: unable to create in memory target host set: %w", err)
		}
		newHostSets = append(newHostSets, ths)
	}
	t := allocTargetView()
	t.PublicId = targetId
	if err := r.reader.LookupByPublicId(ctx, &t); err != nil {
		return nil, nil, fmt.Errorf("add target host sets: failed %w for %s", err, targetId)
	}
	var metadata oplog.Metadata
	var target interface{}
	switch t.Type {
	case TcpTargetType.String():
		tcpT := allocTcpTarget()
		tcpT.PublicId = t.PublicId
		tcpT.Version = targetVersion + 1
		target = &tcpT
		metadata = tcpT.oplog(oplog.OpType_OP_TYPE_CREATE)
	default:
		return nil, nil, fmt.Errorf("delete target host sets: %s is an unsupported target type %s", t.PublicId, t.Type)
	}
	oplogWrapper, err := r.kms.GetWrapper(ctx, t.GetScopeId(), kms.KeyPurposeOplog)
	if err != nil {
		return nil, nil, fmt.Errorf("add target host sets: unable to get oplog wrapper: %w", err)
	}
	var currentHostSets []string
	var updatedTarget interface{}
	_, err = r.writer.DoTx(
		ctx,
		db.StdRetryCnt,
		db.ExpBackoff{},
		func(reader db.Reader, w db.Writer) error {
			msgs := make([]*oplog.Message, 0, 2)
			targetTicket, err := w.GetTicket(target)
			if err != nil {
				return fmt.Errorf("add target host sets: unable to get ticket: %w", err)
			}
			updatedTarget = target.(Cloneable).Clone()
			var targetOplogMsg oplog.Message
			rowsUpdated, err := w.Update(ctx, updatedTarget, []string{"Version"}, nil, db.NewOplogMsg(&targetOplogMsg), db.WithVersion(&targetVersion))
			if err != nil {
				return fmt.Errorf("add target host sets: unable to update role version: %w", err)
			}
			if rowsUpdated != 1 {
				return fmt.Errorf("add target host sets: updated role and %d rows updated", rowsUpdated)
			}
			msgs = append(msgs, &targetOplogMsg)
			if len(newHostSets) > 0 {
				hostSetsOplogMsgs := make([]*oplog.Message, 0, len(newHostSets))
				if err := w.CreateItems(ctx, newHostSets, db.NewOplogMsgs(&hostSetsOplogMsgs)); err != nil {
					return fmt.Errorf("add target host sets: unable to add target host sets: %w", err)
				}
				msgs = append(msgs, hostSetsOplogMsgs...)
			}
			if err := w.WriteOplogEntryWith(ctx, oplogWrapper, targetTicket, metadata, msgs); err != nil {
				return fmt.Errorf("add target host sets: unable to write oplog: %w", err)
			}
			currentHostSets, err = fetchHostSets(ctx, reader, targetId)
			if err != nil {
				return fmt.Errorf("add target host sets: unable to retrieve current host sets after adds: %w", err)
			}
			return nil
		},
	)
	if err != nil {
		return nil, nil, fmt.Errorf("add target host sets: error creating roles: %w", err)
	}
	return updatedTarget.(Target), currentHostSets, nil
}
