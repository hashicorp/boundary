package target

import (
	"context"
	"fmt"
	"strings"

	dbcommon "github.com/hashicorp/boundary/internal/db/common"

	"github.com/hashicorp/boundary/internal/db"
	"github.com/hashicorp/boundary/internal/kms"
	"github.com/hashicorp/boundary/internal/oplog"
)

// CreateTcpTarget inserts into the repository and returns the new Target with
// its list of host sets.  WithHostSets is currently the only supported option.
func (r *Repository) CreateTcpTarget(ctx context.Context, target *TcpTarget, opt ...Option) (Target, []*TargetSet, error) {
	opts := getOpts(opt...)
	if target == nil {
		return nil, nil, fmt.Errorf("create tcp target: missing target: %w", db.ErrInvalidParameter)
	}
	if target.TcpTarget == nil {
		return nil, nil, fmt.Errorf("create tcp target: missing target store: %w", db.ErrInvalidParameter)
	}
	if target.ScopeId == "" {
		return nil, nil, fmt.Errorf("create tcp target: scope id empty: %w", db.ErrInvalidParameter)
	}
	if target.Name == "" {
		return nil, nil, fmt.Errorf("create tcp target: name empty: %w", db.ErrInvalidParameter)
	}
	if target.PublicId != "" {
		return nil, nil, fmt.Errorf("create tcp target: public id not empty: %w", db.ErrInvalidParameter)
	}

	t := target.Clone().(*TcpTarget)

	if opts.withPublicId != "" {
		if !strings.HasPrefix(opts.withPublicId, TcpTargetPrefix+"_") {
			return nil, nil, fmt.Errorf("create tcp target: passed-in public ID %q has wrong prefix, should be %q: %w", opts.withPublicId, TcpTargetPrefix, db.ErrInvalidPublicId)
		}
		t.PublicId = opts.withPublicId
	} else {

		id, err := newTcpTargetId()
		if err != nil {
			return nil, nil, fmt.Errorf("create tcp target: %w", err)
		}
		t.PublicId = id
	}

	oplogWrapper, err := r.kms.GetWrapper(ctx, target.ScopeId, kms.KeyPurposeOplog)
	if err != nil {
		return nil, nil, fmt.Errorf("create tcp target: unable to get oplog wrapper: %w", err)
	}

	newHostSets := make([]interface{}, 0, len(opts.withHostSets))
	for _, hsId := range opts.withHostSets {
		hostSet, err := NewTargetHostSet(t.PublicId, hsId)
		if err != nil {
			return nil, nil, fmt.Errorf("create tcp target: unable to create in memory target host set: %w", err)
		}
		newHostSets = append(newHostSets, hostSet)
	}

	metadata := t.oplog(oplog.OpType_OP_TYPE_CREATE)
	var returnedTarget interface{}
	var returnedHostSet []*TargetSet
	_, err = r.writer.DoTx(
		ctx,
		db.StdRetryCnt,
		db.ExpBackoff{},
		func(read db.Reader, w db.Writer) error {
			targetTicket, err := w.GetTicket(t)
			if err != nil {
				return fmt.Errorf("create tcp target: unable to get ticket: %w", err)
			}
			msgs := make([]*oplog.Message, 0, 2)
			var targetOplogMsg oplog.Message
			returnedTarget = t.Clone()
			if err := w.Create(ctx, returnedTarget, db.NewOplogMsg(&targetOplogMsg)); err != nil {
				return err
			}
			msgs = append(msgs, &targetOplogMsg)
			if len(newHostSets) > 0 {
				hostSetOplogMsgs := make([]*oplog.Message, 0, len(newHostSets))
				if err := w.CreateItems(ctx, newHostSets, db.NewOplogMsgs(&hostSetOplogMsgs)); err != nil {
					return fmt.Errorf("create tcp target: unable to add host sets: %w", err)
				}
				if returnedHostSet, err = fetchSets(ctx, read, t.PublicId); err != nil {
					return fmt.Errorf("create tcp target: unable to read host sets: %w", err)
				}
				msgs = append(msgs, hostSetOplogMsgs...)
			}
			if err := w.WriteOplogEntryWith(ctx, oplogWrapper, targetTicket, metadata, msgs); err != nil {
				return fmt.Errorf("create tcp target: unable to write oplog: %w", err)
			}

			return nil
		},
	)
	if err != nil {
		return nil, nil, fmt.Errorf("create tcp target: %w for %s target id id", err, t.PublicId)
	}
	return returnedTarget.(*TcpTarget), returnedHostSet, err
}

// UpdateTcpTarget will update a target in the repository and return the written
// target. fieldMaskPaths provides field_mask.proto paths for fields that should
// be updated.  Fields will be set to NULL if the field is a zero value and
// included in fieldMask. Name and Description are the only updatable fields,
// If no updatable fields are included in the fieldMaskPaths, then an error is
// returned.
func (r *Repository) UpdateTcpTarget(ctx context.Context, target *TcpTarget, version uint32, fieldMaskPaths []string, opt ...Option) (Target, []*TargetSet, int, error) {
	if target == nil {
		return nil, nil, db.NoRowsAffected, fmt.Errorf("update tcp target: missing target %w", db.ErrInvalidParameter)
	}
	if target.TcpTarget == nil {
		return nil, nil, db.NoRowsAffected, fmt.Errorf("update tcp target: missing target store %w", db.ErrInvalidParameter)
	}
	if target.PublicId == "" {
		return nil, nil, db.NoRowsAffected, fmt.Errorf("update tcp target: missing target public id %w", db.ErrInvalidParameter)
	}
	for _, f := range fieldMaskPaths {
		switch {
		case strings.EqualFold("name", f):
		case strings.EqualFold("description", f):
		case strings.EqualFold("defaultport", f):
		case strings.EqualFold("sessionmaxseconds", f):
		case strings.EqualFold("sessionconnectionlimit", f):
		default:
			return nil, nil, db.NoRowsAffected, fmt.Errorf("update tcp target: field: %s: %w", f, db.ErrInvalidFieldMask)
		}
	}
	var dbMask, nullFields []string
	dbMask, nullFields = dbcommon.BuildUpdatePaths(
		map[string]interface{}{
			"Name":                   target.Name,
			"Description":            target.Description,
			"DefaultPort":            target.DefaultPort,
			"SessionMaxSeconds":      target.SessionMaxSeconds,
			"SessionConnectionLimit": target.SessionConnectionLimit,
		},
		fieldMaskPaths,
		[]string{"SessionMaxSeconds", "SessionConnectionLimit"},
	)
	if len(dbMask) == 0 && len(nullFields) == 0 {
		return nil, nil, db.NoRowsAffected, fmt.Errorf("update tcp target: %w", db.ErrEmptyFieldMask)
	}
	var returnedTarget Target
	var rowsUpdated int
	var targetSets []*TargetSet
	_, err := r.writer.DoTx(
		ctx,
		db.StdRetryCnt,
		db.ExpBackoff{},
		func(read db.Reader, w db.Writer) error {
			var err error
			t := target.Clone().(*TcpTarget)
			returnedTarget, targetSets, rowsUpdated, err = r.update(ctx, t, version, dbMask, nullFields)
			if err != nil {
				return err
			}
			return nil
		},
	)
	if err != nil {
		if db.IsUniqueError(err) {
			return nil, nil, db.NoRowsAffected, fmt.Errorf("update tcp target: target %s already exists in scope %s: %w", target.Name, target.ScopeId, db.ErrNotUnique)
		}
		return nil, nil, db.NoRowsAffected, fmt.Errorf("update tcp target: %w for %s", err, target.PublicId)
	}
	return returnedTarget.(Target), targetSets, rowsUpdated, err
}
