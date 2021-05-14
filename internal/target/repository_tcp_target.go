package target

import (
	"context"
	"fmt"
	"strings"

	"github.com/hashicorp/boundary/internal/db"
	dbcommon "github.com/hashicorp/boundary/internal/db/common"
	"github.com/hashicorp/boundary/internal/errors"
	"github.com/hashicorp/boundary/internal/kms"
	"github.com/hashicorp/boundary/internal/oplog"
)

// CreateTcpTarget inserts into the repository and returns the new Target with
// its list of host sets and credential libraries.
// WithHostSets and WithCredentialLibraries are the only supported option.
func (r *Repository) CreateTcpTarget(ctx context.Context, target *TcpTarget, opt ...Option) (Target, []*TargetSet, []*TargetLibrary, error) {
	const op = "target.(Repository).CreateTcpTarget"
	opts := getOpts(opt...)
	if target == nil {
		return nil, nil, nil, errors.New(errors.InvalidParameter, op, "missing target")
	}
	if target.TcpTarget == nil {
		return nil, nil, nil, errors.New(errors.InvalidParameter, op, "missing target store")
	}
	if target.ScopeId == "" {
		return nil, nil, nil, errors.New(errors.InvalidParameter, op, "missing scope id")
	}
	if target.Name == "" {
		return nil, nil, nil, errors.New(errors.InvalidParameter, op, "missing name")
	}
	if target.PublicId != "" {
		return nil, nil, nil, errors.New(errors.InvalidParameter, op, "public id not empty")
	}

	t := target.Clone().(*TcpTarget)

	if opts.withPublicId != "" {
		if !strings.HasPrefix(opts.withPublicId, TcpTargetPrefix+"_") {
			return nil, nil, nil, errors.New(errors.InvalidParameter, op, fmt.Sprintf("passed-in public ID %q has wrong prefix, should be %q", opts.withPublicId, TcpTargetPrefix))
		}
		t.PublicId = opts.withPublicId
	} else {
		id, err := newTcpTargetId()
		if err != nil {
			return nil, nil, nil, errors.Wrap(err, op)
		}
		t.PublicId = id
	}

	oplogWrapper, err := r.kms.GetWrapper(ctx, target.ScopeId, kms.KeyPurposeOplog)
	if err != nil {
		return nil, nil, nil, errors.Wrap(err, op, errors.WithMsg("unable to get oplog wrapper"))
	}

	newHostSets := make([]interface{}, 0, len(opts.withHostSets))
	for _, hsId := range opts.withHostSets {
		hostSet, err := NewTargetHostSet(t.PublicId, hsId)
		if err != nil {
			return nil, nil, nil, errors.Wrap(err, op, errors.WithMsg("unable to create in memory target host set"))
		}
		newHostSets = append(newHostSets, hostSet)
	}

	newCredLibs := make([]interface{}, 0, len(opts.withCredentialLibraries))
	for _, clId := range opts.withCredentialLibraries {
		credLib, err := NewCredentialLibrary(t.PublicId, clId)
		if err != nil {
			return nil, nil, nil, errors.Wrap(err, op, errors.WithMsg("unable to create in memory target credential library"))
		}
		newCredLibs = append(newCredLibs, credLib)
	}

	metadata := t.oplog(oplog.OpType_OP_TYPE_CREATE)
	var returnedTarget interface{}
	var returnedHostSet []*TargetSet
	var returnedCredLibs []*TargetLibrary
	_, err = r.writer.DoTx(
		ctx,
		db.StdRetryCnt,
		db.ExpBackoff{},
		func(read db.Reader, w db.Writer) error {
			targetTicket, err := w.GetTicket(t)
			if err != nil {
				return errors.Wrap(err, op, errors.WithMsg("unable to get ticket"))
			}
			msgs := make([]*oplog.Message, 0, 2)
			var targetOplogMsg oplog.Message
			returnedTarget = t.Clone()
			if err := w.Create(ctx, returnedTarget, db.NewOplogMsg(&targetOplogMsg)); err != nil {
				return errors.Wrap(err, op, errors.WithMsg("unable to create target"))
			}
			msgs = append(msgs, &targetOplogMsg)
			if len(newHostSets) > 0 {
				hostSetOplogMsgs := make([]*oplog.Message, 0, len(newHostSets))
				if err := w.CreateItems(ctx, newHostSets, db.NewOplogMsgs(&hostSetOplogMsgs)); err != nil {
					return errors.Wrap(err, op, errors.WithMsg("unable to add host sets"))
				}
				if returnedHostSet, err = fetchSets(ctx, read, t.PublicId); err != nil {
					return errors.Wrap(err, op, errors.WithMsg("unable to read host sets"))
				}
				msgs = append(msgs, hostSetOplogMsgs...)
			}
			if len(newCredLibs) > 0 {
				credLibOplogMsgs := make([]*oplog.Message, 0, len(newCredLibs))
				if err := w.CreateItems(ctx, newCredLibs, db.NewOplogMsgs(&credLibOplogMsgs)); err != nil {
					return errors.Wrap(err, op, errors.WithMsg("unable to add credential libraries"))
				}
				if returnedCredLibs, err = fetchLibraries(ctx, read, t.PublicId); err != nil {
					return errors.Wrap(err, op, errors.WithMsg("unable to read host sets"))
				}
				msgs = append(msgs, credLibOplogMsgs...)
			}
			if err := w.WriteOplogEntryWith(ctx, oplogWrapper, targetTicket, metadata, msgs); err != nil {
				return errors.Wrap(err, op, errors.WithMsg("unable to write oplog"))
			}

			return nil
		},
	)
	if err != nil {
		return nil, nil, nil, errors.Wrap(err, op, errors.WithMsg(fmt.Sprintf("failed for %s target id", t.PublicId)))
	}
	return returnedTarget.(*TcpTarget), returnedHostSet, returnedCredLibs, nil
}

// UpdateTcpTarget will update a target in the repository and return the written
// target. fieldMaskPaths provides field_mask.proto paths for fields that should
// be updated.  Fields will be set to NULL if the field is a zero value and
// included in fieldMask. Name, Description, and WorkerFilter are the only
// updatable fields. If no updatable fields are included in the fieldMaskPaths,
// then an error is returned.
func (r *Repository) UpdateTcpTarget(ctx context.Context, target *TcpTarget, version uint32, fieldMaskPaths []string, _ ...Option) (Target, []*TargetSet, []*TargetLibrary, int, error) {
	const op = "target.(Repository).UpdateTcpTarget"
	if target == nil {
		return nil, nil, nil, db.NoRowsAffected, errors.New(errors.InvalidParameter, op, "missing target")
	}
	if target.TcpTarget == nil {
		return nil, nil, nil, db.NoRowsAffected, errors.New(errors.InvalidParameter, op, "missing target store")
	}
	if target.PublicId == "" {
		return nil, nil, nil, db.NoRowsAffected, errors.New(errors.InvalidParameter, op, "missing target public id")
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
			return nil, nil, nil, db.NoRowsAffected, errors.New(errors.InvalidFieldMask, op, fmt.Sprintf("invalid field mask: %s", f))
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
			"WorkerFilter":           target.WorkerFilter,
		},
		fieldMaskPaths,
		[]string{"SessionMaxSeconds", "SessionConnectionLimit"},
	)
	if len(dbMask) == 0 && len(nullFields) == 0 {
		return nil, nil, nil, db.NoRowsAffected, errors.New(errors.EmptyFieldMask, op, "empty field mask")
	}
	var returnedTarget Target
	var rowsUpdated int
	var targetSets []*TargetSet
	var credLibs []*TargetLibrary
	_, err := r.writer.DoTx(
		ctx,
		db.StdRetryCnt,
		db.ExpBackoff{},
		func(read db.Reader, w db.Writer) error {
			var err error
			t := target.Clone().(*TcpTarget)
			returnedTarget, targetSets, credLibs, rowsUpdated, err = r.update(ctx, t, version, dbMask, nullFields)
			if err != nil {
				return errors.Wrap(err, op)
			}
			return nil
		},
	)
	if err != nil {
		if errors.IsUniqueError(err) {
			return nil, nil, nil, db.NoRowsAffected, errors.New(errors.NotUnique, op, fmt.Sprintf("target %s already exists in scope %s", target.Name, target.ScopeId))
		}
		return nil, nil, nil, db.NoRowsAffected, errors.Wrap(err, op, errors.WithMsg(fmt.Sprintf("failed for %s", target.PublicId)))
	}
	return returnedTarget.(Target), targetSets, credLibs, rowsUpdated, nil
}
