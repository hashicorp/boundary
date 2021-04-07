package oidc

import (
	"context"

	"github.com/hashicorp/boundary/internal/db"
	"github.com/hashicorp/boundary/internal/errors"
	"github.com/hashicorp/boundary/internal/kms"
	"github.com/hashicorp/boundary/internal/oplog"
	"github.com/hashicorp/boundary/internal/servers/controller/handlers"
)

// CreateAuthMethod creates am (*AuthMethod) in the repo along with its
// associated embedded optional value objects of SigningAlgs, AudClaims,
// and Certificates and returns the newly created AuthMethod
// (with its PublicId set)
//
// The AuthMethod's public id and version must be empty (zero values).
//
// All options are ignored.
func (r *Repository) CreateAuthMethod(ctx context.Context, am *AuthMethod, opt ...Option) (*AuthMethod, error) {
	const op = "oidc.(Repository).CreateAuthMethod"
	if am == nil {
		return nil, errors.New(errors.InvalidParameter, op, "missing auth method")
	}
	if am.PublicId != "" {
		return nil, errors.New(errors.InvalidParameter, op, "public id must be empty")
	}
	if am.Version != 0 {
		return nil, errors.New(errors.InvalidParameter, op, "version must be empty")
	}
	if err := am.validate(op); err != nil {
		return nil, err // validate properly sets the op to the caller, the code and the msg, so just return it.
	}

	opts := getOpts(opt...)
	am.PublicId = opts.withPublicId
	if am.PublicId == "" {
		id, err := newAuthMethodId()
		if err != nil {
			return nil, errors.Wrap(err, op)
		}
		am.PublicId = id
	} else {
		if !handlers.ValidId(handlers.Id(am.PublicId), AuthMethodPrefix) {
			return nil, errors.New(errors.InvalidParameter, op, "bad custom auth method id")
		}
	}

	vo, err := am.convertValueObjects()
	if err != nil {
		return nil, errors.Wrap(err, op)
	}

	oplogWrapper, err := r.kms.GetWrapper(ctx, am.ScopeId, kms.KeyPurposeOplog)
	if err != nil {
		return nil, errors.Wrap(err, op, errors.WithMsg("unable to get oplog wrapper"))
	}

	databaseWrapper, err := r.kms.GetWrapper(context.Background(), am.ScopeId, kms.KeyPurposeDatabase)
	if err != nil {
		return nil, errors.Wrap(err, op, errors.WithMsg("unable to get database wrapper"))
	}
	if err := am.encrypt(ctx, databaseWrapper); err != nil {
		return nil, errors.Wrap(err, op)
	}

	var returnedAuthMethod *AuthMethod
	_, err = r.writer.DoTx(
		ctx,
		db.StdRetryCnt,
		db.ExpBackoff{},
		func(_ db.Reader, w db.Writer) error {
			msgs := make([]*oplog.Message, 0, 5)
			ticket, err := w.GetTicket(am)
			if err != nil {
				return errors.Wrap(err, op, errors.WithMsg("unable to get ticket"))
			}

			returnedAuthMethod = am.Clone()
			var amOplogMsg oplog.Message
			if err := w.Create(ctx, returnedAuthMethod, db.NewOplogMsg(&amOplogMsg)); err != nil {
				return err
			}
			msgs = append(msgs, &amOplogMsg)

			if len(vo.Algs) > 0 {
				algOplogMsgs := make([]*oplog.Message, 0, len(vo.Algs))
				if err := w.CreateItems(ctx, vo.Algs, db.NewOplogMsgs(&algOplogMsgs)); err != nil {
					return err
				}
				msgs = append(msgs, algOplogMsgs...)
			}
			if len(vo.Auds) > 0 {
				audOplogMsgs := make([]*oplog.Message, 0, len(vo.Auds))
				if err := w.CreateItems(ctx, vo.Auds, db.NewOplogMsgs(&audOplogMsgs)); err != nil {
					return err
				}
				msgs = append(msgs, audOplogMsgs...)
			}
			if len(vo.Certs) > 0 {
				certOplogMsgs := make([]*oplog.Message, 0, len(vo.Certs))
				if err := w.CreateItems(ctx, vo.Certs, db.NewOplogMsgs(&certOplogMsgs)); err != nil {
					return err
				}
				msgs = append(msgs, certOplogMsgs...)
			}

			metadata := am.oplog(oplog.OpType_OP_TYPE_CREATE)
			if err := w.WriteOplogEntryWith(ctx, oplogWrapper, ticket, metadata, msgs); err != nil {
				return errors.Wrap(err, op, errors.WithMsg("unable to write oplog"))
			}
			return nil
		},
	)
	if err != nil {
		return nil, errors.Wrap(err, op)
	}
	return returnedAuthMethod, nil
}
