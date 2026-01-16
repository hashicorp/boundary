// Copyright IBM Corp. 2020, 2025
// SPDX-License-Identifier: BUSL-1.1

package oidc

import (
	"context"
	"strings"

	"github.com/hashicorp/boundary/globals"
	"github.com/hashicorp/boundary/internal/db"
	"github.com/hashicorp/boundary/internal/errors"
	"github.com/hashicorp/boundary/internal/kms"
	"github.com/hashicorp/boundary/internal/oplog"
)

// CreateAuthMethod creates am (*AuthMethod) in the repo along with its
// associated embedded optional value objects of SigningAlgs, AudClaims,
// Prompts, and Certificates and returns the newly created AuthMethod
// (with its PublicId set)
//
// The AuthMethod's public id and version must be empty (zero values).
//
// All options are ignored.
func (r *Repository) CreateAuthMethod(ctx context.Context, am *AuthMethod, opt ...Option) (*AuthMethod, error) {
	const op = "oidc.(Repository).CreateAuthMethod"
	if am == nil {
		return nil, errors.New(ctx, errors.InvalidParameter, op, "missing auth method")
	}
	if am.PublicId != "" {
		return nil, errors.New(ctx, errors.InvalidParameter, op, "public id must be empty")
	}
	if am.Version != 0 {
		return nil, errors.New(ctx, errors.InvalidParameter, op, "version must be empty")
	}
	if err := am.validate(ctx, op); err != nil {
		return nil, err // validate properly sets the op to the caller, the code and the msg, so just return it.
	}

	opts := getOpts(opt...)
	am.PublicId = opts.withPublicId
	if am.PublicId == "" {
		id, err := newAuthMethodId(ctx)
		if err != nil {
			return nil, errors.Wrap(ctx, err, op)
		}
		am.PublicId = id
	} else {
		if !strings.HasPrefix(am.PublicId, globals.OidcAuthMethodPrefix+"_") {
			return nil, errors.New(ctx, errors.InvalidParameter, op, "wrong auth method id prefix")
		}
	}

	vo, err := am.convertValueObjects(ctx)
	if err != nil {
		return nil, errors.Wrap(ctx, err, op)
	}

	oplogWrapper, err := r.kms.GetWrapper(ctx, am.ScopeId, kms.KeyPurposeOplog)
	if err != nil {
		return nil, errors.Wrap(ctx, err, op, errors.WithMsg("unable to get oplog wrapper"))
	}

	databaseWrapper, err := r.kms.GetWrapper(context.Background(), am.ScopeId, kms.KeyPurposeDatabase)
	if err != nil {
		return nil, errors.Wrap(ctx, err, op, errors.WithMsg("unable to get database wrapper"))
	}
	if err := am.encrypt(ctx, databaseWrapper); err != nil {
		return nil, errors.Wrap(ctx, err, op)
	}

	var returnedAuthMethod *AuthMethod
	_, err = r.writer.DoTx(
		ctx,
		db.StdRetryCnt,
		db.ExpBackoff{},
		func(_ db.Reader, w db.Writer) error {
			msgs := make([]*oplog.Message, 0, 5)
			ticket, err := w.GetTicket(ctx, am)
			if err != nil {
				return errors.Wrap(ctx, err, op, errors.WithMsg("unable to get ticket"))
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
			if len(vo.ClaimsScopes) > 0 {
				scopesOplogMsgs := make([]*oplog.Message, 0, len(vo.ClaimsScopes))
				if err := w.CreateItems(ctx, vo.ClaimsScopes, db.NewOplogMsgs(&scopesOplogMsgs)); err != nil {
					return err
				}
				msgs = append(msgs, scopesOplogMsgs...)
			}
			if len(vo.AccountClaimMaps) > 0 {
				accountClaimMapsOplogMsgs := make([]*oplog.Message, 0, len(vo.AccountClaimMaps))
				if err := w.CreateItems(ctx, vo.AccountClaimMaps, db.NewOplogMsgs(&accountClaimMapsOplogMsgs)); err != nil {
					return err
				}
				msgs = append(msgs, accountClaimMapsOplogMsgs...)
			}
			if len(vo.Prompts) > 0 {
				promptOplogMsgs := make([]*oplog.Message, 0, len(vo.Prompts))
				if err := w.CreateItems(ctx, vo.Prompts, db.NewOplogMsgs(&promptOplogMsgs)); err != nil {
					return err
				}
				msgs = append(msgs, promptOplogMsgs...)
			}
			metadata := am.oplog(oplog.OpType_OP_TYPE_CREATE)
			if err := w.WriteOplogEntryWith(ctx, oplogWrapper, ticket, metadata, msgs); err != nil {
				return errors.Wrap(ctx, err, op, errors.WithMsg("unable to write oplog"))
			}
			return nil
		},
	)
	if err != nil {
		return nil, errors.Wrap(ctx, err, op)
	}
	return returnedAuthMethod, nil
}
