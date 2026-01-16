// Copyright IBM Corp. 2020, 2025
// SPDX-License-Identifier: BUSL-1.1

package ldap

import (
	"context"
	"fmt"
	"strings"

	"github.com/hashicorp/boundary/globals"
	"github.com/hashicorp/boundary/internal/db"
	"github.com/hashicorp/boundary/internal/errors"
	"github.com/hashicorp/boundary/internal/kms"
	"github.com/hashicorp/boundary/internal/oplog"
)

// CreateAuthMethod creates am (*AuthMethod) in the repo along with its
// associated embedded optional value objects (urls, certs, client certs, bind
// creds, user search conf and group search conf) and returns the newly created
// AuthMethod (with its PublicId set)
//
// The AuthMethod's public id and version must be empty (zero values).
//
// All options are ignored.
func (r *Repository) CreateAuthMethod(ctx context.Context, am *AuthMethod, opt ...Option) (*AuthMethod, error) {
	const op = "ldap.(Repository).CreateAuthMethod"
	switch {
	case am == nil:
		return nil, errors.New(ctx, errors.InvalidParameter, op, "missing auth method")
	case am.PublicId != "":
		return nil, errors.New(ctx, errors.InvalidParameter, op, "public id must be empty")
	case am.Version != 0:
		return nil, errors.New(ctx, errors.InvalidParameter, op, "version must be empty")
	case am.ScopeId == "":
		return nil, errors.New(ctx, errors.InvalidParameter, op, "missing scope id")
	case !validState(am.OperationalState):
		return nil, errors.New(ctx, errors.InvalidParameter, op, fmt.Sprintf("invalid state: %q", am.OperationalState))
	case len(am.Urls) == 0:
		return nil, errors.New(ctx, errors.InvalidParameter, op, "missing urls (there must be at least one)")
	}

	opts, err := getOpts(opt...)
	if err != nil {
		return nil, errors.Wrap(ctx, err, op)
	}
	am.PublicId = opts.withPublicId
	if am.PublicId == "" {
		id, err := newAuthMethodId(ctx)
		if err != nil {
			return nil, errors.Wrap(ctx, err, op)
		}
		am.PublicId = id
	} else {
		if !strings.HasPrefix(am.PublicId, globals.LdapAuthMethodPrefix+"_") {
			return nil, errors.New(ctx, errors.InvalidParameter, op, "wrong auth method id prefix")
		}
	}

	cv, err := am.convertValueObjects(ctx)
	if err != nil {
		return nil, errors.Wrap(ctx, err, op)
	}

	dbWrapper, err := r.kms.GetWrapper(context.Background(), am.ScopeId, kms.KeyPurposeDatabase)
	if err != nil {
		return nil, errors.Wrap(ctx, err, op, errors.WithMsg("unable to get database wrapper"))
	}

	if cv.BindCredential != nil {
		if err := cv.BindCredential.encrypt(ctx, dbWrapper); err != nil {
			return nil, errors.Wrap(ctx, err, op, errors.WithMsg("failed to encrypt bind credential"))
		}
	}
	if cv.ClientCertificate != nil {
		if err := cv.ClientCertificate.encrypt(ctx, dbWrapper); err != nil {
			return nil, errors.Wrap(ctx, err, op, errors.WithMsg("failed to encrypt client certificate"))
		}
	}

	oplogWrapper, err := r.kms.GetWrapper(ctx, am.ScopeId, kms.KeyPurposeOplog)
	if err != nil {
		return nil, errors.Wrap(ctx, err, op, errors.WithMsg("unable to get oplog wrapper"))
	}

	var returnedAuthMethod *AuthMethod
	_, err = r.writer.DoTx(
		ctx,
		db.StdRetryCnt,
		db.ExpBackoff{},
		func(r db.Reader, w db.Writer) error {
			var ()
			msgs := make([]*oplog.Message, 0, 4)
			ticket, err := w.GetTicket(ctx, am)
			if err != nil {
				return errors.Wrap(ctx, err, op, errors.WithMsg("unable to get ticket"))
			}

			returnedAuthMethod = am.clone()
			var amOplogMsg oplog.Message
			if err := w.Create(ctx, returnedAuthMethod, db.NewOplogMsg(&amOplogMsg)); err != nil {
				return err
			}
			msgs = append(msgs, &amOplogMsg)

			urlOplogMsgs := make([]*oplog.Message, 0, len(cv.Urls))
			if err := w.CreateItems(ctx, cv.Urls, db.NewOplogMsgs(&urlOplogMsgs)); err != nil {
				return err
			}
			msgs = append(msgs, urlOplogMsgs...)

			if len(cv.Certs) > 0 {
				certOplogMsgs := make([]*oplog.Message, 0, len(cv.Certs))
				if err := w.CreateItems(ctx, cv.Certs, db.NewOplogMsgs(&certOplogMsgs)); err != nil {
					return err
				}
				msgs = append(msgs, certOplogMsgs...)
			}
			if cv.UserEntrySearchConf != nil {
				var ucOplogMsg oplog.Message
				if err := w.Create(ctx, cv.UserEntrySearchConf, db.NewOplogMsg(&ucOplogMsg)); err != nil {
					return err
				}
				msgs = append(msgs, &ucOplogMsg)
			}
			if cv.GroupEntrySearchConf != nil {
				var gcOplogMsg oplog.Message
				if err := w.Create(ctx, cv.GroupEntrySearchConf, db.NewOplogMsg(&gcOplogMsg)); err != nil {
					return err
				}
				msgs = append(msgs, &gcOplogMsg)
			}
			if cv.ClientCertificate != nil {
				var ccOplogMsg oplog.Message
				if err := w.Create(ctx, cv.ClientCertificate, db.NewOplogMsg(&ccOplogMsg)); err != nil {
					return err
				}
				msgs = append(msgs, &ccOplogMsg)
			}
			if cv.BindCredential != nil {
				var bcOplogMsg oplog.Message
				if err := w.Create(ctx, cv.BindCredential, db.NewOplogMsg(&bcOplogMsg)); err != nil {
					return err
				}
				msgs = append(msgs, &bcOplogMsg)
			}
			if len(cv.AccountAttributeMaps) > 0 {
				attrMapsOplogMsgs := make([]*oplog.Message, 0, len(cv.AccountAttributeMaps))
				if err := w.CreateItems(ctx, cv.AccountAttributeMaps, db.NewOplogMsgs(&attrMapsOplogMsgs)); err != nil {
					return err
				}
				msgs = append(msgs, attrMapsOplogMsgs...)
			}
			if cv.DerefAliases != nil {
				var daOplogMsg oplog.Message
				if err := w.Create(ctx, cv.DerefAliases, db.NewOplogMsg(&daOplogMsg)); err != nil {
					return err
				}
				msgs = append(msgs, &daOplogMsg)
			}
			md, err := am.oplog(ctx, oplog.OpType_OP_TYPE_CREATE)
			if err != nil {
				return errors.Wrap(ctx, err, op, errors.WithMsg("unable to generate oplog metadata"))
			}
			if err := w.WriteOplogEntryWith(ctx, oplogWrapper, ticket, md, msgs); err != nil {
				return errors.Wrap(ctx, err, op, errors.WithMsg("unable to write oplog"))
			}
			return nil
		},
	)
	if err != nil {
		return nil, errors.Wrap(ctx, err, op)
	}
	found, err := r.getAuthMethods(ctx, am.GetPublicId(), nil)
	switch {
	case err != nil:
		return nil, errors.Wrap(ctx, err, op, errors.WithMsg("failed to lookup created auth method %q", am.GetPublicId()))
	case len(found) != 1:
		return nil, errors.Wrap(ctx, err, op, errors.WithMsg("found %d auth methods with public id of %q and expected 1", len(found), am.GetPublicId()))
	default:
		return found[0], nil
	}
}
