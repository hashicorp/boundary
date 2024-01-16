// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: BUSL-1.1

package apptoken

import (
	"context"
	"time"

	"github.com/hashicorp/boundary/internal/db"
	"github.com/hashicorp/boundary/internal/errors"
	"github.com/hashicorp/boundary/internal/kms"
	"github.com/hashicorp/boundary/internal/oplog"
	"github.com/hashicorp/boundary/internal/perms"
)

// CreateAppToken will create an apptoken in the repository and return the written apptoken
// Takes in grant string.  Options supported: WithName, WithDescription
func (r *Repository) CreateAppToken(ctx context.Context, scopeId string, expTime time.Time, createdByUserId string, grantsStr []string, opt ...Option) (*AppToken, []*AppTokenGrant, error) {
	const op = "apptoken.(Repository).CreateAppToken"

	switch {
	case scopeId == "":
		return nil, nil, errors.New(ctx, errors.InvalidParameter, op, "missing scope id")
	case createdByUserId == "":
		return nil, nil, errors.New(ctx, errors.InvalidParameter, op, "missing created by user id")
	case expTime.IsZero():
		return nil, nil, errors.New(ctx, errors.InvalidParameter, op, "missing expiration time")
	case len(grantsStr) == 0:
		return nil, nil, errors.New(ctx, errors.InvalidParameter, op, "missing grants")
	}

	grants := make([]*perms.Grant, 0, len(grantsStr))
	for _, grantStr := range grantsStr {
		// Validate that the grant parses successfully. Note that we fake the scope
		// here to avoid a lookup as the scope is only relevant at actual ACL
		// checking time and we just care that it parses correctly.
		const fakeScopeId = "o_abcd1234"
		grant, err := perms.Parse(ctx, fakeScopeId, grantStr)
		if err != nil {
			return nil, nil, errors.Wrap(ctx, err, op)
		}
		grants = append(grants, &grant)
	}

	// factory supports options: WithName and WithDescription
	appT, err := NewAppToken(ctx, scopeId, expTime, createdByUserId, opt...)
	if err != nil {
		return nil, nil, errors.Wrap(ctx, err, op)
	}
	appTId, err := newAppTokenId(ctx)
	if err != nil {
		return nil, nil, errors.Wrap(ctx, err, op)
	}

	appT.PublicId = appTId

	opLogWrapper, err := r.kms.GetWrapper(ctx, scopeId, kms.KeyPurposeOplog)
	if err != nil {
		return nil, nil, errors.Wrap(ctx, err, op)
	}

	appTokenGrants := make([]*AppTokenGrant, 0, len(grantsStr))
	for _, grant := range grants {
		g, err := NewAppTokenGrant(ctx, appT.PublicId, grant.CanonicalString())
		if err != nil {
			return nil, nil, errors.Wrap(ctx, err, op)
		}
		appTokenGrants = append(appTokenGrants, g)
	}

	var appTokenPeriodicExpInterval *AppTokenPeriodicExpirationInterval
	if appT.ExpirationIntervalInMaxSeconds > 0 {
		if appTokenPeriodicExpInterval, err = NewAppTokenPeriodicExpirationInterval(ctx, appT.PublicId, appT.ExpirationIntervalInMaxSeconds); err != nil {
			return nil, nil, errors.Wrap(ctx, err, op)
		}
	}

	// TODO: We need to validate that the apptoken grants don't exceed the
	// grants for the createdByUserId.  You can't give grants you don't have.
	if err := ValidateAppTokenGrants(ctx, r.grantFinder, createdByUserId, grantsStr); err != nil {
		return nil, nil, errors.Wrap(ctx, err, op)
	}

	appTokenMetadata, err := appT.oplog(ctx, oplog.OpType_OP_TYPE_CREATE)
	if err != nil {
		return nil, nil, errors.Wrap(ctx, err, op)
	}

	var retAppToken *AppToken
	var retAppTokenGrants []*AppTokenGrant
	_, err = r.writer.DoTx(ctx, db.StdRetryCnt, db.ExpBackoff{}, func(r db.Reader, w db.Writer) error {
		ticket, err := w.GetTicket(ctx, appT)
		if err != nil {
			return err
		}
		var msgs []*oplog.Message
		var appTokenOpLogMsg oplog.Message

		retAppToken = appT.clone()
		if err := w.Create(ctx, retAppToken, db.NewOplogMsg(&appTokenOpLogMsg)); err != nil {
			return err
		}
		msgs = append(msgs, &appTokenOpLogMsg)

		var tg []any
		for _, g := range appTokenGrants {
			tg = append(tg, g.clone())
		}

		var appTokenGrantOpLogMsgs []*oplog.Message
		if err := w.CreateItems(ctx, tg, db.NewOplogMsgs(&appTokenGrantOpLogMsgs)); err != nil {
			return err
		}
		msgs = append(msgs, appTokenGrantOpLogMsgs...)

		if appTokenPeriodicExpInterval != nil {
			p := appTokenPeriodicExpInterval.clone()
			var appTokenPeriodicExpIntervalOpLogMsg oplog.Message
			if err := w.Create(ctx, p, db.NewOplogMsg(&appTokenPeriodicExpIntervalOpLogMsg)); err != nil {
				return err
			}
			msgs = append(msgs, &appTokenPeriodicExpIntervalOpLogMsg)
			retAppToken.ExpirationIntervalInMaxSeconds = p.GetExpirationIntervalInMaxSeconds()
		}

		// we're done writing, so we can write the oplog
		if err := w.WriteOplogEntryWith(ctx, opLogWrapper, ticket, appTokenMetadata, msgs); err != nil {
			return err
		}

		retAppTokenGrants = make([]*AppTokenGrant, 0, len(tg))
		for _, g := range tg {
			retAppTokenGrants = append(retAppTokenGrants, g.(*AppTokenGrant))
		}
		return nil
	})
	if err != nil {
		return nil, nil, errors.Wrap(ctx, err, op)
	}

	return retAppToken, retAppTokenGrants, nil
}
