package oidc

import (
	"context"
	"fmt"

	"github.com/hashicorp/boundary/internal/db"
	"github.com/hashicorp/boundary/internal/errors"
	"github.com/hashicorp/boundary/internal/kms"
	"github.com/hashicorp/boundary/internal/oplog"
)

// MakeInactive will transision an OIDC auth method from either the
// ActivePrivateState or the ActivePublicState to the InactiveState.
// No options are supported.
func (r *Repository) MakeInactive(ctx context.Context, authMethodId string, _ ...Option) error {
	const op = "oidc.(Repository).MakeInactive"
	if err := r.transitionAuthMethodTo(ctx, authMethodId, InactiveState); err != nil {
		return errors.Wrap(err, op)
	}
	return nil
}

// MakePrivate will transision an OIDC auth method from either the
// InactiveState or the ActivePublicState to the ActivePrivateState.  If
// transitioning from the InactiveState, the transition will only succeed if
// the oidc.ValidateAuthMethod(...) succeeds. No options are supported.
func (r *Repository) MakePrivate(ctx context.Context, authMethodId string, _ ...Option) error {
	const op = "oidc.(Repository).MakePrivate"
	if err := r.transitionAuthMethodTo(ctx, authMethodId, ActivePrivateState); err != nil {
		return errors.Wrap(err, op)
	}
	return nil
}

// MakePublic will transision an OIDC auth method from either the
// InactiveState or the ActivePrivateState to the ActivePublicState.  If
// transitioning from the InactiveState, the transition will only succeed if
// the oidc.ValidateAuthMethod(...) succeeds. No options are supported.
func (r *Repository) MakePublic(ctx context.Context, authMethodId string, _ ...Option) error {
	const op = "oidc.(Repository).MakePublic"
	if err := r.transitionAuthMethodTo(ctx, authMethodId, ActivePublicState); err != nil {
		return errors.Wrap(err, op)
	}
	return nil
}

func (r *Repository) transitionAuthMethodTo(ctx context.Context, authMethodId string, desiredState AuthMethodState, _ ...Option) error {
	const op = "oidc.(Repository).updateOperationalState"
	if authMethodId == "" {
		return errors.New(errors.InvalidParameter, op, "missing auth method id")
	}
	if !validState(string(desiredState)) {
		return errors.New(errors.InvalidParameter, op, fmt.Sprintf("%s is not a valid auth method state", desiredState))
	}
	am, err := r.lookupAuthMethod(ctx, authMethodId)
	if err != nil {
		return errors.Wrap(err, op)
	}
	if am == nil {
		return errors.New(errors.RecordNotFound, op, fmt.Sprintf("%s auth method not found", authMethodId))
	}
	if am.OperationalState == string(desiredState) {
		return nil
	}
	if am.OperationalState == string(InactiveState) {
		if err := am.isComplete(); err != nil {
			return errors.Wrap(err, op, errors.WithMsg(fmt.Sprintf("unable to transition from %s to %s", InactiveState, desiredState)))
		}
	}

	oplogWrapper, err := r.kms.GetWrapper(ctx, am.ScopeId, kms.KeyPurposeOplog)
	if err != nil {
		return errors.Wrap(err, op, errors.WithMsg("unable to get oplog wrapper"))
	}
	_, err = r.writer.DoTx(
		ctx,
		db.StdRetryCnt,
		db.ExpBackoff{},
		func(_ db.Reader, w db.Writer) error {
			updatedAm := am.Clone()
			updatedAm.OperationalState = string(desiredState)
			dbMask := []string{"OperationalState"}
			rowsUpdated, err := w.Update(ctx, updatedAm, dbMask, nil, db.WithOplog(oplogWrapper, updatedAm.oplog(oplog.OpType_OP_TYPE_UPDATE)))
			if err != nil {
				return errors.Wrap(err, op, errors.WithMsg("unable to update auth method"))
			}
			if rowsUpdated != 1 {
				return errors.New(errors.MultipleRecords, op, fmt.Sprintf("updated auth method and %d rows updated", rowsUpdated))
			}
			return nil
		},
	)
	if err != nil {
		return errors.Wrap(err, op)
	}
	return nil
}
