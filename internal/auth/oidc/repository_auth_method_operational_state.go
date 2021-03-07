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
func (r *Repository) MakeInactive(ctx context.Context, authMethodId string, version uint32, _ ...Option) (*AuthMethod, error) {
	const op = "oidc.(Repository).MakeInactive"
	updated, err := r.transitionAuthMethodTo(ctx, authMethodId, InactiveState, version)
	if err != nil {
		return nil, errors.Wrap(err, op)
	}
	return updated, nil
}

// MakePrivate will transision an OIDC auth method from either the
// InactiveState or the ActivePublicState to the ActivePrivateState.  If
// transitioning from the InactiveState, the transition will only succeed if
// the auth method is complete and the oidc.ValidateAuthMethod(...) succeeds.
// If the WithForce option is provided, oidc.ValidateAuthMethod(...) success
// is not required.
func (r *Repository) MakePrivate(ctx context.Context, authMethodId string, version uint32, opt ...Option) (*AuthMethod, error) {
	const op = "oidc.(Repository).MakePrivate"
	updated, err := r.transitionAuthMethodTo(ctx, authMethodId, ActivePrivateState, version, opt...)
	if err != nil {
		return nil, errors.Wrap(err, op)
	}
	return updated, nil
}

// MakePublic will transision an OIDC auth method from either the
// InactiveState or the ActivePrivateState to the ActivePublicState.  If
// transitioning from the InactiveState, the transition will only succeed if
// the auth method is complete and the oidc.ValidateAuthMethod(...) succeeds.
// If the WithForce option is provided, oidc.ValidateAuthMethod(...) success
// is not required.
func (r *Repository) MakePublic(ctx context.Context, authMethodId string, version uint32, opt ...Option) (*AuthMethod, error) {
	const op = "oidc.(Repository).MakePublic"
	updated, err := r.transitionAuthMethodTo(ctx, authMethodId, ActivePublicState, version, opt...)
	if err != nil {
		return nil, errors.Wrap(err, op)
	}
	return updated, nil
}

func (r *Repository) transitionAuthMethodTo(ctx context.Context, authMethodId string, desiredState AuthMethodState, version uint32, opt ...Option) (*AuthMethod, error) {
	const op = "oidc.(Repository).transitionAuthMethodTo"
	if authMethodId == "" {
		return nil, errors.New(errors.InvalidParameter, op, "missing auth method id")
	}
	if !validState(string(desiredState)) {
		return nil, errors.New(errors.InvalidParameter, op, fmt.Sprintf("%s is not a valid auth method state", desiredState))
	}
	am, err := r.lookupAuthMethod(ctx, authMethodId)
	if err != nil {
		return nil, errors.Wrap(err, op)
	}
	if am == nil {
		return nil, errors.New(errors.RecordNotFound, op, fmt.Sprintf("%s auth method not found", authMethodId))
	}
	if am.OperationalState == string(desiredState) {
		return am, nil
	}
	opts := getOpts(opt...)
	if am.OperationalState == string(InactiveState) {
		if !opts.withForce {
			if err := r.ValidateAuthMethod(ctx, WithAuthMethod(am)); err != nil {
				return nil, errors.Wrap(err, op)
			}
		}
		if err := am.isComplete(); err != nil {
			return nil, errors.Wrap(err, op, errors.WithMsg(fmt.Sprintf("unable to transition from %s to %s", InactiveState, desiredState)))
		}
	}

	oplogWrapper, err := r.kms.GetWrapper(ctx, am.ScopeId, kms.KeyPurposeOplog)
	if err != nil {
		return nil, errors.Wrap(err, op, errors.WithMsg("unable to get oplog wrapper"))
	}

	var updatedAm *AuthMethod
	_, err = r.writer.DoTx(
		ctx,
		db.StdRetryCnt,
		db.ExpBackoff{},
		func(_ db.Reader, w db.Writer) error {
			updatedAm = am.Clone()
			updatedAm.OperationalState = string(desiredState)
			dbMask := []string{"OperationalState"}
			rowsUpdated, err := w.Update(ctx, updatedAm, dbMask, nil, db.WithOplog(oplogWrapper, updatedAm.oplog(oplog.OpType_OP_TYPE_UPDATE)), db.WithVersion(&version))
			if err == nil && rowsUpdated > 1 {
				return errors.New(errors.MultipleRecords, op, fmt.Sprintf("updated auth method and %d rows updated", rowsUpdated))
			}
			return err
		},
	)
	if err != nil {
		return nil, errors.Wrap(err, op)
	}
	return updatedAm, nil
}
