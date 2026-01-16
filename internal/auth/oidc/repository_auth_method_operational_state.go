// Copyright IBM Corp. 2020, 2025
// SPDX-License-Identifier: BUSL-1.1

package oidc

import (
	"context"
	"fmt"

	"github.com/hashicorp/boundary/internal/db"
	"github.com/hashicorp/boundary/internal/errors"
	"github.com/hashicorp/boundary/internal/kms"
	"github.com/hashicorp/boundary/internal/oplog"
)

// MakeInactive will transition an OIDC auth method from either the
// ActivePrivateState or the ActivePublicState to the InactiveState.
// No options are supported.
func (r *Repository) MakeInactive(ctx context.Context, authMethodId string, version uint32, _ ...Option) (*AuthMethod, error) {
	const op = "oidc.(Repository).MakeInactive"
	updated, err := r.transitionAuthMethodTo(ctx, authMethodId, InactiveState, version)
	if err != nil {
		return nil, errors.Wrap(ctx, err, op)
	}
	return updated, nil
}

// MakePrivate will transition an OIDC auth method from either the
// InactiveState or the ActivePublicState to the ActivePrivateState.  If
// transitioning from the InactiveState, the transition will only succeed if
// the auth method is complete and the oidc.ValidateAuthMethod(...) succeeds.
// If the WithForce option is provided, oidc.ValidateAuthMethod(...) success
// is not required.
func (r *Repository) MakePrivate(ctx context.Context, authMethodId string, version uint32, opt ...Option) (*AuthMethod, error) {
	const op = "oidc.(Repository).MakePrivate"
	updated, err := r.transitionAuthMethodTo(ctx, authMethodId, ActivePrivateState, version, opt...)
	if err != nil {
		return nil, errors.Wrap(ctx, err, op)
	}
	return updated, nil
}

// MakePublic will transition an OIDC auth method from either the
// InactiveState or the ActivePrivateState to the ActivePublicState.  If
// transitioning from the InactiveState, the transition will only succeed if
// the auth method is complete and the oidc.ValidateAuthMethod(...) succeeds.
// If the WithForce option is provided, oidc.ValidateAuthMethod(...) success
// is not required.
func (r *Repository) MakePublic(ctx context.Context, authMethodId string, version uint32, opt ...Option) (*AuthMethod, error) {
	const op = "oidc.(Repository).MakePublic"
	updated, err := r.transitionAuthMethodTo(ctx, authMethodId, ActivePublicState, version, opt...)
	if err != nil {
		return nil, errors.Wrap(ctx, err, op)
	}
	return updated, nil
}

func (r *Repository) transitionAuthMethodTo(ctx context.Context, authMethodId string, desiredState AuthMethodState, version uint32, opt ...Option) (*AuthMethod, error) {
	const op = "oidc.(Repository).transitionAuthMethodTo"
	if authMethodId == "" {
		return nil, errors.New(ctx, errors.InvalidParameter, op, "missing auth method id")
	}
	if !validState(string(desiredState)) {
		return nil, errors.New(ctx, errors.InvalidParameter, op, fmt.Sprintf("%s is not a valid auth method state", desiredState))
	}
	am, err := r.lookupAuthMethod(ctx, authMethodId)
	if err != nil {
		return nil, errors.Wrap(ctx, err, op)
	}
	if am == nil {
		return nil, errors.New(ctx, errors.RecordNotFound, op, fmt.Sprintf("%s auth method not found", authMethodId))
	}
	opts := getOpts(opt...)
	if am.OperationalState == string(desiredState) && am.DisableDiscoveredConfigValidation == opts.withForce {
		return am, nil
	}
	if am.OperationalState == string(InactiveState) {
		if !opts.withForce {
			updatedAm := am.Clone()
			updatedAm.OperationalState = string(desiredState)
			if err := r.ValidateDiscoveryInfo(ctx, WithAuthMethod(updatedAm)); err != nil {
				return nil, errors.Wrap(ctx, err, op)
			}
		}
		if err := am.isComplete(ctx); err != nil {
			return nil, errors.Wrap(ctx, err, op, errors.WithMsg(fmt.Sprintf("unable to transition from %s to %s", InactiveState, desiredState)))
		}
	}

	oplogWrapper, err := r.kms.GetWrapper(ctx, am.ScopeId, kms.KeyPurposeOplog)
	if err != nil {
		return nil, errors.Wrap(ctx, err, op, errors.WithMsg("unable to get oplog wrapper"))
	}

	var updatedAm *AuthMethod
	_, err = r.writer.DoTx(
		ctx,
		db.StdRetryCnt,
		db.ExpBackoff{},
		func(reader db.Reader, w db.Writer) error {
			updatedAm = am.Clone()
			updatedAm.OperationalState = string(desiredState)
			updatedAm.DisableDiscoveredConfigValidation = opts.withForce
			dbMask := []string{OperationalStateField, DisableDiscoveredConfigValidationField}
			rowsUpdated, err := w.Update(ctx, updatedAm, dbMask, nil, db.WithOplog(oplogWrapper, updatedAm.oplog(oplog.OpType_OP_TYPE_UPDATE)), db.WithVersion(&version))
			switch {
			case err != nil:
				return errors.Wrap(ctx, err, op, errors.WithMsg("unable to update auth method"))
			case err == nil && rowsUpdated > 1:
				return errors.New(ctx, errors.MultipleRecords, op, fmt.Sprintf("updated auth method and %d rows updated", rowsUpdated))
			case err == nil && rowsUpdated == 0:
				// this is different than how "no rows updated" is handled in
				// the typical update pattern since we are not returning the
				// number of rows updated, we need to raise an error here.
				return errors.New(ctx, errors.RecordNotFound, op, fmt.Sprintf("updated auth method and %d rows updated", rowsUpdated))
			default:
			}
			// we need a new repo, that's using the same reader/writer as this TxHandler
			txRepo := &Repository{
				reader: reader,
				writer: w,
				kms:    r.kms,
				// intentionally not setting the defaultLimit, so we'll get all
				// the account ids without a limit
			}
			updatedAm, err = txRepo.lookupAuthMethod(ctx, updatedAm.PublicId)
			if err != nil {
				return errors.Wrap(ctx, err, op, errors.WithMsg("unable to lookup auth method after update"))
			}
			if updatedAm == nil {
				return errors.New(ctx, errors.RecordNotFound, op, "unable to lookup auth method after update")
			}
			return err
		},
	)
	if err != nil {
		return nil, errors.Wrap(ctx, err, op)
	}
	return updatedAm, nil
}
