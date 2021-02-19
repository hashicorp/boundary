package oidc

import (
	"context"

	"github.com/hashicorp/boundary/internal/auth/oidc/store"
	"github.com/hashicorp/boundary/internal/errors"
	"google.golang.org/protobuf/proto"
)

func (r *Repository) verifyOperationalState(ctx context.Context, am *AuthMethod, opt ...Option) (bool, error) {
	const op = "oidc.(Repository).verifyOperationalState"
	if am.OperationalState != string(StoppingState) {
		return false, nil
	}
	// TODO (jimlambrt 2/18): resolve any stuck stopping auth methods.
	// * check transition table for stuck stopping.
	// * if found, unstick and update *AuthMethod with new values
	//

	got, err := r.LookupAuthMethod(ctx, am.PublicId, opt...)
	if err != nil {
		return false, errors.Wrap(err, op)
	}
	if got == nil {
		return true, nil
	}
	cp := proto.Clone(got.AuthMethod)
	am.AuthMethod = cp.(*store.AuthMethod)

	return false, nil
}
