package oidc

import (
	"context"
)

// MakeInactive will transision an OIDC auth method from either the
// ActivePrivateState or the ActivePublicState to the InactiveState.
func (r *Repository) MakeInactive(ctx context.Context, authMethodId string, _ ...Option) error {
	panic("to-do")
}

// MakePrivate will transision an OIDC auth method from either the
// InactiveState or the ActivePublicState to the ActivePrivateState.  If
// transitioning from the InactiveState, the transition will only succeed if
// the oidc.TestAuthMethod(...) succeeds. No options are currently supported.
func (r *Repository) MakePrivate(ctx context.Context, authMethodId string, opt ...Option) error {
	panic("to-do")
}

// MakePublic will transision an OIDC auth method from either the
// InactiveState or the ActivePrivateState to the ActivePublicState.  If
// transitioning from the InactiveState, the transition will only succeed if
// the oidc.TestAuthMethod(...) succeeds. No options are currently supported.
func (r *Repository) MakePublic(ctx context.Context, authMethodId string, opt ...Option) error {
	panic("to-do")
}

// upsertAccount will create/update account using claims from the user's ID Token.
func (r *Repository) upsertAccount(ctx context.Context, authMethodId string, IdTokenClaims map[string]interface{}) (*Account, error) {
	panic("to-do")
}
