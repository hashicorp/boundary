package oidc

import (
	"context"
)

// upsertAccount will create/update account using claims from the user's ID Token.
func (r *Repository) upsertAccount(ctx context.Context, authMethodId string, IdTokenClaims map[string]interface{}) (*Account, error) {
	panic("to-do")
}
