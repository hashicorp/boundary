package authtoken

import (
	"context"
	"testing"

	"github.com/hashicorp/boundary/internal/auth/password"
	"github.com/hashicorp/boundary/internal/db"
	"github.com/hashicorp/boundary/internal/iam"
	"github.com/hashicorp/boundary/internal/kms"
	"github.com/stretchr/testify/require"
)

func TestAuthToken(t testing.TB, conn *db.DB, kms *kms.Kms, scopeId string, opt ...Option) *AuthToken {
	t.Helper()
	authMethod := password.TestAuthMethods(t, conn, scopeId, 1)[0]
	// auth account is only used to join auth method to user.
	// We don't do anything else with the auth account in the test setup.
	acct := password.TestAccount(t, conn, authMethod.GetPublicId(), "name1")

	ctx := context.Background()
	rw := db.New(conn)
	iamRepo, err := iam.NewRepository(rw, rw, kms)
	require.NoError(t, err)

	u := iam.TestUser(t, iamRepo, scopeId, iam.WithAccountIds(acct.PublicId))

	repo, err := NewRepository(rw, rw, kms)
	require.NoError(t, err)

	at, err := repo.CreateAuthToken(ctx, u, acct.GetPublicId(), opt...)
	require.NoError(t, err)
	return at
}
