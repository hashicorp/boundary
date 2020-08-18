package authtoken

import (
	"context"
	"testing"

	"github.com/hashicorp/boundary/internal/auth/password"
	"github.com/hashicorp/boundary/internal/db"
	"github.com/hashicorp/boundary/internal/iam"
	"github.com/hashicorp/boundary/internal/kms"
	"github.com/jinzhu/gorm"
	"github.com/stretchr/testify/require"
)

func TestAuthToken(t *testing.T, conn *gorm.DB, kms *kms.Kms, scopeId string) *AuthToken {
	t.Helper()
	authMethod := password.TestAuthMethods(t, conn, scopeId, 1)[0]
	// auth account is only used to join auth method to user.
	// We don't do anything else with the auth account in the test setup.
	acct := password.TestAccounts(t, conn, authMethod.GetPublicId(), 1)[0]

	ctx := context.Background()
	rw := db.New(conn)
	iamRepo, err := iam.NewRepository(rw, rw, kms)
	require.NoError(t, err)

	u, err := iamRepo.LookupUserWithLogin(ctx, acct.GetPublicId(), iam.WithAutoVivify(true))
	require.NoError(t, err)

	repo, err := NewRepository(rw, rw, kms)
	require.NoError(t, err)

	at, err := repo.CreateAuthToken(ctx, u, acct.GetPublicId())
	require.NoError(t, err)
	return at
}
