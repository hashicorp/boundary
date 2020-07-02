package authtoken

import (
	"context"
	"testing"

	wrapping "github.com/hashicorp/go-kms-wrapping"
	"github.com/hashicorp/watchtower/internal/db"
	"github.com/hashicorp/watchtower/internal/iam"
	iamStore "github.com/hashicorp/watchtower/internal/iam/store"
	"github.com/jinzhu/gorm"
	"github.com/stretchr/testify/require"
)

func testAuthToken(t *testing.T, conn *gorm.DB, wrapper wrapping.Wrapper) *AuthToken {
	t.Helper()
	require := require.New(t)
	org, _ := iam.TestScopes(t, conn)
	u := iam.TestUser(t, conn, org.GetPublicId())
	amId := setupAuthMethod(t, conn, org.GetPublicId())

	// auth account is only used to join auth method to user.
	// We don't do anything else with the auth account in the test setup.
	acct := setupAuthAccount(t, conn, org.GetPublicId(), amId, u.GetPublicId())

	rw := db.New(conn)
	repo, err := NewRepository(rw, rw, wrapper)
	require.NoError(err)

	ctx := context.Background()
	at, err := repo.CreateAuthToken(ctx, u.GetPublicId(), acct.GetPublicId())
	require.NoError(err)
	return at
}

// Returns auth method id
// TODO: Remove this when the auth method repos are created with the relevant test methods.
func setupAuthMethod(t *testing.T, conn *gorm.DB, scope string) string {
	t.Helper()
	require := require.New(t)
	insert := `insert into auth_method
	(public_id, scope_id)
	values
	($1, $2);`
	amId, err := db.NewPublicId("am")
	require.NoError(err)
	_, err = conn.DB().Exec(insert, amId, scope)
	require.NoError(err)
	return amId
}

// TODO: Remove this when the auth method repos are created with the relevant test methods.
func setupAuthAccount(t *testing.T, conn *gorm.DB, scopeId, authMethodId, userId string) *iam.AuthAccount {
	t.Helper()
	require := require.New(t)
	require.NotEmpty(scopeId)
	require.NotEmpty(authMethodId)
	require.NotEmpty(userId)

	authAcctId, err := db.NewPublicId("aa")
	require.NoError(err)

	acct := &iam.AuthAccount{
		AuthAccount: &iamStore.AuthAccount{
			PublicId:     authAcctId,
			ScopeId:      scopeId,
			AuthMethodId: authMethodId,
			IamUserId:    userId,
		},
	}
	rw := db.New(conn)
	err = rw.Create(context.Background(), acct)
	require.NoError(err)
	require.NotEmpty(acct.PublicId)
	return acct
}
