package authtoken

import (
	"context"
	"testing"

	wrapping "github.com/hashicorp/go-kms-wrapping"
	"github.com/hashicorp/watchtower/internal/db"
	"github.com/hashicorp/watchtower/internal/iam"
	"github.com/jinzhu/gorm"
	"github.com/stretchr/testify/require"
)

func testAuthToken(t *testing.T, conn *gorm.DB, wrapper wrapping.Wrapper) *AuthToken {
	t.Helper()
	require := require.New(t)
	org, _ := iam.TestScopes(t, conn)
	u := iam.TestUser(t, conn, org.GetPublicId())
	amId := setupAuthMethod(t, conn, org.GetPublicId())
	at, err := NewAuthToken(org.GetPublicId(), u.GetPublicId(), amId)
	require.NoError(err)
	require.NotNil(at)

	ctx := context.Background()

	rw := db.New(conn)
	repo, err := NewRepository(rw, rw, wrapper)
	require.NoError(err)

	at, err = repo.CreateAuthToken(ctx, at)
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
