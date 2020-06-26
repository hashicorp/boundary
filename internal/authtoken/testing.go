package authtoken

import (
	"context"
	"testing"

	"github.com/hashicorp/watchtower/internal/db"
	"github.com/hashicorp/watchtower/internal/iam"
	"github.com/jinzhu/gorm"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func testAuthToken(t *testing.T, conn *gorm.DB) *AuthToken {
	t.Helper()
	assert := assert.New(t)
	org, _ := iam.TestScopes(t, conn)
	u := iam.TestUser(t, conn, org.GetPublicId())
	amId := setupAuthMethod(t, conn, org.GetPublicId())
	at, err := NewAuthToken(org.GetPublicId(), u.GetPublicId(), amId)
	assert.NoError(err)
	assert.NotNil(at)
	id, err := newAuthTokenId()
	assert.NoError(err)
	assert.NotEmpty(id)
	at.PublicId = id

	token, err := newAuthToken()
	assert.NoError(err)
	assert.NotEmpty(token)
	at.Token = token

	w := db.New(conn)
	err2 := w.Create(context.Background(), at)
	assert.NoError(err2)
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
