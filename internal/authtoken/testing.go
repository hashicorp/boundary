package authtoken

import (
	"context"
	"strings"
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
	sess, err := NewAuthToken(org.GetPublicId(), u.GetPublicId(), amId)
	assert.NoError(err)
	assert.NotNil(sess)
	id, err := newAuthTokenId()
	assert.NoError(err)
	assert.NotEmpty(id)
	sess.PublicId = id

	token, err := newAuthToken()
	assert.NoError(err)
	assert.NotEmpty(token)
	sess.Token = token

	w := db.New(conn)
	err2 := w.Create(context.Background(), sess)
	assert.NoError(err2)
	return sess
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

func assertPublicId(t *testing.T, prefix, actual string) {
	t.Helper()
	assert.NotEmpty(t, actual)
	parts := strings.Split(actual, "_")
	assert.Equalf(t, 2, len(parts), "want one '_' in PublicId, got multiple in %q", actual)
	assert.Equalf(t, prefix, parts[0], "PublicId want prefix: %q, got: %q in %q", prefix, parts[0], actual)
}
