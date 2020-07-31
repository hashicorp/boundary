package password

import (
	"testing"

	"github.com/hashicorp/watchtower/internal/db"
	"github.com/hashicorp/watchtower/internal/iam"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func Test_TestAuthMethods(t *testing.T) {
	assert, require := assert.New(t), require.New(t)
	conn, _ := db.TestSetup(t, "postgres")
	org, _ := iam.TestScopes(t, conn)
	require.NotNil(org)
	assert.NotEmpty(org.GetPublicId())

	count := 4
	ams := TestAuthMethods(t, conn, org.GetPublicId(), count)
	assert.Len(ams, count)
	for _, am := range ams {
		assert.NotEmpty(am.GetPublicId())
	}
}

func Test_TestAccounts(t *testing.T) {
	t.Helper()
	assert, require := assert.New(t), require.New(t)
	conn, _ := db.TestSetup(t, "postgres")
	org, _ := iam.TestScopes(t, conn)

	require.NotNil(org)
	assert.NotEmpty(org.GetPublicId())

	am := TestAuthMethods(t, conn, org.GetPublicId(), 1)[0]

	count := 4
	accounts := TestAccounts(t, conn, am.GetPublicId(), count)
	assert.Len(accounts, count)
	for _, a := range accounts {
		assert.NotEmpty(a.GetPublicId())
	}
}
