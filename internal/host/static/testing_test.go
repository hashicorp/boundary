package static

import (
	"testing"

	"github.com/hashicorp/boundary/internal/db"
	"github.com/hashicorp/boundary/internal/iam"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func Test_TestCatalogs(t *testing.T) {
	assert, require := assert.New(t), require.New(t)
	conn, _ := db.TestSetup(t, "postgres")
	wrapper := db.TestWrapper(t)
	_, proj := iam.TestScopes(t, iam.TestRepo(t, conn, wrapper))
	require.NotNil(proj)
	assert.NotEmpty(proj.GetPublicId())

	count := 4
	cs := TestCatalogs(t, conn, proj.GetPublicId(), count)
	assert.Len(cs, count)
	for _, c := range cs {
		assert.NotEmpty(c.GetPublicId())
	}
}

func Test_TestHosts(t *testing.T) {
	t.Helper()
	assert, require := assert.New(t), require.New(t)
	conn, _ := db.TestSetup(t, "postgres")
	wrapper := db.TestWrapper(t)
	org, _ := iam.TestScopes(t, iam.TestRepo(t, conn, wrapper))

	require.NotNil(org)
	assert.NotEmpty(org.GetPublicId())

	c := TestCatalogs(t, conn, org.GetPublicId(), 1)[0]

	count := 4
	accounts := TestHosts(t, conn, c.GetPublicId(), count)
	assert.Len(accounts, count)
	for _, a := range accounts {
		assert.NotEmpty(a.GetPublicId())
	}
}

func Test_TestSets(t *testing.T) {
	t.Helper()
	assert, require := assert.New(t), require.New(t)
	conn, _ := db.TestSetup(t, "postgres")
	wrapper := db.TestWrapper(t)
	_, prj := iam.TestScopes(t, iam.TestRepo(t, conn, wrapper))

	require.NotNil(prj)
	assert.NotEmpty(prj.GetPublicId())

	c := TestCatalogs(t, conn, prj.GetPublicId(), 1)[0]

	count := 4
	sets := TestSets(t, conn, c.GetPublicId(), count)
	assert.Len(sets, count)
	for _, s := range sets {
		assert.NotEmpty(s.GetPublicId())
	}
}
