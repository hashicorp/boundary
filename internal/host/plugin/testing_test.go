package plugin

import (
	"testing"

	"github.com/hashicorp/boundary/internal/db"
	"github.com/hashicorp/boundary/internal/iam"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func Test_TestPlugins(t *testing.T) {
	assert, require := assert.New(t), require.New(t)
	conn, _ := db.TestSetup(t, "postgres")

	plg := TestPlugin(t, conn, "test")
	require.NotNil(plg)
	assert.NotEmpty(plg.GetPublicId())
}

func Test_TestCatalogs(t *testing.T) {
	assert, require := assert.New(t), require.New(t)
	conn, _ := db.TestSetup(t, "postgres")
	wrapper := db.TestWrapper(t)
	_, proj := iam.TestScopes(t, iam.TestRepo(t, conn, wrapper))
	require.NotNil(proj)
	assert.NotEmpty(proj.GetPublicId())

	plg := TestPlugin(t, conn, "test")
	require.NotNil(plg)
	assert.NotEmpty(plg.GetPublicId())

	count := 4
	cs := TestCatalogs(t, conn, plg.GetPublicId(), proj.GetPublicId(), count)
	assert.Len(cs, count)
	for _, c := range cs {
		assert.NotEmpty(c.GetPublicId())
	}
}

func Test_TestSets(t *testing.T) {
	assert, require := assert.New(t), require.New(t)
	conn, _ := db.TestSetup(t, "postgres")
	wrapper := db.TestWrapper(t)
	_, prj := iam.TestScopes(t, iam.TestRepo(t, conn, wrapper))
	require.NotNil(prj)
	assert.NotEmpty(prj.GetPublicId())

	plg := TestPlugin(t, conn, "test")
	require.NotNil(plg)
	assert.NotEmpty(plg.GetPublicId())

	c := TestCatalogs(t, conn, plg.GetPublicId(), prj.GetPublicId(), 1)[0]

	count := 4
	sets := TestSets(t, conn, c.GetPublicId(), count)
	assert.Len(sets, count)
	for _, s := range sets {
		assert.NotEmpty(s.GetPublicId())
	}
}
