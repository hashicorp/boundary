package plugin

import (
	"testing"

	"github.com/hashicorp/boundary/internal/db"
	"github.com/hashicorp/boundary/internal/iam"
	"github.com/hashicorp/boundary/internal/plugin/host"
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

	plg := host.TestPlugin(t, conn, "test", "prefix")
	require.NotNil(plg)
	assert.NotEmpty(plg.GetPublicId())

	cs := TestCatalog(t, conn, plg.GetPublicId(), proj.GetPublicId(), WithName("foo"), WithDescription("bar"))
	assert.NotEmpty(cs.GetPublicId())
	assert.Equal("foo", cs.GetName())
	assert.Equal("bar", cs.GetDescription())
}

func Test_TestSet(t *testing.T) {
	assert, require := assert.New(t), require.New(t)
	conn, _ := db.TestSetup(t, "postgres")
	wrapper := db.TestWrapper(t)
	_, prj := iam.TestScopes(t, iam.TestRepo(t, conn, wrapper))
	require.NotNil(prj)
	assert.NotEmpty(prj.GetPublicId())

	plg := host.TestPlugin(t, conn, "test", "prefix")
	require.NotNil(plg)
	assert.NotEmpty(plg.GetPublicId())

	c := TestCatalog(t, conn, plg.GetPublicId(), prj.GetPublicId())
	set := TestSet(t, conn, c.GetPublicId(), WithName("foo"), WithDescription("bar"))
	assert.NotEmpty(set.GetPublicId())
	assert.Equal("foo", set.GetName())
	assert.Equal("bar", set.GetDescription())
}
