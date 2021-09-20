package plugin

import (
	"fmt"
	"strings"
	"testing"

	"github.com/hashicorp/boundary/internal/db"
	"github.com/hashicorp/boundary/internal/iam"
	"github.com/hashicorp/boundary/internal/kms"
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

	cs := TestCatalog(t, conn, proj.GetPublicId(), plg.GetPublicId(), WithName("foo"), WithDescription("bar"))
	assert.NotEmpty(cs.GetPublicId())
	assert.True(strings.HasPrefix(cs.GetPublicId(), fmt.Sprintf("%s_%s", HostCatalogPrefix, "prefix")))
	assert.Equal("foo", cs.GetName())
	assert.Equal("bar", cs.GetDescription())
}

func Test_TestSet(t *testing.T) {
	assert, require := assert.New(t), require.New(t)
	conn, _ := db.TestSetup(t, "postgres")
	wrapper := db.TestWrapper(t)
	kmsCache := kms.TestKms(t, conn, wrapper)
	_, prj := iam.TestScopes(t, iam.TestRepo(t, conn, wrapper))
	require.NotNil(prj)
	assert.NotEmpty(prj.GetPublicId())

	plg := host.TestPlugin(t, conn, "test", "prefix")
	require.NotNil(plg)
	assert.NotEmpty(plg.GetPublicId())

	c := TestCatalog(t, conn, prj.GetPublicId(), plg.GetPublicId())
	set := TestSet(t, conn, kmsCache, c, WithName("foo"), WithDescription("bar"))
	assert.NotEmpty(set.GetPublicId())
	assert.True(strings.HasPrefix(set.GetPublicId(), fmt.Sprintf("%s_%s", HostSetPrefix, "prefix")))
	assert.Equal("foo", set.GetName())
	assert.Equal("bar", set.GetDescription())
}
