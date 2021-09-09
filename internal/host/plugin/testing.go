package plugin

import (
	"context"
	"testing"

	"github.com/hashicorp/boundary/internal/db"
	"github.com/hashicorp/boundary/internal/plugin/host"
	"github.com/jinzhu/gorm"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestCatalog creates count number of plugin host catalogs to the provided DB
// with the provided scope id.  If any errors are encountered during the creation of
// the host catalog, the test will fail.
func TestCatalog(t *testing.T, conn *gorm.DB, scopeId, pluginId string, opt ...Option) *HostCatalog {
	t.Helper()
	ctx := context.Background()
	w := db.New(conn)

	cat, err := NewHostCatalog(ctx, scopeId, pluginId, opt...)
	require.NoError(t, err)
	assert.NotNil(t, cat)

	plg := host.NewPlugin("", "")
	plg.PublicId = pluginId
	require.NoError(t, w.LookupByPublicId(ctx, plg))

	id, err := newHostCatalogId(ctx, plg.GetIdPrefix())
	assert.NoError(t, err)
	assert.NotEmpty(t, id)
	cat.PublicId = id

	require.NoError(t, w.Create(ctx, cat))
	return cat
}

// TestSet creates a plugin host sets in the provided DB
// with the provided catalog id. The catalog must have been created
// previously. The test will fail if any errors are encountered.
func TestSet(t *testing.T, conn *gorm.DB, catalogId string, opt ...Option) *HostSet {
	t.Helper()
	ctx := context.Background()
	w := db.New(conn)

	assert := assert.New(t)
	set, err := NewHostSet(ctx, catalogId, opt...)
	require.NoError(t, err)
	assert.NotNil(set)

	cg := allocHostCatalog()
	cg.PublicId = catalogId
	require.NoError(t, w.LookupByPublicId(ctx, cg))

	plg := host.NewPlugin("", "")
	plg.PublicId = cg.GetPluginId()
	require.NoError(t, w.LookupByPublicId(ctx, plg))

	id, err := newHostSetId(ctx, plg.GetIdPrefix())
	assert.NoError(err)
	assert.NotEmpty(id)
	set.PublicId = id

	require.NoError(t, w.Create(ctx, set))
	return set
}
