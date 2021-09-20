package plugin

import (
	"context"
	"testing"

	"github.com/hashicorp/boundary/internal/db"
	"github.com/hashicorp/boundary/internal/kms"
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
func TestSet(t *testing.T, conn *gorm.DB, kmsCache *kms.Kms, hc *HostCatalog, opt ...Option) *HostSet {
	t.Helper()
	require := require.New(t)
	ctx := context.Background()
	rw := db.New(conn)

	repo, err := NewRepository(rw, rw, kmsCache)
	require.NoError(err)

	set, err := NewHostSet(ctx, hc.PublicId, opt...)
	require.NoError(err)
	require.NotNil(set)

	plg := host.NewPlugin("", "")
	plg.PublicId = hc.GetPluginId()
	require.NoError(rw.LookupByPublicId(ctx, plg))

	id, err := newHostSetId(ctx, plg.GetIdPrefix())
	require.NoError(err)
	require.NotEmpty(id)

	set, err = repo.CreateSet(ctx, hc.ScopeId, set, opt...)
	require.NoError(err)

	return set
}
