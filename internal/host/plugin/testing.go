package plugin

import (
	"context"
	"testing"

	"github.com/hashicorp/boundary/internal/db"
	"github.com/jinzhu/gorm"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestCatalogs creates count number of plugin host catalogs to the provided DB
// with the provided scope id.  If any errors are encountered during the creation of
// the host catalog, the test will fail.
func TestCatalogs(t *testing.T, conn *gorm.DB, pluginId, scopeId string, count int) []*HostCatalog {
	t.Helper()
	ctx := context.Background()
	var cats []*HostCatalog
	for i := 0; i < count; i++ {
		cat, err := NewHostCatalog(ctx, pluginId, scopeId)
		require.NoError(t, err)
		assert.NotNil(t, cat)
		id, err := newHostCatalogId()
		assert.NoError(t, err)
		assert.NotEmpty(t, id)
		cat.PublicId = id

		w := db.New(conn)
		require.NoError(t, w.Create(ctx, cat))
		cats = append(cats, cat)
	}
	return cats
}

// TestSets creates count number of plugin host sets in the provided DB
// with the provided catalog id. The catalog must have been created
// previously. The test will fail if any errors are encountered.
func TestSets(t *testing.T, conn *gorm.DB, catalogId string, count int) []*HostSet {
	t.Helper()
	ctx := context.Background()
	assert := assert.New(t)
	var sets []*HostSet

	for i := 0; i < count; i++ {
		set, err := NewHostSet(ctx, catalogId)
		require.NoError(t, err)
		assert.NotNil(set)
		id, err := newHostSetId()
		assert.NoError(err)
		assert.NotEmpty(id)
		set.PublicId = id

		w := db.New(conn)
		require.NoError(t, w.Create(ctx, set))
		sets = append(sets, set)
	}
	return sets
}
