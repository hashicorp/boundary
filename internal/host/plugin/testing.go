package plugin

import (
	"context"
	"testing"

	"github.com/hashicorp/boundary/internal/db"
	"github.com/jinzhu/gorm"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestCatalog creates count number of plugin host catalogs to the provided DB
// with the provided scope id.  If any errors are encountered during the creation of
// the host catalog, the test will fail.
func TestCatalog(t *testing.T, conn *gorm.DB, pluginId, scopeId string, opt ...Option) *HostCatalog {
	t.Helper()
	ctx := context.Background()
	cat, err := NewHostCatalog(ctx, pluginId, scopeId, opt...)
	require.NoError(t, err)
	assert.NotNil(t, cat)
	id, err := newHostCatalogId()
	assert.NoError(t, err)
	assert.NotEmpty(t, id)
	cat.PublicId = id

	w := db.New(conn)
	require.NoError(t, w.Create(ctx, cat))
	return cat
}

// TestSet creates count number of plugin host sets in the provided DB
// with the provided catalog id. The catalog must have been created
// previously. The test will fail if any errors are encountered.
func TestSet(t *testing.T, conn *gorm.DB, catalogId string, opt ...Option) *HostSet {
	t.Helper()
	ctx := context.Background()
	assert := assert.New(t)
	set, err := NewHostSet(ctx, catalogId, opt...)
	require.NoError(t, err)
	assert.NotNil(set)
	id, err := newHostSetId()
	assert.NoError(err)
	assert.NotEmpty(id)
	set.PublicId = id

	w := db.New(conn)
	require.NoError(t, w.Create(ctx, set))
	return set
}
