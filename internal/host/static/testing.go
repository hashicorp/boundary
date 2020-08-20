package static

import (
	"context"
	"testing"

	"github.com/hashicorp/boundary/internal/db"
	"github.com/jinzhu/gorm"
	"github.com/stretchr/testify/assert"
)

// TestCatalogs creates count number of static host catalogs to the provided DB
// with the provided scope id.  If any errors are encountered during the creation of
// the host catalog, the test will fail.
func TestCatalogs(t *testing.T, conn *gorm.DB, scopeId string, count int) []*HostCatalog {
	t.Helper()
	assert := assert.New(t)
	var cats []*HostCatalog
	for i := 0; i < count; i++ {
		cat, err := NewHostCatalog(scopeId)
		assert.NoError(err)
		assert.NotNil(cat)
		id, err := newHostCatalogId()
		assert.NoError(err)
		assert.NotEmpty(id)
		cat.PublicId = id

		w := db.New(conn)
		err2 := w.Create(context.Background(), cat)
		assert.NoError(err2)
		cats = append(cats, cat)
	}
	return cats
}
