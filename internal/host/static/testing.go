package static

import (
	"context"
	"fmt"
	"testing"

	"github.com/hashicorp/boundary/internal/db"
	"github.com/stretchr/testify/assert"
)

// TestCatalogs creates count number of static host catalogs to the provided DB
// with the provided scope id.  If any errors are encountered during the creation of
// the host catalog, the test will fail.
func TestCatalogs(t *testing.T, conn *db.DB, scopeId string, count int) []*HostCatalog {
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

// TestHosts creates count number of static hosts to the provided DB
// with the provided catalog id.  The catalog must have been created previously.
// If any errors are encountered during the creation of the host, the test will fail.
func TestHosts(t *testing.T, conn *db.DB, catalogId string, count int) []*Host {
	t.Helper()
	assert := assert.New(t)
	var hosts []*Host

	for i := 0; i < count; i++ {
		host, err := NewHost(catalogId, WithAddress(fmt.Sprintf("%s-%d", catalogId, i)))
		assert.NoError(err)
		assert.NotNil(host)

		id, err := newHostId()
		assert.NoError(err)
		assert.NotEmpty(id)
		host.PublicId = id

		w := db.New(conn)
		err2 := w.Create(context.Background(), host)
		assert.NoError(err2)
		hosts = append(hosts, host)
	}
	return hosts
}

// TestSets creates count number of static host sets in the provided DB
// with the provided catalog id. The catalog must have been created
// previously. The test will fail if any errors are encountered.
func TestSets(t *testing.T, conn *db.DB, catalogId string, count int) []*HostSet {
	t.Helper()
	assert := assert.New(t)
	var sets []*HostSet

	for i := 0; i < count; i++ {
		set, err := NewHostSet(catalogId)
		assert.NoError(err)
		assert.NotNil(set)
		id, err := newHostSetId()
		assert.NoError(err)
		assert.NotEmpty(id)
		set.PublicId = id

		w := db.New(conn)
		err2 := w.Create(context.Background(), set)
		assert.NoError(err2)
		sets = append(sets, set)
	}
	return sets
}

// TestSetMembers adds hosts to the specified setId in the provided DB.
// The set and hosts must have been created previously and belong to the
// same catalog. The test will fail if any errors are encountered.
func TestSetMembers(t *testing.T, conn *db.DB, setId string, hosts []*Host) []*HostSetMember {
	t.Helper()
	assert := assert.New(t)

	var members []*HostSetMember
	for _, host := range hosts {
		member, err := NewHostSetMember(setId, host.PublicId)
		assert.NoError(err)
		assert.NotNil(member)

		w := db.New(conn)
		err2 := w.Create(context.Background(), member)
		assert.NoError(err2)
		members = append(members, member)
	}
	return members
}
