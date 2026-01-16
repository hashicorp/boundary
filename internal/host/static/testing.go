// Copyright IBM Corp. 2020, 2025
// SPDX-License-Identifier: BUSL-1.1

package static

import (
	"context"
	"fmt"
	"testing"

	"github.com/hashicorp/boundary/internal/db"
	"github.com/stretchr/testify/assert"
)

// TestCatalog creates a static host catalog to the provided DB
// with the provided project id.  If any errors are encountered during the creation of
// the host catalog, the test will fail.
// Name and description are the only valid options. All other options are
// ignored.
func TestCatalog(t testing.TB, conn *db.DB, projectId string, opt ...Option) *HostCatalog {
	t.Helper()
	ctx := context.Background()
	assert := assert.New(t)

	cat, err := NewHostCatalog(ctx, projectId, opt...)
	assert.NoError(err)
	assert.NotNil(cat)
	id, err := newHostCatalogId(ctx)
	assert.NoError(err)
	assert.NotEmpty(id)
	cat.PublicId = id

	w := db.New(conn)
	err2 := w.Create(ctx, cat)
	assert.NoError(err2)

	return cat
}

// TestCatalogs creates count number of static host catalogs to the provided DB
// with the provided project id.  If any errors are encountered during the creation of
// the host catalog, the test will fail.
func TestCatalogs(t testing.TB, conn *db.DB, projectId string, count int) []*HostCatalog {
	t.Helper()
	ctx := context.Background()
	assert := assert.New(t)
	var cats []*HostCatalog
	for i := 0; i < count; i++ {
		cat, err := NewHostCatalog(ctx, projectId)
		assert.NoError(err)
		assert.NotNil(cat)
		id, err := newHostCatalogId(ctx)
		assert.NoError(err)
		assert.NotEmpty(id)
		cat.PublicId = id

		w := db.New(conn)
		err2 := w.Create(ctx, cat)
		assert.NoError(err2)
		cats = append(cats, cat)
	}
	return cats
}

// TestHost creates a static host to the provided DB with the provided catalog id.
// The catalog must have been created previously. If any errors are encountered
// during the creation of the host, the test will fail.
func TestHost(t testing.TB, conn *db.DB, catalogId string, opt ...Option) *Host {
	t.Helper()
	ctx := context.Background()
	assert := assert.New(t)

	host, err := NewHost(ctx, catalogId, opt...)
	assert.NoError(err)
	assert.NotNil(host)

	id, err := newHostId(ctx)
	assert.NoError(err)
	assert.NotEmpty(id)
	host.PublicId = id

	w := db.New(conn)
	err2 := w.Create(ctx, host)
	assert.NoError(err2)

	return host
}

// TestHosts creates count number of static hosts to the provided DB
// with the provided catalog id.  The catalog must have been created previously.
// If any errors are encountered during the creation of the host, the test will fail.
func TestHosts(t testing.TB, conn *db.DB, catalogId string, count int) []*Host {
	t.Helper()
	ctx := context.Background()
	assert := assert.New(t)
	var hosts []*Host

	for i := 0; i < count; i++ {
		host, err := NewHost(ctx, catalogId, WithAddress(fmt.Sprintf("%s-%d", catalogId, i)))
		assert.NoError(err)
		assert.NotNil(host)

		id, err := newHostId(ctx)
		assert.NoError(err)
		assert.NotEmpty(id)
		host.PublicId = id

		w := db.New(conn)
		err2 := w.Create(ctx, host)
		assert.NoError(err2)
		hosts = append(hosts, host)
	}
	return hosts
}

// TestSet creates a static host set in the provided DB
// with the provided catalog id. The catalog must have been created
// previously. Name and description are the only valid options. All other options are
// ignored. The test will fail if any errors are encountered.
func TestSet(t testing.TB, conn *db.DB, catalogId string, opt ...Option) *HostSet {
	t.Helper()
	ctx := context.Background()
	assert := assert.New(t)

	set, err := NewHostSet(ctx, catalogId, opt...)
	assert.NoError(err)
	assert.NotNil(set)

	id, err := newHostSetId(ctx)
	assert.NoError(err)
	assert.NotEmpty(id)
	set.PublicId = id

	w := db.New(conn)
	err2 := w.Create(ctx, set)
	assert.NoError(err2)

	return set
}

// TestSets creates count number of static host sets in the provided DB
// with the provided catalog id. The catalog must have been created
// previously. The test will fail if any errors are encountered.
func TestSets(t testing.TB, conn *db.DB, catalogId string, count int) []*HostSet {
	t.Helper()
	ctx := context.Background()
	assert := assert.New(t)
	var sets []*HostSet

	for i := 0; i < count; i++ {
		set, err := NewHostSet(ctx, catalogId)
		assert.NoError(err)
		assert.NotNil(set)
		id, err := newHostSetId(ctx)
		assert.NoError(err)
		assert.NotEmpty(id)
		set.PublicId = id

		w := db.New(conn)
		err2 := w.Create(ctx, set)
		assert.NoError(err2)
		sets = append(sets, set)
	}
	return sets
}

// TestSetMembers adds hosts to the specified setId in the provided DB.
// The set and hosts must have been created previously and belong to the
// same catalog. The test will fail if any errors are encountered.
func TestSetMembers(t testing.TB, conn *db.DB, setId string, hosts []*Host) []*HostSetMember {
	t.Helper()
	assert := assert.New(t)
	ctx := context.Background()

	var members []*HostSetMember
	for _, host := range hosts {
		member, err := NewHostSetMember(ctx, setId, host.PublicId)
		assert.NoError(err)
		assert.NotNil(member)

		w := db.New(conn)
		err2 := w.Create(ctx, member)
		assert.NoError(err2)
		members = append(members, member)
	}
	return members
}
