// Copyright IBM Corp. 2020, 2025
// SPDX-License-Identifier: BUSL-1.1

package plugin

import (
	"context"
	"crypto/rand"
	"fmt"
	"io"
	"net"
	"sort"
	"testing"

	"github.com/hashicorp/boundary/internal/db"
	"github.com/hashicorp/boundary/internal/host"
	"github.com/hashicorp/boundary/internal/host/plugin/store"
	"github.com/hashicorp/boundary/internal/kms"
	"github.com/hashicorp/boundary/internal/plugin"
	"github.com/hashicorp/boundary/internal/scheduler"
	plgpb "github.com/hashicorp/boundary/sdk/pbs/plugin"
	"github.com/hashicorp/go-secure-stdlib/base62"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestCatalogs creates count number of static host catalogs to the provided DB
// with the provided project id.  If any errors are encountered during the creation of
// the host catalog, the test will fail.
func TestCatalogs(t testing.TB, conn *db.DB, projectId, pluginId string, count int) []*HostCatalog {
	t.Helper()
	var cats []*HostCatalog
	for i := 0; i < count; i++ {
		cats = append(cats, TestCatalog(t, conn, projectId, pluginId))
	}
	return cats
}

// TestCatalog creates a plugin host catalogs to the provided DB
// with the provided project id.  If any errors are encountered during the creation of
// the host catalog, the test will fail.
func TestCatalog(t testing.TB, conn *db.DB, projectId, pluginId string, opt ...Option) *HostCatalog {
	t.Helper()
	ctx := context.Background()
	w := db.New(conn)

	cat, err := NewHostCatalog(ctx, projectId, pluginId, opt...)
	require.NoError(t, err)
	assert.NotNil(t, cat)

	plg := plugin.NewPlugin()
	plg.PublicId = pluginId
	require.NoError(t, w.LookupByPublicId(ctx, plg))

	id, err := newHostCatalogId(ctx)
	assert.NoError(t, err)
	assert.NotEmpty(t, id)
	cat.PublicId = id

	require.NoError(t, w.Create(ctx, cat))
	return cat
}

// TestSet creates a plugin host sets in the provided DB
// with the provided catalog id. The catalog must have been created
// previously. The test will fail if any errors are encountered.
func TestSet(t testing.TB, conn *db.DB, kmsCache *kms.Kms, sched *scheduler.Scheduler, hc *HostCatalog, plgm map[string]plgpb.HostPluginServiceClient, opt ...Option) *HostSet {
	t.Helper()
	require := require.New(t)
	ctx := context.Background()
	rw := db.New(conn)

	repo, err := NewRepository(ctx, rw, rw, kmsCache, sched, plgm)
	require.NoError(err)

	set, err := NewHostSet(ctx, hc.PublicId, opt...)
	require.NoError(err)
	require.NotNil(set)

	plg := plugin.NewPlugin()
	plg.PublicId = hc.GetPluginId()
	require.NoError(rw.LookupByPublicId(ctx, plg))

	id, err := newHostSetId(ctx)
	require.NoError(err)
	require.NotEmpty(id)

	set, _, err = repo.CreateSet(ctx, hc.ProjectId, set, opt...)
	require.NoError(err)

	return set
}

// TestSetMembers adds hosts to the specified setId in the provided DB.
// The set and hosts must have been created previously and belong to the
// same catalog. The test will fail if any errors are encountered.
func TestSetMembers(t testing.TB, conn *db.DB, setId string, hosts []*Host) []*HostSetMember {
	t.Helper()
	assert := assert.New(t)

	var members []*HostSetMember
	for _, host := range hosts {
		member, err := NewHostSetMember(context.Background(), setId, host.PublicId)
		assert.NoError(err)
		assert.NotNil(member)

		w := db.New(conn)
		err2 := w.Create(context.Background(), member)
		assert.NoError(err2)
		members = append(members, member)
	}
	return members
}

// TestHost creates a plugin host in the provided DB in the catalog with the
// provided catalog id. The catalog must have been created previously.
// The test will fail if any errors are encountered.
func TestHost(t testing.TB, conn *db.DB, catId, externId string, opt ...Option) *Host {
	t.Helper()
	w := db.New(conn)
	ctx := context.Background()
	host1 := NewHost(ctx, catId, externId, opt...)
	var err error
	host1.PublicId, err = newHostId(ctx, catId, externId)
	require.NoError(t, err)
	require.NoError(t, w.Create(ctx, host1))

	var ipAddresses []*host.IpAddress
	if len(host1.GetIpAddresses()) > 0 {
		sort.Strings(host1.IpAddresses)
		ipAddresses = make([]*host.IpAddress, 0, len(host1.GetIpAddresses()))
		for _, a := range host1.GetIpAddresses() {
			obj, err := host.NewIpAddress(ctx, host1.PublicId, a)
			require.NoError(t, err)
			ipAddresses = append(ipAddresses, obj)
		}
		require.NoError(t, w.CreateItems(ctx, ipAddresses))
	}

	var dnsNames []*host.DnsName
	if len(host1.GetDnsNames()) > 0 {
		sort.Strings(host1.DnsNames)
		dnsNames = make([]*host.DnsName, 0, len(host1.GetDnsNames()))
		for _, n := range host1.GetDnsNames() {
			obj, err := host.NewDnsName(ctx, host1.PublicId, n)
			require.NoError(t, err)
			dnsNames = append(dnsNames, obj)
		}
		require.NoError(t, w.CreateItems(ctx, dnsNames))
	}
	return host1
}

func TestExternalHosts(t testing.TB, catalog *HostCatalog, setIds []string, count int) ([]*plgpb.ListHostsResponseHost, []*Host) {
	t.Helper()
	require := require.New(t)
	retRH := make([]*plgpb.ListHostsResponseHost, 0, count)
	retH := make([]*Host, 0, count)
	if setIds == nil {
		// Prevent panics
		setIds = make([]string, 0)
	}

	for i := 0; i < count; i++ {
		externalId, err := base62.Random(10)
		require.NoError(err)

		ipv4Str := testGetIpv4Address(t)
		ipv6Str := testGetIpv6Address(t)
		dnsName := testGetDnsName(t)

		rh := &plgpb.ListHostsResponseHost{
			ExternalId:  externalId,
			Name:        base62.MustRandom(10),
			Description: base62.MustRandom(10),
			SetIds:      setIds[0 : i+1],
			IpAddresses: []string{ipv4Str, ipv6Str},
			DnsNames:    []string{dnsName},
		}
		retRH = append(retRH, rh)

		publicId, err := newHostId(context.Background(), catalog.PublicId, externalId)
		require.NoError(err)

		retH = append(retH, &Host{
			PluginId: catalog.PluginId,
			SetIds:   setIds[0 : i+1],
			Host: &store.Host{
				Name:        rh.Name,
				Description: rh.Description,
				CatalogId:   catalog.PublicId,
				PublicId:    publicId,
				ExternalId:  externalId,
				IpAddresses: []string{ipv4Str, ipv6Str},
				DnsNames:    []string{dnsName},
				Version:     1,
			},
		})
	}

	return retRH, retH
}

// TestRunSetSync runs the set sync job a single time.
func TestRunSetSync(t testing.TB, conn *db.DB, kmsCache *kms.Kms, plgm map[string]plgpb.HostPluginServiceClient) {
	t.Helper()
	rw := db.New(conn)
	ctx := context.Background()

	j, err := newSetSyncJob(ctx, rw, rw, kmsCache, plgm)
	require.NoError(t, err)
	require.NoError(t, j.Run(ctx, 0))
}

func testGetDnsName(t testing.TB) string {
	dnsName, err := base62.Random(10)
	require.NoError(t, err)
	return fmt.Sprintf("%s.example.com", dnsName)
}

func testGetIpv4Address(t testing.TB) string {
	ipBytes := make([]byte, 4)
	for {
		lr := io.LimitReader(rand.Reader, 4)
		n, err := lr.Read(ipBytes)
		require.NoError(t, err)
		require.Equal(t, n, 4)
		ip := net.IP(ipBytes)
		v4 := ip.To4()
		if v4 != nil {
			return v4.String()
		}
	}
}

func testGetIpv6Address(t testing.TB) string {
	ipBytes := make([]byte, 16)
	for {
		lr := io.LimitReader(rand.Reader, 16)
		n, err := lr.Read(ipBytes)
		require.NoError(t, err)
		require.Equal(t, n, 16)
		ip := net.IP(ipBytes)
		v6 := ip.To16()
		if v6 != nil {
			return v6.String()
		}
	}
}
