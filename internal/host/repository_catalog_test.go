// Copyright IBM Corp. 2020, 2025
// SPDX-License-Identifier: BUSL-1.1

package host_test

import (
	"context"
	"slices"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	"github.com/hashicorp/boundary/internal/db"
	"github.com/hashicorp/boundary/internal/db/timestamp"
	"github.com/hashicorp/boundary/internal/host"
	hostplugin "github.com/hashicorp/boundary/internal/host/plugin"
	pstore "github.com/hashicorp/boundary/internal/host/plugin/store"
	"github.com/hashicorp/boundary/internal/host/static"
	sstore "github.com/hashicorp/boundary/internal/host/static/store"
	"github.com/hashicorp/boundary/internal/iam"
	"github.com/hashicorp/boundary/internal/kms"
	"github.com/hashicorp/boundary/internal/plugin"
	"github.com/hashicorp/boundary/internal/plugin/loopback"
	plstore "github.com/hashicorp/boundary/internal/plugin/store"
	"github.com/hashicorp/boundary/internal/scheduler"
	plgpb "github.com/hashicorp/boundary/sdk/pbs/plugin"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/types/known/timestamppb"
)

func TestCatalogRepository_List(t *testing.T) {
	t.Parallel()
	assert, require := assert.New(t), require.New(t)
	ctx := context.Background()
	conn, _ := db.TestSetup(t, "postgres")
	rw := db.New(conn)
	wrapper := db.TestWrapper(t)
	plg1 := plugin.TestPlugin(t, conn, "plugin1")
	plg2 := plugin.TestPlugin(t, conn, "plugin2")
	_, prj := iam.TestScopes(t, iam.TestRepo(t, conn, wrapper))

	catalogs := []host.Catalog{
		hostplugin.TestCatalog(t, conn, prj.GetPublicId(), plg1.PublicId),
		static.TestCatalogs(t, conn, prj.GetPublicId(), 1)[0],
		hostplugin.TestCatalog(t, conn, prj.GetPublicId(), plg2.PublicId),
		static.TestCatalogs(t, conn, prj.GetPublicId(), 1)[0],
		static.TestCatalogs(t, conn, prj.GetPublicId(), 1)[0],
	}

	// since we sort descending, we need to reverse the slice
	slices.Reverse(catalogs)

	repo, err := host.NewCatalogRepository(ctx, rw, rw)
	require.NoError(err)

	cmpOpts := []cmp.Option{
		cmpopts.IgnoreUnexported(
			hostplugin.HostCatalog{},
			pstore.HostCatalog{},
			static.HostCatalog{},
			sstore.HostCatalog{},
			plstore.Plugin{},
			plugin.Plugin{},
			timestamp.Timestamp{},
			timestamppb.Timestamp{},
		),
	}

	t.Run("validation", func(t *testing.T) {
		t.Parallel()
		t.Run("missing project ids", func(t *testing.T) {
			t.Parallel()
			_, _, _, err := repo.List(ctx, nil, nil, 1)
			require.ErrorContains(err, "missing project ids")
		})
		t.Run("invalid limit", func(t *testing.T) {
			t.Parallel()
			_, _, _, err := repo.List(ctx, []string{prj.PublicId}, nil, 0)
			require.ErrorContains(err, "missing limit")
		})
	})

	t.Run("success-without-after-item", func(t *testing.T) {
		t.Parallel()
		resp, plgs, ttime, err := repo.List(ctx, []string{prj.PublicId}, nil, 10)
		require.NoError(err)
		// Transaction timestamp should be within ~10 seconds of now
		assert.True(time.Now().Before(ttime.Add(10 * time.Second)))
		assert.True(time.Now().After(ttime.Add(-10 * time.Second)))
		require.Empty(cmp.Diff(resp, catalogs, cmpOpts...))
		require.Empty(cmp.Diff(plgs, []*plugin.Plugin{plg1, plg2}, append(cmpOpts, cmpopts.SortSlices(func(i, j *plugin.Plugin) bool { return i.PublicId < j.PublicId }))...))
	})
	t.Run("success-with-after-item", func(t *testing.T) {
		t.Parallel()
		resp, plgs, ttime, err := repo.List(ctx, []string{prj.PublicId}, catalogs[0], 10)
		require.NoError(err)
		// Transaction timestamp should be within ~10 seconds of now
		assert.True(time.Now().Before(ttime.Add(10 * time.Second)))
		assert.True(time.Now().After(ttime.Add(-10 * time.Second)))
		require.Empty(cmp.Diff(resp, catalogs[1:], cmpOpts...))
		require.Empty(cmp.Diff(plgs, []*plugin.Plugin{plg1, plg2}, append(cmpOpts, cmpopts.SortSlices(func(i, j *plugin.Plugin) bool { return i.PublicId < j.PublicId }))...))
	})
}

func TestCatalogRepository_ListRefresh(t *testing.T) {
	t.Parallel()
	assert, require := assert.New(t), require.New(t)
	ctx := context.Background()
	conn, _ := db.TestSetup(t, "postgres")
	rw := db.New(conn)
	wrapper := db.TestWrapper(t)
	plg1 := plugin.TestPlugin(t, conn, "plugin1")
	plg2 := plugin.TestPlugin(t, conn, "plugin2")
	_, prj := iam.TestScopes(t, iam.TestRepo(t, conn, wrapper))
	fiveDaysAgo := time.Now().AddDate(0, 0, -5)

	catalogs := []host.Catalog{
		hostplugin.TestCatalog(t, conn, prj.GetPublicId(), plg1.PublicId),
		static.TestCatalogs(t, conn, prj.GetPublicId(), 1)[0],
		hostplugin.TestCatalog(t, conn, prj.GetPublicId(), plg2.PublicId),
		static.TestCatalogs(t, conn, prj.GetPublicId(), 1)[0],
		static.TestCatalogs(t, conn, prj.GetPublicId(), 1)[0],
	}

	// since we sort descending, we need to reverse the slice
	slices.Reverse(catalogs)

	repo, err := host.NewCatalogRepository(ctx, rw, rw)
	require.NoError(err)

	cmpOpts := []cmp.Option{
		cmpopts.IgnoreUnexported(
			hostplugin.HostCatalog{},
			pstore.HostCatalog{},
			static.HostCatalog{},
			sstore.HostCatalog{},
			plugin.Plugin{},
			plstore.Plugin{},
			timestamp.Timestamp{},
			timestamppb.Timestamp{},
		),
	}

	t.Run("validation", func(t *testing.T) {
		t.Parallel()
		t.Run("missing updated after", func(t *testing.T) {
			t.Parallel()
			_, _, _, err := repo.ListRefresh(ctx, []string{prj.PublicId}, time.Time{}, nil, 1)
			require.ErrorContains(err, "missing updated after time")
		})
		t.Run("missing project ids", func(t *testing.T) {
			t.Parallel()
			_, _, _, err := repo.ListRefresh(ctx, nil, fiveDaysAgo, nil, 1)
			require.ErrorContains(err, "missing project ids")
		})
		t.Run("invalid limit", func(t *testing.T) {
			t.Parallel()
			_, _, _, err := repo.ListRefresh(ctx, []string{prj.PublicId}, fiveDaysAgo, nil, 0)
			require.ErrorContains(err, "missing limit")
		})
	})

	t.Run("success-without-after-item", func(t *testing.T) {
		t.Parallel()
		resp, plgs, ttime, err := repo.ListRefresh(ctx, []string{prj.PublicId}, fiveDaysAgo, nil, 10)
		require.NoError(err)
		// Transaction timestamp should be within ~10 seconds of now
		assert.True(time.Now().Before(ttime.Add(10 * time.Second)))
		assert.True(time.Now().After(ttime.Add(-10 * time.Second)))
		require.Empty(cmp.Diff(resp, catalogs, cmpOpts...))
		require.Empty(cmp.Diff(plgs, []*plugin.Plugin{plg1, plg2}, append(cmpOpts, cmpopts.SortSlices(func(i, j *plugin.Plugin) bool { return i.PublicId < j.PublicId }))...))
	})
	t.Run("success-with-after-item", func(t *testing.T) {
		t.Parallel()
		resp, plgs, ttime, err := repo.ListRefresh(ctx, []string{prj.PublicId}, fiveDaysAgo, catalogs[0], 10)
		require.NoError(err)
		// Transaction timestamp should be within ~10 seconds of now
		assert.True(time.Now().Before(ttime.Add(10 * time.Second)))
		assert.True(time.Now().After(ttime.Add(-10 * time.Second)))
		require.Empty(cmp.Diff(resp, catalogs[1:], cmpOpts...))
		require.Empty(cmp.Diff(plgs, []*plugin.Plugin{plg1, plg2}, append(cmpOpts, cmpopts.SortSlices(func(i, j *plugin.Plugin) bool { return i.PublicId < j.PublicId }))...))
	})
	t.Run("success-without-after-item-recent-updated-after", func(t *testing.T) {
		t.Parallel()
		resp, plgs, ttime, err := repo.ListRefresh(ctx, []string{prj.PublicId}, catalogs[len(catalogs)-1].GetUpdateTime().AsTime(), nil, 10)
		require.NoError(err)
		// Transaction timestamp should be within ~10 seconds of now
		assert.True(time.Now().Before(ttime.Add(10 * time.Second)))
		assert.True(time.Now().After(ttime.Add(-10 * time.Second)))
		require.Empty(cmp.Diff(resp, catalogs[:len(catalogs)-1], cmpOpts...))
		require.Empty(cmp.Diff(plgs, []*plugin.Plugin{plg2}, append(cmpOpts, cmpopts.SortSlices(func(i, j *plugin.Plugin) bool { return i.PublicId < j.PublicId }))...))
	})
	t.Run("success-with-after-item-recent-updated-after", func(t *testing.T) {
		t.Parallel()
		resp, plgs, ttime, err := repo.ListRefresh(ctx, []string{prj.PublicId}, catalogs[len(catalogs)-1].GetUpdateTime().AsTime(), catalogs[0], 10)
		require.NoError(err)
		// Transaction timestamp should be within ~10 seconds of now
		assert.True(time.Now().Before(ttime.Add(10 * time.Second)))
		assert.True(time.Now().After(ttime.Add(-10 * time.Second)))
		require.Empty(cmp.Diff(resp, catalogs[1:len(catalogs)-1], cmpOpts...))
		require.Empty(cmp.Diff(plgs, []*plugin.Plugin{plg2}, append(cmpOpts, cmpopts.SortSlices(func(i, j *plugin.Plugin) bool { return i.PublicId < j.PublicId }))...))
	})
}

func TestCatalogRepository_EstimatedCount(t *testing.T) {
	t.Parallel()
	assert, require := assert.New(t), require.New(t)
	ctx := context.Background()
	conn, _ := db.TestSetup(t, "postgres")
	sqlDb, err := conn.SqlDB(ctx)
	require.NoError(err)
	rw := db.New(conn)
	wrapper := db.TestWrapper(t)
	kmsCache := kms.TestKms(t, conn, wrapper)
	staticRepo, err := static.NewRepository(ctx, rw, rw, kmsCache)
	require.NoError(err)
	plg := plugin.TestPlugin(t, conn, "test")
	_, prj := iam.TestScopes(t, iam.TestRepo(t, conn, wrapper))

	repo, err := host.NewCatalogRepository(ctx, rw, rw)
	require.NoError(err)

	// Check total entries at start, expect 0
	numItems, err := repo.EstimatedCount(ctx)
	require.NoError(err)
	assert.Equal(0, numItems)

	// Create some catalogs
	staticCatalogs := static.TestCatalogs(t, conn, prj.PublicId, 2)
	_ = hostplugin.TestCatalogs(t, conn, prj.PublicId, plg.PublicId, 2)
	// Run analyze to update postgres meta tables
	_, err = sqlDb.ExecContext(ctx, "analyze")
	require.NoError(err)

	numItems, err = repo.EstimatedCount(ctx)
	require.NoError(err)
	assert.Equal(4, numItems)

	// Delete a catalog
	_, err = staticRepo.DeleteCatalog(ctx, staticCatalogs[0].GetPublicId())
	require.NoError(err)
	_, err = sqlDb.ExecContext(ctx, "analyze")
	require.NoError(err)

	numItems, err = repo.EstimatedCount(ctx)
	require.NoError(err)
	assert.Equal(3, numItems)
}

func TestRepository_ListDeletedCatalogIds(t *testing.T) {
	t.Parallel()
	require, assert := require.New(t), assert.New(t)
	ctx := context.Background()
	conn, _ := db.TestSetup(t, "postgres")
	rw := db.New(conn)
	wrapper := db.TestWrapper(t)
	kms := kms.TestKms(t, conn, wrapper)
	sche := scheduler.TestScheduler(t, conn, wrapper)
	plg := plugin.TestPlugin(t, conn, "test")
	_, prj := iam.TestScopes(t, iam.TestRepo(t, conn, wrapper))
	staticCatalog := static.TestCatalogs(t, conn, prj.GetPublicId(), 1)[0]
	pluginCatalog := hostplugin.TestCatalog(t, conn, prj.GetPublicId(), plg.PublicId)
	plgm := map[string]plgpb.HostPluginServiceClient{
		plg.GetPublicId(): &loopback.WrappingPluginHostClient{Server: &loopback.TestPluginServer{}},
	}

	staticRepo, err := static.NewRepository(ctx, rw, rw, kms)
	require.NoError(err)
	pluginRepo, err := hostplugin.NewRepository(ctx, rw, rw, kms, sche, plgm)
	require.NoError(err)
	repo, err := host.NewCatalogRepository(ctx, rw, rw)
	require.NoError(err)

	// Expect no entries at the start
	deletedIds, ttime, err := repo.ListDeletedIds(ctx, time.Now().AddDate(-1, 0, 0))
	require.NoError(err)
	require.Empty(deletedIds)
	// Transaction timestamp should be within ~10 seconds of now
	assert.True(time.Now().Before(ttime.Add(10 * time.Second)))
	assert.True(time.Now().After(ttime.Add(-10 * time.Second)))

	_, err = staticRepo.DeleteCatalog(ctx, staticCatalog.GetPublicId())
	require.NoError(err)

	// Expect one entry
	deletedIds, ttime, err = repo.ListDeletedIds(ctx, time.Now().AddDate(-1, 0, 0))
	require.NoError(err)
	assert.Empty(
		cmp.Diff(
			[]string{staticCatalog.GetPublicId()},
			deletedIds,
			cmpopts.SortSlices(func(i, j string) bool { return i < j }),
		),
	)
	assert.True(time.Now().Before(ttime.Add(10 * time.Second)))
	assert.True(time.Now().After(ttime.Add(-10 * time.Second)))

	_, err = pluginRepo.DeleteCatalog(ctx, pluginCatalog.GetPublicId())
	require.NoError(err)

	// Expect two entries
	deletedIds, ttime, err = repo.ListDeletedIds(ctx, time.Now().AddDate(-1, 0, 0))
	require.NoError(err)
	assert.Empty(
		cmp.Diff(
			[]string{staticCatalog.GetPublicId(), pluginCatalog.GetPublicId()},
			deletedIds,
			cmpopts.SortSlices(func(i, j string) bool { return i < j }),
		),
	)
	assert.True(time.Now().Before(ttime.Add(10 * time.Second)))
	assert.True(time.Now().After(ttime.Add(-10 * time.Second)))

	// Try again with the time set to now, expect no entries
	deletedIds, ttime, err = repo.ListDeletedIds(ctx, time.Now())
	require.NoError(err)
	require.Empty(deletedIds)
	assert.True(time.Now().Before(ttime.Add(10 * time.Second)))
	assert.True(time.Now().After(ttime.Add(-10 * time.Second)))
}
