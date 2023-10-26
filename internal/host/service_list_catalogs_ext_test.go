// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: BUSL-1.1

package host_test

import (
	"context"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	"github.com/hashicorp/boundary/internal/db"
	"github.com/hashicorp/boundary/internal/db/timestamp"
	"github.com/hashicorp/boundary/internal/host"
	"github.com/hashicorp/boundary/internal/host/plugin"
	pstore "github.com/hashicorp/boundary/internal/host/plugin/store"
	"github.com/hashicorp/boundary/internal/host/static"
	sstore "github.com/hashicorp/boundary/internal/host/static/store"
	"github.com/hashicorp/boundary/internal/iam"
	"github.com/hashicorp/boundary/internal/kms"
	pg "github.com/hashicorp/boundary/internal/plugin"
	"github.com/hashicorp/boundary/internal/plugin/loopback"
	"github.com/hashicorp/boundary/internal/refreshtoken"
	"github.com/hashicorp/boundary/internal/scheduler"
	"github.com/hashicorp/boundary/internal/types/resource"
	plgpb "github.com/hashicorp/boundary/sdk/pbs/plugin"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/types/known/timestamppb"
)

type fakeWriter struct {
	db.Writer
}

type fakePluginRepository struct {
	host.PluginCatalogRepository
}

type fakeStaticRepository struct {
	host.StaticCatalogRepository
}

func TestNewCatalogService(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	t.Run("success", func(t *testing.T) {
		t.Parallel()
		got, err := host.NewCatalogService(ctx, &fakeWriter{}, &fakePluginRepository{}, &fakeStaticRepository{})
		require.NoError(t, err)
		require.NotNil(t, got)
	})
	t.Run("nil-writer", func(t *testing.T) {
		t.Parallel()
		_, err := host.NewCatalogService(ctx, nil, &fakePluginRepository{}, &fakeStaticRepository{})
		require.Error(t, err)
	})
	t.Run("nil-interface-writer", func(t *testing.T) {
		t.Parallel()
		_, err := host.NewCatalogService(ctx, (*fakeWriter)(nil), &fakePluginRepository{}, &fakeStaticRepository{})
		require.Error(t, err)
	})
	t.Run("nil-plugin-repo", func(t *testing.T) {
		t.Parallel()
		_, err := host.NewCatalogService(ctx, &fakeWriter{}, nil, &fakeStaticRepository{})
		require.Error(t, err)
	})
	t.Run("nil-plugin-interface-repo", func(t *testing.T) {
		t.Parallel()
		_, err := host.NewCatalogService(ctx, &fakeWriter{}, (*fakePluginRepository)(nil), &fakeStaticRepository{})
		require.Error(t, err)
	})
	t.Run("nil-static-repo", func(t *testing.T) {
		t.Parallel()
		_, err := host.NewCatalogService(ctx, &fakeWriter{}, &fakePluginRepository{}, nil)
		require.Error(t, err)
	})
	t.Run("nil-static-interface-repo", func(t *testing.T) {
		t.Parallel()
		_, err := host.NewCatalogService(ctx, &fakeWriter{}, &fakePluginRepository{}, (*fakeStaticRepository)(nil))
		require.Error(t, err)
	})
}

func TestService_List(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	conn, _ := db.TestSetup(t, "postgres")
	sqlDb, err := conn.SqlDB(ctx)
	require.NoError(t, err)
	wrapper := db.TestWrapper(t)
	testKms := kms.TestKms(t, conn, wrapper)
	sche := scheduler.TestScheduler(t, conn, wrapper)
	iamRepo := iam.TestRepo(t, conn, wrapper)
	_, proj1 := iam.TestScopes(t, iamRepo)
	plg := pg.TestPlugin(t, conn, "test")
	catalogs := []host.Catalog{
		plugin.TestCatalog(t, conn, proj1.GetPublicId(), plg.GetPublicId()),
		static.TestCatalogs(t, conn, proj1.GetPublicId(), 1)[0],
		plugin.TestCatalog(t, conn, proj1.GetPublicId(), plg.GetPublicId()),
		static.TestCatalogs(t, conn, proj1.GetPublicId(), 1)[0],
		plugin.TestCatalog(t, conn, proj1.GetPublicId(), plg.GetPublicId()),
	}

	// Run analyze to update catalogs estimate
	_, err = sqlDb.ExecContext(ctx, "analyze")
	require.NoError(t, err)

	rw := db.New(conn)
	plgm := map[string]plgpb.HostPluginServiceClient{
		plg.GetPublicId(): loopback.NewWrappingPluginHostClient(&plgpb.UnimplementedHostPluginServiceServer{}),
	}
	pluginRepo, err := plugin.NewRepository(ctx, rw, rw, testKms, sche, plgm)
	require.NoError(t, err)
	staticRepo, err := static.NewRepository(ctx, rw, rw, testKms)
	require.NoError(t, err)

	service, err := host.NewCatalogService(ctx, rw, pluginRepo, staticRepo)
	require.NoError(t, err)

	cmpOpts := cmpopts.IgnoreUnexported(
		plugin.HostCatalog{},
		pstore.HostCatalog{},
		static.HostCatalog{},
		sstore.HostCatalog{},
		timestamp.Timestamp{},
		timestamppb.Timestamp{},
	)

	t.Run("List validation", func(t *testing.T) {
		t.Parallel()
		t.Run("missing grants hash", func(t *testing.T) {
			t.Parallel()
			filterFunc := func(_ context.Context, c host.Catalog, _ []*pg.Plugin) (bool, error) {
				return true, nil
			}
			_, _, err := service.List(ctx, nil, 1, filterFunc, []string{proj1.GetPublicId()})
			require.ErrorContains(t, err, "missing grants hash")
		})
		t.Run("zero page size", func(t *testing.T) {
			t.Parallel()
			filterFunc := func(_ context.Context, c host.Catalog, _ []*pg.Plugin) (bool, error) {
				return true, nil
			}
			_, _, err := service.List(ctx, []byte("some hash"), 0, filterFunc, []string{proj1.GetPublicId()})
			require.ErrorContains(t, err, "page size must be at least 1")
		})
		t.Run("negative page size", func(t *testing.T) {
			t.Parallel()
			filterFunc := func(_ context.Context, c host.Catalog, _ []*pg.Plugin) (bool, error) {
				return true, nil
			}
			_, _, err := service.List(ctx, []byte("some hash"), -1, filterFunc, []string{proj1.GetPublicId()})
			require.ErrorContains(t, err, "page size must be at least 1")
		})
		t.Run("nil filter func", func(t *testing.T) {
			t.Parallel()
			_, _, err := service.List(ctx, []byte("some hash"), 1, nil, []string{proj1.GetPublicId()})
			require.ErrorContains(t, err, "missing filter item callback")
		})
		t.Run("missing project ids", func(t *testing.T) {
			t.Parallel()
			filterFunc := func(_ context.Context, c host.Catalog, _ []*pg.Plugin) (bool, error) {
				return true, nil
			}
			_, _, err := service.List(ctx, []byte("some hash"), 1, filterFunc, nil)
			require.ErrorContains(t, err, "missing project ids")
		})
	})

	t.Run("ListRefresh validation", func(t *testing.T) {
		t.Parallel()
		t.Run("missing grants hash", func(t *testing.T) {
			t.Parallel()
			filterFunc := func(_ context.Context, c host.Catalog, _ []*pg.Plugin) (bool, error) {
				return true, nil
			}
			tok, err := refreshtoken.New(ctx, time.Now(), time.Now(), resource.HostCatalog, []byte("some hash"), "some-id", time.Now())
			require.NoError(t, err)
			_, _, err = service.ListRefresh(ctx, nil, 1, filterFunc, tok, []string{proj1.GetPublicId()})
			require.ErrorContains(t, err, "missing grants hash")
		})
		t.Run("zero page size", func(t *testing.T) {
			t.Parallel()
			filterFunc := func(_ context.Context, c host.Catalog, _ []*pg.Plugin) (bool, error) {
				return true, nil
			}
			tok, err := refreshtoken.New(ctx, time.Now(), time.Now(), resource.HostCatalog, []byte("some hash"), "some-id", time.Now())
			require.NoError(t, err)
			_, _, err = service.ListRefresh(ctx, []byte("some hash"), 0, filterFunc, tok, []string{proj1.GetPublicId()})
			require.ErrorContains(t, err, "page size must be at least 1")
		})
		t.Run("negative page size", func(t *testing.T) {
			t.Parallel()
			filterFunc := func(_ context.Context, c host.Catalog, _ []*pg.Plugin) (bool, error) {
				return true, nil
			}
			tok, err := refreshtoken.New(ctx, time.Now(), time.Now(), resource.HostCatalog, []byte("some hash"), "some-id", time.Now())
			require.NoError(t, err)
			_, _, err = service.ListRefresh(ctx, []byte("some hash"), -1, filterFunc, tok, []string{proj1.GetPublicId()})
			require.ErrorContains(t, err, "page size must be at least 1")
		})
		t.Run("nil filter func", func(t *testing.T) {
			t.Parallel()
			tok, err := refreshtoken.New(ctx, time.Now(), time.Now(), resource.HostCatalog, []byte("some hash"), "some-id", time.Now())
			require.NoError(t, err)
			_, _, err = service.ListRefresh(ctx, []byte("some hash"), 1, nil, tok, []string{proj1.GetPublicId()})
			require.ErrorContains(t, err, "missing filter item callback")
		})
		t.Run("nil token", func(t *testing.T) {
			t.Parallel()
			filterFunc := func(_ context.Context, c host.Catalog, _ []*pg.Plugin) (bool, error) {
				return true, nil
			}
			_, _, err = service.ListRefresh(ctx, []byte("some hash"), 1, filterFunc, nil, []string{proj1.GetPublicId()})
			require.ErrorContains(t, err, "missing token")
		})
		t.Run("missing project ids", func(t *testing.T) {
			t.Parallel()
			filterFunc := func(_ context.Context, c host.Catalog, _ []*pg.Plugin) (bool, error) {
				return true, nil
			}
			tok, err := refreshtoken.New(ctx, time.Now(), time.Now(), resource.HostCatalog, []byte("some hash"), "some-id", time.Now())
			require.NoError(t, err)
			_, _, err = service.ListRefresh(ctx, []byte("some hash"), 1, filterFunc, tok, nil)
			require.ErrorContains(t, err, "missing project ids")
		})
	})

	t.Run("simple pagination", func(t *testing.T) {
		filterFunc := func(_ context.Context, c host.Catalog, _ []*pg.Plugin) (bool, error) {
			return true, nil
		}
		resp, plgs, err := service.List(ctx, []byte("some hash"), 1, filterFunc, []string{proj1.GetPublicId()})
		require.NoError(t, err)
		require.NotNil(t, resp.RefreshToken)
		require.Equal(t, resp.RefreshToken.GrantsHash, []byte("some hash"))
		require.False(t, resp.CompleteListing)
		require.Equal(t, resp.EstimatedItemCount, 5)
		require.Empty(t, resp.DeletedIds)
		require.Len(t, resp.Items, 1)
		require.Empty(t, cmp.Diff(resp.Items[0], catalogs[0], cmpOpts))
		require.Len(t, plgs, 1)
		require.Equal(t, plgs[0], plg)

		resp2, plgs, err := service.ListRefresh(ctx, []byte("some hash"), 1, filterFunc, resp.RefreshToken, []string{proj1.GetPublicId()})
		require.NoError(t, err)
		require.Equal(t, resp2.RefreshToken.GrantsHash, []byte("some hash"))
		require.False(t, resp2.CompleteListing)
		require.Equal(t, resp2.EstimatedItemCount, 5)
		require.Empty(t, resp2.DeletedIds)
		require.Len(t, resp2.Items, 1)
		require.Empty(t, cmp.Diff(resp2.Items[0], catalogs[1], cmpOpts))
		require.Len(t, plgs, 1)
		require.Equal(t, plgs[0], plg)

		resp3, plgs, err := service.ListRefresh(ctx, []byte("some hash"), 1, filterFunc, resp2.RefreshToken, []string{proj1.GetPublicId()})
		require.NoError(t, err)
		require.Equal(t, resp3.RefreshToken.GrantsHash, []byte("some hash"))
		require.False(t, resp3.CompleteListing)
		require.Equal(t, resp3.EstimatedItemCount, 5)
		require.Empty(t, resp3.DeletedIds)
		require.Len(t, resp3.Items, 1)
		require.Empty(t, cmp.Diff(resp3.Items[0], catalogs[2], cmpOpts))
		require.Len(t, plgs, 1)
		require.Equal(t, plgs[0], plg)

		resp4, plgs, err := service.ListRefresh(ctx, []byte("some hash"), 1, filterFunc, resp3.RefreshToken, []string{proj1.GetPublicId()})
		require.NoError(t, err)
		require.Equal(t, resp4.RefreshToken.GrantsHash, []byte("some hash"))
		require.False(t, resp4.CompleteListing)
		require.Equal(t, resp4.EstimatedItemCount, 5)
		require.Empty(t, resp4.DeletedIds)
		require.Len(t, resp4.Items, 1)
		require.Empty(t, cmp.Diff(resp4.Items[0], catalogs[3], cmpOpts))
		require.Len(t, plgs, 1)
		require.Equal(t, plgs[0], plg)

		resp5, plgs, err := service.ListRefresh(ctx, []byte("some hash"), 1, filterFunc, resp4.RefreshToken, []string{proj1.GetPublicId()})
		require.NoError(t, err)
		require.Equal(t, resp5.RefreshToken.GrantsHash, []byte("some hash"))
		require.True(t, resp5.CompleteListing)
		require.Equal(t, resp5.EstimatedItemCount, 5)
		require.Empty(t, resp5.DeletedIds)
		require.Len(t, resp5.Items, 1)
		require.Empty(t, cmp.Diff(resp5.Items[0], catalogs[4], cmpOpts))
		require.Len(t, plgs, 1)
		require.Equal(t, plgs[0], plg)

		resp6, plgs, err := service.ListRefresh(ctx, []byte("some hash"), 1, filterFunc, resp5.RefreshToken, []string{proj1.GetPublicId()})
		require.NoError(t, err)
		require.Equal(t, resp6.RefreshToken.GrantsHash, []byte("some hash"))
		require.True(t, resp6.CompleteListing)
		require.Equal(t, resp6.EstimatedItemCount, 5)
		require.Empty(t, resp6.DeletedIds)
		require.Empty(t, resp6.Items)
		require.Empty(t, plgs)
	})

	t.Run("simple pagination with aggressive filtering", func(t *testing.T) {
		filterFunc := func(_ context.Context, c host.Catalog, _ []*pg.Plugin) (bool, error) {
			return c.GetPublicId() == catalogs[len(catalogs)-1].GetPublicId(), nil
		}
		resp, plgs, err := service.List(ctx, []byte("some hash"), 1, filterFunc, []string{proj1.GetPublicId()})
		require.NoError(t, err)
		require.NotNil(t, resp.RefreshToken)
		require.Equal(t, resp.RefreshToken.GrantsHash, []byte("some hash"))
		require.True(t, resp.CompleteListing)
		require.Equal(t, resp.EstimatedItemCount, 1)
		require.Empty(t, resp.DeletedIds)
		require.Len(t, resp.Items, 1)
		require.Empty(t, cmp.Diff(resp.Items[0], catalogs[4], cmpOpts))
		require.Len(t, plgs, 1)
		require.Equal(t, plgs[0], plg)

		resp2, plgs, err := service.ListRefresh(ctx, []byte("some hash"), 1, filterFunc, resp.RefreshToken, []string{proj1.GetPublicId()})
		require.NoError(t, err)
		require.Equal(t, resp2.RefreshToken.GrantsHash, []byte("some hash"))
		require.True(t, resp2.CompleteListing)
		// Note: this might be surprising, but there isn't any way for the refresh
		// call to know that the last call got a different number.
		require.Equal(t, resp2.EstimatedItemCount, 5)
		require.Empty(t, resp2.DeletedIds)
		require.Empty(t, resp2.Items)
		require.Empty(t, plgs)
	})

	t.Run("simple pagination with deletion", func(t *testing.T) {
		filterFunc := func(_ context.Context, c host.Catalog, _ []*pg.Plugin) (bool, error) {
			return true, nil
		}
		deletedCatalogId := catalogs[0].GetPublicId()
		_, err := pluginRepo.DeleteCatalog(ctx, deletedCatalogId)
		require.NoError(t, err)
		catalogs = catalogs[1:]

		// Run analyze to update target estimate
		_, err = sqlDb.ExecContext(ctx, "analyze")
		require.NoError(t, err)

		resp, plgs, err := service.List(ctx, []byte("some hash"), 1, filterFunc, []string{proj1.GetPublicId()})
		require.NoError(t, err)
		require.NotNil(t, resp.RefreshToken)
		require.Equal(t, resp.RefreshToken.GrantsHash, []byte("some hash"))
		require.False(t, resp.CompleteListing)
		require.Equal(t, resp.EstimatedItemCount, 4)
		require.Empty(t, resp.DeletedIds)
		require.Len(t, resp.Items, 1)
		require.Empty(t, cmp.Diff(resp.Items[0], catalogs[0], cmpOpts))
		require.Len(t, plgs, 1)
		require.Equal(t, plgs[0], plg)

		resp2, plgs, err := service.ListRefresh(ctx, []byte("some hash"), 1, filterFunc, resp.RefreshToken, []string{proj1.GetPublicId()})
		require.NoError(t, err)
		require.Equal(t, resp2.RefreshToken.GrantsHash, []byte("some hash"))
		require.False(t, resp2.CompleteListing)
		require.Equal(t, resp2.EstimatedItemCount, 4)
		require.Empty(t, resp2.DeletedIds)
		require.Len(t, resp2.Items, 1)
		require.Empty(t, cmp.Diff(resp2.Items[0], catalogs[1], cmpOpts))
		require.Len(t, plgs, 1)
		require.Equal(t, plgs[0], plg)

		deletedCatalogId = catalogs[0].GetPublicId()
		_, err = staticRepo.DeleteCatalog(ctx, deletedCatalogId)
		require.NoError(t, err)
		catalogs = catalogs[1:]

		// Run analyze to update target estimate
		_, err = sqlDb.ExecContext(ctx, "analyze")
		require.NoError(t, err)

		resp3, plgs, err := service.ListRefresh(ctx, []byte("some hash"), 1, filterFunc, resp2.RefreshToken, []string{proj1.GetPublicId()})
		require.NoError(t, err)
		require.Equal(t, resp3.RefreshToken.GrantsHash, []byte("some hash"))
		require.False(t, resp3.CompleteListing)
		require.Equal(t, resp3.EstimatedItemCount, 3)
		require.Contains(t, resp3.DeletedIds, deletedCatalogId)
		require.Len(t, resp3.Items, 1)
		require.Empty(t, cmp.Diff(resp3.Items[0], catalogs[1], cmpOpts))
		require.Len(t, plgs, 1)
		require.Equal(t, plgs[0], plg)

		resp4, plgs, err := service.ListRefresh(ctx, []byte("some hash"), 1, filterFunc, resp3.RefreshToken, []string{proj1.GetPublicId()})
		require.NoError(t, err)
		require.Equal(t, resp4.RefreshToken.GrantsHash, []byte("some hash"))
		require.True(t, resp4.CompleteListing)
		require.Equal(t, resp4.EstimatedItemCount, 3)
		require.Len(t, resp4.Items, 1)
		require.Empty(t, cmp.Diff(resp4.Items[0], catalogs[2], cmpOpts))
		require.Len(t, plgs, 1)
		require.Equal(t, plgs[0], plg)

		resp5, plgs, err := service.ListRefresh(ctx, []byte("some hash"), 1, filterFunc, resp4.RefreshToken, []string{proj1.GetPublicId()})
		require.NoError(t, err)
		require.Equal(t, resp5.RefreshToken.GrantsHash, []byte("some hash"))
		require.True(t, resp5.CompleteListing)
		require.Equal(t, resp5.EstimatedItemCount, 3)
		require.Empty(t, resp5.Items)
		require.Empty(t, plgs)
	})
}
