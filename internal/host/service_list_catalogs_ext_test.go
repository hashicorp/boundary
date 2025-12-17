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
	"github.com/hashicorp/boundary/globals"
	"github.com/hashicorp/boundary/internal/db"
	"github.com/hashicorp/boundary/internal/db/timestamp"
	"github.com/hashicorp/boundary/internal/host"
	hostplugin "github.com/hashicorp/boundary/internal/host/plugin"
	pstore "github.com/hashicorp/boundary/internal/host/plugin/store"
	"github.com/hashicorp/boundary/internal/host/static"
	sstore "github.com/hashicorp/boundary/internal/host/static/store"
	"github.com/hashicorp/boundary/internal/iam"
	"github.com/hashicorp/boundary/internal/kms"
	"github.com/hashicorp/boundary/internal/listtoken"
	"github.com/hashicorp/boundary/internal/plugin"
	plstore "github.com/hashicorp/boundary/internal/plugin/store"
	"github.com/hashicorp/boundary/internal/types/resource"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/types/known/timestamppb"
)

type fakeReader struct {
	db.Reader
}

type fakeWriter struct {
	db.Writer
}

func TestNewCatalogService(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	t.Run("success", func(t *testing.T) {
		t.Parallel()
		got, err := host.NewCatalogRepository(ctx, &fakeReader{}, &fakeWriter{})
		require.NoError(t, err)
		require.NotNil(t, got)
	})
	t.Run("nil-reader", func(t *testing.T) {
		t.Parallel()
		_, err := host.NewCatalogRepository(ctx, nil, &fakeWriter{})
		require.Error(t, err)
	})
	t.Run("nil-interface-reader", func(t *testing.T) {
		t.Parallel()
		_, err := host.NewCatalogRepository(ctx, (*fakeReader)(nil), &fakeWriter{})
		require.Error(t, err)
	})
	t.Run("nil-writer", func(t *testing.T) {
		t.Parallel()
		_, err := host.NewCatalogRepository(ctx, &fakeReader{}, nil)
		require.Error(t, err)
	})
	t.Run("nil-interface-writer", func(t *testing.T) {
		t.Parallel()
		_, err := host.NewCatalogRepository(ctx, &fakeReader{}, (*fakeWriter)(nil))
		require.Error(t, err)
	})
}

func TestCatalogService_List(t *testing.T) {
	// Set database read timeout to avoid duplicates in response
	oldReadTimeout := globals.RefreshReadLookbackDuration
	globals.RefreshReadLookbackDuration = 0
	t.Cleanup(func() {
		globals.RefreshReadLookbackDuration = oldReadTimeout
	})
	ctx := context.Background()
	conn, _ := db.TestSetup(t, "postgres")
	sqlDb, err := conn.SqlDB(ctx)
	require.NoError(t, err)
	rw := db.New(conn)
	wrapper := db.TestWrapper(t)
	kms := kms.TestKms(t, conn, wrapper)
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

	staticRepo, err := static.NewRepository(ctx, rw, rw, kms)
	require.NoError(t, err)
	repo, err := host.NewCatalogRepository(ctx, rw, rw)
	require.NoError(t, err)

	// Run analyze to update count estimate
	_, err = sqlDb.ExecContext(ctx, "analyze")
	require.NoError(t, err)

	cmpOpts := []cmp.Option{
		cmpopts.IgnoreUnexported(
			hostplugin.HostCatalog{},
			pstore.HostCatalog{},
			static.HostCatalog{},
			sstore.HostCatalog{},
			plstore.Plugin{},
			timestamp.Timestamp{},
			timestamppb.Timestamp{},
		),
	}

	t.Run("List validation", func(t *testing.T) {
		t.Parallel()
		t.Run("missing grants hash", func(t *testing.T) {
			t.Parallel()
			filterFunc := func(_ context.Context, c host.Catalog, plgs map[string]*plugin.Plugin) (bool, error) {
				return true, nil
			}
			_, _, err := host.ListCatalogs(ctx, nil, 1, filterFunc, repo, []string{prj.PublicId})
			require.ErrorContains(t, err, "missing grants hash")
		})
		t.Run("zero page size", func(t *testing.T) {
			t.Parallel()
			filterFunc := func(_ context.Context, c host.Catalog, plgs map[string]*plugin.Plugin) (bool, error) {
				return true, nil
			}
			_, _, err := host.ListCatalogs(ctx, []byte("some hash"), 0, filterFunc, repo, []string{prj.PublicId})
			require.ErrorContains(t, err, "page size must be at least 1")
		})
		t.Run("negative page size", func(t *testing.T) {
			t.Parallel()
			filterFunc := func(_ context.Context, c host.Catalog, plgs map[string]*plugin.Plugin) (bool, error) {
				return true, nil
			}
			_, _, err := host.ListCatalogs(ctx, []byte("some hash"), -1, filterFunc, repo, []string{prj.PublicId})
			require.ErrorContains(t, err, "page size must be at least 1")
		})
		t.Run("nil filter func", func(t *testing.T) {
			t.Parallel()
			_, _, err := host.ListCatalogs(ctx, []byte("some hash"), 1, nil, repo, []string{prj.PublicId})
			require.ErrorContains(t, err, "missing filter item callback")
		})
		t.Run("missing repo", func(t *testing.T) {
			t.Parallel()
			filterFunc := func(_ context.Context, c host.Catalog, plgs map[string]*plugin.Plugin) (bool, error) {
				return true, nil
			}
			_, _, err := host.ListCatalogs(ctx, []byte("some hash"), 1, filterFunc, nil, []string{prj.PublicId})
			require.ErrorContains(t, err, "missing repo")
		})
		t.Run("missing public Ids", func(t *testing.T) {
			t.Parallel()
			filterFunc := func(_ context.Context, c host.Catalog, plgs map[string]*plugin.Plugin) (bool, error) {
				return true, nil
			}
			_, _, err := host.ListCatalogs(ctx, []byte("some hash"), 1, filterFunc, repo, nil)
			require.ErrorContains(t, err, "missing project ids")
		})
	})
	t.Run("ListPage validation", func(t *testing.T) {
		t.Parallel()
		t.Run("missing grants hash", func(t *testing.T) {
			t.Parallel()
			filterFunc := func(_ context.Context, c host.Catalog, plgs map[string]*plugin.Plugin) (bool, error) {
				return true, nil
			}
			tok, err := listtoken.NewPagination(ctx, fiveDaysAgo, resource.HostCatalog, []byte("some hash"), "some-id", fiveDaysAgo)
			require.NoError(t, err)
			_, _, err = host.ListCatalogsPage(ctx, nil, 1, filterFunc, tok, repo, []string{prj.PublicId})
			require.ErrorContains(t, err, "missing grants hash")
		})
		t.Run("zero page size", func(t *testing.T) {
			t.Parallel()
			filterFunc := func(_ context.Context, c host.Catalog, plgs map[string]*plugin.Plugin) (bool, error) {
				return true, nil
			}
			tok, err := listtoken.NewPagination(ctx, fiveDaysAgo, resource.HostCatalog, []byte("some hash"), "some-id", fiveDaysAgo)
			require.NoError(t, err)
			_, _, err = host.ListCatalogsPage(ctx, []byte("some hash"), 0, filterFunc, tok, repo, []string{prj.PublicId})
			require.ErrorContains(t, err, "page size must be at least 1")
		})
		t.Run("negative page size", func(t *testing.T) {
			t.Parallel()
			filterFunc := func(_ context.Context, c host.Catalog, plgs map[string]*plugin.Plugin) (bool, error) {
				return true, nil
			}
			tok, err := listtoken.NewPagination(ctx, fiveDaysAgo, resource.HostCatalog, []byte("some hash"), "some-id", fiveDaysAgo)
			require.NoError(t, err)
			_, _, err = host.ListCatalogsPage(ctx, []byte("some hash"), -1, filterFunc, tok, repo, []string{prj.PublicId})
			require.ErrorContains(t, err, "page size must be at least 1")
		})
		t.Run("nil filter func", func(t *testing.T) {
			t.Parallel()
			tok, err := listtoken.NewPagination(ctx, fiveDaysAgo, resource.HostCatalog, []byte("some hash"), "some-id", fiveDaysAgo)
			require.NoError(t, err)
			_, _, err = host.ListCatalogsPage(ctx, []byte("some hash"), 1, nil, tok, repo, []string{prj.PublicId})
			require.ErrorContains(t, err, "missing filter item callback")
		})
		t.Run("nil token", func(t *testing.T) {
			t.Parallel()
			filterFunc := func(_ context.Context, c host.Catalog, plgs map[string]*plugin.Plugin) (bool, error) {
				return true, nil
			}
			_, _, err := host.ListCatalogsPage(ctx, []byte("some hash"), 1, filterFunc, nil, repo, []string{prj.PublicId})
			require.ErrorContains(t, err, "missing token")
		})
		t.Run("wrong token type", func(t *testing.T) {
			t.Parallel()
			filterFunc := func(_ context.Context, c host.Catalog, plgs map[string]*plugin.Plugin) (bool, error) {
				return true, nil
			}
			tok, err := listtoken.NewStartRefresh(ctx, fiveDaysAgo, resource.HostCatalog, []byte("some hash"), fiveDaysAgo, fiveDaysAgo)
			require.NoError(t, err)
			_, _, err = host.ListCatalogsPage(ctx, []byte("some hash"), 1, filterFunc, tok, repo, []string{prj.PublicId})
			require.ErrorContains(t, err, "token did not have a pagination token component")
		})
		t.Run("missing repo", func(t *testing.T) {
			t.Parallel()
			filterFunc := func(_ context.Context, c host.Catalog, plgs map[string]*plugin.Plugin) (bool, error) {
				return true, nil
			}
			tok, err := listtoken.NewPagination(ctx, fiveDaysAgo, resource.HostCatalog, []byte("some hash"), "some-id", fiveDaysAgo)
			require.NoError(t, err)
			_, _, err = host.ListCatalogsPage(ctx, []byte("some hash"), 1, filterFunc, tok, nil, []string{prj.PublicId})
			require.ErrorContains(t, err, "missing repo")
		})
		t.Run("missing project ids", func(t *testing.T) {
			t.Parallel()
			filterFunc := func(_ context.Context, c host.Catalog, plgs map[string]*plugin.Plugin) (bool, error) {
				return true, nil
			}
			tok, err := listtoken.NewPagination(ctx, fiveDaysAgo, resource.HostCatalog, []byte("some hash"), "some-id", fiveDaysAgo)
			require.NoError(t, err)
			_, _, err = host.ListCatalogsPage(ctx, []byte("some hash"), 1, filterFunc, tok, repo, nil)
			require.ErrorContains(t, err, "missing project ids")
		})
		t.Run("wrong token resource type", func(t *testing.T) {
			t.Parallel()
			filterFunc := func(_ context.Context, c host.Catalog, plgs map[string]*plugin.Plugin) (bool, error) {
				return true, nil
			}
			tok, err := listtoken.NewPagination(ctx, fiveDaysAgo, resource.Target, []byte("some hash"), "some-id", fiveDaysAgo)
			require.NoError(t, err)
			_, _, err = host.ListCatalogsPage(ctx, []byte("some hash"), 1, filterFunc, tok, repo, []string{prj.PublicId})
			require.ErrorContains(t, err, "token did not have a host catalog resource type")
		})
	})
	t.Run("ListRefresh validation", func(t *testing.T) {
		t.Parallel()
		t.Run("missing grants hash", func(t *testing.T) {
			t.Parallel()
			filterFunc := func(_ context.Context, c host.Catalog, plgs map[string]*plugin.Plugin) (bool, error) {
				return true, nil
			}
			tok, err := listtoken.NewStartRefresh(ctx, fiveDaysAgo, resource.HostCatalog, []byte("some hash"), fiveDaysAgo, fiveDaysAgo)
			require.NoError(t, err)
			_, _, err = host.ListCatalogsRefresh(ctx, nil, 1, filterFunc, tok, repo, []string{prj.PublicId})
			require.ErrorContains(t, err, "missing grants hash")
		})
		t.Run("zero page size", func(t *testing.T) {
			t.Parallel()
			filterFunc := func(_ context.Context, c host.Catalog, plgs map[string]*plugin.Plugin) (bool, error) {
				return true, nil
			}
			tok, err := listtoken.NewStartRefresh(ctx, fiveDaysAgo, resource.HostCatalog, []byte("some hash"), fiveDaysAgo, fiveDaysAgo)
			require.NoError(t, err)
			_, _, err = host.ListCatalogsRefresh(ctx, []byte("some hash"), 0, filterFunc, tok, repo, []string{prj.PublicId})
			require.ErrorContains(t, err, "page size must be at least 1")
		})
		t.Run("negative page size", func(t *testing.T) {
			t.Parallel()
			filterFunc := func(_ context.Context, c host.Catalog, plgs map[string]*plugin.Plugin) (bool, error) {
				return true, nil
			}
			tok, err := listtoken.NewStartRefresh(ctx, fiveDaysAgo, resource.HostCatalog, []byte("some hash"), fiveDaysAgo, fiveDaysAgo)
			require.NoError(t, err)
			_, _, err = host.ListCatalogsRefresh(ctx, []byte("some hash"), -1, filterFunc, tok, repo, []string{prj.PublicId})
			require.ErrorContains(t, err, "page size must be at least 1")
		})
		t.Run("nil filter func", func(t *testing.T) {
			t.Parallel()
			tok, err := listtoken.NewStartRefresh(ctx, fiveDaysAgo, resource.HostCatalog, []byte("some hash"), fiveDaysAgo, fiveDaysAgo)
			require.NoError(t, err)
			_, _, err = host.ListCatalogsRefresh(ctx, []byte("some hash"), 1, nil, tok, repo, []string{prj.PublicId})
			require.ErrorContains(t, err, "missing filter item callback")
		})
		t.Run("nil token", func(t *testing.T) {
			t.Parallel()
			filterFunc := func(_ context.Context, c host.Catalog, plgs map[string]*plugin.Plugin) (bool, error) {
				return true, nil
			}
			_, _, err := host.ListCatalogsRefresh(ctx, []byte("some hash"), 1, filterFunc, nil, repo, []string{prj.PublicId})
			require.ErrorContains(t, err, "missing token")
		})
		t.Run("missing repo", func(t *testing.T) {
			t.Parallel()
			filterFunc := func(_ context.Context, c host.Catalog, plgs map[string]*plugin.Plugin) (bool, error) {
				return true, nil
			}
			tok, err := listtoken.NewStartRefresh(ctx, fiveDaysAgo, resource.HostCatalog, []byte("some hash"), fiveDaysAgo, fiveDaysAgo)
			require.NoError(t, err)
			_, _, err = host.ListCatalogsRefresh(ctx, []byte("some hash"), 1, filterFunc, tok, nil, []string{prj.PublicId})
			require.ErrorContains(t, err, "missing repo")
		})
		t.Run("missing project ids", func(t *testing.T) {
			t.Parallel()
			filterFunc := func(_ context.Context, c host.Catalog, plgs map[string]*plugin.Plugin) (bool, error) {
				return true, nil
			}
			tok, err := listtoken.NewStartRefresh(ctx, fiveDaysAgo, resource.HostCatalog, []byte("some hash"), fiveDaysAgo, fiveDaysAgo)
			require.NoError(t, err)
			_, _, err = host.ListCatalogsRefresh(ctx, []byte("some hash"), 1, filterFunc, tok, repo, nil)
			require.ErrorContains(t, err, "missing project ids")
		})
		t.Run("wrong token resource type", func(t *testing.T) {
			t.Parallel()
			filterFunc := func(_ context.Context, c host.Catalog, plgs map[string]*plugin.Plugin) (bool, error) {
				return true, nil
			}
			tok, err := listtoken.NewStartRefresh(ctx, fiveDaysAgo, resource.Target, []byte("some hash"), fiveDaysAgo, fiveDaysAgo)
			require.NoError(t, err)
			_, _, err = host.ListCatalogsRefresh(ctx, []byte("some hash"), 1, filterFunc, tok, repo, []string{prj.PublicId})
			require.ErrorContains(t, err, "token did not have a host catalog resource type")
		})
	})
	t.Run("ListRefreshPage validation", func(t *testing.T) {
		t.Parallel()
		t.Run("missing grants hash", func(t *testing.T) {
			t.Parallel()
			filterFunc := func(_ context.Context, c host.Catalog, plgs map[string]*plugin.Plugin) (bool, error) {
				return true, nil
			}
			tok, err := listtoken.NewRefresh(ctx, fiveDaysAgo, resource.HostCatalog, []byte("some hash"), fiveDaysAgo, fiveDaysAgo, fiveDaysAgo, "some other id", fiveDaysAgo)
			require.NoError(t, err)
			_, _, err = host.ListCatalogsRefreshPage(ctx, nil, 1, filterFunc, tok, repo, []string{prj.PublicId})
			require.ErrorContains(t, err, "missing grants hash")
		})
		t.Run("zero page size", func(t *testing.T) {
			t.Parallel()
			filterFunc := func(_ context.Context, c host.Catalog, plgs map[string]*plugin.Plugin) (bool, error) {
				return true, nil
			}
			tok, err := listtoken.NewRefresh(ctx, fiveDaysAgo, resource.HostCatalog, []byte("some hash"), fiveDaysAgo, fiveDaysAgo, fiveDaysAgo, "some other id", fiveDaysAgo)
			require.NoError(t, err)
			_, _, err = host.ListCatalogsRefreshPage(ctx, []byte("some hash"), 0, filterFunc, tok, repo, []string{prj.PublicId})
			require.ErrorContains(t, err, "page size must be at least 1")
		})
		t.Run("negative page size", func(t *testing.T) {
			t.Parallel()
			filterFunc := func(_ context.Context, c host.Catalog, plgs map[string]*plugin.Plugin) (bool, error) {
				return true, nil
			}
			tok, err := listtoken.NewRefresh(ctx, fiveDaysAgo, resource.HostCatalog, []byte("some hash"), fiveDaysAgo, fiveDaysAgo, fiveDaysAgo, "some other id", fiveDaysAgo)
			require.NoError(t, err)
			_, _, err = host.ListCatalogsRefreshPage(ctx, []byte("some hash"), -1, filterFunc, tok, repo, []string{prj.PublicId})
			require.ErrorContains(t, err, "page size must be at least 1")
		})
		t.Run("nil filter func", func(t *testing.T) {
			t.Parallel()
			tok, err := listtoken.NewRefresh(ctx, fiveDaysAgo, resource.HostCatalog, []byte("some hash"), fiveDaysAgo, fiveDaysAgo, fiveDaysAgo, "some other id", fiveDaysAgo)
			require.NoError(t, err)
			_, _, err = host.ListCatalogsRefreshPage(ctx, []byte("some hash"), 1, nil, tok, repo, []string{prj.PublicId})
			require.ErrorContains(t, err, "missing filter item callback")
		})
		t.Run("nil token", func(t *testing.T) {
			t.Parallel()
			filterFunc := func(_ context.Context, c host.Catalog, plgs map[string]*plugin.Plugin) (bool, error) {
				return true, nil
			}
			_, _, err := host.ListCatalogsRefreshPage(ctx, []byte("some hash"), 1, filterFunc, nil, repo, []string{prj.PublicId})
			require.ErrorContains(t, err, "missing token")
		})
		t.Run("wrong token type", func(t *testing.T) {
			t.Parallel()
			filterFunc := func(_ context.Context, c host.Catalog, plgs map[string]*plugin.Plugin) (bool, error) {
				return true, nil
			}
			tok, err := listtoken.NewPagination(ctx, fiveDaysAgo, resource.HostCatalog, []byte("some hash"), "some-id", fiveDaysAgo)
			require.NoError(t, err)
			_, _, err = host.ListCatalogsRefreshPage(ctx, []byte("some hash"), 1, filterFunc, tok, repo, []string{prj.PublicId})
			require.ErrorContains(t, err, "token did not have a refresh token component")
		})
		t.Run("missing repo", func(t *testing.T) {
			t.Parallel()
			filterFunc := func(_ context.Context, c host.Catalog, plgs map[string]*plugin.Plugin) (bool, error) {
				return true, nil
			}
			tok, err := listtoken.NewRefresh(ctx, fiveDaysAgo, resource.HostCatalog, []byte("some hash"), fiveDaysAgo, fiveDaysAgo, fiveDaysAgo, "some other id", fiveDaysAgo)
			require.NoError(t, err)
			_, _, err = host.ListCatalogsRefreshPage(ctx, []byte("some hash"), 1, filterFunc, tok, nil, []string{prj.PublicId})
			require.ErrorContains(t, err, "missing repo")
		})
		t.Run("missing project ids", func(t *testing.T) {
			t.Parallel()
			filterFunc := func(_ context.Context, c host.Catalog, plgs map[string]*plugin.Plugin) (bool, error) {
				return true, nil
			}
			tok, err := listtoken.NewRefresh(ctx, fiveDaysAgo, resource.HostCatalog, []byte("some hash"), fiveDaysAgo, fiveDaysAgo, fiveDaysAgo, "some other id", fiveDaysAgo)
			require.NoError(t, err)
			_, _, err = host.ListCatalogsRefreshPage(ctx, []byte("some hash"), 1, filterFunc, tok, repo, nil)
			require.ErrorContains(t, err, "missing project ids")
		})
		t.Run("wrong token resource type", func(t *testing.T) {
			t.Parallel()
			filterFunc := func(_ context.Context, c host.Catalog, plgs map[string]*plugin.Plugin) (bool, error) {
				return true, nil
			}
			tok, err := listtoken.NewRefresh(ctx, fiveDaysAgo, resource.Target, []byte("some hash"), fiveDaysAgo, fiveDaysAgo, fiveDaysAgo, "some other id", fiveDaysAgo)
			require.NoError(t, err)
			_, _, err = host.ListCatalogsRefreshPage(ctx, []byte("some hash"), 1, filterFunc, tok, repo, []string{prj.PublicId})
			require.ErrorContains(t, err, "token did not have a host catalog resource type")
		})
	})

	t.Run("simple pagination", func(t *testing.T) {
		filterFunc := func(context.Context, host.Catalog, map[string]*plugin.Plugin) (bool, error) {
			return true, nil
		}
		resp, _, err := host.ListCatalogs(ctx, []byte("some hash"), 1, filterFunc, repo, []string{prj.PublicId})
		require.NoError(t, err)
		require.NotNil(t, resp.ListToken)
		require.Equal(t, resp.ListToken.GrantsHash, []byte("some hash"))
		require.False(t, resp.CompleteListing)
		require.Equal(t, resp.EstimatedItemCount, 5)
		require.Empty(t, resp.DeletedIds)
		require.Len(t, resp.Items, 1)
		require.Empty(t, cmp.Diff(resp.Items[0], catalogs[0], cmpOpts...))
		// Do not assert anything about the plugin map, it may
		// contain a superset of the plugins associated with the catalog.

		resp2, _, err := host.ListCatalogsPage(ctx, []byte("some hash"), 1, filterFunc, resp.ListToken, repo, []string{prj.PublicId})
		require.NoError(t, err)
		require.Equal(t, resp2.ListToken.GrantsHash, []byte("some hash"))
		require.False(t, resp2.CompleteListing)
		require.Equal(t, resp2.EstimatedItemCount, 5)
		require.Empty(t, resp2.DeletedIds)
		require.Len(t, resp2.Items, 1)
		require.Empty(t, cmp.Diff(resp2.Items[0], catalogs[1], cmpOpts...))
		// Do not assert anything about the plugin map, it may
		// contain a superset of the plugins associated with the catalog.

		resp3, plgs, err := host.ListCatalogsPage(ctx, []byte("some hash"), 1, filterFunc, resp2.ListToken, repo, []string{prj.PublicId})
		require.NoError(t, err)
		require.Equal(t, resp3.ListToken.GrantsHash, []byte("some hash"))
		require.False(t, resp3.CompleteListing)
		require.Equal(t, resp3.EstimatedItemCount, 5)
		require.Empty(t, resp3.DeletedIds)
		require.Len(t, resp3.Items, 1)
		require.Empty(t, cmp.Diff(resp3.Items[0], catalogs[2], cmpOpts...))
		// Assert that plg2 is in the map as that is the plugin associated with this catalog.
		require.Contains(t, plgs, plg2.PublicId)
		require.Equal(t, plgs[plg2.PublicId], plg2)

		resp4, _, err := host.ListCatalogsPage(ctx, []byte("some hash"), 1, filterFunc, resp3.ListToken, repo, []string{prj.PublicId})
		require.NoError(t, err)
		require.Equal(t, resp4.ListToken.GrantsHash, []byte("some hash"))
		require.False(t, resp4.CompleteListing)
		require.Equal(t, resp4.EstimatedItemCount, 5)
		require.Empty(t, resp4.DeletedIds)
		require.Len(t, resp4.Items, 1)
		require.Empty(t, cmp.Diff(resp4.Items[0], catalogs[3], cmpOpts...))
		// Do not assert anything about the plugin map, it may
		// contain a superset of the plugins associated with the catalog.

		resp5, plgs, err := host.ListCatalogsPage(ctx, []byte("some hash"), 1, filterFunc, resp4.ListToken, repo, []string{prj.PublicId})
		require.NoError(t, err)
		require.Equal(t, resp5.ListToken.GrantsHash, []byte("some hash"))
		require.True(t, resp5.CompleteListing)
		require.Equal(t, resp5.EstimatedItemCount, 5)
		require.Empty(t, resp5.DeletedIds)
		require.Len(t, resp5.Items, 1)
		require.Empty(t, cmp.Diff(resp5.Items[0], catalogs[4], cmpOpts...))
		// Assert that plg1 is in the map as that is the plugin associated with this catalog.
		require.Contains(t, plgs, plg1.PublicId)
		require.Equal(t, plgs[plg1.PublicId], plg1)

		// Finished initial pagination phase, request refresh
		// Expect no results.
		resp6, _, err := host.ListCatalogsRefresh(ctx, []byte("some hash"), 1, filterFunc, resp5.ListToken, repo, []string{prj.PublicId})
		require.NoError(t, err)
		require.Equal(t, resp6.ListToken.GrantsHash, []byte("some hash"))
		require.True(t, resp6.CompleteListing)
		require.Equal(t, resp6.EstimatedItemCount, 5)
		require.Empty(t, resp6.DeletedIds)
		require.Empty(t, resp6.Items)
		// Do not assert anything about the plugin map, it may
		// contain a superset of the plugins associated with the catalog.

		// Create some new host catalogs
		newCatalog1 := static.TestCatalogs(t, conn, prj.PublicId, 1)[0]
		newCatalog2 := static.TestCatalogs(t, conn, prj.PublicId, 1)[0]
		t.Cleanup(func() {
			_, err := staticRepo.DeleteCatalog(ctx, newCatalog1.PublicId)
			require.NoError(t, err)
			_, err = staticRepo.DeleteCatalog(ctx, newCatalog2.PublicId)
			require.NoError(t, err)
			// Run analyze to update count estimate
			_, err = sqlDb.ExecContext(ctx, "analyze")
			require.NoError(t, err)
		})
		// Run analyze to update count estimate
		_, err = sqlDb.ExecContext(ctx, "analyze")
		require.NoError(t, err)

		// Refresh again, should get newCatalog2
		resp7, _, err := host.ListCatalogsRefresh(ctx, []byte("some hash"), 1, filterFunc, resp6.ListToken, repo, []string{prj.PublicId})
		require.NoError(t, err)
		require.Equal(t, resp7.ListToken.GrantsHash, []byte("some hash"))
		require.False(t, resp7.CompleteListing)
		require.Equal(t, resp7.EstimatedItemCount, 7)
		require.Empty(t, resp7.DeletedIds)
		require.Len(t, resp7.Items, 1)
		require.Empty(t, cmp.Diff(resp7.Items[0], newCatalog2, cmpOpts...))
		// Do not assert anything about the plugin map, it may
		// contain a superset of the plugins associated with the catalog.

		// Refresh again, should get newCatalog1
		resp8, _, err := host.ListCatalogsRefreshPage(ctx, []byte("some hash"), 1, filterFunc, resp7.ListToken, repo, []string{prj.PublicId})
		require.NoError(t, err)
		require.Equal(t, resp8.ListToken.GrantsHash, []byte("some hash"))
		require.True(t, resp8.CompleteListing)
		require.Equal(t, resp8.EstimatedItemCount, 7)
		require.Empty(t, resp8.DeletedIds)
		require.Len(t, resp8.Items, 1)
		require.Empty(t, cmp.Diff(resp8.Items[0], newCatalog1, cmpOpts...))
		// Do not assert anything about the plugin map, it may
		// contain a superset of the plugins associated with the catalog.

		// Refresh again, should get no results
		resp9, _, err := host.ListCatalogsRefresh(ctx, []byte("some hash"), 1, filterFunc, resp8.ListToken, repo, []string{prj.PublicId})
		require.NoError(t, err)
		require.Equal(t, resp9.ListToken.GrantsHash, []byte("some hash"))
		require.True(t, resp9.CompleteListing)
		require.Equal(t, resp9.EstimatedItemCount, 7)
		require.Empty(t, resp9.DeletedIds)
		require.Empty(t, resp9.Items)
		// Do not assert anything about the plugin map, it may
		// contain a superset of the plugins associated with the catalog.
	})

	t.Run("simple pagination with aggressive filtering", func(t *testing.T) {
		filterFunc := func(ctx context.Context, c host.Catalog, plgs map[string]*plugin.Plugin) (bool, error) {
			return c.GetPublicId() == catalogs[1].GetPublicId() ||
				c.GetPublicId() == catalogs[len(catalogs)-1].GetPublicId(), nil
		}
		resp, _, err := host.ListCatalogs(ctx, []byte("some hash"), 1, filterFunc, repo, []string{prj.PublicId})
		require.NoError(t, err)
		require.NotNil(t, resp.ListToken)
		require.Equal(t, resp.ListToken.GrantsHash, []byte("some hash"))
		require.False(t, resp.CompleteListing)
		require.Equal(t, resp.EstimatedItemCount, 5)
		require.Empty(t, resp.DeletedIds)
		require.Len(t, resp.Items, 1)
		require.Empty(t, cmp.Diff(resp.Items[0], catalogs[1], cmpOpts...))
		// Do not assert anything about the plugin map, it may
		// contain a superset of the plugins associated with the catalog.

		resp2, _, err := host.ListCatalogsPage(ctx, []byte("some hash"), 1, filterFunc, resp.ListToken, repo, []string{prj.PublicId})
		require.NoError(t, err)
		require.NotNil(t, resp2.ListToken)
		require.Equal(t, resp2.ListToken.GrantsHash, []byte("some hash"))
		require.True(t, resp2.CompleteListing)
		require.Equal(t, resp2.EstimatedItemCount, 5)
		require.Empty(t, resp2.DeletedIds)
		require.Len(t, resp2.Items, 1)
		require.Empty(t, cmp.Diff(resp2.Items[0], catalogs[len(catalogs)-1], cmpOpts...))
		// Do not assert anything about the plugin map, it may
		// contain a superset of the plugins associated with the catalog.

		// request a refresh, nothing should be returned
		resp3, _, err := host.ListCatalogsRefresh(ctx, []byte("some hash"), 1, filterFunc, resp.ListToken, repo, []string{prj.PublicId})
		require.NoError(t, err)
		require.Equal(t, resp3.ListToken.GrantsHash, []byte("some hash"))
		require.True(t, resp3.CompleteListing)
		require.Equal(t, resp3.EstimatedItemCount, 5)
		require.Empty(t, resp3.DeletedIds)
		require.Empty(t, resp3.Items)
		// Do not assert anything about the plugin map, it may
		// contain a superset of the plugins associated with the catalog.

		// Create some new host catalogs
		newCatalog1 := static.TestCatalogs(t, conn, prj.PublicId, 1)[0]
		newCatalog2 := static.TestCatalogs(t, conn, prj.PublicId, 1)[0]
		newCatalog3 := static.TestCatalogs(t, conn, prj.PublicId, 1)[0]
		newCatalog4 := static.TestCatalogs(t, conn, prj.PublicId, 1)[0]
		t.Cleanup(func() {
			_, err := staticRepo.DeleteCatalog(ctx, newCatalog1.PublicId)
			require.NoError(t, err)
			_, err = staticRepo.DeleteCatalog(ctx, newCatalog2.PublicId)
			require.NoError(t, err)
			_, err = staticRepo.DeleteCatalog(ctx, newCatalog3.PublicId)
			require.NoError(t, err)
			_, err = staticRepo.DeleteCatalog(ctx, newCatalog4.PublicId)
			require.NoError(t, err)
			// Run analyze to update count estimate
			_, err = sqlDb.ExecContext(ctx, "analyze")
			require.NoError(t, err)
		})
		// Run analyze to update count estimate
		_, err = sqlDb.ExecContext(ctx, "analyze")
		require.NoError(t, err)

		filterFunc = func(ctx context.Context, c host.Catalog, plgs map[string]*plugin.Plugin) (bool, error) {
			return c.GetPublicId() == newCatalog1.GetPublicId() ||
				c.GetPublicId() == newCatalog3.GetPublicId(), nil
		}
		// Refresh again, should get newCatalog3
		resp4, _, err := host.ListCatalogsRefresh(ctx, []byte("some hash"), 1, filterFunc, resp3.ListToken, repo, []string{prj.PublicId})
		require.NoError(t, err)
		require.Equal(t, resp4.ListToken.GrantsHash, []byte("some hash"))
		require.False(t, resp4.CompleteListing)
		require.Equal(t, resp4.EstimatedItemCount, 9)
		require.Empty(t, resp4.DeletedIds)
		require.Len(t, resp4.Items, 1)
		require.Empty(t, cmp.Diff(resp4.Items[0], newCatalog3, cmpOpts...))
		// Do not assert anything about the plugin map, it may
		// contain a superset of the plugins associated with the catalog.

		// Refresh again, should get newCatalog1
		resp5, _, err := host.ListCatalogsRefreshPage(ctx, []byte("some hash"), 1, filterFunc, resp4.ListToken, repo, []string{prj.PublicId})
		require.NoError(t, err)
		require.Equal(t, resp5.ListToken.GrantsHash, []byte("some hash"))
		require.True(t, resp5.CompleteListing)
		require.Equal(t, resp5.EstimatedItemCount, 9)
		require.Empty(t, resp5.DeletedIds)
		require.Len(t, resp5.Items, 1)
		require.Empty(t, cmp.Diff(resp5.Items[0], newCatalog1, cmpOpts...))
		// Do not assert anything about the plugin map, it may
		// contain a superset of the plugins associated with the catalog.
	})

	t.Run("simple pagination with deletion", func(t *testing.T) {
		filterFunc := func(ctx context.Context, c host.Catalog, plgs map[string]*plugin.Plugin) (bool, error) {
			return true, nil
		}
		deletedCatalogId := catalogs[0].GetPublicId()
		_, err := staticRepo.DeleteCatalog(ctx, deletedCatalogId)
		require.NoError(t, err)
		catalogs = catalogs[1:]

		// Run analyze to update count estimate
		_, err = sqlDb.ExecContext(ctx, "analyze")
		require.NoError(t, err)

		resp, _, err := host.ListCatalogs(ctx, []byte("some hash"), 1, filterFunc, repo, []string{prj.PublicId})
		require.NoError(t, err)
		require.NotNil(t, resp.ListToken)
		require.Equal(t, resp.ListToken.GrantsHash, []byte("some hash"))
		require.False(t, resp.CompleteListing)
		require.Equal(t, resp.EstimatedItemCount, 4)
		require.Empty(t, resp.DeletedIds)
		require.Len(t, resp.Items, 1)
		require.Empty(t, cmp.Diff(resp.Items[0], catalogs[0], cmpOpts...))
		// Do not assert anything about the plugin map, it may
		// contain a superset of the plugins associated with the catalog.

		// request remaining results
		resp2, plgs, err := host.ListCatalogsPage(ctx, []byte("some hash"), 3, filterFunc, resp.ListToken, repo, []string{prj.PublicId})
		require.NoError(t, err)
		require.Equal(t, resp2.ListToken.GrantsHash, []byte("some hash"))
		require.True(t, resp2.CompleteListing)
		require.Equal(t, resp2.EstimatedItemCount, 4)
		require.Empty(t, resp2.DeletedIds)
		require.Len(t, resp2.Items, 3)
		require.Empty(t, cmp.Diff(resp2.Items, catalogs[1:], cmpOpts...))
		// Assert that plg1 and plg2 are in the map as those are associated with these catalogs.
		require.Contains(t, plgs, plg1.PublicId)
		require.Equal(t, plgs[plg1.PublicId], plg1)
		require.Contains(t, plgs, plg2.PublicId)
		require.Equal(t, plgs[plg2.PublicId], plg2)

		deletedCatalogId = catalogs[0].GetPublicId()
		_, err = staticRepo.DeleteCatalog(ctx, deletedCatalogId)
		require.NoError(t, err)
		catalogs = catalogs[1:]

		// Run analyze to update count estimate
		_, err = sqlDb.ExecContext(ctx, "analyze")
		require.NoError(t, err)

		resp3, _, err := host.ListCatalogsRefresh(ctx, []byte("some hash"), 1, filterFunc, resp2.ListToken, repo, []string{prj.PublicId})
		require.NoError(t, err)
		require.Equal(t, resp3.ListToken.GrantsHash, []byte("some hash"))
		require.True(t, resp3.CompleteListing)
		require.Equal(t, resp3.EstimatedItemCount, 3)
		require.Contains(t, resp3.DeletedIds, deletedCatalogId)
		require.Empty(t, resp3.Items)
		// Do not assert anything about the plugin map, it may
		// contain a superset of the plugins associated with the catalog.
	})
}
