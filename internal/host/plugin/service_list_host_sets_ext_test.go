// Copyright IBM Corp. 2020, 2025
// SPDX-License-Identifier: BUSL-1.1

package plugin_test

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
	"github.com/hashicorp/boundary/internal/host/plugin/store"
	"github.com/hashicorp/boundary/internal/iam"
	"github.com/hashicorp/boundary/internal/kms"
	"github.com/hashicorp/boundary/internal/listtoken"
	"github.com/hashicorp/boundary/internal/plugin"
	"github.com/hashicorp/boundary/internal/plugin/loopback"
	"github.com/hashicorp/boundary/internal/scheduler"
	"github.com/hashicorp/boundary/internal/types/resource"
	plgpb "github.com/hashicorp/boundary/sdk/pbs/plugin"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/types/known/timestamppb"
)

func TestService_ListHostSets(t *testing.T) {
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
	wrapper := db.TestWrapper(t)
	testKms := kms.TestKms(t, conn, wrapper)
	sche := scheduler.TestScheduler(t, conn, wrapper)
	iamRepo := iam.TestRepo(t, conn, wrapper)
	_, proj1 := iam.TestScopes(t, iamRepo)
	plg := plugin.TestPlugin(t, conn, "test")
	fiveDaysAgo := time.Now().AddDate(0, 0, -5)
	catalog := hostplugin.TestCatalog(t, conn, proj1.GetPublicId(), plg.GetPublicId())
	plgm := map[string]plgpb.HostPluginServiceClient{
		plg.GetPublicId(): loopback.NewWrappingPluginHostClient(&plgpb.UnimplementedHostPluginServiceServer{}),
	}
	var hostSets []host.Set
	for i := 0; i < 5; i++ {
		hostSet := hostplugin.TestSet(t, conn, testKms, sche, catalog, plgm)
		hostSet.PluginId = plg.GetPublicId()
		hostSets = append(hostSets, hostSet)
	}
	// since we sort by create time descending, we need to reverse the slice
	slices.Reverse(hostSets)

	// Run analyze to update host estimate
	_, err = sqlDb.ExecContext(ctx, "analyze")
	require.NoError(t, err)

	rw := db.New(conn)
	repo, err := hostplugin.NewRepository(ctx, rw, rw, testKms, sche, plgm)
	require.NoError(t, err)

	cmpOpts := []cmp.Option{
		cmpopts.IgnoreUnexported(
			hostplugin.HostSet{},
			store.HostSet{},
			timestamp.Timestamp{},
			timestamppb.Timestamp{},
		),
	}

	t.Run("ListHostSets validation", func(t *testing.T) {
		t.Parallel()
		t.Run("missing grants hash", func(t *testing.T) {
			t.Parallel()
			filterFunc := func(_ context.Context, s host.Set, plg *plugin.Plugin) (bool, error) {
				return true, nil
			}
			_, _, err := hostplugin.ListHostSets(ctx, nil, 1, filterFunc, repo, catalog.GetPublicId())
			require.ErrorContains(t, err, "missing grants hash")
		})
		t.Run("zero page size", func(t *testing.T) {
			t.Parallel()
			filterFunc := func(_ context.Context, s host.Set, plg *plugin.Plugin) (bool, error) {
				return true, nil
			}
			_, _, err := hostplugin.ListHostSets(ctx, []byte("some hash"), 0, filterFunc, repo, catalog.GetPublicId())
			require.ErrorContains(t, err, "page size must be at least 1")
		})
		t.Run("negative page size", func(t *testing.T) {
			t.Parallel()
			filterFunc := func(_ context.Context, s host.Set, plg *plugin.Plugin) (bool, error) {
				return true, nil
			}
			_, _, err := hostplugin.ListHostSets(ctx, []byte("some hash"), -1, filterFunc, repo, catalog.GetPublicId())
			require.ErrorContains(t, err, "page size must be at least 1")
		})
		t.Run("nil filter func", func(t *testing.T) {
			t.Parallel()
			_, _, err := hostplugin.ListHostSets(ctx, []byte("some hash"), 1, nil, repo, catalog.GetPublicId())
			require.ErrorContains(t, err, "missing filter item callback")
		})
		t.Run("nil repo", func(t *testing.T) {
			t.Parallel()
			filterFunc := func(_ context.Context, s host.Set, plg *plugin.Plugin) (bool, error) {
				return true, nil
			}
			_, _, err := hostplugin.ListHostSets(ctx, []byte("some hash"), 1, filterFunc, nil, catalog.GetPublicId())
			require.ErrorContains(t, err, "missing repo")
		})
		t.Run("missing host catalog ID", func(t *testing.T) {
			t.Parallel()
			filterFunc := func(_ context.Context, s host.Set, plg *plugin.Plugin) (bool, error) {
				return true, nil
			}
			_, _, err := hostplugin.ListHostSets(ctx, []byte("some hash"), 1, filterFunc, repo, "")
			require.ErrorContains(t, err, "missing host catalog ID")
		})
	})
	t.Run("ListHostSetsPage validation", func(t *testing.T) {
		t.Parallel()
		t.Run("missing grants hash", func(t *testing.T) {
			t.Parallel()
			filterFunc := func(_ context.Context, s host.Set, plg *plugin.Plugin) (bool, error) {
				return true, nil
			}
			tok, err := listtoken.NewPagination(ctx, fiveDaysAgo, resource.HostSet, []byte("some hash"), "some-id", fiveDaysAgo)
			require.NoError(t, err)
			_, _, err = hostplugin.ListHostSetsPage(ctx, nil, 1, filterFunc, tok, repo, catalog.GetPublicId())
			require.ErrorContains(t, err, "missing grants hash")
		})
		t.Run("zero page size", func(t *testing.T) {
			t.Parallel()
			filterFunc := func(_ context.Context, s host.Set, plg *plugin.Plugin) (bool, error) {
				return true, nil
			}
			tok, err := listtoken.NewPagination(ctx, fiveDaysAgo, resource.HostSet, []byte("some hash"), "some-id", fiveDaysAgo)
			require.NoError(t, err)
			_, _, err = hostplugin.ListHostSetsPage(ctx, []byte("some hash"), 0, filterFunc, tok, repo, catalog.GetPublicId())
			require.ErrorContains(t, err, "page size must be at least 1")
		})
		t.Run("negative page size", func(t *testing.T) {
			t.Parallel()
			filterFunc := func(_ context.Context, s host.Set, plg *plugin.Plugin) (bool, error) {
				return true, nil
			}
			tok, err := listtoken.NewPagination(ctx, fiveDaysAgo, resource.HostSet, []byte("some hash"), "some-id", fiveDaysAgo)
			require.NoError(t, err)
			_, _, err = hostplugin.ListHostSetsPage(ctx, []byte("some hash"), -1, filterFunc, tok, repo, catalog.GetPublicId())
			require.ErrorContains(t, err, "page size must be at least 1")
		})
		t.Run("nil filter func", func(t *testing.T) {
			t.Parallel()
			tok, err := listtoken.NewPagination(ctx, fiveDaysAgo, resource.HostSet, []byte("some hash"), "some-id", fiveDaysAgo)
			require.NoError(t, err)
			_, _, err = hostplugin.ListHostSetsPage(ctx, []byte("some hash"), 1, nil, tok, repo, catalog.GetPublicId())
			require.ErrorContains(t, err, "missing filter item callback")
		})
		t.Run("nil token", func(t *testing.T) {
			t.Parallel()
			filterFunc := func(_ context.Context, s host.Set, plg *plugin.Plugin) (bool, error) {
				return true, nil
			}
			_, _, err := hostplugin.ListHostSetsPage(ctx, []byte("some hash"), 1, filterFunc, nil, repo, catalog.GetPublicId())
			require.ErrorContains(t, err, "missing token")
		})
		t.Run("wrong token type", func(t *testing.T) {
			t.Parallel()
			filterFunc := func(_ context.Context, s host.Set, plg *plugin.Plugin) (bool, error) {
				return true, nil
			}
			tok, err := listtoken.NewStartRefresh(ctx, fiveDaysAgo, resource.HostSet, []byte("some hash"), fiveDaysAgo, fiveDaysAgo)
			require.NoError(t, err)
			_, _, err = hostplugin.ListHostSetsPage(ctx, []byte("some hash"), 1, filterFunc, tok, repo, catalog.GetPublicId())
			require.ErrorContains(t, err, "token did not have a pagination token component")
		})
		t.Run("nil repo", func(t *testing.T) {
			t.Parallel()
			filterFunc := func(_ context.Context, s host.Set, plg *plugin.Plugin) (bool, error) {
				return true, nil
			}
			tok, err := listtoken.NewPagination(ctx, fiveDaysAgo, resource.HostSet, []byte("some hash"), "some-id", fiveDaysAgo)
			require.NoError(t, err)
			_, _, err = hostplugin.ListHostSetsPage(ctx, []byte("some hash"), 1, filterFunc, tok, nil, catalog.GetPublicId())
			require.ErrorContains(t, err, "missing repo")
		})
		t.Run("missing host catalog ID", func(t *testing.T) {
			t.Parallel()
			filterFunc := func(_ context.Context, s host.Set, plg *plugin.Plugin) (bool, error) {
				return true, nil
			}
			tok, err := listtoken.NewPagination(ctx, fiveDaysAgo, resource.HostSet, []byte("some hash"), "some-id", fiveDaysAgo)
			require.NoError(t, err)
			_, _, err = hostplugin.ListHostSetsPage(ctx, []byte("some hash"), 1, filterFunc, tok, repo, "")
			require.ErrorContains(t, err, "missing host catalog ID")
		})
		t.Run("wrong token resource type", func(t *testing.T) {
			t.Parallel()
			filterFunc := func(_ context.Context, s host.Set, plg *plugin.Plugin) (bool, error) {
				return true, nil
			}
			tok, err := listtoken.NewPagination(ctx, fiveDaysAgo, resource.Target, []byte("some hash"), "some-id", fiveDaysAgo)
			require.NoError(t, err)
			_, _, err = hostplugin.ListHostSetsPage(ctx, []byte("some hash"), 1, filterFunc, tok, repo, catalog.GetPublicId())
			require.ErrorContains(t, err, "token did not have a host set resource type")
		})
	})
	t.Run("ListHostSetsRefresh validation", func(t *testing.T) {
		t.Parallel()
		t.Run("missing grants hash", func(t *testing.T) {
			t.Parallel()
			filterFunc := func(_ context.Context, s host.Set, plg *plugin.Plugin) (bool, error) {
				return true, nil
			}
			tok, err := listtoken.NewStartRefresh(ctx, fiveDaysAgo, resource.HostSet, []byte("some hash"), fiveDaysAgo, fiveDaysAgo)
			require.NoError(t, err)
			_, _, err = hostplugin.ListHostSetsRefresh(ctx, nil, 1, filterFunc, tok, repo, catalog.GetPublicId())
			require.ErrorContains(t, err, "missing grants hash")
		})
		t.Run("zero page size", func(t *testing.T) {
			t.Parallel()
			filterFunc := func(_ context.Context, s host.Set, plg *plugin.Plugin) (bool, error) {
				return true, nil
			}
			tok, err := listtoken.NewStartRefresh(ctx, fiveDaysAgo, resource.HostSet, []byte("some hash"), fiveDaysAgo, fiveDaysAgo)
			require.NoError(t, err)
			_, _, err = hostplugin.ListHostSetsRefresh(ctx, []byte("some hash"), 0, filterFunc, tok, repo, catalog.GetPublicId())
			require.ErrorContains(t, err, "page size must be at least 1")
		})
		t.Run("negative page size", func(t *testing.T) {
			t.Parallel()
			filterFunc := func(_ context.Context, s host.Set, plg *plugin.Plugin) (bool, error) {
				return true, nil
			}
			tok, err := listtoken.NewStartRefresh(ctx, fiveDaysAgo, resource.HostSet, []byte("some hash"), fiveDaysAgo, fiveDaysAgo)
			require.NoError(t, err)
			_, _, err = hostplugin.ListHostSetsRefresh(ctx, []byte("some hash"), -1, filterFunc, tok, repo, catalog.GetPublicId())
			require.ErrorContains(t, err, "page size must be at least 1")
		})
		t.Run("nil filter func", func(t *testing.T) {
			t.Parallel()
			tok, err := listtoken.NewStartRefresh(ctx, fiveDaysAgo, resource.HostSet, []byte("some hash"), fiveDaysAgo, fiveDaysAgo)
			require.NoError(t, err)
			_, _, err = hostplugin.ListHostSetsRefresh(ctx, []byte("some hash"), 1, nil, tok, repo, catalog.GetPublicId())
			require.ErrorContains(t, err, "missing filter item callback")
		})
		t.Run("nil token", func(t *testing.T) {
			t.Parallel()
			filterFunc := func(_ context.Context, s host.Set, plg *plugin.Plugin) (bool, error) {
				return true, nil
			}
			_, _, err := hostplugin.ListHostSetsRefresh(ctx, []byte("some hash"), 1, filterFunc, nil, repo, catalog.GetPublicId())
			require.ErrorContains(t, err, "missing token")
		})
		t.Run("nil repo", func(t *testing.T) {
			t.Parallel()
			filterFunc := func(_ context.Context, s host.Set, plg *plugin.Plugin) (bool, error) {
				return true, nil
			}
			tok, err := listtoken.NewStartRefresh(ctx, fiveDaysAgo, resource.HostSet, []byte("some hash"), fiveDaysAgo, fiveDaysAgo)
			require.NoError(t, err)
			_, _, err = hostplugin.ListHostSetsRefresh(ctx, []byte("some hash"), 1, filterFunc, tok, nil, catalog.GetPublicId())
			require.ErrorContains(t, err, "missing repo")
		})
		t.Run("missing host catalog ID", func(t *testing.T) {
			t.Parallel()
			filterFunc := func(_ context.Context, s host.Set, plg *plugin.Plugin) (bool, error) {
				return true, nil
			}
			tok, err := listtoken.NewStartRefresh(ctx, fiveDaysAgo, resource.HostSet, []byte("some hash"), fiveDaysAgo, fiveDaysAgo)
			require.NoError(t, err)
			_, _, err = hostplugin.ListHostSetsRefresh(ctx, []byte("some hash"), 1, filterFunc, tok, repo, "")
			require.ErrorContains(t, err, "missing host catalog ID")
		})
		t.Run("wrong token resource type", func(t *testing.T) {
			t.Parallel()
			filterFunc := func(_ context.Context, s host.Set, plg *plugin.Plugin) (bool, error) {
				return true, nil
			}
			tok, err := listtoken.NewStartRefresh(ctx, fiveDaysAgo, resource.Target, []byte("some hash"), fiveDaysAgo, fiveDaysAgo)
			require.NoError(t, err)
			_, _, err = hostplugin.ListHostSetsRefresh(ctx, []byte("some hash"), 1, filterFunc, tok, repo, catalog.GetPublicId())
			require.ErrorContains(t, err, "token did not have a host set resource type")
		})
	})
	t.Run("ListHostsRefreshPage validation", func(t *testing.T) {
		t.Parallel()
		t.Run("missing grants hash", func(t *testing.T) {
			t.Parallel()
			filterFunc := func(_ context.Context, s host.Set, plg *plugin.Plugin) (bool, error) {
				return true, nil
			}
			tok, err := listtoken.NewRefresh(ctx, fiveDaysAgo, resource.HostSet, []byte("some hash"), fiveDaysAgo, fiveDaysAgo, fiveDaysAgo, "some other id", fiveDaysAgo)
			require.NoError(t, err)
			_, _, err = hostplugin.ListHostSetsRefreshPage(ctx, nil, 1, filterFunc, tok, repo, catalog.GetPublicId())
			require.ErrorContains(t, err, "missing grants hash")
		})
		t.Run("zero page size", func(t *testing.T) {
			t.Parallel()
			filterFunc := func(_ context.Context, s host.Set, plg *plugin.Plugin) (bool, error) {
				return true, nil
			}
			tok, err := listtoken.NewRefresh(ctx, fiveDaysAgo, resource.HostSet, []byte("some hash"), fiveDaysAgo, fiveDaysAgo, fiveDaysAgo, "some other id", fiveDaysAgo)
			require.NoError(t, err)
			_, _, err = hostplugin.ListHostSetsRefreshPage(ctx, []byte("some hash"), 0, filterFunc, tok, repo, catalog.GetPublicId())
			require.ErrorContains(t, err, "page size must be at least 1")
		})
		t.Run("negative page size", func(t *testing.T) {
			t.Parallel()
			filterFunc := func(_ context.Context, s host.Set, plg *plugin.Plugin) (bool, error) {
				return true, nil
			}
			tok, err := listtoken.NewRefresh(ctx, fiveDaysAgo, resource.HostSet, []byte("some hash"), fiveDaysAgo, fiveDaysAgo, fiveDaysAgo, "some other id", fiveDaysAgo)
			require.NoError(t, err)
			_, _, err = hostplugin.ListHostSetsRefreshPage(ctx, []byte("some hash"), -1, filterFunc, tok, repo, catalog.GetPublicId())
			require.ErrorContains(t, err, "page size must be at least 1")
		})
		t.Run("nil filter func", func(t *testing.T) {
			t.Parallel()
			tok, err := listtoken.NewRefresh(ctx, fiveDaysAgo, resource.HostSet, []byte("some hash"), fiveDaysAgo, fiveDaysAgo, fiveDaysAgo, "some other id", fiveDaysAgo)
			require.NoError(t, err)
			_, _, err = hostplugin.ListHostSetsRefreshPage(ctx, []byte("some hash"), 1, nil, tok, repo, catalog.GetPublicId())
			require.ErrorContains(t, err, "missing filter item callback")
		})
		t.Run("nil token", func(t *testing.T) {
			t.Parallel()
			filterFunc := func(_ context.Context, s host.Set, plg *plugin.Plugin) (bool, error) {
				return true, nil
			}
			_, _, err := hostplugin.ListHostSetsRefreshPage(ctx, []byte("some hash"), 1, filterFunc, nil, repo, catalog.GetPublicId())
			require.ErrorContains(t, err, "missing token")
		})
		t.Run("wrong token type", func(t *testing.T) {
			t.Parallel()
			filterFunc := func(_ context.Context, s host.Set, plg *plugin.Plugin) (bool, error) {
				return true, nil
			}
			tok, err := listtoken.NewPagination(ctx, fiveDaysAgo, resource.HostSet, []byte("some hash"), "some-id", fiveDaysAgo)
			require.NoError(t, err)
			_, _, err = hostplugin.ListHostSetsRefreshPage(ctx, []byte("some hash"), 1, filterFunc, tok, repo, catalog.GetPublicId())
			require.ErrorContains(t, err, "token did not have a refresh token component")
		})
		t.Run("nil repo", func(t *testing.T) {
			t.Parallel()
			filterFunc := func(_ context.Context, s host.Set, plg *plugin.Plugin) (bool, error) {
				return true, nil
			}
			tok, err := listtoken.NewRefresh(ctx, fiveDaysAgo, resource.HostSet, []byte("some hash"), fiveDaysAgo, fiveDaysAgo, fiveDaysAgo, "some other id", fiveDaysAgo)
			require.NoError(t, err)
			_, _, err = hostplugin.ListHostSetsRefreshPage(ctx, []byte("some hash"), 1, filterFunc, tok, nil, catalog.GetPublicId())
			require.ErrorContains(t, err, "missing repo")
		})
		t.Run("missing credential store id", func(t *testing.T) {
			t.Parallel()
			filterFunc := func(_ context.Context, s host.Set, plg *plugin.Plugin) (bool, error) {
				return true, nil
			}
			tok, err := listtoken.NewRefresh(ctx, fiveDaysAgo, resource.HostSet, []byte("some hash"), fiveDaysAgo, fiveDaysAgo, fiveDaysAgo, "some other id", fiveDaysAgo)
			require.NoError(t, err)
			_, _, err = hostplugin.ListHostSetsRefreshPage(ctx, []byte("some hash"), 1, filterFunc, tok, repo, "")
			require.ErrorContains(t, err, "missing host catalog ID")
		})
		t.Run("wrong token resource type", func(t *testing.T) {
			t.Parallel()
			filterFunc := func(_ context.Context, s host.Set, plg *plugin.Plugin) (bool, error) {
				return true, nil
			}
			tok, err := listtoken.NewRefresh(ctx, fiveDaysAgo, resource.Target, []byte("some hash"), fiveDaysAgo, fiveDaysAgo, fiveDaysAgo, "some other id", fiveDaysAgo)
			require.NoError(t, err)
			_, _, err = hostplugin.ListHostSetsRefreshPage(ctx, []byte("some hash"), 1, filterFunc, tok, repo, catalog.GetPublicId())
			require.ErrorContains(t, err, "token did not have a host set resource type")
		})
	})

	t.Run("simple pagination", func(t *testing.T) {
		filterFunc := func(context.Context, host.Set, *plugin.Plugin) (bool, error) {
			return true, nil
		}
		resp, retPlg, err := hostplugin.ListHostSets(ctx, []byte("some hash"), 1, filterFunc, repo, catalog.GetPublicId())
		require.NoError(t, err)
		require.NotNil(t, resp.ListToken)
		require.Equal(t, resp.ListToken.GrantsHash, []byte("some hash"))
		require.False(t, resp.CompleteListing)
		require.Equal(t, resp.EstimatedItemCount, 5)
		require.Empty(t, resp.DeletedIds)
		require.Len(t, resp.Items, 1)
		require.Empty(t, cmp.Diff(resp.Items[0], hostSets[0], cmpOpts...))
		require.Equal(t, retPlg, plg)

		resp2, retPlg, err := hostplugin.ListHostSetsPage(ctx, []byte("some hash"), 1, filterFunc, resp.ListToken, repo, catalog.GetPublicId())
		require.NoError(t, err)
		require.Equal(t, resp2.ListToken.GrantsHash, []byte("some hash"))
		require.False(t, resp2.CompleteListing)
		require.Equal(t, resp2.EstimatedItemCount, 5)
		require.Empty(t, resp2.DeletedIds)
		require.Len(t, resp2.Items, 1)
		require.Empty(t, cmp.Diff(resp2.Items[0], hostSets[1], cmpOpts...))
		require.Equal(t, retPlg, plg)

		resp3, retPlg, err := hostplugin.ListHostSetsPage(ctx, []byte("some hash"), 1, filterFunc, resp2.ListToken, repo, catalog.GetPublicId())
		require.NoError(t, err)
		require.Equal(t, resp3.ListToken.GrantsHash, []byte("some hash"))
		require.False(t, resp3.CompleteListing)
		require.Equal(t, resp3.EstimatedItemCount, 5)
		require.Empty(t, resp3.DeletedIds)
		require.Len(t, resp3.Items, 1)
		require.Empty(t, cmp.Diff(resp3.Items[0], hostSets[2], cmpOpts...))
		require.Equal(t, retPlg, plg)

		resp4, retPlg, err := hostplugin.ListHostSetsPage(ctx, []byte("some hash"), 1, filterFunc, resp3.ListToken, repo, catalog.GetPublicId())
		require.NoError(t, err)
		require.Equal(t, resp4.ListToken.GrantsHash, []byte("some hash"))
		require.False(t, resp4.CompleteListing)
		require.Equal(t, resp4.EstimatedItemCount, 5)
		require.Empty(t, resp4.DeletedIds)
		require.Len(t, resp4.Items, 1)
		require.Empty(t, cmp.Diff(resp4.Items[0], hostSets[3], cmpOpts...))
		require.Equal(t, retPlg, plg)

		resp5, retPlg, err := hostplugin.ListHostSetsPage(ctx, []byte("some hash"), 1, filterFunc, resp4.ListToken, repo, catalog.GetPublicId())
		require.NoError(t, err)
		require.Equal(t, resp5.ListToken.GrantsHash, []byte("some hash"))
		require.True(t, resp5.CompleteListing)
		require.Equal(t, resp5.EstimatedItemCount, 5)
		require.Empty(t, resp5.DeletedIds)
		require.Len(t, resp5.Items, 1)
		require.Empty(t, cmp.Diff(resp5.Items[0], hostSets[4], cmpOpts...))
		require.Equal(t, retPlg, plg)

		// Finished initial pagination phase, request refresh
		// Expect no results.
		resp6, retPlg, err := hostplugin.ListHostSetsRefresh(ctx, []byte("some hash"), 1, filterFunc, resp5.ListToken, repo, catalog.GetPublicId())
		require.NoError(t, err)
		require.Equal(t, resp6.ListToken.GrantsHash, []byte("some hash"))
		require.True(t, resp6.CompleteListing)
		require.Equal(t, resp6.EstimatedItemCount, 5)
		require.Empty(t, resp6.DeletedIds)
		require.Empty(t, resp6.Items)
		require.Empty(t, retPlg)

		// Create some new hosts
		host1 := hostplugin.TestSet(t, conn, testKms, sche, catalog, plgm)
		host1.PluginId = plg.GetPublicId()
		host2 := hostplugin.TestSet(t, conn, testKms, sche, catalog, plgm)
		host2.PluginId = plg.GetPublicId()
		t.Cleanup(func() {
			_, err := repo.DeleteSet(ctx, proj1.PublicId, host1.GetPublicId())
			require.NoError(t, err)
			_, err = repo.DeleteSet(ctx, proj1.PublicId, host2.GetPublicId())
			require.NoError(t, err)
			// Run analyze to update count estimate
			_, err = sqlDb.ExecContext(ctx, "analyze")
			require.NoError(t, err)
		})

		// Run analyze to update count estimate
		_, err = sqlDb.ExecContext(ctx, "analyze")
		require.NoError(t, err)

		// Refresh again, should get host2
		resp7, retPlg, err := hostplugin.ListHostSetsRefresh(ctx, []byte("some hash"), 1, filterFunc, resp6.ListToken, repo, catalog.GetPublicId())
		require.NoError(t, err)
		require.Equal(t, resp7.ListToken.GrantsHash, []byte("some hash"))
		require.False(t, resp7.CompleteListing)
		require.Equal(t, resp7.EstimatedItemCount, 7)
		require.Empty(t, resp7.DeletedIds)
		require.Len(t, resp7.Items, 1)
		require.Empty(t, cmp.Diff(resp7.Items[0], host2, cmpOpts...))
		require.Equal(t, retPlg, plg)

		// Refresh again, should get host1
		resp8, retPlg, err := hostplugin.ListHostSetsRefreshPage(ctx, []byte("some hash"), 1, filterFunc, resp7.ListToken, repo, catalog.GetPublicId())
		require.NoError(t, err)
		require.Equal(t, resp8.ListToken.GrantsHash, []byte("some hash"))
		require.True(t, resp8.CompleteListing)
		require.Equal(t, resp8.EstimatedItemCount, 7)
		require.Empty(t, resp8.DeletedIds)
		require.Len(t, resp8.Items, 1)
		require.Empty(t, cmp.Diff(resp8.Items[0], host1, cmpOpts...))
		require.Equal(t, retPlg, plg)

		// Refresh again, should get no results
		resp9, retPlg, err := hostplugin.ListHostSetsRefresh(ctx, []byte("some hash"), 1, filterFunc, resp8.ListToken, repo, catalog.GetPublicId())
		require.NoError(t, err)
		require.Equal(t, resp9.ListToken.GrantsHash, []byte("some hash"))
		require.True(t, resp9.CompleteListing)
		require.Equal(t, resp9.EstimatedItemCount, 7)
		require.Empty(t, resp9.DeletedIds)
		require.Empty(t, resp9.Items)
		require.Empty(t, retPlg)
	})

	t.Run("simple pagination with aggressive filtering", func(t *testing.T) {
		filterFunc := func(ctx context.Context, s host.Set, plg *plugin.Plugin) (bool, error) {
			return s.GetPublicId() == hostSets[1].GetPublicId() ||
				s.GetPublicId() == hostSets[len(hostSets)-1].GetPublicId(), nil
		}
		resp, retPlg, err := hostplugin.ListHostSets(ctx, []byte("some hash"), 1, filterFunc, repo, catalog.GetPublicId())
		require.NoError(t, err)
		require.NotNil(t, resp.ListToken)
		require.Equal(t, resp.ListToken.GrantsHash, []byte("some hash"))
		require.False(t, resp.CompleteListing)
		require.Equal(t, resp.EstimatedItemCount, 5)
		require.Empty(t, resp.DeletedIds)
		require.Len(t, resp.Items, 1)
		require.Empty(t, cmp.Diff(resp.Items[0], hostSets[1], cmpOpts...))
		require.Equal(t, retPlg, plg)

		resp2, retPlg, err := hostplugin.ListHostSetsPage(ctx, []byte("some hash"), 1, filterFunc, resp.ListToken, repo, catalog.GetPublicId())
		require.NoError(t, err)
		require.NotNil(t, resp2.ListToken)
		require.Equal(t, resp2.ListToken.GrantsHash, []byte("some hash"))
		require.True(t, resp2.CompleteListing)
		require.Equal(t, resp2.EstimatedItemCount, 5)
		require.Empty(t, resp2.DeletedIds)
		require.Len(t, resp2.Items, 1)
		require.Empty(t, cmp.Diff(resp2.Items[0], hostSets[len(hostSets)-1], cmpOpts...))
		require.Equal(t, retPlg, plg)

		// request a refresh, nothing should be returned
		resp3, retPlg, err := hostplugin.ListHostSetsRefresh(ctx, []byte("some hash"), 1, filterFunc, resp.ListToken, repo, catalog.GetPublicId())
		require.NoError(t, err)
		require.Equal(t, resp3.ListToken.GrantsHash, []byte("some hash"))
		require.True(t, resp3.CompleteListing)
		require.Equal(t, resp3.EstimatedItemCount, 5)
		require.Empty(t, resp3.DeletedIds)
		require.Empty(t, resp3.Items)
		require.Empty(t, retPlg)

		// Create some new hosts
		host1 := hostplugin.TestSet(t, conn, testKms, sche, catalog, plgm)
		host1.PluginId = plg.GetPublicId()
		host2 := hostplugin.TestSet(t, conn, testKms, sche, catalog, plgm)
		host2.PluginId = plg.GetPublicId()
		host3 := hostplugin.TestSet(t, conn, testKms, sche, catalog, plgm)
		host3.PluginId = plg.GetPublicId()
		host4 := hostplugin.TestSet(t, conn, testKms, sche, catalog, plgm)
		host4.PluginId = plg.GetPublicId()
		t.Cleanup(func() {
			_, err := repo.DeleteSet(ctx, proj1.PublicId, host1.GetPublicId())
			require.NoError(t, err)
			_, err = repo.DeleteSet(ctx, proj1.PublicId, host2.GetPublicId())
			require.NoError(t, err)
			_, err = repo.DeleteSet(ctx, proj1.PublicId, host3.GetPublicId())
			require.NoError(t, err)
			_, err = repo.DeleteSet(ctx, proj1.PublicId, host4.GetPublicId())
			require.NoError(t, err)
			// Run analyze to update count estimate
			_, err = sqlDb.ExecContext(ctx, "analyze")
			require.NoError(t, err)
		})

		// Run analyze to update count estimate
		_, err = sqlDb.ExecContext(ctx, "analyze")
		require.NoError(t, err)

		filterFunc = func(_ context.Context, s host.Set, retPlg *plugin.Plugin) (bool, error) {
			return s.GetPublicId() == host3.GetPublicId() ||
				s.GetPublicId() == host1.GetPublicId(), nil
		}
		// Refresh again, should get host3
		resp4, retPlg, err := hostplugin.ListHostSetsRefresh(ctx, []byte("some hash"), 1, filterFunc, resp3.ListToken, repo, catalog.GetPublicId())
		require.NoError(t, err)
		require.Equal(t, resp4.ListToken.GrantsHash, []byte("some hash"))
		require.False(t, resp4.CompleteListing)
		require.Equal(t, resp4.EstimatedItemCount, 9)
		require.Empty(t, resp4.DeletedIds)
		require.Len(t, resp4.Items, 1)
		require.Empty(t, cmp.Diff(resp4.Items[0], host3, cmpOpts...))
		require.Equal(t, retPlg, plg)

		// Refresh again, should get host1
		resp5, retPlg, err := hostplugin.ListHostSetsRefreshPage(ctx, []byte("some hash"), 1, filterFunc, resp4.ListToken, repo, catalog.GetPublicId())
		require.NoError(t, err)
		require.Equal(t, resp5.ListToken.GrantsHash, []byte("some hash"))
		require.True(t, resp5.CompleteListing)
		require.Equal(t, resp5.EstimatedItemCount, 9)
		require.Empty(t, resp5.DeletedIds)
		require.Len(t, resp5.Items, 1)
		require.Empty(t, cmp.Diff(resp5.Items[0], host1, cmpOpts...))
		require.Equal(t, retPlg, plg)
	})

	t.Run("simple pagination with deletion", func(t *testing.T) {
		filterFunc := func(context.Context, host.Set, *plugin.Plugin) (bool, error) {
			return true, nil
		}
		deletedHostId := hostSets[0].GetPublicId()
		_, err := repo.DeleteSet(ctx, proj1.PublicId, deletedHostId)
		require.NoError(t, err)
		hostSets = hostSets[1:]

		// Run analyze to update count estimate
		_, err = sqlDb.ExecContext(ctx, "analyze")
		require.NoError(t, err)

		resp, retPlg, err := hostplugin.ListHostSets(ctx, []byte("some hash"), 1, filterFunc, repo, catalog.GetPublicId())
		require.NoError(t, err)
		require.NotNil(t, resp.ListToken)
		require.Equal(t, resp.ListToken.GrantsHash, []byte("some hash"))
		require.False(t, resp.CompleteListing)
		require.Equal(t, resp.EstimatedItemCount, 4)
		require.Empty(t, resp.DeletedIds)
		require.Len(t, resp.Items, 1)
		require.Empty(t, cmp.Diff(resp.Items[0], hostSets[0], cmpOpts...))
		require.Equal(t, retPlg, plg)

		// request remaining results
		resp2, retPlg, err := hostplugin.ListHostSetsPage(ctx, []byte("some hash"), 3, filterFunc, resp.ListToken, repo, catalog.GetPublicId())
		require.NoError(t, err)
		require.Equal(t, resp2.ListToken.GrantsHash, []byte("some hash"))
		require.True(t, resp2.CompleteListing)
		require.Equal(t, resp2.EstimatedItemCount, 4)
		require.Empty(t, resp2.DeletedIds)
		require.Len(t, resp2.Items, 3)
		require.Empty(t, cmp.Diff(resp2.Items, hostSets[1:], cmpOpts...))
		require.Equal(t, retPlg, plg)

		deletedHostId = hostSets[0].GetPublicId()
		_, err = repo.DeleteSet(ctx, proj1.PublicId, deletedHostId)
		require.NoError(t, err)
		hostSets = hostSets[1:]

		// Run analyze to update count estimate
		_, err = sqlDb.ExecContext(ctx, "analyze")
		require.NoError(t, err)

		// request a refresh, nothing should be returned except the deleted id
		resp3, retPlg, err := hostplugin.ListHostSetsRefresh(ctx, []byte("some hash"), 1, filterFunc, resp2.ListToken, repo, catalog.GetPublicId())
		require.NoError(t, err)
		require.Equal(t, resp3.ListToken.GrantsHash, []byte("some hash"))
		require.True(t, resp3.CompleteListing)
		require.Equal(t, resp3.EstimatedItemCount, 3)
		require.Contains(t, resp3.DeletedIds, deletedHostId)
		require.Empty(t, resp3.Items)
		require.Empty(t, retPlg)
	})
}
