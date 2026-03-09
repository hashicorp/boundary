// Copyright IBM Corp. 2020, 2025
// SPDX-License-Identifier: BUSL-1.1

package credential_test

import (
	"context"
	"slices"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	"github.com/hashicorp/boundary/globals"
	"github.com/hashicorp/boundary/internal/credential"
	"github.com/hashicorp/boundary/internal/credential/vault"
	"github.com/hashicorp/boundary/internal/credential/vault/store"
	"github.com/hashicorp/boundary/internal/db"
	"github.com/hashicorp/boundary/internal/db/timestamp"
	"github.com/hashicorp/boundary/internal/iam"
	"github.com/hashicorp/boundary/internal/kms"
	"github.com/hashicorp/boundary/internal/listtoken"
	"github.com/hashicorp/boundary/internal/scheduler"
	"github.com/hashicorp/boundary/internal/types/resource"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/types/known/timestamppb"
)

func TestLibraryService_List(t *testing.T) {
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
	sche := scheduler.TestScheduler(t, conn, wrapper)
	_, prj := iam.TestScopes(t, iam.TestRepo(t, conn, wrapper))
	fiveDaysAgo := time.Now().AddDate(0, 0, -5)
	credStore := vault.TestCredentialStores(t, conn, wrapper, prj.GetPublicId(), 1)[0]
	libs := []credential.Library{
		vault.TestCredentialLibraries(t, conn, wrapper, credStore.GetPublicId(), globals.UnspecifiedCredentialType, 1)[0],
		vault.TestSSHCertificateCredentialLibraries(t, conn, wrapper, credStore.GetPublicId(), 1)[0],
		vault.TestCredentialLibraries(t, conn, wrapper, credStore.GetPublicId(), globals.UnspecifiedCredentialType, 1)[0],
		vault.TestLdapCredentialLibraries(t, conn, wrapper, credStore.GetPublicId(), 1)[0],
		vault.TestSSHCertificateCredentialLibraries(t, conn, wrapper, credStore.GetPublicId(), 1)[0],
		vault.TestSSHCertificateCredentialLibraries(t, conn, wrapper, credStore.GetPublicId(), 1)[0],
		vault.TestLdapCredentialLibraries(t, conn, wrapper, credStore.GetPublicId(), 1)[0],
	}

	// since we sort by create time descending, we need to reverse the slice
	slices.Reverse(libs)

	repo, err := vault.NewRepository(ctx, rw, rw, kms, sche)
	require.NoError(t, err)

	// Run analyze to update count estimate
	_, err = sqlDb.ExecContext(ctx, "analyze")
	require.NoError(t, err)

	cmpOpts := []cmp.Option{
		cmpopts.IgnoreUnexported(
			vault.CredentialLibrary{},
			vault.SSHCertificateCredentialLibrary{},
			vault.LdapCredentialLibrary{},
			store.SSHCertificateCredentialLibrary{},
			store.LdapCredentialLibrary{},
			store.CredentialLibrary{},
			timestamp.Timestamp{},
			timestamppb.Timestamp{},
		),
	}

	t.Run("ListLibraries validation", func(t *testing.T) {
		t.Parallel()
		t.Run("missing grants hash", func(t *testing.T) {
			t.Parallel()
			filterFunc := func(_ context.Context, l credential.Library) (bool, error) {
				return true, nil
			}
			_, err := credential.ListLibraries(ctx, nil, 1, filterFunc, repo, credStore.GetPublicId())
			require.ErrorContains(t, err, "missing grants hash")
		})
		t.Run("zero page size", func(t *testing.T) {
			t.Parallel()
			filterFunc := func(_ context.Context, l credential.Library) (bool, error) {
				return true, nil
			}
			_, err := credential.ListLibraries(ctx, []byte("some hash"), 0, filterFunc, repo, credStore.GetPublicId())
			require.ErrorContains(t, err, "page size must be at least 1")
		})
		t.Run("negative page size", func(t *testing.T) {
			t.Parallel()
			filterFunc := func(_ context.Context, l credential.Library) (bool, error) {
				return true, nil
			}
			_, err := credential.ListLibraries(ctx, []byte("some hash"), -1, filterFunc, repo, credStore.GetPublicId())
			require.ErrorContains(t, err, "page size must be at least 1")
		})
		t.Run("nil filter func", func(t *testing.T) {
			t.Parallel()
			_, err := credential.ListLibraries(ctx, []byte("some hash"), 1, nil, repo, credStore.GetPublicId())
			require.ErrorContains(t, err, "missing filter item callback")
		})
		t.Run("nil repo", func(t *testing.T) {
			t.Parallel()
			filterFunc := func(_ context.Context, l credential.Library) (bool, error) {
				return true, nil
			}
			_, err := credential.ListLibraries(ctx, []byte("some hash"), 1, filterFunc, nil, credStore.GetPublicId())
			require.ErrorContains(t, err, "missing service")
		})
		t.Run("missing credential store ID", func(t *testing.T) {
			t.Parallel()
			filterFunc := func(_ context.Context, l credential.Library) (bool, error) {
				return true, nil
			}
			_, err := credential.ListLibraries(ctx, []byte("some hash"), 1, filterFunc, repo, "")
			require.ErrorContains(t, err, "missing credential store ID")
		})
	})
	t.Run("ListLibrariesPage validation", func(t *testing.T) {
		t.Parallel()
		t.Run("missing grants hash", func(t *testing.T) {
			t.Parallel()
			filterFunc := func(_ context.Context, l credential.Library) (bool, error) {
				return true, nil
			}
			tok, err := listtoken.NewPagination(ctx, fiveDaysAgo, resource.CredentialLibrary, []byte("some hash"), "some-id", fiveDaysAgo)
			require.NoError(t, err)
			_, err = credential.ListLibrariesPage(ctx, nil, 1, filterFunc, tok, repo, credStore.GetPublicId())
			require.ErrorContains(t, err, "missing grants hash")
		})
		t.Run("zero page size", func(t *testing.T) {
			t.Parallel()
			filterFunc := func(_ context.Context, l credential.Library) (bool, error) {
				return true, nil
			}
			tok, err := listtoken.NewPagination(ctx, fiveDaysAgo, resource.CredentialLibrary, []byte("some hash"), "some-id", fiveDaysAgo)
			require.NoError(t, err)
			_, err = credential.ListLibrariesPage(ctx, []byte("some hash"), 0, filterFunc, tok, repo, credStore.GetPublicId())
			require.ErrorContains(t, err, "page size must be at least 1")
		})
		t.Run("negative page size", func(t *testing.T) {
			t.Parallel()
			filterFunc := func(_ context.Context, l credential.Library) (bool, error) {
				return true, nil
			}
			tok, err := listtoken.NewPagination(ctx, fiveDaysAgo, resource.CredentialLibrary, []byte("some hash"), "some-id", fiveDaysAgo)
			require.NoError(t, err)
			_, err = credential.ListLibrariesPage(ctx, []byte("some hash"), -1, filterFunc, tok, repo, credStore.GetPublicId())
			require.ErrorContains(t, err, "page size must be at least 1")
		})
		t.Run("nil filter func", func(t *testing.T) {
			t.Parallel()
			tok, err := listtoken.NewPagination(ctx, fiveDaysAgo, resource.CredentialLibrary, []byte("some hash"), "some-id", fiveDaysAgo)
			require.NoError(t, err)
			_, err = credential.ListLibrariesPage(ctx, []byte("some hash"), 1, nil, tok, repo, credStore.GetPublicId())
			require.ErrorContains(t, err, "missing filter item callback")
		})
		t.Run("nil token", func(t *testing.T) {
			t.Parallel()
			filterFunc := func(_ context.Context, l credential.Library) (bool, error) {
				return true, nil
			}
			_, err := credential.ListLibrariesPage(ctx, []byte("some hash"), 1, filterFunc, nil, repo, credStore.GetPublicId())
			require.ErrorContains(t, err, "missing token")
		})
		t.Run("wrong token type", func(t *testing.T) {
			t.Parallel()
			filterFunc := func(_ context.Context, l credential.Library) (bool, error) {
				return true, nil
			}
			tok, err := listtoken.NewStartRefresh(ctx, fiveDaysAgo, resource.CredentialLibrary, []byte("some hash"), fiveDaysAgo, fiveDaysAgo)
			require.NoError(t, err)
			_, err = credential.ListLibrariesPage(ctx, []byte("some hash"), 1, filterFunc, tok, repo, credStore.GetPublicId())
			require.ErrorContains(t, err, "token did not have a pagination token component")
		})
		t.Run("nil repo", func(t *testing.T) {
			t.Parallel()
			filterFunc := func(_ context.Context, l credential.Library) (bool, error) {
				return true, nil
			}
			tok, err := listtoken.NewPagination(ctx, fiveDaysAgo, resource.CredentialLibrary, []byte("some hash"), "some-id", fiveDaysAgo)
			require.NoError(t, err)
			_, err = credential.ListLibrariesPage(ctx, []byte("some hash"), 1, filterFunc, tok, nil, credStore.GetPublicId())
			require.ErrorContains(t, err, "missing service")
		})
		t.Run("missing credential store ID", func(t *testing.T) {
			t.Parallel()
			filterFunc := func(_ context.Context, l credential.Library) (bool, error) {
				return true, nil
			}
			tok, err := listtoken.NewPagination(ctx, fiveDaysAgo, resource.CredentialLibrary, []byte("some hash"), "some-id", fiveDaysAgo)
			require.NoError(t, err)
			_, err = credential.ListLibrariesPage(ctx, []byte("some hash"), 1, filterFunc, tok, repo, "")
			require.ErrorContains(t, err, "missing credential store id")
		})
		t.Run("wrong token resource type", func(t *testing.T) {
			t.Parallel()
			filterFunc := func(_ context.Context, l credential.Library) (bool, error) {
				return true, nil
			}
			tok, err := listtoken.NewPagination(ctx, fiveDaysAgo, resource.Target, []byte("some hash"), "some-id", fiveDaysAgo)
			require.NoError(t, err)
			_, err = credential.ListLibrariesPage(ctx, []byte("some hash"), 1, filterFunc, tok, repo, credStore.GetPublicId())
			require.ErrorContains(t, err, "token did not have an credential library resource type")
		})
	})
	t.Run("ListLibrariesRefresh validation", func(t *testing.T) {
		t.Parallel()
		t.Run("missing grants hash", func(t *testing.T) {
			t.Parallel()
			filterFunc := func(_ context.Context, l credential.Library) (bool, error) {
				return true, nil
			}
			tok, err := listtoken.NewStartRefresh(ctx, fiveDaysAgo, resource.CredentialLibrary, []byte("some hash"), fiveDaysAgo, fiveDaysAgo)
			require.NoError(t, err)
			_, err = credential.ListLibrariesRefresh(ctx, nil, 1, filterFunc, tok, repo, credStore.GetPublicId())
			require.ErrorContains(t, err, "missing grants hash")
		})
		t.Run("zero page size", func(t *testing.T) {
			t.Parallel()
			filterFunc := func(_ context.Context, l credential.Library) (bool, error) {
				return true, nil
			}
			tok, err := listtoken.NewStartRefresh(ctx, fiveDaysAgo, resource.CredentialLibrary, []byte("some hash"), fiveDaysAgo, fiveDaysAgo)
			require.NoError(t, err)
			_, err = credential.ListLibrariesRefresh(ctx, []byte("some hash"), 0, filterFunc, tok, repo, credStore.GetPublicId())
			require.ErrorContains(t, err, "page size must be at least 1")
		})
		t.Run("negative page size", func(t *testing.T) {
			t.Parallel()
			filterFunc := func(_ context.Context, l credential.Library) (bool, error) {
				return true, nil
			}
			tok, err := listtoken.NewStartRefresh(ctx, fiveDaysAgo, resource.CredentialLibrary, []byte("some hash"), fiveDaysAgo, fiveDaysAgo)
			require.NoError(t, err)
			_, err = credential.ListLibrariesRefresh(ctx, []byte("some hash"), -1, filterFunc, tok, repo, credStore.GetPublicId())
			require.ErrorContains(t, err, "page size must be at least 1")
		})
		t.Run("nil filter func", func(t *testing.T) {
			t.Parallel()
			tok, err := listtoken.NewStartRefresh(ctx, fiveDaysAgo, resource.CredentialLibrary, []byte("some hash"), fiveDaysAgo, fiveDaysAgo)
			require.NoError(t, err)
			_, err = credential.ListLibrariesRefresh(ctx, []byte("some hash"), 1, nil, tok, repo, credStore.GetPublicId())
			require.ErrorContains(t, err, "missing filter item callback")
		})
		t.Run("nil token", func(t *testing.T) {
			t.Parallel()
			filterFunc := func(_ context.Context, l credential.Library) (bool, error) {
				return true, nil
			}
			_, err := credential.ListLibrariesRefresh(ctx, []byte("some hash"), 1, filterFunc, nil, repo, credStore.GetPublicId())
			require.ErrorContains(t, err, "missing token")
		})
		t.Run("nil repo", func(t *testing.T) {
			t.Parallel()
			filterFunc := func(_ context.Context, l credential.Library) (bool, error) {
				return true, nil
			}
			tok, err := listtoken.NewStartRefresh(ctx, fiveDaysAgo, resource.CredentialLibrary, []byte("some hash"), fiveDaysAgo, fiveDaysAgo)
			require.NoError(t, err)
			_, err = credential.ListLibrariesRefresh(ctx, []byte("some hash"), 1, filterFunc, tok, nil, credStore.GetPublicId())
			require.ErrorContains(t, err, "missing service")
		})
		t.Run("missing credential store ID", func(t *testing.T) {
			t.Parallel()
			filterFunc := func(_ context.Context, l credential.Library) (bool, error) {
				return true, nil
			}
			tok, err := listtoken.NewStartRefresh(ctx, fiveDaysAgo, resource.CredentialLibrary, []byte("some hash"), fiveDaysAgo, fiveDaysAgo)
			require.NoError(t, err)
			_, err = credential.ListLibrariesRefresh(ctx, []byte("some hash"), 1, filterFunc, tok, repo, "")
			require.ErrorContains(t, err, "missing credential store ID")
		})
		t.Run("wrong token resource type", func(t *testing.T) {
			t.Parallel()
			filterFunc := func(_ context.Context, l credential.Library) (bool, error) {
				return true, nil
			}
			tok, err := listtoken.NewStartRefresh(ctx, fiveDaysAgo, resource.Target, []byte("some hash"), fiveDaysAgo, fiveDaysAgo)
			require.NoError(t, err)
			_, err = credential.ListLibrariesRefresh(ctx, []byte("some hash"), 1, filterFunc, tok, repo, credStore.GetPublicId())
			require.ErrorContains(t, err, "token did not have an credential library resource type")
		})
	})
	t.Run("ListLibrariesRefreshPage validation", func(t *testing.T) {
		t.Parallel()
		t.Run("missing grants hash", func(t *testing.T) {
			t.Parallel()
			filterFunc := func(_ context.Context, l credential.Library) (bool, error) {
				return true, nil
			}
			tok, err := listtoken.NewRefresh(ctx, fiveDaysAgo, resource.CredentialLibrary, []byte("some hash"), fiveDaysAgo, fiveDaysAgo, fiveDaysAgo, "some other id", fiveDaysAgo)
			require.NoError(t, err)
			_, err = credential.ListLibrariesRefreshPage(ctx, nil, 1, filterFunc, tok, repo, credStore.GetPublicId())
			require.ErrorContains(t, err, "missing grants hash")
		})
		t.Run("zero page size", func(t *testing.T) {
			t.Parallel()
			filterFunc := func(_ context.Context, l credential.Library) (bool, error) {
				return true, nil
			}
			tok, err := listtoken.NewRefresh(ctx, fiveDaysAgo, resource.CredentialLibrary, []byte("some hash"), fiveDaysAgo, fiveDaysAgo, fiveDaysAgo, "some other id", fiveDaysAgo)
			require.NoError(t, err)
			_, err = credential.ListLibrariesRefreshPage(ctx, []byte("some hash"), 0, filterFunc, tok, repo, credStore.GetPublicId())
			require.ErrorContains(t, err, "page size must be at least 1")
		})
		t.Run("negative page size", func(t *testing.T) {
			t.Parallel()
			filterFunc := func(_ context.Context, l credential.Library) (bool, error) {
				return true, nil
			}
			tok, err := listtoken.NewRefresh(ctx, fiveDaysAgo, resource.CredentialLibrary, []byte("some hash"), fiveDaysAgo, fiveDaysAgo, fiveDaysAgo, "some other id", fiveDaysAgo)
			require.NoError(t, err)
			_, err = credential.ListLibrariesRefreshPage(ctx, []byte("some hash"), -1, filterFunc, tok, repo, credStore.GetPublicId())
			require.ErrorContains(t, err, "page size must be at least 1")
		})
		t.Run("nil filter func", func(t *testing.T) {
			t.Parallel()
			tok, err := listtoken.NewRefresh(ctx, fiveDaysAgo, resource.CredentialLibrary, []byte("some hash"), fiveDaysAgo, fiveDaysAgo, fiveDaysAgo, "some other id", fiveDaysAgo)
			require.NoError(t, err)
			_, err = credential.ListLibrariesRefreshPage(ctx, []byte("some hash"), 1, nil, tok, repo, credStore.GetPublicId())
			require.ErrorContains(t, err, "missing filter item callback")
		})
		t.Run("nil token", func(t *testing.T) {
			t.Parallel()
			filterFunc := func(_ context.Context, l credential.Library) (bool, error) {
				return true, nil
			}
			_, err := credential.ListLibrariesRefreshPage(ctx, []byte("some hash"), 1, filterFunc, nil, repo, credStore.GetPublicId())
			require.ErrorContains(t, err, "missing token")
		})
		t.Run("wrong token type", func(t *testing.T) {
			t.Parallel()
			filterFunc := func(_ context.Context, l credential.Library) (bool, error) {
				return true, nil
			}
			tok, err := listtoken.NewPagination(ctx, fiveDaysAgo, resource.CredentialLibrary, []byte("some hash"), "some-id", fiveDaysAgo)
			require.NoError(t, err)
			_, err = credential.ListLibrariesRefreshPage(ctx, []byte("some hash"), 1, filterFunc, tok, repo, credStore.GetPublicId())
			require.ErrorContains(t, err, "token did not have a refresh token component")
		})
		t.Run("nil repo", func(t *testing.T) {
			t.Parallel()
			filterFunc := func(_ context.Context, l credential.Library) (bool, error) {
				return true, nil
			}
			tok, err := listtoken.NewRefresh(ctx, fiveDaysAgo, resource.CredentialLibrary, []byte("some hash"), fiveDaysAgo, fiveDaysAgo, fiveDaysAgo, "some other id", fiveDaysAgo)
			require.NoError(t, err)
			_, err = credential.ListLibrariesRefreshPage(ctx, []byte("some hash"), 1, filterFunc, tok, nil, credStore.GetPublicId())
			require.ErrorContains(t, err, "missing service")
		})
		t.Run("missing credential store ID", func(t *testing.T) {
			t.Parallel()
			filterFunc := func(_ context.Context, l credential.Library) (bool, error) {
				return true, nil
			}
			tok, err := listtoken.NewRefresh(ctx, fiveDaysAgo, resource.CredentialLibrary, []byte("some hash"), fiveDaysAgo, fiveDaysAgo, fiveDaysAgo, "some other id", fiveDaysAgo)
			require.NoError(t, err)
			_, err = credential.ListLibrariesRefreshPage(ctx, []byte("some hash"), 1, filterFunc, tok, repo, "")
			require.ErrorContains(t, err, "missing credential store id")
		})
		t.Run("wrong token resource type", func(t *testing.T) {
			t.Parallel()
			filterFunc := func(_ context.Context, l credential.Library) (bool, error) {
				return true, nil
			}
			tok, err := listtoken.NewRefresh(ctx, fiveDaysAgo, resource.Target, []byte("some hash"), fiveDaysAgo, fiveDaysAgo, fiveDaysAgo, "some other id", fiveDaysAgo)
			require.NoError(t, err)
			_, err = credential.ListLibrariesRefreshPage(ctx, []byte("some hash"), 1, filterFunc, tok, repo, credStore.GetPublicId())
			require.ErrorContains(t, err, "token did not have an credential library resource type")
		})
	})

	t.Run("simple pagination", func(t *testing.T) {
		filterFunc := func(context.Context, credential.Library) (bool, error) {
			return true, nil
		}
		resp, err := credential.ListLibraries(ctx, []byte("some hash"), 1, filterFunc, repo, credStore.GetPublicId())
		require.NoError(t, err)
		require.NotNil(t, resp.ListToken)
		require.Equal(t, resp.ListToken.GrantsHash, []byte("some hash"))
		require.False(t, resp.CompleteListing)
		require.Equal(t, resp.EstimatedItemCount, 7)
		require.Empty(t, resp.DeletedIds)
		require.Len(t, resp.Items, 1)
		require.Empty(t, cmp.Diff(resp.Items[0], libs[0], cmpOpts...))

		resp2, err := credential.ListLibrariesPage(ctx, []byte("some hash"), 1, filterFunc, resp.ListToken, repo, credStore.GetPublicId())
		require.NoError(t, err)
		require.Equal(t, resp2.ListToken.GrantsHash, []byte("some hash"))
		require.False(t, resp2.CompleteListing)
		require.Equal(t, resp2.EstimatedItemCount, 7)
		require.Empty(t, resp2.DeletedIds)
		require.Len(t, resp2.Items, 1)
		require.Empty(t, cmp.Diff(resp2.Items[0], libs[1], cmpOpts...))

		resp3, err := credential.ListLibrariesPage(ctx, []byte("some hash"), 1, filterFunc, resp2.ListToken, repo, credStore.GetPublicId())
		require.NoError(t, err)
		require.Equal(t, resp3.ListToken.GrantsHash, []byte("some hash"))
		require.False(t, resp3.CompleteListing)
		require.Equal(t, resp3.EstimatedItemCount, 7)
		require.Empty(t, resp3.DeletedIds)
		require.Len(t, resp3.Items, 1)
		require.Empty(t, cmp.Diff(resp3.Items[0], libs[2], cmpOpts...))

		resp4, err := credential.ListLibrariesPage(ctx, []byte("some hash"), 1, filterFunc, resp3.ListToken, repo, credStore.GetPublicId())
		require.NoError(t, err)
		require.Equal(t, resp4.ListToken.GrantsHash, []byte("some hash"))
		require.False(t, resp4.CompleteListing)
		require.Equal(t, resp4.EstimatedItemCount, 7)
		require.Empty(t, resp4.DeletedIds)
		require.Len(t, resp4.Items, 1)
		require.Empty(t, cmp.Diff(resp4.Items[0], libs[3], cmpOpts...))

		resp5, err := credential.ListLibrariesPage(ctx, []byte("some hash"), 1, filterFunc, resp4.ListToken, repo, credStore.GetPublicId())
		require.NoError(t, err)
		require.Equal(t, resp5.ListToken.GrantsHash, []byte("some hash"))
		require.False(t, resp5.CompleteListing)
		require.Equal(t, resp5.EstimatedItemCount, 7)
		require.Empty(t, resp5.DeletedIds)
		require.Len(t, resp5.Items, 1)
		require.Empty(t, cmp.Diff(resp5.Items[0], libs[4], cmpOpts...))

		resp6, err := credential.ListLibrariesPage(ctx, []byte("some hash"), 1, filterFunc, resp4.ListToken, repo, credStore.GetPublicId())
		require.NoError(t, err)
		require.Equal(t, resp6.ListToken.GrantsHash, []byte("some hash"))
		require.False(t, resp6.CompleteListing)
		require.Equal(t, resp6.EstimatedItemCount, 7)
		require.Empty(t, resp6.DeletedIds)
		require.Len(t, resp6.Items, 1)
		require.Empty(t, cmp.Diff(resp6.Items[0], libs[5], cmpOpts...))

		resp7, err := credential.ListLibrariesPage(ctx, []byte("some hash"), 1, filterFunc, resp4.ListToken, repo, credStore.GetPublicId())
		require.NoError(t, err)
		require.Equal(t, resp7.ListToken.GrantsHash, []byte("some hash"))
		require.True(t, resp7.CompleteListing)
		require.Equal(t, resp7.EstimatedItemCount, 7)
		require.Empty(t, resp7.DeletedIds)
		require.Len(t, resp7.Items, 1)
		require.Empty(t, cmp.Diff(resp7.Items[0], libs[6], cmpOpts...))

		// Finished initial pagination phase, request refresh
		// Expect no results.
		resp8, err := credential.ListLibrariesRefresh(ctx, []byte("some hash"), 1, filterFunc, resp5.ListToken, repo, credStore.GetPublicId())
		require.NoError(t, err)
		require.Equal(t, resp8.ListToken.GrantsHash, []byte("some hash"))
		require.True(t, resp8.CompleteListing)
		require.Equal(t, resp8.EstimatedItemCount, 7)
		require.Empty(t, resp8.DeletedIds)
		require.Empty(t, resp8.Items)

		// Create some new libraries
		newLib1 := vault.TestCredentialLibraries(t, conn, wrapper, credStore.GetPublicId(), globals.UnspecifiedCredentialType, 1)[0]
		newLib2 := vault.TestSSHCertificateCredentialLibraries(t, conn, wrapper, credStore.GetPublicId(), 1)[0]
		t.Cleanup(func() {
			_, err := repo.DeleteCredentialLibrary(ctx, credStore.ProjectId, newLib1.GetPublicId())
			require.NoError(t, err)
			_, err = repo.DeleteSSHCertificateCredentialLibrary(ctx, credStore.ProjectId, newLib2.GetPublicId())
			require.NoError(t, err)
			// Run analyze to update count estimate
			_, err = sqlDb.ExecContext(ctx, "analyze")
			require.NoError(t, err)
		})
		// Run analyze to update count estimate
		_, err = sqlDb.ExecContext(ctx, "analyze")
		require.NoError(t, err)

		// Refresh again, should get newLib2
		resp9, err := credential.ListLibrariesRefresh(ctx, []byte("some hash"), 1, filterFunc, resp6.ListToken, repo, credStore.GetPublicId())
		require.NoError(t, err)
		require.Equal(t, resp9.ListToken.GrantsHash, []byte("some hash"))
		require.False(t, resp9.CompleteListing)
		require.Equal(t, resp9.EstimatedItemCount, 9)
		require.Empty(t, resp9.DeletedIds)
		require.Len(t, resp9.Items, 1)
		require.Empty(t, cmp.Diff(resp9.Items[0], newLib2, cmpOpts...))

		// Refresh again, should get newLib1
		resp10, err := credential.ListLibrariesRefreshPage(ctx, []byte("some hash"), 1, filterFunc, resp7.ListToken, repo, credStore.GetPublicId())
		require.NoError(t, err)
		require.Equal(t, resp10.ListToken.GrantsHash, []byte("some hash"))
		require.True(t, resp10.CompleteListing)
		require.Equal(t, resp10.EstimatedItemCount, 9)
		require.Empty(t, resp10.DeletedIds)
		require.Len(t, resp10.Items, 1)
		require.Empty(t, cmp.Diff(resp10.Items[0], newLib1, cmpOpts...))

		// Refresh again, should get no results
		resp11, err := credential.ListLibrariesRefresh(ctx, []byte("some hash"), 1, filterFunc, resp8.ListToken, repo, credStore.GetPublicId())
		require.NoError(t, err)
		require.Equal(t, resp11.ListToken.GrantsHash, []byte("some hash"))
		require.True(t, resp11.CompleteListing)
		require.Equal(t, resp11.EstimatedItemCount, 9)
		require.Empty(t, resp11.DeletedIds)
		require.Empty(t, resp11.Items)
	})

	t.Run("simple pagination with aggressive filtering", func(t *testing.T) {
		filterFunc := func(ctx context.Context, l credential.Library) (bool, error) {
			return l.GetPublicId() == libs[1].GetPublicId() ||
				l.GetPublicId() == libs[len(libs)-1].GetPublicId(), nil
		}
		resp, err := credential.ListLibraries(ctx, []byte("some hash"), 1, filterFunc, repo, credStore.GetPublicId())
		require.NoError(t, err)
		require.NotNil(t, resp.ListToken)
		require.Equal(t, resp.ListToken.GrantsHash, []byte("some hash"))
		require.False(t, resp.CompleteListing)
		require.Equal(t, resp.EstimatedItemCount, 7)
		require.Empty(t, resp.DeletedIds)
		require.Len(t, resp.Items, 1)
		require.Empty(t, cmp.Diff(resp.Items[0], libs[1], cmpOpts...))

		resp2, err := credential.ListLibrariesPage(ctx, []byte("some hash"), 1, filterFunc, resp.ListToken, repo, credStore.GetPublicId())
		require.NoError(t, err)
		require.NotNil(t, resp2.ListToken)
		require.Equal(t, resp2.ListToken.GrantsHash, []byte("some hash"))
		require.True(t, resp2.CompleteListing)
		require.Equal(t, resp2.EstimatedItemCount, 7)
		require.Empty(t, resp2.DeletedIds)
		require.Len(t, resp2.Items, 1)
		require.Empty(t, cmp.Diff(resp2.Items[0], libs[len(libs)-1], cmpOpts...))

		// request a refresh, nothing should be returned
		resp3, err := credential.ListLibrariesRefresh(ctx, []byte("some hash"), 1, filterFunc, resp2.ListToken, repo, credStore.GetPublicId())
		require.NoError(t, err)
		require.Equal(t, resp3.ListToken.GrantsHash, []byte("some hash"))
		require.True(t, resp3.CompleteListing)
		require.Equal(t, resp3.EstimatedItemCount, 7)
		require.Empty(t, resp3.DeletedIds)
		require.Empty(t, resp3.Items)

		// Create some new libraries
		newLibs1 := vault.TestCredentialLibraries(t, conn, wrapper, credStore.GetPublicId(), globals.UnspecifiedCredentialType, 2)
		newLibs2 := vault.TestSSHCertificateCredentialLibraries(t, conn, wrapper, credStore.GetPublicId(), 2)
		t.Cleanup(func() {
			_, err := repo.DeleteCredentialLibrary(ctx, credStore.ProjectId, newLibs1[0].GetPublicId())
			require.NoError(t, err)
			_, err = repo.DeleteCredentialLibrary(ctx, credStore.ProjectId, newLibs1[1].GetPublicId())
			require.NoError(t, err)
			_, err = repo.DeleteSSHCertificateCredentialLibrary(ctx, credStore.ProjectId, newLibs2[0].GetPublicId())
			require.NoError(t, err)
			_, err = repo.DeleteSSHCertificateCredentialLibrary(ctx, credStore.ProjectId, newLibs2[1].GetPublicId())
			require.NoError(t, err)
			// Run analyze to update count estimate
			_, err = sqlDb.ExecContext(ctx, "analyze")
			require.NoError(t, err)
		})
		// Run analyze to update count estimate
		_, err = sqlDb.ExecContext(ctx, "analyze")
		require.NoError(t, err)

		filterFunc = func(_ context.Context, l credential.Library) (bool, error) {
			return l.GetPublicId() == newLibs2[0].GetPublicId() ||
				l.GetPublicId() == newLibs1[0].GetPublicId(), nil
		}
		// Refresh again, should get newLibs2[0]
		resp4, err := credential.ListLibrariesRefresh(ctx, []byte("some hash"), 1, filterFunc, resp3.ListToken, repo, credStore.GetPublicId())
		require.NoError(t, err)
		require.Equal(t, resp4.ListToken.GrantsHash, []byte("some hash"))
		require.False(t, resp4.CompleteListing)
		require.Equal(t, resp4.EstimatedItemCount, 11)
		require.Empty(t, resp4.DeletedIds)
		require.Len(t, resp4.Items, 1)
		require.Empty(t, cmp.Diff(resp4.Items[0], newLibs2[0], cmpOpts...))

		// Refresh again, should get newLibs1[0]
		resp5, err := credential.ListLibrariesRefreshPage(ctx, []byte("some hash"), 1, filterFunc, resp4.ListToken, repo, credStore.GetPublicId())
		require.NoError(t, err)
		require.Equal(t, resp5.ListToken.GrantsHash, []byte("some hash"))
		require.True(t, resp5.CompleteListing)
		require.Equal(t, resp5.EstimatedItemCount, 11)
		require.Empty(t, resp5.DeletedIds)
		require.Len(t, resp5.Items, 1)
		require.Empty(t, cmp.Diff(resp5.Items[0], newLibs1[0], cmpOpts...))
	})

	t.Run("simple pagination with deletion", func(t *testing.T) {
		filterFunc := func(context.Context, credential.Library) (bool, error) {
			return true, nil
		}
		deletedCredentialLibraryId := libs[0].GetPublicId()
		_, err := repo.DeleteLdapCredentialLibrary(ctx, prj.GetPublicId(), deletedCredentialLibraryId)
		require.NoError(t, err)
		libs = libs[1:]

		// Run analyze to update count estimate
		_, err = sqlDb.ExecContext(ctx, "analyze")
		require.NoError(t, err)

		resp, err := credential.ListLibraries(ctx, []byte("some hash"), 1, filterFunc, repo, credStore.GetPublicId())
		require.NoError(t, err)
		require.NotNil(t, resp.ListToken)
		require.Equal(t, resp.ListToken.GrantsHash, []byte("some hash"))
		require.False(t, resp.CompleteListing)
		require.Equal(t, resp.EstimatedItemCount, 6)
		require.Empty(t, resp.DeletedIds)
		require.Len(t, resp.Items, 1)
		require.Empty(t, cmp.Diff(resp.Items[0], libs[0], cmpOpts...))

		// request remaining results
		resp2, err := credential.ListLibrariesPage(ctx, []byte("some hash"), 5, filterFunc, resp.ListToken, repo, credStore.GetPublicId())
		require.NoError(t, err)
		require.Equal(t, resp2.ListToken.GrantsHash, []byte("some hash"))
		require.True(t, resp2.CompleteListing)
		require.Equal(t, resp2.EstimatedItemCount, 6)
		require.Empty(t, resp2.DeletedIds)
		require.Len(t, resp2.Items, 5)
		require.Empty(t, cmp.Diff(resp2.Items, libs[1:], cmpOpts...))

		deletedCredentialLibraryId = libs[0].GetPublicId()
		_, err = repo.DeleteSSHCertificateCredentialLibrary(ctx, prj.GetPublicId(), deletedCredentialLibraryId)
		require.NoError(t, err)
		libs = libs[1:]

		// Run analyze to update count estimate
		_, err = sqlDb.ExecContext(ctx, "analyze")
		require.NoError(t, err)

		// request a refresh, nothing should be returned except the deleted id
		resp3, err := credential.ListLibrariesRefresh(ctx, []byte("some hash"), 1, filterFunc, resp2.ListToken, repo, credStore.GetPublicId())
		require.NoError(t, err)
		require.Equal(t, resp3.ListToken.GrantsHash, []byte("some hash"))
		require.True(t, resp3.CompleteListing)
		require.Equal(t, resp3.EstimatedItemCount, 5)
		require.Contains(t, resp3.DeletedIds, deletedCredentialLibraryId)
		require.Empty(t, resp3.Items)
	})
}
