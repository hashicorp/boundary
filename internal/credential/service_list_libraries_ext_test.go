// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: BUSL-1.1

package credential_test

import (
	"context"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	"github.com/hashicorp/boundary/internal/credential"
	"github.com/hashicorp/boundary/internal/credential/vault"
	"github.com/hashicorp/boundary/internal/credential/vault/store"
	"github.com/hashicorp/boundary/internal/db"
	"github.com/hashicorp/boundary/internal/db/timestamp"
	"github.com/hashicorp/boundary/internal/iam"
	"github.com/hashicorp/boundary/internal/kms"
	"github.com/hashicorp/boundary/internal/refreshtoken"
	"github.com/hashicorp/boundary/internal/scheduler"
	"github.com/hashicorp/boundary/internal/types/resource"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/types/known/timestamppb"
)

func TestLibraryService_List(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	conn, _ := db.TestSetup(t, "postgres")
	sqlDb, err := conn.SqlDB(ctx)
	require.NoError(t, err)
	rw := db.New(conn)
	wrapper := db.TestWrapper(t)
	kms := kms.TestKms(t, conn, wrapper)
	sche := scheduler.TestScheduler(t, conn, wrapper)
	_, prj := iam.TestScopes(t, iam.TestRepo(t, conn, wrapper))
	credStore := vault.TestCredentialStores(t, conn, wrapper, prj.GetPublicId(), 1)[0]
	libs := []credential.Library{
		vault.TestCredentialLibraries(t, conn, wrapper, credStore.GetPublicId(), 1)[0],
		vault.TestSSHCertificateCredentialLibraries(t, conn, wrapper, credStore.GetPublicId(), 1)[0],
		vault.TestCredentialLibraries(t, conn, wrapper, credStore.GetPublicId(), 1)[0],
		vault.TestSSHCertificateCredentialLibraries(t, conn, wrapper, credStore.GetPublicId(), 1)[0],
		vault.TestSSHCertificateCredentialLibraries(t, conn, wrapper, credStore.GetPublicId(), 1)[0],
	}

	repo, err := vault.NewRepository(ctx, rw, rw, kms, sche)
	require.NoError(t, err)

	service, err := vault.NewLibraryListingService(ctx, rw, repo)
	require.NoError(t, err)

	// Run analyze to update count estimate
	_, err = sqlDb.ExecContext(ctx, "analyze")
	require.NoError(t, err)

	cmpOpts := []cmp.Option{
		cmpopts.IgnoreUnexported(
			vault.CredentialLibrary{},
			vault.SSHCertificateCredentialLibrary{},
			store.SSHCertificateCredentialLibrary{},
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
			_, err := credential.ListLibraries(ctx, nil, 1, filterFunc, service, credStore.GetPublicId())
			require.ErrorContains(t, err, "missing grants hash")
		})
		t.Run("zero page size", func(t *testing.T) {
			t.Parallel()
			filterFunc := func(_ context.Context, l credential.Library) (bool, error) {
				return true, nil
			}
			_, err := credential.ListLibraries(ctx, []byte("some hash"), 0, filterFunc, service, credStore.GetPublicId())
			require.ErrorContains(t, err, "page size must be at least 1")
		})
		t.Run("negative page size", func(t *testing.T) {
			t.Parallel()
			filterFunc := func(_ context.Context, l credential.Library) (bool, error) {
				return true, nil
			}
			_, err := credential.ListLibraries(ctx, []byte("some hash"), -1, filterFunc, service, credStore.GetPublicId())
			require.ErrorContains(t, err, "page size must be at least 1")
		})
		t.Run("nil filter func", func(t *testing.T) {
			t.Parallel()
			_, err := credential.ListLibraries(ctx, []byte("some hash"), 1, nil, service, credStore.GetPublicId())
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
			_, err := credential.ListLibraries(ctx, []byte("some hash"), 1, filterFunc, service, "")
			require.ErrorContains(t, err, "missing credential store ID")
		})
	})

	t.Run("ListLibrariesRefresh validation", func(t *testing.T) {
		t.Parallel()
		t.Run("missing grants hash", func(t *testing.T) {
			t.Parallel()
			filterFunc := func(_ context.Context, l credential.Library) (bool, error) {
				return true, nil
			}
			tok, err := refreshtoken.New(ctx, time.Now(), time.Now(), resource.CredentialLibrary, []byte("some hash"), "some-id", time.Now())
			require.NoError(t, err)
			_, err = credential.ListLibrariesRefresh(ctx, nil, 1, filterFunc, tok, service, credStore.GetPublicId())
			require.ErrorContains(t, err, "missing grants hash")
		})
		t.Run("zero page size", func(t *testing.T) {
			t.Parallel()
			filterFunc := func(_ context.Context, l credential.Library) (bool, error) {
				return true, nil
			}
			tok, err := refreshtoken.New(ctx, time.Now(), time.Now(), resource.CredentialLibrary, []byte("some hash"), "some-id", time.Now())
			require.NoError(t, err)
			_, err = credential.ListLibrariesRefresh(ctx, []byte("some hash"), 0, filterFunc, tok, service, credStore.GetPublicId())
			require.ErrorContains(t, err, "page size must be at least 1")
		})
		t.Run("negative page size", func(t *testing.T) {
			t.Parallel()
			filterFunc := func(_ context.Context, l credential.Library) (bool, error) {
				return true, nil
			}
			tok, err := refreshtoken.New(ctx, time.Now(), time.Now(), resource.CredentialLibrary, []byte("some hash"), "some-id", time.Now())
			require.NoError(t, err)
			_, err = credential.ListLibrariesRefresh(ctx, []byte("some hash"), -1, filterFunc, tok, service, credStore.GetPublicId())
			require.ErrorContains(t, err, "page size must be at least 1")
		})
		t.Run("nil filter func", func(t *testing.T) {
			t.Parallel()
			tok, err := refreshtoken.New(ctx, time.Now(), time.Now(), resource.CredentialLibrary, []byte("some hash"), "some-id", time.Now())
			require.NoError(t, err)
			_, err = credential.ListLibrariesRefresh(ctx, []byte("some hash"), 1, nil, tok, service, credStore.GetPublicId())
			require.ErrorContains(t, err, "missing filter item callback")
		})
		t.Run("nil token", func(t *testing.T) {
			t.Parallel()
			filterFunc := func(_ context.Context, l credential.Library) (bool, error) {
				return true, nil
			}
			_, err = credential.ListLibrariesRefresh(ctx, []byte("some hash"), 1, filterFunc, nil, service, credStore.GetPublicId())
			require.ErrorContains(t, err, "missing token")
		})
		t.Run("nil repo", func(t *testing.T) {
			t.Parallel()
			filterFunc := func(_ context.Context, l credential.Library) (bool, error) {
				return true, nil
			}
			tok, err := refreshtoken.New(ctx, time.Now(), time.Now(), resource.CredentialLibrary, []byte("some hash"), "some-id", time.Now())
			require.NoError(t, err)
			_, err = credential.ListLibrariesRefresh(ctx, []byte("some hash"), 1, filterFunc, tok, nil, credStore.GetPublicId())
			require.ErrorContains(t, err, "missing service")
		})
		t.Run("missing credential store ID", func(t *testing.T) {
			t.Parallel()
			filterFunc := func(_ context.Context, l credential.Library) (bool, error) {
				return true, nil
			}
			tok, err := refreshtoken.New(ctx, time.Now(), time.Now(), resource.CredentialLibrary, []byte("some hash"), "some-id", time.Now())
			require.NoError(t, err)
			_, err = credential.ListLibrariesRefresh(ctx, []byte("some hash"), 1, filterFunc, tok, service, "")
			require.ErrorContains(t, err, "missing credential store ID")
		})
	})

	t.Run("simple pagination", func(t *testing.T) {
		filterFunc := func(context.Context, credential.Library) (bool, error) {
			return true, nil
		}
		resp, err := credential.ListLibraries(ctx, []byte("some hash"), 1, filterFunc, service, credStore.GetPublicId())
		require.NoError(t, err)
		require.NotNil(t, resp.RefreshToken)
		require.Equal(t, resp.RefreshToken.GrantsHash, []byte("some hash"))
		require.False(t, resp.CompleteListing)
		require.Equal(t, resp.EstimatedItemCount, 5)
		require.Empty(t, resp.DeletedIds)
		require.Len(t, resp.Items, 1)
		require.Empty(t, cmp.Diff(resp.Items[0], libs[0], cmpOpts...))

		resp2, err := credential.ListLibrariesRefresh(ctx, []byte("some hash"), 1, filterFunc, resp.RefreshToken, service, credStore.GetPublicId())
		require.NoError(t, err)
		require.Equal(t, resp2.RefreshToken.GrantsHash, []byte("some hash"))
		require.False(t, resp2.CompleteListing)
		require.Equal(t, resp2.EstimatedItemCount, 5)
		require.Empty(t, resp2.DeletedIds)
		require.Len(t, resp2.Items, 1)
		require.Empty(t, cmp.Diff(resp2.Items[0], libs[1], cmpOpts...))

		resp3, err := credential.ListLibrariesRefresh(ctx, []byte("some hash"), 1, filterFunc, resp2.RefreshToken, service, credStore.GetPublicId())
		require.NoError(t, err)
		require.Equal(t, resp3.RefreshToken.GrantsHash, []byte("some hash"))
		require.False(t, resp3.CompleteListing)
		require.Equal(t, resp3.EstimatedItemCount, 5)
		require.Empty(t, resp3.DeletedIds)
		require.Len(t, resp3.Items, 1)
		require.Empty(t, cmp.Diff(resp3.Items[0], libs[2], cmpOpts...))

		resp4, err := credential.ListLibrariesRefresh(ctx, []byte("some hash"), 1, filterFunc, resp3.RefreshToken, service, credStore.GetPublicId())
		require.NoError(t, err)
		require.Equal(t, resp4.RefreshToken.GrantsHash, []byte("some hash"))
		require.False(t, resp4.CompleteListing)
		require.Equal(t, resp4.EstimatedItemCount, 5)
		require.Empty(t, resp4.DeletedIds)
		require.Len(t, resp4.Items, 1)
		require.Empty(t, cmp.Diff(resp4.Items[0], libs[3], cmpOpts...))

		resp5, err := credential.ListLibrariesRefresh(ctx, []byte("some hash"), 1, filterFunc, resp4.RefreshToken, service, credStore.GetPublicId())
		require.NoError(t, err)
		require.Equal(t, resp5.RefreshToken.GrantsHash, []byte("some hash"))
		require.True(t, resp5.CompleteListing)
		require.Equal(t, resp5.EstimatedItemCount, 5)
		require.Empty(t, resp5.DeletedIds)
		require.Len(t, resp5.Items, 1)
		require.Empty(t, cmp.Diff(resp5.Items[0], libs[4], cmpOpts...))

		resp6, err := credential.ListLibrariesRefresh(ctx, []byte("some hash"), 1, filterFunc, resp5.RefreshToken, service, credStore.GetPublicId())
		require.NoError(t, err)
		require.Equal(t, resp6.RefreshToken.GrantsHash, []byte("some hash"))
		require.True(t, resp6.CompleteListing)
		require.Equal(t, resp6.EstimatedItemCount, 5)
		require.Empty(t, resp6.DeletedIds)
		require.Empty(t, resp6.Items)
	})

	t.Run("simple pagination with aggressive filtering", func(t *testing.T) {
		filterFunc := func(ctx context.Context, l credential.Library) (bool, error) {
			return l.GetPublicId() == libs[len(libs)-1].GetPublicId(), nil
		}
		resp, err := credential.ListLibraries(ctx, []byte("some hash"), 1, filterFunc, service, credStore.GetPublicId())
		require.NoError(t, err)
		require.NotNil(t, resp.RefreshToken)
		require.Equal(t, resp.RefreshToken.GrantsHash, []byte("some hash"))
		require.True(t, resp.CompleteListing)
		require.Equal(t, resp.EstimatedItemCount, 1)
		require.Empty(t, resp.DeletedIds)
		require.Len(t, resp.Items, 1)
		require.Empty(t, cmp.Diff(resp.Items[0], libs[4], cmpOpts...))

		resp2, err := credential.ListLibrariesRefresh(ctx, []byte("some hash"), 1, filterFunc, resp.RefreshToken, service, credStore.GetPublicId())
		require.NoError(t, err)
		require.Equal(t, resp2.RefreshToken.GrantsHash, []byte("some hash"))
		require.True(t, resp2.CompleteListing)
		// Note: this might be surprising, but there isn't any way for the refresh
		// call to know that the last call got a different number.
		require.Equal(t, resp2.EstimatedItemCount, 5)
		require.Empty(t, resp2.DeletedIds)
		require.Empty(t, resp2.Items)
	})

	t.Run("simple pagination with deletion", func(t *testing.T) {
		filterFunc := func(ctx context.Context, l credential.Library) (bool, error) {
			return true, nil
		}
		deletedLibraryId := libs[0].GetPublicId()
		_, err := repo.DeleteCredentialLibrary(ctx, prj.GetPublicId(), deletedLibraryId)
		require.NoError(t, err)
		libs = libs[1:]

		// Run analyze to update count estimate
		_, err = sqlDb.ExecContext(ctx, "analyze")
		require.NoError(t, err)

		resp, err := credential.ListLibraries(ctx, []byte("some hash"), 1, filterFunc, service, credStore.GetPublicId())
		require.NoError(t, err)
		require.NotNil(t, resp.RefreshToken)
		require.Equal(t, resp.RefreshToken.GrantsHash, []byte("some hash"))
		require.False(t, resp.CompleteListing)
		require.Equal(t, resp.EstimatedItemCount, 4)
		require.Empty(t, resp.DeletedIds)
		require.Len(t, resp.Items, 1)
		require.Empty(t, cmp.Diff(resp.Items[0], libs[0], cmpOpts...))

		resp2, err := credential.ListLibrariesRefresh(ctx, []byte("some hash"), 1, filterFunc, resp.RefreshToken, service, credStore.GetPublicId())
		require.NoError(t, err)
		require.Equal(t, resp2.RefreshToken.GrantsHash, []byte("some hash"))
		require.False(t, resp2.CompleteListing)
		require.Equal(t, resp2.EstimatedItemCount, 4)
		require.Empty(t, resp2.DeletedIds)
		require.Len(t, resp2.Items, 1)
		require.Empty(t, cmp.Diff(resp2.Items[0], libs[1], cmpOpts...))

		deletedLibraryId = libs[0].GetPublicId()
		_, err = repo.DeleteSSHCertificateCredentialLibrary(ctx, prj.GetPublicId(), deletedLibraryId)
		require.NoError(t, err)
		libs = libs[1:]

		// Run analyze to update count estimate
		_, err = sqlDb.ExecContext(ctx, "analyze")
		require.NoError(t, err)

		resp3, err := credential.ListLibrariesRefresh(ctx, []byte("some hash"), 1, filterFunc, resp2.RefreshToken, service, credStore.GetPublicId())
		require.NoError(t, err)
		require.Equal(t, resp3.RefreshToken.GrantsHash, []byte("some hash"))
		require.False(t, resp3.CompleteListing)
		require.Equal(t, resp3.EstimatedItemCount, 3)
		require.Contains(t, resp3.DeletedIds, deletedLibraryId)
		require.Len(t, resp3.Items, 1)
		require.Empty(t, cmp.Diff(resp3.Items[0], libs[1], cmpOpts...))

		resp4, err := credential.ListLibrariesRefresh(ctx, []byte("some hash"), 1, filterFunc, resp3.RefreshToken, service, credStore.GetPublicId())
		require.NoError(t, err)
		require.Equal(t, resp4.RefreshToken.GrantsHash, []byte("some hash"))
		require.True(t, resp4.CompleteListing)
		require.Equal(t, resp4.EstimatedItemCount, 3)
		require.Len(t, resp4.Items, 1)
		require.Empty(t, cmp.Diff(resp4.Items[0], libs[2], cmpOpts...))

		resp5, err := credential.ListLibrariesRefresh(ctx, []byte("some hash"), 1, filterFunc, resp4.RefreshToken, service, credStore.GetPublicId())
		require.NoError(t, err)
		require.Equal(t, resp5.RefreshToken.GrantsHash, []byte("some hash"))
		require.True(t, resp5.CompleteListing)
		require.Equal(t, resp5.EstimatedItemCount, 3)
		require.Empty(t, resp5.Items)
	})
}
