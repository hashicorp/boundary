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
	"github.com/hashicorp/boundary/internal/credential/static"
	"github.com/hashicorp/boundary/internal/credential/static/store"
	"github.com/hashicorp/boundary/internal/db"
	"github.com/hashicorp/boundary/internal/db/timestamp"
	"github.com/hashicorp/boundary/internal/iam"
	"github.com/hashicorp/boundary/internal/kms"
	"github.com/hashicorp/boundary/internal/listtoken"
	"github.com/hashicorp/boundary/internal/types/resource"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/testing/protocmp"
	"google.golang.org/protobuf/types/known/timestamppb"
)

func TestService_List(t *testing.T) {
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
	_, prj := iam.TestScopes(t, iam.TestRepo(t, conn, wrapper))
	fiveDaysAgo := time.Now().AddDate(0, 0, -5)
	credStore := static.TestCredentialStore(t, conn, wrapper, prj.GetPublicId())
	obj, _ := static.TestJsonObject(t)
	creds := []credential.Static{
		static.TestJsonCredential(t, conn, wrapper, credStore.GetPublicId(), prj.GetPublicId(), obj),
		static.TestUsernamePasswordCredential(t, conn, wrapper, "someuser", "somepassword", credStore.GetPublicId(), prj.GetPublicId()),
		static.TestSshPrivateKeyCredential(t, conn, wrapper, "someuser", static.TestSshPrivateKeyPem, credStore.GetPublicId(), prj.GetPublicId()),
		static.TestJsonCredential(t, conn, wrapper, credStore.GetPublicId(), prj.GetPublicId(), obj),
		static.TestJsonCredential(t, conn, wrapper, credStore.GetPublicId(), prj.GetPublicId(), obj),
	}
	// since we sort by create time descending, we need to reverse the slice
	slices.Reverse(creds)

	// Run analyze to update count estimates
	_, err = sqlDb.ExecContext(ctx, "analyze")
	require.NoError(t, err)

	repo, err := static.NewRepository(ctx, rw, rw, kms)
	require.NoError(t, err)

	cmpOpts := []cmp.Option{
		cmpopts.IgnoreUnexported(
			static.JsonCredential{},
			store.JsonCredential{},
			static.UsernamePasswordCredential{},
			store.UsernamePasswordCredential{},
			static.SshPrivateKeyCredential{},
			store.SshPrivateKeyCredential{},
			timestamp.Timestamp{},
			timestamppb.Timestamp{},
		),
		protocmp.Transform(),
		protocmp.IgnoreFields(
			&store.JsonCredential{},
			"object",
			"object_encrypted",
		),
		protocmp.IgnoreFields(
			&store.UsernamePasswordCredential{},
			"password",
			"ct_password",
		),
		protocmp.IgnoreFields(
			&store.SshPrivateKeyCredential{},
			"private_key",
			"private_key_encrypted",
		),
	}

	t.Run("List validation", func(t *testing.T) {
		t.Parallel()
		t.Run("missing grants hash", func(t *testing.T) {
			t.Parallel()
			filterFunc := func(_ context.Context, c credential.Static) (bool, error) {
				return true, nil
			}
			_, err := credential.List(ctx, nil, 1, filterFunc, repo, credStore.GetPublicId())
			require.ErrorContains(t, err, "missing grants hash")
		})
		t.Run("zero page size", func(t *testing.T) {
			t.Parallel()
			filterFunc := func(_ context.Context, c credential.Static) (bool, error) {
				return true, nil
			}
			_, err := credential.List(ctx, []byte("some hash"), 0, filterFunc, repo, credStore.GetPublicId())
			require.ErrorContains(t, err, "page size must be at least 1")
		})
		t.Run("negative page size", func(t *testing.T) {
			t.Parallel()
			filterFunc := func(_ context.Context, c credential.Static) (bool, error) {
				return true, nil
			}
			_, err := credential.List(ctx, []byte("some hash"), -1, filterFunc, repo, credStore.GetPublicId())
			require.ErrorContains(t, err, "page size must be at least 1")
		})
		t.Run("nil filter func", func(t *testing.T) {
			t.Parallel()
			_, err := credential.List(ctx, []byte("some hash"), 1, nil, repo, credStore.GetPublicId())
			require.ErrorContains(t, err, "missing filter item callback")
		})
		t.Run("nil repo", func(t *testing.T) {
			t.Parallel()
			filterFunc := func(_ context.Context, c credential.Static) (bool, error) {
				return true, nil
			}
			_, err := credential.List(ctx, []byte("some hash"), 1, filterFunc, nil, credStore.GetPublicId())
			require.ErrorContains(t, err, "missing service")
		})
		t.Run("missing credential store ID", func(t *testing.T) {
			t.Parallel()
			filterFunc := func(_ context.Context, c credential.Static) (bool, error) {
				return true, nil
			}
			_, err := credential.List(ctx, []byte("some hash"), 1, filterFunc, repo, "")
			require.ErrorContains(t, err, "missing credential store ID")
		})
	})
	t.Run("ListPage validation", func(t *testing.T) {
		t.Parallel()
		t.Run("missing grants hash", func(t *testing.T) {
			t.Parallel()
			filterFunc := func(_ context.Context, c credential.Static) (bool, error) {
				return true, nil
			}
			tok, err := listtoken.NewPagination(ctx, fiveDaysAgo, resource.Credential, []byte("some hash"), "some-id", fiveDaysAgo)
			require.NoError(t, err)
			_, err = credential.ListPage(ctx, nil, 1, filterFunc, tok, repo, credStore.GetPublicId())
			require.ErrorContains(t, err, "missing grants hash")
		})
		t.Run("zero page size", func(t *testing.T) {
			t.Parallel()
			filterFunc := func(_ context.Context, c credential.Static) (bool, error) {
				return true, nil
			}
			tok, err := listtoken.NewPagination(ctx, fiveDaysAgo, resource.Credential, []byte("some hash"), "some-id", fiveDaysAgo)
			require.NoError(t, err)
			_, err = credential.ListPage(ctx, []byte("some hash"), 0, filterFunc, tok, repo, credStore.GetPublicId())
			require.ErrorContains(t, err, "page size must be at least 1")
		})
		t.Run("negative page size", func(t *testing.T) {
			t.Parallel()
			filterFunc := func(_ context.Context, c credential.Static) (bool, error) {
				return true, nil
			}
			tok, err := listtoken.NewPagination(ctx, fiveDaysAgo, resource.Credential, []byte("some hash"), "some-id", fiveDaysAgo)
			require.NoError(t, err)
			_, err = credential.ListPage(ctx, []byte("some hash"), -1, filterFunc, tok, repo, credStore.GetPublicId())
			require.ErrorContains(t, err, "page size must be at least 1")
		})
		t.Run("nil filter func", func(t *testing.T) {
			t.Parallel()
			tok, err := listtoken.NewPagination(ctx, fiveDaysAgo, resource.Credential, []byte("some hash"), "some-id", fiveDaysAgo)
			require.NoError(t, err)
			_, err = credential.ListPage(ctx, []byte("some hash"), 1, nil, tok, repo, credStore.GetPublicId())
			require.ErrorContains(t, err, "missing filter item callback")
		})
		t.Run("nil token", func(t *testing.T) {
			t.Parallel()
			filterFunc := func(_ context.Context, c credential.Static) (bool, error) {
				return true, nil
			}
			_, err := credential.ListPage(ctx, []byte("some hash"), 1, filterFunc, nil, repo, credStore.GetPublicId())
			require.ErrorContains(t, err, "missing token")
		})
		t.Run("wrong token type", func(t *testing.T) {
			t.Parallel()
			filterFunc := func(_ context.Context, c credential.Static) (bool, error) {
				return true, nil
			}
			tok, err := listtoken.NewStartRefresh(ctx, fiveDaysAgo, resource.Credential, []byte("some hash"), fiveDaysAgo, fiveDaysAgo)
			require.NoError(t, err)
			_, err = credential.ListPage(ctx, []byte("some hash"), 1, filterFunc, tok, repo, credStore.GetPublicId())
			require.ErrorContains(t, err, "token did not have a pagination token component")
		})
		t.Run("nil repo", func(t *testing.T) {
			t.Parallel()
			filterFunc := func(_ context.Context, c credential.Static) (bool, error) {
				return true, nil
			}
			tok, err := listtoken.NewPagination(ctx, fiveDaysAgo, resource.Credential, []byte("some hash"), "some-id", fiveDaysAgo)
			require.NoError(t, err)
			_, err = credential.ListPage(ctx, []byte("some hash"), 1, filterFunc, tok, nil, credStore.GetPublicId())
			require.ErrorContains(t, err, "missing service")
		})
		t.Run("missing credential store ID", func(t *testing.T) {
			t.Parallel()
			filterFunc := func(_ context.Context, c credential.Static) (bool, error) {
				return true, nil
			}
			tok, err := listtoken.NewPagination(ctx, fiveDaysAgo, resource.Credential, []byte("some hash"), "some-id", fiveDaysAgo)
			require.NoError(t, err)
			_, err = credential.ListPage(ctx, []byte("some hash"), 1, filterFunc, tok, repo, "")
			require.ErrorContains(t, err, "missing credential store ID")
		})
		t.Run("wrong token resource type", func(t *testing.T) {
			t.Parallel()
			filterFunc := func(_ context.Context, c credential.Static) (bool, error) {
				return true, nil
			}
			tok, err := listtoken.NewPagination(ctx, fiveDaysAgo, resource.Target, []byte("some hash"), "some-id", fiveDaysAgo)
			require.NoError(t, err)
			_, err = credential.ListPage(ctx, []byte("some hash"), 1, filterFunc, tok, repo, credStore.GetPublicId())
			require.ErrorContains(t, err, "token did not have a credential resource type")
		})
	})
	t.Run("ListRefresh validation", func(t *testing.T) {
		t.Parallel()
		t.Run("missing grants hash", func(t *testing.T) {
			t.Parallel()
			filterFunc := func(_ context.Context, c credential.Static) (bool, error) {
				return true, nil
			}
			tok, err := listtoken.NewStartRefresh(ctx, fiveDaysAgo, resource.Credential, []byte("some hash"), fiveDaysAgo, fiveDaysAgo)
			require.NoError(t, err)
			_, err = credential.ListRefresh(ctx, nil, 1, filterFunc, tok, repo, credStore.GetPublicId())
			require.ErrorContains(t, err, "missing grants hash")
		})
		t.Run("zero page size", func(t *testing.T) {
			t.Parallel()
			filterFunc := func(_ context.Context, c credential.Static) (bool, error) {
				return true, nil
			}
			tok, err := listtoken.NewStartRefresh(ctx, fiveDaysAgo, resource.Credential, []byte("some hash"), fiveDaysAgo, fiveDaysAgo)
			require.NoError(t, err)
			_, err = credential.ListRefresh(ctx, []byte("some hash"), 0, filterFunc, tok, repo, credStore.GetPublicId())
			require.ErrorContains(t, err, "page size must be at least 1")
		})
		t.Run("negative page size", func(t *testing.T) {
			t.Parallel()
			filterFunc := func(_ context.Context, c credential.Static) (bool, error) {
				return true, nil
			}
			tok, err := listtoken.NewStartRefresh(ctx, fiveDaysAgo, resource.Credential, []byte("some hash"), fiveDaysAgo, fiveDaysAgo)
			require.NoError(t, err)
			_, err = credential.ListRefresh(ctx, []byte("some hash"), -1, filterFunc, tok, repo, credStore.GetPublicId())
			require.ErrorContains(t, err, "page size must be at least 1")
		})
		t.Run("nil filter func", func(t *testing.T) {
			t.Parallel()
			tok, err := listtoken.NewStartRefresh(ctx, fiveDaysAgo, resource.Credential, []byte("some hash"), fiveDaysAgo, fiveDaysAgo)
			require.NoError(t, err)
			_, err = credential.ListRefresh(ctx, []byte("some hash"), 1, nil, tok, repo, credStore.GetPublicId())
			require.ErrorContains(t, err, "missing filter item callback")
		})
		t.Run("nil token", func(t *testing.T) {
			t.Parallel()
			filterFunc := func(_ context.Context, c credential.Static) (bool, error) {
				return true, nil
			}
			_, err := credential.ListRefresh(ctx, []byte("some hash"), 1, filterFunc, nil, repo, credStore.GetPublicId())
			require.ErrorContains(t, err, "missing token")
		})
		t.Run("nil repo", func(t *testing.T) {
			t.Parallel()
			filterFunc := func(_ context.Context, c credential.Static) (bool, error) {
				return true, nil
			}
			tok, err := listtoken.NewStartRefresh(ctx, fiveDaysAgo, resource.Credential, []byte("some hash"), fiveDaysAgo, fiveDaysAgo)
			require.NoError(t, err)
			_, err = credential.ListRefresh(ctx, []byte("some hash"), 1, filterFunc, tok, nil, credStore.GetPublicId())
			require.ErrorContains(t, err, "missing service")
		})
		t.Run("missing credential store ID", func(t *testing.T) {
			t.Parallel()
			filterFunc := func(_ context.Context, c credential.Static) (bool, error) {
				return true, nil
			}
			tok, err := listtoken.NewStartRefresh(ctx, fiveDaysAgo, resource.Credential, []byte("some hash"), fiveDaysAgo, fiveDaysAgo)
			require.NoError(t, err)
			_, err = credential.ListRefresh(ctx, []byte("some hash"), 1, filterFunc, tok, repo, "")
			require.ErrorContains(t, err, "missing credential store ID")
		})
		t.Run("wrong token resource type", func(t *testing.T) {
			t.Parallel()
			filterFunc := func(_ context.Context, c credential.Static) (bool, error) {
				return true, nil
			}
			tok, err := listtoken.NewStartRefresh(ctx, fiveDaysAgo, resource.Target, []byte("some hash"), fiveDaysAgo, fiveDaysAgo)
			require.NoError(t, err)
			_, err = credential.ListRefresh(ctx, []byte("some hash"), 1, filterFunc, tok, repo, credStore.GetPublicId())
			require.ErrorContains(t, err, "token did not have a credential resource type")
		})
	})
	t.Run("ListRefreshPage validation", func(t *testing.T) {
		t.Parallel()
		t.Run("missing grants hash", func(t *testing.T) {
			t.Parallel()
			filterFunc := func(_ context.Context, c credential.Static) (bool, error) {
				return true, nil
			}
			tok, err := listtoken.NewRefresh(ctx, fiveDaysAgo, resource.Credential, []byte("some hash"), fiveDaysAgo, fiveDaysAgo, fiveDaysAgo, "some other id", fiveDaysAgo)
			require.NoError(t, err)
			_, err = credential.ListRefreshPage(ctx, nil, 1, filterFunc, tok, repo, credStore.GetPublicId())
			require.ErrorContains(t, err, "missing grants hash")
		})
		t.Run("zero page size", func(t *testing.T) {
			t.Parallel()
			filterFunc := func(_ context.Context, c credential.Static) (bool, error) {
				return true, nil
			}
			tok, err := listtoken.NewRefresh(ctx, fiveDaysAgo, resource.Credential, []byte("some hash"), fiveDaysAgo, fiveDaysAgo, fiveDaysAgo, "some other id", fiveDaysAgo)
			require.NoError(t, err)
			_, err = credential.ListRefreshPage(ctx, []byte("some hash"), 0, filterFunc, tok, repo, credStore.GetPublicId())
			require.ErrorContains(t, err, "page size must be at least 1")
		})
		t.Run("negative page size", func(t *testing.T) {
			t.Parallel()
			filterFunc := func(_ context.Context, c credential.Static) (bool, error) {
				return true, nil
			}
			tok, err := listtoken.NewRefresh(ctx, fiveDaysAgo, resource.Credential, []byte("some hash"), fiveDaysAgo, fiveDaysAgo, fiveDaysAgo, "some other id", fiveDaysAgo)
			require.NoError(t, err)
			_, err = credential.ListRefreshPage(ctx, []byte("some hash"), -1, filterFunc, tok, repo, credStore.GetPublicId())
			require.ErrorContains(t, err, "page size must be at least 1")
		})
		t.Run("nil filter func", func(t *testing.T) {
			t.Parallel()
			tok, err := listtoken.NewRefresh(ctx, fiveDaysAgo, resource.Credential, []byte("some hash"), fiveDaysAgo, fiveDaysAgo, fiveDaysAgo, "some other id", fiveDaysAgo)
			require.NoError(t, err)
			_, err = credential.ListRefreshPage(ctx, []byte("some hash"), 1, nil, tok, repo, credStore.GetPublicId())
			require.ErrorContains(t, err, "missing filter item callback")
		})
		t.Run("nil token", func(t *testing.T) {
			t.Parallel()
			filterFunc := func(_ context.Context, c credential.Static) (bool, error) {
				return true, nil
			}
			_, err := credential.ListRefreshPage(ctx, []byte("some hash"), 1, filterFunc, nil, repo, credStore.GetPublicId())
			require.ErrorContains(t, err, "missing token")
		})
		t.Run("wrong token type", func(t *testing.T) {
			t.Parallel()
			filterFunc := func(_ context.Context, c credential.Static) (bool, error) {
				return true, nil
			}
			tok, err := listtoken.NewPagination(ctx, fiveDaysAgo, resource.Credential, []byte("some hash"), "some-id", fiveDaysAgo)
			require.NoError(t, err)
			_, err = credential.ListRefreshPage(ctx, []byte("some hash"), 1, filterFunc, tok, repo, credStore.GetPublicId())
			require.ErrorContains(t, err, "token did not have a refresh token component")
		})
		t.Run("nil repo", func(t *testing.T) {
			t.Parallel()
			filterFunc := func(_ context.Context, c credential.Static) (bool, error) {
				return true, nil
			}
			tok, err := listtoken.NewRefresh(ctx, fiveDaysAgo, resource.Credential, []byte("some hash"), fiveDaysAgo, fiveDaysAgo, fiveDaysAgo, "some other id", fiveDaysAgo)
			require.NoError(t, err)
			_, err = credential.ListRefreshPage(ctx, []byte("some hash"), 1, filterFunc, tok, nil, credStore.GetPublicId())
			require.ErrorContains(t, err, "missing service")
		})
		t.Run("missing credential store id", func(t *testing.T) {
			t.Parallel()
			filterFunc := func(_ context.Context, c credential.Static) (bool, error) {
				return true, nil
			}
			tok, err := listtoken.NewRefresh(ctx, fiveDaysAgo, resource.Credential, []byte("some hash"), fiveDaysAgo, fiveDaysAgo, fiveDaysAgo, "some other id", fiveDaysAgo)
			require.NoError(t, err)
			_, err = credential.ListRefreshPage(ctx, []byte("some hash"), 1, filterFunc, tok, repo, "")
			require.ErrorContains(t, err, "missing credential store ID")
		})
		t.Run("wrong token resource type", func(t *testing.T) {
			t.Parallel()
			filterFunc := func(_ context.Context, c credential.Static) (bool, error) {
				return true, nil
			}
			tok, err := listtoken.NewRefresh(ctx, fiveDaysAgo, resource.Target, []byte("some hash"), fiveDaysAgo, fiveDaysAgo, fiveDaysAgo, "some other id", fiveDaysAgo)
			require.NoError(t, err)
			_, err = credential.ListRefreshPage(ctx, []byte("some hash"), 1, filterFunc, tok, repo, credStore.GetPublicId())
			require.ErrorContains(t, err, "token did not have a credential resource type")
		})
	})

	t.Run("simple pagination", func(t *testing.T) {
		filterFunc := func(context.Context, credential.Static) (bool, error) {
			return true, nil
		}
		resp, err := credential.List(ctx, []byte("some hash"), 1, filterFunc, repo, credStore.GetPublicId())
		require.NoError(t, err)
		require.NotNil(t, resp.ListToken)
		require.Equal(t, resp.ListToken.GrantsHash, []byte("some hash"))
		require.False(t, resp.CompleteListing)
		require.Equal(t, resp.EstimatedItemCount, 5)
		require.Empty(t, resp.DeletedIds)
		require.Len(t, resp.Items, 1)
		require.Empty(t, cmp.Diff(resp.Items[0], creds[0], cmpOpts...))

		resp2, err := credential.ListPage(ctx, []byte("some hash"), 1, filterFunc, resp.ListToken, repo, credStore.GetPublicId())
		require.NoError(t, err)
		require.Equal(t, resp2.ListToken.GrantsHash, []byte("some hash"))
		require.False(t, resp2.CompleteListing)
		require.Equal(t, resp2.EstimatedItemCount, 5)
		require.Empty(t, resp2.DeletedIds)
		require.Len(t, resp2.Items, 1)
		require.Empty(t, cmp.Diff(resp2.Items[0], creds[1], cmpOpts...))

		resp3, err := credential.ListPage(ctx, []byte("some hash"), 1, filterFunc, resp2.ListToken, repo, credStore.GetPublicId())
		require.NoError(t, err)
		require.Equal(t, resp3.ListToken.GrantsHash, []byte("some hash"))
		require.False(t, resp3.CompleteListing)
		require.Equal(t, resp3.EstimatedItemCount, 5)
		require.Empty(t, resp3.DeletedIds)
		require.Len(t, resp3.Items, 1)
		require.Empty(t, cmp.Diff(resp3.Items[0], creds[2], cmpOpts...))

		resp4, err := credential.ListPage(ctx, []byte("some hash"), 1, filterFunc, resp3.ListToken, repo, credStore.GetPublicId())
		require.NoError(t, err)
		require.Equal(t, resp4.ListToken.GrantsHash, []byte("some hash"))
		require.False(t, resp4.CompleteListing)
		require.Equal(t, resp4.EstimatedItemCount, 5)
		require.Empty(t, resp4.DeletedIds)
		require.Len(t, resp4.Items, 1)
		require.Empty(t, cmp.Diff(resp4.Items[0], creds[3], cmpOpts...))

		resp5, err := credential.ListPage(ctx, []byte("some hash"), 1, filterFunc, resp4.ListToken, repo, credStore.GetPublicId())
		require.NoError(t, err)
		require.Equal(t, resp5.ListToken.GrantsHash, []byte("some hash"))
		require.True(t, resp5.CompleteListing)
		require.Equal(t, resp5.EstimatedItemCount, 5)
		require.Empty(t, resp5.DeletedIds)
		require.Len(t, resp5.Items, 1)
		require.Empty(t, cmp.Diff(resp5.Items[0], creds[4], cmpOpts...))

		// Finished initial pagination phase, request refresh
		// Expect no results.
		resp6, err := credential.ListRefresh(ctx, []byte("some hash"), 1, filterFunc, resp5.ListToken, repo, credStore.GetPublicId())
		require.NoError(t, err)
		require.Equal(t, resp6.ListToken.GrantsHash, []byte("some hash"))
		require.True(t, resp6.CompleteListing)
		require.Equal(t, resp6.EstimatedItemCount, 5)
		require.Empty(t, resp6.DeletedIds)
		require.Empty(t, resp6.Items)

		// Create some new credentials
		newCred1 := static.TestJsonCredential(t, conn, wrapper, credStore.GetPublicId(), prj.GetPublicId(), obj)
		newCred2 := static.TestUsernamePasswordCredential(t, conn, wrapper, "someuser", "somepassword", credStore.GetPublicId(), prj.GetPublicId())
		newCred3 := static.TestSshPrivateKeyCredential(t, conn, wrapper, "someuser", static.TestSshPrivateKeyPem, credStore.GetPublicId(), prj.GetPublicId())
		t.Cleanup(func() {
			_, err := repo.DeleteCredential(ctx, credStore.ProjectId, newCred1.GetPublicId())
			require.NoError(t, err)
			_, err = repo.DeleteCredential(ctx, credStore.ProjectId, newCred2.GetPublicId())
			require.NoError(t, err)
			_, err = repo.DeleteCredential(ctx, credStore.ProjectId, newCred3.GetPublicId())
			require.NoError(t, err)
			// Run analyze to update count estimate
			_, err = sqlDb.ExecContext(ctx, "analyze")
			require.NoError(t, err)
		})
		// Run analyze to update count estimate
		_, err = sqlDb.ExecContext(ctx, "analyze")
		require.NoError(t, err)

		// Refresh again, should get newCred3
		resp7, err := credential.ListRefresh(ctx, []byte("some hash"), 1, filterFunc, resp6.ListToken, repo, credStore.GetPublicId())
		require.NoError(t, err)
		require.Equal(t, resp7.ListToken.GrantsHash, []byte("some hash"))
		require.False(t, resp7.CompleteListing)
		require.Equal(t, resp7.EstimatedItemCount, 8)
		require.Empty(t, resp7.DeletedIds)
		require.Len(t, resp7.Items, 1)
		require.Empty(t, cmp.Diff(resp7.Items[0], newCred3, cmpOpts...))

		// Refresh again, should get newCred2
		resp8, err := credential.ListRefreshPage(ctx, []byte("some hash"), 1, filterFunc, resp7.ListToken, repo, credStore.GetPublicId())
		require.NoError(t, err)
		require.Equal(t, resp8.ListToken.GrantsHash, []byte("some hash"))
		require.False(t, resp8.CompleteListing)
		require.Equal(t, resp8.EstimatedItemCount, 8)
		require.Empty(t, resp8.DeletedIds)
		require.Len(t, resp8.Items, 1)
		require.Empty(t, cmp.Diff(resp8.Items[0], newCred2, cmpOpts...))

		// Refresh again, should get newCred1
		resp9, err := credential.ListRefreshPage(ctx, []byte("some hash"), 1, filterFunc, resp8.ListToken, repo, credStore.GetPublicId())
		require.NoError(t, err)
		require.Equal(t, resp9.ListToken.GrantsHash, []byte("some hash"))
		require.True(t, resp9.CompleteListing)
		require.Equal(t, resp9.EstimatedItemCount, 8)
		require.Empty(t, resp9.DeletedIds)
		require.Len(t, resp9.Items, 1)
		require.Empty(t, cmp.Diff(resp9.Items[0], newCred1, cmpOpts...))

		// Refresh again, should get no results
		resp10, err := credential.ListRefresh(ctx, []byte("some hash"), 1, filterFunc, resp9.ListToken, repo, credStore.GetPublicId())
		require.NoError(t, err)
		require.Equal(t, resp10.ListToken.GrantsHash, []byte("some hash"))
		require.True(t, resp10.CompleteListing)
		require.Equal(t, resp10.EstimatedItemCount, 8)
		require.Empty(t, resp10.DeletedIds)
		require.Empty(t, resp10.Items)
	})

	t.Run("simple pagination with aggressive filtering", func(t *testing.T) {
		filterFunc := func(ctx context.Context, c credential.Static) (bool, error) {
			return c.GetPublicId() == creds[1].GetPublicId() ||
				c.GetPublicId() == creds[len(creds)-1].GetPublicId(), nil
		}
		resp, err := credential.List(ctx, []byte("some hash"), 1, filterFunc, repo, credStore.GetPublicId())
		require.NoError(t, err)
		require.NotNil(t, resp.ListToken)
		require.Equal(t, resp.ListToken.GrantsHash, []byte("some hash"))
		require.False(t, resp.CompleteListing)
		require.Equal(t, resp.EstimatedItemCount, 5)
		require.Empty(t, resp.DeletedIds)
		require.Len(t, resp.Items, 1)
		require.Empty(t, cmp.Diff(resp.Items[0], creds[1], cmpOpts...))

		resp2, err := credential.ListPage(ctx, []byte("some hash"), 1, filterFunc, resp.ListToken, repo, credStore.GetPublicId())
		require.NoError(t, err)
		require.NotNil(t, resp2.ListToken)
		require.Equal(t, resp2.ListToken.GrantsHash, []byte("some hash"))
		require.True(t, resp2.CompleteListing)
		require.Equal(t, resp2.EstimatedItemCount, 5)
		require.Empty(t, resp2.DeletedIds)
		require.Len(t, resp2.Items, 1)
		require.Empty(t, cmp.Diff(resp2.Items[0], creds[len(creds)-1], cmpOpts...))

		// request a refresh, nothing should be returned
		resp3, err := credential.ListRefresh(ctx, []byte("some hash"), 1, filterFunc, resp.ListToken, repo, credStore.GetPublicId())
		require.NoError(t, err)
		require.Equal(t, resp3.ListToken.GrantsHash, []byte("some hash"))
		require.True(t, resp3.CompleteListing)
		require.Equal(t, resp3.EstimatedItemCount, 5)
		require.Empty(t, resp3.DeletedIds)
		require.Empty(t, resp3.Items)

		newCred1 := static.TestJsonCredential(t, conn, wrapper, credStore.GetPublicId(), prj.GetPublicId(), obj)
		newCred2 := static.TestUsernamePasswordCredential(t, conn, wrapper, "someuser", "somepassword", credStore.GetPublicId(), prj.GetPublicId())
		newCred3 := static.TestSshPrivateKeyCredential(t, conn, wrapper, "someuser", static.TestSshPrivateKeyPem, credStore.GetPublicId(), prj.GetPublicId())
		newCred4 := static.TestJsonCredential(t, conn, wrapper, credStore.GetPublicId(), prj.GetPublicId(), obj)
		t.Cleanup(func() {
			_, err := repo.DeleteCredential(ctx, credStore.ProjectId, newCred1.GetPublicId())
			require.NoError(t, err)
			_, err = repo.DeleteCredential(ctx, credStore.ProjectId, newCred2.GetPublicId())
			require.NoError(t, err)
			_, err = repo.DeleteCredential(ctx, credStore.ProjectId, newCred3.GetPublicId())
			require.NoError(t, err)
			_, err = repo.DeleteCredential(ctx, credStore.ProjectId, newCred4.GetPublicId())
			require.NoError(t, err)
			// Run analyze to update count estimate
			_, err = sqlDb.ExecContext(ctx, "analyze")
			require.NoError(t, err)
		})
		// Run analyze to update count estimate
		_, err = sqlDb.ExecContext(ctx, "analyze")
		require.NoError(t, err)

		filterFunc = func(_ context.Context, c credential.Static) (bool, error) {
			return c.GetPublicId() == newCred3.GetPublicId() ||
				c.GetPublicId() == newCred1.GetPublicId(), nil
		}
		// Refresh again, should get newCred3
		resp4, err := credential.ListRefresh(ctx, []byte("some hash"), 1, filterFunc, resp3.ListToken, repo, credStore.GetPublicId())
		require.NoError(t, err)
		require.Equal(t, resp4.ListToken.GrantsHash, []byte("some hash"))
		require.False(t, resp4.CompleteListing)
		require.Equal(t, resp4.EstimatedItemCount, 9)
		require.Empty(t, resp4.DeletedIds)
		require.Len(t, resp4.Items, 1)
		require.Empty(t, cmp.Diff(resp4.Items[0], newCred3, cmpOpts...))

		// Refresh again, should get newCred1
		resp5, err := credential.ListRefreshPage(ctx, []byte("some hash"), 1, filterFunc, resp4.ListToken, repo, credStore.GetPublicId())
		require.NoError(t, err)
		require.Equal(t, resp5.ListToken.GrantsHash, []byte("some hash"))
		require.True(t, resp5.CompleteListing)
		require.Equal(t, resp5.EstimatedItemCount, 9)
		require.Empty(t, resp5.DeletedIds)
		require.Len(t, resp5.Items, 1)
		require.Empty(t, cmp.Diff(resp5.Items[0], newCred1, cmpOpts...))
	})

	t.Run("simple pagination with deletion", func(t *testing.T) {
		filterFunc := func(context.Context, credential.Static) (bool, error) {
			return true, nil
		}
		deletedCredentialId := creds[0].GetPublicId()
		_, err := repo.DeleteCredential(ctx, prj.GetPublicId(), deletedCredentialId)
		require.NoError(t, err)
		creds = creds[1:]

		// Run analyze to update count estimate
		_, err = sqlDb.ExecContext(ctx, "analyze")
		require.NoError(t, err)

		resp, err := credential.List(ctx, []byte("some hash"), 1, filterFunc, repo, credStore.GetPublicId())
		require.NoError(t, err)
		require.NotNil(t, resp.ListToken)
		require.Equal(t, resp.ListToken.GrantsHash, []byte("some hash"))
		require.False(t, resp.CompleteListing)
		require.Equal(t, resp.EstimatedItemCount, 4)
		require.Empty(t, resp.DeletedIds)
		require.Len(t, resp.Items, 1)
		require.Empty(t, cmp.Diff(resp.Items[0], creds[0], cmpOpts...))

		// request remaining results
		resp2, err := credential.ListPage(ctx, []byte("some hash"), 3, filterFunc, resp.ListToken, repo, credStore.GetPublicId())
		require.NoError(t, err)
		require.Equal(t, resp2.ListToken.GrantsHash, []byte("some hash"))
		require.True(t, resp2.CompleteListing)
		require.Equal(t, resp2.EstimatedItemCount, 4)
		require.Empty(t, resp2.DeletedIds)
		require.Len(t, resp2.Items, 3)
		require.Empty(t, cmp.Diff(resp2.Items, creds[1:], cmpOpts...))

		deletedCredentialId = creds[0].GetPublicId()
		_, err = repo.DeleteCredential(ctx, prj.GetPublicId(), deletedCredentialId)
		require.NoError(t, err)
		creds = creds[1:]

		// Run analyze to update count estimate
		_, err = sqlDb.ExecContext(ctx, "analyze")
		require.NoError(t, err)

		// request a refresh, nothing should be returned except the deleted id
		resp3, err := credential.ListRefresh(ctx, []byte("some hash"), 1, filterFunc, resp2.ListToken, repo, credStore.GetPublicId())
		require.NoError(t, err)
		require.Equal(t, resp3.ListToken.GrantsHash, []byte("some hash"))
		require.True(t, resp3.CompleteListing)
		require.Equal(t, resp3.EstimatedItemCount, 3)
		require.Contains(t, resp3.DeletedIds, deletedCredentialId)
		require.Empty(t, resp3.Items)
	})
}
