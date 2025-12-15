// Copyright IBM Corp. 2020, 2025
// SPDX-License-Identifier: BUSL-1.1

package password_test

import (
	"context"
	"slices"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	"github.com/hashicorp/boundary/globals"
	"github.com/hashicorp/boundary/internal/auth"
	"github.com/hashicorp/boundary/internal/auth/password"
	"github.com/hashicorp/boundary/internal/auth/password/store"
	"github.com/hashicorp/boundary/internal/db"
	"github.com/hashicorp/boundary/internal/db/timestamp"
	"github.com/hashicorp/boundary/internal/iam"
	"github.com/hashicorp/boundary/internal/kms"
	"github.com/hashicorp/boundary/internal/listtoken"
	"github.com/hashicorp/boundary/internal/types/resource"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/types/known/timestamppb"
)

func TestService_ListAccounts(t *testing.T) {
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
	fiveDaysAgo := time.Now().AddDate(0, 0, -5)
	rw := db.New(conn)

	kms := kms.TestKms(t, conn, wrapper)
	iamRepo := iam.TestRepo(t, conn, wrapper)
	org, _ := iam.TestScopes(t, iamRepo)

	repo, err := password.NewRepository(context.Background(), rw, rw, kms)
	require.NoError(t, err)

	authMethod := password.TestAuthMethod(t, conn, org.GetPublicId())
	passAccts := password.TestMultipleAccounts(t, conn, authMethod.GetPublicId(), 5)
	var accounts []auth.Account
	for _, acct := range passAccts {
		accounts = append(accounts, acct)
	}
	// since we sort by create time descending, we need to reverse the slice
	slices.Reverse(accounts)

	// Run analyze to update host estimate
	_, err = sqlDb.ExecContext(ctx, "analyze")
	require.NoError(t, err)

	cmpOpts := []cmp.Option{
		cmpopts.IgnoreUnexported(
			password.Account{},
			store.Account{},
			timestamp.Timestamp{},
			timestamppb.Timestamp{},
		),
	}

	t.Run("ListAccounts validation", func(t *testing.T) {
		t.Parallel()
		t.Run("missing grants hash", func(t *testing.T) {
			t.Parallel()
			filterFunc := func(_ context.Context, a auth.Account) (bool, error) {
				return true, nil
			}
			_, err := password.ListAccounts(ctx, nil, 1, filterFunc, repo, authMethod.GetPublicId())
			require.ErrorContains(t, err, "missing grants hash")
		})
		t.Run("zero page size", func(t *testing.T) {
			t.Parallel()
			filterFunc := func(_ context.Context, a auth.Account) (bool, error) {
				return true, nil
			}
			_, err := password.ListAccounts(ctx, []byte("some hash"), 0, filterFunc, repo, authMethod.GetPublicId())
			require.ErrorContains(t, err, "page size must be at least 1")
		})
		t.Run("negative page size", func(t *testing.T) {
			t.Parallel()
			filterFunc := func(_ context.Context, a auth.Account) (bool, error) {
				return true, nil
			}
			_, err := password.ListAccounts(ctx, []byte("some hash"), -1, filterFunc, repo, authMethod.GetPublicId())
			require.ErrorContains(t, err, "page size must be at least 1")
		})
		t.Run("nil filter func", func(t *testing.T) {
			t.Parallel()
			_, err := password.ListAccounts(ctx, []byte("some hash"), 1, nil, repo, authMethod.GetPublicId())
			require.ErrorContains(t, err, "missing filter item callback")
		})
		t.Run("nil repo", func(t *testing.T) {
			t.Parallel()
			filterFunc := func(_ context.Context, a auth.Account) (bool, error) {
				return true, nil
			}
			_, err := password.ListAccounts(ctx, []byte("some hash"), 1, filterFunc, nil, authMethod.GetPublicId())
			require.ErrorContains(t, err, "missing repo")
		})
		t.Run("missing auth method ID", func(t *testing.T) {
			t.Parallel()
			filterFunc := func(_ context.Context, a auth.Account) (bool, error) {
				return true, nil
			}
			_, err := password.ListAccounts(ctx, []byte("some hash"), 1, filterFunc, repo, "")
			require.ErrorContains(t, err, "missing auth method ID")
		})
	})
	t.Run("ListAccountsPage validation", func(t *testing.T) {
		t.Parallel()
		t.Run("missing grants hash", func(t *testing.T) {
			t.Parallel()
			filterFunc := func(_ context.Context, a auth.Account) (bool, error) {
				return true, nil
			}
			tok, err := listtoken.NewPagination(ctx, fiveDaysAgo, resource.Account, []byte("some hash"), "some-id", fiveDaysAgo)
			require.NoError(t, err)
			_, err = password.ListAccountsPage(ctx, nil, 1, filterFunc, tok, repo, authMethod.GetPublicId())
			require.ErrorContains(t, err, "missing grants hash")
		})
		t.Run("zero page size", func(t *testing.T) {
			t.Parallel()
			filterFunc := func(_ context.Context, a auth.Account) (bool, error) {
				return true, nil
			}
			tok, err := listtoken.NewPagination(ctx, fiveDaysAgo, resource.Account, []byte("some hash"), "some-id", fiveDaysAgo)
			require.NoError(t, err)
			_, err = password.ListAccountsPage(ctx, []byte("some hash"), 0, filterFunc, tok, repo, authMethod.GetPublicId())
			require.ErrorContains(t, err, "page size must be at least 1")
		})
		t.Run("negative page size", func(t *testing.T) {
			t.Parallel()
			filterFunc := func(_ context.Context, a auth.Account) (bool, error) {
				return true, nil
			}
			tok, err := listtoken.NewPagination(ctx, fiveDaysAgo, resource.Account, []byte("some hash"), "some-id", fiveDaysAgo)
			require.NoError(t, err)
			_, err = password.ListAccountsPage(ctx, []byte("some hash"), -1, filterFunc, tok, repo, authMethod.GetPublicId())
			require.ErrorContains(t, err, "page size must be at least 1")
		})
		t.Run("nil filter func", func(t *testing.T) {
			t.Parallel()
			tok, err := listtoken.NewPagination(ctx, fiveDaysAgo, resource.Account, []byte("some hash"), "some-id", fiveDaysAgo)
			require.NoError(t, err)
			_, err = password.ListAccountsPage(ctx, []byte("some hash"), 1, nil, tok, repo, authMethod.GetPublicId())
			require.ErrorContains(t, err, "missing filter item callback")
		})
		t.Run("nil token", func(t *testing.T) {
			t.Parallel()
			filterFunc := func(_ context.Context, a auth.Account) (bool, error) {
				return true, nil
			}
			_, err := password.ListAccountsPage(ctx, []byte("some hash"), 1, filterFunc, nil, repo, authMethod.GetPublicId())
			require.ErrorContains(t, err, "missing token")
		})
		t.Run("wrong token type", func(t *testing.T) {
			t.Parallel()
			filterFunc := func(_ context.Context, a auth.Account) (bool, error) {
				return true, nil
			}
			tok, err := listtoken.NewStartRefresh(ctx, fiveDaysAgo, resource.Account, []byte("some hash"), fiveDaysAgo, fiveDaysAgo)
			require.NoError(t, err)
			_, err = password.ListAccountsPage(ctx, []byte("some hash"), 1, filterFunc, tok, repo, authMethod.GetPublicId())
			require.ErrorContains(t, err, "token did not have a pagination token component")
		})
		t.Run("nil repo", func(t *testing.T) {
			t.Parallel()
			filterFunc := func(_ context.Context, a auth.Account) (bool, error) {
				return true, nil
			}
			tok, err := listtoken.NewPagination(ctx, fiveDaysAgo, resource.Account, []byte("some hash"), "some-id", fiveDaysAgo)
			require.NoError(t, err)
			_, err = password.ListAccountsPage(ctx, []byte("some hash"), 1, filterFunc, tok, nil, authMethod.GetPublicId())
			require.ErrorContains(t, err, "missing repo")
		})
		t.Run("missing auth method ID", func(t *testing.T) {
			t.Parallel()
			filterFunc := func(_ context.Context, a auth.Account) (bool, error) {
				return true, nil
			}
			tok, err := listtoken.NewPagination(ctx, fiveDaysAgo, resource.Account, []byte("some hash"), "some-id", fiveDaysAgo)
			require.NoError(t, err)
			_, err = password.ListAccountsPage(ctx, []byte("some hash"), 1, filterFunc, tok, repo, "")
			require.ErrorContains(t, err, "missing auth method ID")
		})
		t.Run("wrong token resource type", func(t *testing.T) {
			t.Parallel()
			filterFunc := func(_ context.Context, a auth.Account) (bool, error) {
				return true, nil
			}
			tok, err := listtoken.NewPagination(ctx, fiveDaysAgo, resource.Target, []byte("some hash"), "some-id", fiveDaysAgo)
			require.NoError(t, err)
			_, err = password.ListAccountsPage(ctx, []byte("some hash"), 1, filterFunc, tok, repo, authMethod.GetPublicId())
			require.ErrorContains(t, err, "token did not have an account resource type")
		})
	})
	t.Run("ListAccountsRefresh validation", func(t *testing.T) {
		t.Parallel()
		t.Run("missing grants hash", func(t *testing.T) {
			t.Parallel()
			filterFunc := func(_ context.Context, a auth.Account) (bool, error) {
				return true, nil
			}
			tok, err := listtoken.NewStartRefresh(ctx, fiveDaysAgo, resource.Account, []byte("some hash"), fiveDaysAgo, fiveDaysAgo)
			require.NoError(t, err)
			_, err = password.ListAccountsRefresh(ctx, nil, 1, filterFunc, tok, repo, authMethod.GetPublicId())
			require.ErrorContains(t, err, "missing grants hash")
		})
		t.Run("zero page size", func(t *testing.T) {
			t.Parallel()
			filterFunc := func(_ context.Context, a auth.Account) (bool, error) {
				return true, nil
			}
			tok, err := listtoken.NewStartRefresh(ctx, fiveDaysAgo, resource.Account, []byte("some hash"), fiveDaysAgo, fiveDaysAgo)
			require.NoError(t, err)
			_, err = password.ListAccountsRefresh(ctx, []byte("some hash"), 0, filterFunc, tok, repo, authMethod.GetPublicId())
			require.ErrorContains(t, err, "page size must be at least 1")
		})
		t.Run("negative page size", func(t *testing.T) {
			t.Parallel()
			filterFunc := func(_ context.Context, a auth.Account) (bool, error) {
				return true, nil
			}
			tok, err := listtoken.NewStartRefresh(ctx, fiveDaysAgo, resource.Account, []byte("some hash"), fiveDaysAgo, fiveDaysAgo)
			require.NoError(t, err)
			_, err = password.ListAccountsRefresh(ctx, []byte("some hash"), -1, filterFunc, tok, repo, authMethod.GetPublicId())
			require.ErrorContains(t, err, "page size must be at least 1")
		})
		t.Run("nil filter func", func(t *testing.T) {
			t.Parallel()
			tok, err := listtoken.NewStartRefresh(ctx, fiveDaysAgo, resource.Account, []byte("some hash"), fiveDaysAgo, fiveDaysAgo)
			require.NoError(t, err)
			_, err = password.ListAccountsRefresh(ctx, []byte("some hash"), 1, nil, tok, repo, authMethod.GetPublicId())
			require.ErrorContains(t, err, "missing filter item callback")
		})
		t.Run("nil token", func(t *testing.T) {
			t.Parallel()
			filterFunc := func(_ context.Context, a auth.Account) (bool, error) {
				return true, nil
			}
			_, err := password.ListAccountsRefresh(ctx, []byte("some hash"), 1, filterFunc, nil, repo, authMethod.GetPublicId())
			require.ErrorContains(t, err, "missing token")
		})
		t.Run("nil repo", func(t *testing.T) {
			t.Parallel()
			filterFunc := func(_ context.Context, a auth.Account) (bool, error) {
				return true, nil
			}
			tok, err := listtoken.NewStartRefresh(ctx, fiveDaysAgo, resource.Account, []byte("some hash"), fiveDaysAgo, fiveDaysAgo)
			require.NoError(t, err)
			_, err = password.ListAccountsRefresh(ctx, []byte("some hash"), 1, filterFunc, tok, nil, authMethod.GetPublicId())
			require.ErrorContains(t, err, "missing repo")
		})
		t.Run("missing auth method ID", func(t *testing.T) {
			t.Parallel()
			filterFunc := func(_ context.Context, a auth.Account) (bool, error) {
				return true, nil
			}
			tok, err := listtoken.NewStartRefresh(ctx, fiveDaysAgo, resource.Account, []byte("some hash"), fiveDaysAgo, fiveDaysAgo)
			require.NoError(t, err)
			_, err = password.ListAccountsRefresh(ctx, []byte("some hash"), 1, filterFunc, tok, repo, "")
			require.ErrorContains(t, err, "missing auth method ID")
		})
		t.Run("wrong token resource type", func(t *testing.T) {
			t.Parallel()
			filterFunc := func(_ context.Context, a auth.Account) (bool, error) {
				return true, nil
			}
			tok, err := listtoken.NewStartRefresh(ctx, fiveDaysAgo, resource.Target, []byte("some hash"), fiveDaysAgo, fiveDaysAgo)
			require.NoError(t, err)
			_, err = password.ListAccountsRefresh(ctx, []byte("some hash"), 1, filterFunc, tok, repo, authMethod.GetPublicId())
			require.ErrorContains(t, err, "token did not have an account resource type")
		})
	})
	t.Run("ListAccountsRefreshPage validation", func(t *testing.T) {
		t.Parallel()
		t.Run("missing grants hash", func(t *testing.T) {
			t.Parallel()
			filterFunc := func(_ context.Context, a auth.Account) (bool, error) {
				return true, nil
			}
			tok, err := listtoken.NewRefresh(ctx, fiveDaysAgo, resource.Account, []byte("some hash"), fiveDaysAgo, fiveDaysAgo, fiveDaysAgo, "some other id", fiveDaysAgo)
			require.NoError(t, err)
			_, err = password.ListAccountsRefreshPage(ctx, nil, 1, filterFunc, tok, repo, authMethod.GetPublicId())
			require.ErrorContains(t, err, "missing grants hash")
		})
		t.Run("zero page size", func(t *testing.T) {
			t.Parallel()
			filterFunc := func(_ context.Context, a auth.Account) (bool, error) {
				return true, nil
			}
			tok, err := listtoken.NewRefresh(ctx, fiveDaysAgo, resource.Account, []byte("some hash"), fiveDaysAgo, fiveDaysAgo, fiveDaysAgo, "some other id", fiveDaysAgo)
			require.NoError(t, err)
			_, err = password.ListAccountsRefreshPage(ctx, []byte("some hash"), 0, filterFunc, tok, repo, authMethod.GetPublicId())
			require.ErrorContains(t, err, "page size must be at least 1")
		})
		t.Run("negative page size", func(t *testing.T) {
			t.Parallel()
			filterFunc := func(_ context.Context, a auth.Account) (bool, error) {
				return true, nil
			}
			tok, err := listtoken.NewRefresh(ctx, fiveDaysAgo, resource.Account, []byte("some hash"), fiveDaysAgo, fiveDaysAgo, fiveDaysAgo, "some other id", fiveDaysAgo)
			require.NoError(t, err)
			_, err = password.ListAccountsRefreshPage(ctx, []byte("some hash"), -1, filterFunc, tok, repo, authMethod.GetPublicId())
			require.ErrorContains(t, err, "page size must be at least 1")
		})
		t.Run("nil filter func", func(t *testing.T) {
			t.Parallel()
			tok, err := listtoken.NewRefresh(ctx, fiveDaysAgo, resource.Account, []byte("some hash"), fiveDaysAgo, fiveDaysAgo, fiveDaysAgo, "some other id", fiveDaysAgo)
			require.NoError(t, err)
			_, err = password.ListAccountsRefreshPage(ctx, []byte("some hash"), 1, nil, tok, repo, authMethod.GetPublicId())
			require.ErrorContains(t, err, "missing filter item callback")
		})
		t.Run("nil token", func(t *testing.T) {
			t.Parallel()
			filterFunc := func(_ context.Context, a auth.Account) (bool, error) {
				return true, nil
			}
			_, err := password.ListAccountsRefreshPage(ctx, []byte("some hash"), 1, filterFunc, nil, repo, authMethod.GetPublicId())
			require.ErrorContains(t, err, "missing token")
		})
		t.Run("wrong token type", func(t *testing.T) {
			t.Parallel()
			filterFunc := func(_ context.Context, a auth.Account) (bool, error) {
				return true, nil
			}
			tok, err := listtoken.NewPagination(ctx, fiveDaysAgo, resource.Account, []byte("some hash"), "some-id", fiveDaysAgo)
			require.NoError(t, err)
			_, err = password.ListAccountsRefreshPage(ctx, []byte("some hash"), 1, filterFunc, tok, repo, authMethod.GetPublicId())
			require.ErrorContains(t, err, "token did not have a refresh token component")
		})
		t.Run("nil repo", func(t *testing.T) {
			t.Parallel()
			filterFunc := func(_ context.Context, a auth.Account) (bool, error) {
				return true, nil
			}
			tok, err := listtoken.NewRefresh(ctx, fiveDaysAgo, resource.Account, []byte("some hash"), fiveDaysAgo, fiveDaysAgo, fiveDaysAgo, "some other id", fiveDaysAgo)
			require.NoError(t, err)
			_, err = password.ListAccountsRefreshPage(ctx, []byte("some hash"), 1, filterFunc, tok, nil, authMethod.GetPublicId())
			require.ErrorContains(t, err, "missing repo")
		})
		t.Run("missing credential store id", func(t *testing.T) {
			t.Parallel()
			filterFunc := func(_ context.Context, a auth.Account) (bool, error) {
				return true, nil
			}
			tok, err := listtoken.NewRefresh(ctx, fiveDaysAgo, resource.Account, []byte("some hash"), fiveDaysAgo, fiveDaysAgo, fiveDaysAgo, "some other id", fiveDaysAgo)
			require.NoError(t, err)
			_, err = password.ListAccountsRefreshPage(ctx, []byte("some hash"), 1, filterFunc, tok, repo, "")
			require.ErrorContains(t, err, "missing auth method ID")
		})
		t.Run("wrong token resource type", func(t *testing.T) {
			t.Parallel()
			filterFunc := func(_ context.Context, a auth.Account) (bool, error) {
				return true, nil
			}
			tok, err := listtoken.NewRefresh(ctx, fiveDaysAgo, resource.Target, []byte("some hash"), fiveDaysAgo, fiveDaysAgo, fiveDaysAgo, "some other id", fiveDaysAgo)
			require.NoError(t, err)
			_, err = password.ListAccountsRefreshPage(ctx, []byte("some hash"), 1, filterFunc, tok, repo, authMethod.GetPublicId())
			require.ErrorContains(t, err, "token did not have an account resource type")
		})
	})

	t.Run("simple pagination", func(t *testing.T) {
		filterFunc := func(context.Context, auth.Account) (bool, error) {
			return true, nil
		}
		resp, err := password.ListAccounts(ctx, []byte("some hash"), 1, filterFunc, repo, authMethod.GetPublicId())
		require.NoError(t, err)
		require.NotNil(t, resp.ListToken)
		require.Equal(t, resp.ListToken.GrantsHash, []byte("some hash"))
		require.False(t, resp.CompleteListing)
		require.Equal(t, resp.EstimatedItemCount, 5)
		require.Empty(t, resp.DeletedIds)
		require.Len(t, resp.Items, 1)
		require.Empty(t, cmp.Diff(resp.Items[0], accounts[0], cmpOpts...))

		resp2, err := password.ListAccountsPage(ctx, []byte("some hash"), 1, filterFunc, resp.ListToken, repo, authMethod.GetPublicId())
		require.NoError(t, err)
		require.Equal(t, resp2.ListToken.GrantsHash, []byte("some hash"))
		require.False(t, resp2.CompleteListing)
		require.Equal(t, resp2.EstimatedItemCount, 5)
		require.Empty(t, resp2.DeletedIds)
		require.Len(t, resp2.Items, 1)
		require.Empty(t, cmp.Diff(resp2.Items[0], accounts[1], cmpOpts...))

		resp3, err := password.ListAccountsPage(ctx, []byte("some hash"), 1, filterFunc, resp2.ListToken, repo, authMethod.GetPublicId())
		require.NoError(t, err)
		require.Equal(t, resp3.ListToken.GrantsHash, []byte("some hash"))
		require.False(t, resp3.CompleteListing)
		require.Equal(t, resp3.EstimatedItemCount, 5)
		require.Empty(t, resp3.DeletedIds)
		require.Len(t, resp3.Items, 1)
		require.Empty(t, cmp.Diff(resp3.Items[0], accounts[2], cmpOpts...))

		resp4, err := password.ListAccountsPage(ctx, []byte("some hash"), 1, filterFunc, resp3.ListToken, repo, authMethod.GetPublicId())
		require.NoError(t, err)
		require.Equal(t, resp4.ListToken.GrantsHash, []byte("some hash"))
		require.False(t, resp4.CompleteListing)
		require.Equal(t, resp4.EstimatedItemCount, 5)
		require.Empty(t, resp4.DeletedIds)
		require.Len(t, resp4.Items, 1)
		require.Empty(t, cmp.Diff(resp4.Items[0], accounts[3], cmpOpts...))

		resp5, err := password.ListAccountsPage(ctx, []byte("some hash"), 1, filterFunc, resp4.ListToken, repo, authMethod.GetPublicId())
		require.NoError(t, err)
		require.Equal(t, resp5.ListToken.GrantsHash, []byte("some hash"))
		require.True(t, resp5.CompleteListing)
		require.Equal(t, resp5.EstimatedItemCount, 5)
		require.Empty(t, resp5.DeletedIds)
		require.Len(t, resp5.Items, 1)
		require.Empty(t, cmp.Diff(resp5.Items[0], accounts[4], cmpOpts...))

		// Finished initial pagination phase, request refresh
		// Expect no results.
		resp6, err := password.ListAccountsRefresh(ctx, []byte("some hash"), 1, filterFunc, resp5.ListToken, repo, authMethod.GetPublicId())
		require.NoError(t, err)
		require.Equal(t, resp6.ListToken.GrantsHash, []byte("some hash"))
		require.True(t, resp6.CompleteListing)
		require.Equal(t, resp6.EstimatedItemCount, 5)
		require.Empty(t, resp6.DeletedIds)
		require.Empty(t, resp6.Items)

		// Create some new accounts
		account1 := password.TestAccount(t, conn, authMethod.GetPublicId(), "some-id-1")
		account2 := password.TestAccount(t, conn, authMethod.GetPublicId(), "some-id-2")
		t.Cleanup(func() {
			repo.DeleteAccount(ctx, org.PublicId, account1.GetPublicId())
			require.NoError(t, err)
			repo.DeleteAccount(ctx, org.PublicId, account2.GetPublicId())
			require.NoError(t, err)
			// Run analyze to update count estimate
			_, err = sqlDb.ExecContext(ctx, "analyze")
			require.NoError(t, err)
		})

		// Run analyze to update count estimate
		_, err = sqlDb.ExecContext(ctx, "analyze")
		require.NoError(t, err)

		// Refresh again, should get account2
		resp7, err := password.ListAccountsRefresh(ctx, []byte("some hash"), 1, filterFunc, resp6.ListToken, repo, authMethod.GetPublicId())
		require.NoError(t, err)
		require.Equal(t, resp7.ListToken.GrantsHash, []byte("some hash"))
		require.False(t, resp7.CompleteListing)
		require.Equal(t, resp7.EstimatedItemCount, 7)
		require.Empty(t, resp7.DeletedIds)
		require.Len(t, resp7.Items, 1)
		require.Empty(t, cmp.Diff(resp7.Items[0], account2, cmpOpts...))

		// Refresh again, should get account1
		resp8, err := password.ListAccountsRefreshPage(ctx, []byte("some hash"), 1, filterFunc, resp7.ListToken, repo, authMethod.GetPublicId())
		require.NoError(t, err)
		require.Equal(t, resp8.ListToken.GrantsHash, []byte("some hash"))
		require.True(t, resp8.CompleteListing)
		require.Equal(t, resp8.EstimatedItemCount, 7)
		require.Empty(t, resp8.DeletedIds)
		require.Len(t, resp8.Items, 1)
		require.Empty(t, cmp.Diff(resp8.Items[0], account1, cmpOpts...))

		// Refresh again, should get no results
		resp9, err := password.ListAccountsRefresh(ctx, []byte("some hash"), 1, filterFunc, resp8.ListToken, repo, authMethod.GetPublicId())
		require.NoError(t, err)
		require.Equal(t, resp9.ListToken.GrantsHash, []byte("some hash"))
		require.True(t, resp9.CompleteListing)
		require.Equal(t, resp9.EstimatedItemCount, 7)
		require.Empty(t, resp9.DeletedIds)
		require.Empty(t, resp9.Items)
	})

	t.Run("simple pagination with aggressive filtering", func(t *testing.T) {
		filterFunc := func(ctx context.Context, a auth.Account) (bool, error) {
			return a.GetPublicId() == accounts[1].GetPublicId() ||
				a.GetPublicId() == accounts[len(accounts)-1].GetPublicId(), nil
		}
		resp, err := password.ListAccounts(ctx, []byte("some hash"), 1, filterFunc, repo, authMethod.GetPublicId())
		require.NoError(t, err)
		require.NotNil(t, resp.ListToken)
		require.Equal(t, resp.ListToken.GrantsHash, []byte("some hash"))
		require.False(t, resp.CompleteListing)
		require.Equal(t, resp.EstimatedItemCount, 5)
		require.Empty(t, resp.DeletedIds)
		require.Len(t, resp.Items, 1)
		require.Empty(t, cmp.Diff(resp.Items[0], accounts[1], cmpOpts...))

		resp2, err := password.ListAccountsPage(ctx, []byte("some hash"), 1, filterFunc, resp.ListToken, repo, authMethod.GetPublicId())
		require.NoError(t, err)
		require.NotNil(t, resp2.ListToken)
		require.Equal(t, resp2.ListToken.GrantsHash, []byte("some hash"))
		require.True(t, resp2.CompleteListing)
		require.Equal(t, resp2.EstimatedItemCount, 5)
		require.Empty(t, resp2.DeletedIds)
		require.Len(t, resp2.Items, 1)
		require.Empty(t, cmp.Diff(resp2.Items[0], accounts[len(accounts)-1], cmpOpts...))

		// request a refresh, nothing should be returned
		resp3, err := password.ListAccountsRefresh(ctx, []byte("some hash"), 1, filterFunc, resp.ListToken, repo, authMethod.GetPublicId())
		require.NoError(t, err)
		require.Equal(t, resp3.ListToken.GrantsHash, []byte("some hash"))
		require.True(t, resp3.CompleteListing)
		require.Equal(t, resp3.EstimatedItemCount, 5)
		require.Empty(t, resp3.DeletedIds)
		require.Empty(t, resp3.Items)

		// Create some new accounts
		account1 := password.TestAccount(t, conn, authMethod.GetPublicId(), "some-id-1")
		account2 := password.TestAccount(t, conn, authMethod.GetPublicId(), "some-id-2")
		account3 := password.TestAccount(t, conn, authMethod.GetPublicId(), "some-id-3")
		t.Cleanup(func() {
			repo.DeleteAccount(ctx, org.PublicId, account1.GetPublicId())
			require.NoError(t, err)
			repo.DeleteAccount(ctx, org.PublicId, account2.GetPublicId())
			require.NoError(t, err)
			repo.DeleteAccount(ctx, org.PublicId, account3.GetPublicId())
			require.NoError(t, err)
			// Run analyze to update count estimate
			_, err = sqlDb.ExecContext(ctx, "analyze")
			require.NoError(t, err)
		})

		// Run analyze to update count estimate
		_, err = sqlDb.ExecContext(ctx, "analyze")
		require.NoError(t, err)

		filterFunc = func(_ context.Context, a auth.Account) (bool, error) {
			return a.GetPublicId() == account3.GetPublicId() ||
				a.GetPublicId() == account1.GetPublicId(), nil
		}
		// Refresh again, should get account3
		resp4, err := password.ListAccountsRefresh(ctx, []byte("some hash"), 1, filterFunc, resp3.ListToken, repo, authMethod.GetPublicId())
		require.NoError(t, err)
		require.Equal(t, resp4.ListToken.GrantsHash, []byte("some hash"))
		require.False(t, resp4.CompleteListing)
		require.Equal(t, resp4.EstimatedItemCount, 8)
		require.Empty(t, resp4.DeletedIds)
		require.Len(t, resp4.Items, 1)
		require.Empty(t, cmp.Diff(resp4.Items[0], account3, cmpOpts...))

		// Refresh again, should get account1
		resp5, err := password.ListAccountsRefreshPage(ctx, []byte("some hash"), 1, filterFunc, resp4.ListToken, repo, authMethod.GetPublicId())
		require.NoError(t, err)
		require.Equal(t, resp5.ListToken.GrantsHash, []byte("some hash"))
		require.True(t, resp5.CompleteListing)
		require.Equal(t, resp5.EstimatedItemCount, 8)
		require.Empty(t, resp5.DeletedIds)
		require.Len(t, resp5.Items, 1)
		require.Empty(t, cmp.Diff(resp5.Items[0], account1, cmpOpts...))
	})

	t.Run("simple pagination with deletion", func(t *testing.T) {
		filterFunc := func(context.Context, auth.Account) (bool, error) {
			return true, nil
		}
		deletedAccountId := accounts[0].GetPublicId()
		repo.DeleteAccount(ctx, org.PublicId, deletedAccountId)
		require.NoError(t, err)
		accounts = accounts[1:]

		// Run analyze to update count estimate
		_, err = sqlDb.ExecContext(ctx, "analyze")
		require.NoError(t, err)

		resp, err := password.ListAccounts(ctx, []byte("some hash"), 1, filterFunc, repo, authMethod.GetPublicId())
		require.NoError(t, err)
		require.NotNil(t, resp.ListToken)
		require.Equal(t, resp.ListToken.GrantsHash, []byte("some hash"))
		require.False(t, resp.CompleteListing)
		require.Equal(t, resp.EstimatedItemCount, 4)
		require.Empty(t, resp.DeletedIds)
		require.Len(t, resp.Items, 1)
		require.Empty(t, cmp.Diff(resp.Items[0], accounts[0], cmpOpts...))

		// request remaining results
		resp2, err := password.ListAccountsPage(ctx, []byte("some hash"), 3, filterFunc, resp.ListToken, repo, authMethod.GetPublicId())
		require.NoError(t, err)
		require.Equal(t, resp2.ListToken.GrantsHash, []byte("some hash"))
		require.True(t, resp2.CompleteListing)
		require.Equal(t, resp2.EstimatedItemCount, 4)
		require.Empty(t, resp2.DeletedIds)
		require.Len(t, resp2.Items, 3)
		require.Empty(t, cmp.Diff(resp2.Items, accounts[1:], cmpOpts...))

		deletedAccountId = accounts[0].GetPublicId()
		repo.DeleteAccount(ctx, org.PublicId, deletedAccountId)
		require.NoError(t, err)
		accounts = accounts[1:]

		// Run analyze to update count estimate
		_, err = sqlDb.ExecContext(ctx, "analyze")
		require.NoError(t, err)

		// request a refresh, nothing should be returned except the deleted id
		resp3, err := password.ListAccountsRefresh(ctx, []byte("some hash"), 1, filterFunc, resp2.ListToken, repo, authMethod.GetPublicId())
		require.NoError(t, err)
		require.Equal(t, resp3.ListToken.GrantsHash, []byte("some hash"))
		require.True(t, resp3.CompleteListing)
		require.Equal(t, resp3.EstimatedItemCount, 3)
		require.Contains(t, resp3.DeletedIds, deletedAccountId)
		require.Empty(t, resp3.Items)
	})
}
