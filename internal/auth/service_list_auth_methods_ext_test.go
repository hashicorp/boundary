// Copyright IBM Corp. 2020, 2025
// SPDX-License-Identifier: BUSL-1.1

package auth_test

import (
	"context"
	"slices"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	"github.com/hashicorp/boundary/globals"
	"github.com/hashicorp/boundary/internal/auth"
	"github.com/hashicorp/boundary/internal/auth/ldap"
	lstore "github.com/hashicorp/boundary/internal/auth/ldap/store"
	"github.com/hashicorp/boundary/internal/auth/oidc"
	ostore "github.com/hashicorp/boundary/internal/auth/oidc/store"
	"github.com/hashicorp/boundary/internal/auth/password"
	pstore "github.com/hashicorp/boundary/internal/auth/password/store"
	"github.com/hashicorp/boundary/internal/auth/store"
	"github.com/hashicorp/boundary/internal/db"
	"github.com/hashicorp/boundary/internal/db/timestamp"
	"github.com/hashicorp/boundary/internal/iam"
	"github.com/hashicorp/boundary/internal/kms"
	"github.com/hashicorp/boundary/internal/listtoken"
	"github.com/hashicorp/boundary/internal/types/resource"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/types/known/timestamppb"
)

type fakeReader struct {
	db.Reader
}

type fakeWriter struct {
	db.Writer
}

func TestNewAuthMethodService(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	conn, _ := db.TestSetup(t, "postgres")
	wrapper := db.TestWrapper(t)
	testKms := kms.TestKms(t, conn, wrapper)
	t.Run("success", func(t *testing.T) {
		t.Parallel()
		got, err := auth.NewAuthMethodRepository(ctx, &fakeReader{}, &fakeWriter{}, testKms)
		require.NoError(t, err)
		require.NotNil(t, got)
	})
	t.Run("nil-reader", func(t *testing.T) {
		t.Parallel()
		_, err := auth.NewAuthMethodRepository(ctx, nil, &fakeWriter{}, testKms)
		require.Error(t, err)
	})
	t.Run("nil-interface-reader", func(t *testing.T) {
		t.Parallel()
		_, err := auth.NewAuthMethodRepository(ctx, (*fakeReader)(nil), &fakeWriter{}, testKms)
		require.Error(t, err)
	})
	t.Run("nil-writer", func(t *testing.T) {
		t.Parallel()
		_, err := auth.NewAuthMethodRepository(ctx, &fakeReader{}, nil, testKms)
		require.Error(t, err)
	})
	t.Run("nil-interface-writer", func(t *testing.T) {
		t.Parallel()
		_, err := auth.NewAuthMethodRepository(ctx, &fakeReader{}, (*fakeWriter)(nil), testKms)
		require.Error(t, err)
	})
	t.Run("nil-kms", func(t *testing.T) {
		t.Parallel()
		_, err := auth.NewAuthMethodRepository(ctx, &fakeReader{}, &fakeWriter{}, nil)
		require.Error(t, err)
	})
}

func TestStoreService_List(t *testing.T) {
	// Set database read timeout to avoid duplicates in response
	oldReadTimeout := globals.RefreshReadLookbackDuration
	globals.RefreshReadLookbackDuration = 0
	t.Cleanup(func() {
		globals.RefreshReadLookbackDuration = oldReadTimeout
	})

	ctx := context.Background()
	conn, _ := db.TestSetup(t, "postgres")
	rw := db.New(conn)
	wrapper := db.TestWrapper(t)
	testKms := kms.TestKms(t, conn, wrapper)
	org, _ := iam.TestScopes(t, iam.TestRepo(t, conn, wrapper))
	databaseWrapper, err := testKms.GetWrapper(context.Background(), org.PublicId, kms.KeyPurposeDatabase)
	require.NoError(t, err)
	sqlDb, err := conn.SqlDB(ctx)
	require.NoError(t, err)
	fiveDaysAgo := time.Now().AddDate(0, 0, -5)

	ldapRepo, err := ldap.NewRepository(ctx, rw, rw, testKms)
	require.NoError(t, err)
	oidcRepo, err := oidc.NewRepository(ctx, rw, rw, testKms)
	require.NoError(t, err)
	passwordRepo, err := password.NewRepository(ctx, rw, rw, testKms)
	require.NoError(t, err)

	ams := []auth.AuthMethod{
		// two ldap
		ldap.TestAuthMethod(t, conn, databaseWrapper, org.PublicId, []string{"ldaps://ldap1.alice.com"}, ldap.WithOperationalState(ctx, ldap.InactiveState)),
		ldap.TestAuthMethod(t, conn, databaseWrapper, org.PublicId, []string{"ldaps://ldap2.alice.com"}, ldap.WithOperationalState(ctx, ldap.InactiveState)),
		// two oidc
		oidc.TestAuthMethod(t, conn, databaseWrapper, org.PublicId, oidc.InactiveState, "alice_rp", "alices-dogs-name",
			oidc.WithIssuer(oidc.TestConvertToUrls(t, "https://alice-inactive.com")[0]), oidc.WithApiUrl(oidc.TestConvertToUrls(t, "https://api.com")[0])),
		oidc.TestAuthMethod(t, conn, databaseWrapper, org.PublicId, oidc.InactiveState, "bob_rp", "bobs-dogs-name",
			oidc.WithIssuer(oidc.TestConvertToUrls(t, "https://bob-inactive.com")[0]), oidc.WithApiUrl(oidc.TestConvertToUrls(t, "https://api.com")[0])),
		// two password
		password.TestAuthMethod(t, conn, org.GetPublicId()),
		password.TestAuthMethod(t, conn, org.GetPublicId()),
	}

	// since we sort descending, we need to reverse the slice
	slices.Reverse(ams)

	repo, err := auth.NewAuthMethodRepository(ctx, rw, rw, testKms)
	require.NoError(t, err)

	// Run analyze to update count estimate
	_, err = sqlDb.ExecContext(ctx, "analyze")
	require.NoError(t, err)

	cmpOpts := []cmp.Option{
		cmpopts.IgnoreUnexported(
			ldap.AuthMethod{},
			lstore.AuthMethod{},
			oidc.AuthMethod{},
			ostore.AuthMethod{},
			password.AuthMethod{},
			pstore.AuthMethod{},
			store.AuthMethod{},
			timestamp.Timestamp{},
			timestamppb.Timestamp{},
		),
		cmpopts.IgnoreFields(
			oidc.AuthMethod{}, "CtClientSecret", "ClientSecret",
		),
	}

	t.Run("List validation", func(t *testing.T) {
		t.Parallel()
		t.Run("missing grants hash", func(t *testing.T) {
			t.Parallel()
			filterFunc := func(_ context.Context, am auth.AuthMethod) (bool, error) {
				return true, nil
			}
			_, err := auth.ListAuthMethods(ctx, nil, 1, filterFunc, repo, []string{org.PublicId}, false)
			require.ErrorContains(t, err, "missing grants hash")
		})
		t.Run("zero page size", func(t *testing.T) {
			t.Parallel()
			filterFunc := func(_ context.Context, am auth.AuthMethod) (bool, error) {
				return true, nil
			}
			_, err := auth.ListAuthMethods(ctx, []byte("some hash"), 0, filterFunc, repo, []string{org.PublicId}, false)
			require.ErrorContains(t, err, "page size must be at least 1")
		})
		t.Run("negative page size", func(t *testing.T) {
			t.Parallel()
			filterFunc := func(_ context.Context, am auth.AuthMethod) (bool, error) {
				return true, nil
			}
			_, err := auth.ListAuthMethods(ctx, []byte("some hash"), -1, filterFunc, repo, []string{org.PublicId}, false)
			require.ErrorContains(t, err, "page size must be at least 1")
		})
		t.Run("nil filter func", func(t *testing.T) {
			t.Parallel()
			_, err := auth.ListAuthMethods(ctx, []byte("some hash"), 1, nil, repo, []string{org.PublicId}, false)
			require.ErrorContains(t, err, "missing filter item callback")
		})
		t.Run("missing repo", func(t *testing.T) {
			t.Parallel()
			filterFunc := func(_ context.Context, am auth.AuthMethod) (bool, error) {
				return true, nil
			}
			_, err := auth.ListAuthMethods(ctx, []byte("some hash"), 1, filterFunc, nil, []string{org.PublicId}, false)
			require.ErrorContains(t, err, "missing repo")
		})
		t.Run("missing scope ids", func(t *testing.T) {
			t.Parallel()
			filterFunc := func(_ context.Context, am auth.AuthMethod) (bool, error) {
				return true, nil
			}
			_, err := auth.ListAuthMethods(ctx, []byte("some hash"), 1, filterFunc, repo, nil, false)
			require.ErrorContains(t, err, "missing scope ids")
		})
	})
	t.Run("ListPage validation", func(t *testing.T) {
		t.Parallel()
		t.Run("missing grants hash", func(t *testing.T) {
			t.Parallel()
			filterFunc := func(_ context.Context, am auth.AuthMethod) (bool, error) {
				return true, nil
			}
			tok, err := listtoken.NewPagination(ctx, fiveDaysAgo, resource.AuthMethod, []byte("some hash"), "some-id", fiveDaysAgo)
			require.NoError(t, err)
			_, err = auth.ListAuthMethodsPage(ctx, nil, 1, filterFunc, tok, repo, []string{org.PublicId}, false)
			require.ErrorContains(t, err, "missing grants hash")
		})
		t.Run("zero page size", func(t *testing.T) {
			t.Parallel()
			filterFunc := func(_ context.Context, am auth.AuthMethod) (bool, error) {
				return true, nil
			}
			tok, err := listtoken.NewPagination(ctx, fiveDaysAgo, resource.AuthMethod, []byte("some hash"), "some-id", fiveDaysAgo)
			require.NoError(t, err)
			_, err = auth.ListAuthMethodsPage(ctx, []byte("some hash"), 0, filterFunc, tok, repo, []string{org.PublicId}, false)
			require.ErrorContains(t, err, "page size must be at least 1")
		})
		t.Run("negative page size", func(t *testing.T) {
			t.Parallel()
			filterFunc := func(_ context.Context, am auth.AuthMethod) (bool, error) {
				return true, nil
			}
			tok, err := listtoken.NewPagination(ctx, fiveDaysAgo, resource.AuthMethod, []byte("some hash"), "some-id", fiveDaysAgo)
			require.NoError(t, err)
			_, err = auth.ListAuthMethodsPage(ctx, []byte("some hash"), -1, filterFunc, tok, repo, []string{org.PublicId}, false)
			require.ErrorContains(t, err, "page size must be at least 1")
		})
		t.Run("nil filter func", func(t *testing.T) {
			t.Parallel()
			tok, err := listtoken.NewPagination(ctx, fiveDaysAgo, resource.AuthMethod, []byte("some hash"), "some-id", fiveDaysAgo)
			require.NoError(t, err)
			_, err = auth.ListAuthMethodsPage(ctx, []byte("some hash"), 1, nil, tok, repo, []string{org.PublicId}, false)
			require.ErrorContains(t, err, "missing filter item callback")
		})
		t.Run("nil token", func(t *testing.T) {
			t.Parallel()
			filterFunc := func(_ context.Context, am auth.AuthMethod) (bool, error) {
				return true, nil
			}
			_, err := auth.ListAuthMethodsPage(ctx, []byte("some hash"), 1, filterFunc, nil, repo, []string{org.PublicId}, false)
			require.ErrorContains(t, err, "missing token")
		})
		t.Run("wrong token type", func(t *testing.T) {
			t.Parallel()
			filterFunc := func(_ context.Context, am auth.AuthMethod) (bool, error) {
				return true, nil
			}
			tok, err := listtoken.NewStartRefresh(ctx, fiveDaysAgo, resource.AuthMethod, []byte("some hash"), fiveDaysAgo, fiveDaysAgo)
			require.NoError(t, err)
			_, err = auth.ListAuthMethodsPage(ctx, []byte("some hash"), 1, filterFunc, tok, repo, []string{org.PublicId}, false)
			require.ErrorContains(t, err, "token did not have a pagination token component")
		})
		t.Run("missing repo", func(t *testing.T) {
			t.Parallel()
			filterFunc := func(_ context.Context, am auth.AuthMethod) (bool, error) {
				return true, nil
			}
			tok, err := listtoken.NewPagination(ctx, fiveDaysAgo, resource.AuthMethod, []byte("some hash"), "some-id", fiveDaysAgo)
			require.NoError(t, err)
			_, err = auth.ListAuthMethodsPage(ctx, []byte("some hash"), 1, filterFunc, tok, nil, []string{org.PublicId}, false)
			require.ErrorContains(t, err, "missing repo")
		})
		t.Run("missing scope ids", func(t *testing.T) {
			t.Parallel()
			filterFunc := func(_ context.Context, am auth.AuthMethod) (bool, error) {
				return true, nil
			}
			tok, err := listtoken.NewPagination(ctx, fiveDaysAgo, resource.AuthMethod, []byte("some hash"), "some-id", fiveDaysAgo)
			require.NoError(t, err)
			_, err = auth.ListAuthMethodsPage(ctx, []byte("some hash"), 1, filterFunc, tok, repo, nil, false)
			require.ErrorContains(t, err, "missing scope ids")
		})
		t.Run("wrong token resource type", func(t *testing.T) {
			t.Parallel()
			filterFunc := func(_ context.Context, am auth.AuthMethod) (bool, error) {
				return true, nil
			}
			tok, err := listtoken.NewPagination(ctx, fiveDaysAgo, resource.Target, []byte("some hash"), "some-id", fiveDaysAgo)
			require.NoError(t, err)
			_, err = auth.ListAuthMethodsPage(ctx, []byte("some hash"), 1, filterFunc, tok, repo, []string{org.GetPublicId()}, false)
			require.ErrorContains(t, err, "token did not have an auth method resource type")
		})
	})
	t.Run("ListRefresh validation", func(t *testing.T) {
		t.Parallel()
		t.Run("missing grants hash", func(t *testing.T) {
			t.Parallel()
			filterFunc := func(_ context.Context, am auth.AuthMethod) (bool, error) {
				return true, nil
			}
			tok, err := listtoken.NewStartRefresh(ctx, fiveDaysAgo, resource.AuthMethod, []byte("some hash"), fiveDaysAgo, fiveDaysAgo)
			require.NoError(t, err)
			_, err = auth.ListAuthMethodsRefresh(ctx, nil, 1, filterFunc, tok, repo, []string{org.PublicId}, false)
			require.ErrorContains(t, err, "missing grants hash")
		})
		t.Run("zero page size", func(t *testing.T) {
			t.Parallel()
			filterFunc := func(_ context.Context, am auth.AuthMethod) (bool, error) {
				return true, nil
			}
			tok, err := listtoken.NewStartRefresh(ctx, fiveDaysAgo, resource.AuthMethod, []byte("some hash"), fiveDaysAgo, fiveDaysAgo)
			require.NoError(t, err)
			_, err = auth.ListAuthMethodsRefresh(ctx, []byte("some hash"), 0, filterFunc, tok, repo, []string{org.PublicId}, false)
			require.ErrorContains(t, err, "page size must be at least 1")
		})
		t.Run("negative page size", func(t *testing.T) {
			t.Parallel()
			filterFunc := func(_ context.Context, am auth.AuthMethod) (bool, error) {
				return true, nil
			}
			tok, err := listtoken.NewStartRefresh(ctx, fiveDaysAgo, resource.AuthMethod, []byte("some hash"), fiveDaysAgo, fiveDaysAgo)
			require.NoError(t, err)
			_, err = auth.ListAuthMethodsRefresh(ctx, []byte("some hash"), -1, filterFunc, tok, repo, []string{org.PublicId}, false)
			require.ErrorContains(t, err, "page size must be at least 1")
		})
		t.Run("nil filter func", func(t *testing.T) {
			t.Parallel()
			tok, err := listtoken.NewStartRefresh(ctx, fiveDaysAgo, resource.AuthMethod, []byte("some hash"), fiveDaysAgo, fiveDaysAgo)
			require.NoError(t, err)
			_, err = auth.ListAuthMethodsRefresh(ctx, []byte("some hash"), 1, nil, tok, repo, []string{org.PublicId}, false)
			require.ErrorContains(t, err, "missing filter item callback")
		})
		t.Run("nil token", func(t *testing.T) {
			t.Parallel()
			filterFunc := func(_ context.Context, am auth.AuthMethod) (bool, error) {
				return true, nil
			}
			_, err := auth.ListAuthMethodsRefresh(ctx, []byte("some hash"), 1, filterFunc, nil, repo, []string{org.PublicId}, false)
			require.ErrorContains(t, err, "missing token")
		})
		t.Run("missing repo", func(t *testing.T) {
			t.Parallel()
			filterFunc := func(_ context.Context, am auth.AuthMethod) (bool, error) {
				return true, nil
			}
			tok, err := listtoken.NewStartRefresh(ctx, fiveDaysAgo, resource.AuthMethod, []byte("some hash"), fiveDaysAgo, fiveDaysAgo)
			require.NoError(t, err)
			_, err = auth.ListAuthMethodsRefresh(ctx, []byte("some hash"), 1, filterFunc, tok, nil, []string{org.PublicId}, false)
			require.ErrorContains(t, err, "missing repo")
		})
		t.Run("missing scope ids", func(t *testing.T) {
			t.Parallel()
			filterFunc := func(_ context.Context, am auth.AuthMethod) (bool, error) {
				return true, nil
			}
			tok, err := listtoken.NewStartRefresh(ctx, fiveDaysAgo, resource.AuthMethod, []byte("some hash"), fiveDaysAgo, fiveDaysAgo)
			require.NoError(t, err)
			_, err = auth.ListAuthMethodsRefresh(ctx, []byte("some hash"), 1, filterFunc, tok, repo, nil, false)
			require.ErrorContains(t, err, "missing scope ids")
		})
		t.Run("wrong token resource type", func(t *testing.T) {
			t.Parallel()
			filterFunc := func(_ context.Context, am auth.AuthMethod) (bool, error) {
				return true, nil
			}
			tok, err := listtoken.NewStartRefresh(ctx, fiveDaysAgo, resource.Target, []byte("some hash"), fiveDaysAgo, fiveDaysAgo)
			require.NoError(t, err)
			_, err = auth.ListAuthMethodsRefresh(ctx, []byte("some hash"), 1, filterFunc, tok, repo, []string{org.GetPublicId()}, false)
			require.ErrorContains(t, err, "token did not have an auth method resource type")
		})
	})
	t.Run("ListRefreshPage validation", func(t *testing.T) {
		t.Parallel()
		t.Run("missing grants hash", func(t *testing.T) {
			t.Parallel()
			filterFunc := func(_ context.Context, am auth.AuthMethod) (bool, error) {
				return true, nil
			}
			tok, err := listtoken.NewRefresh(ctx, fiveDaysAgo, resource.AuthMethod, []byte("some hash"), fiveDaysAgo, fiveDaysAgo, fiveDaysAgo, "some other id", fiveDaysAgo)
			require.NoError(t, err)
			_, err = auth.ListAuthMethodsRefreshPage(ctx, nil, 1, filterFunc, tok, repo, []string{org.PublicId}, false)
			require.ErrorContains(t, err, "missing grants hash")
		})
		t.Run("zero page size", func(t *testing.T) {
			t.Parallel()
			filterFunc := func(_ context.Context, am auth.AuthMethod) (bool, error) {
				return true, nil
			}
			tok, err := listtoken.NewRefresh(ctx, fiveDaysAgo, resource.AuthMethod, []byte("some hash"), fiveDaysAgo, fiveDaysAgo, fiveDaysAgo, "some other id", fiveDaysAgo)
			require.NoError(t, err)
			_, err = auth.ListAuthMethodsRefreshPage(ctx, []byte("some hash"), 0, filterFunc, tok, repo, []string{org.PublicId}, false)
			require.ErrorContains(t, err, "page size must be at least 1")
		})
		t.Run("negative page size", func(t *testing.T) {
			t.Parallel()
			filterFunc := func(_ context.Context, am auth.AuthMethod) (bool, error) {
				return true, nil
			}
			tok, err := listtoken.NewRefresh(ctx, fiveDaysAgo, resource.AuthMethod, []byte("some hash"), fiveDaysAgo, fiveDaysAgo, fiveDaysAgo, "some other id", fiveDaysAgo)
			require.NoError(t, err)
			_, err = auth.ListAuthMethodsRefreshPage(ctx, []byte("some hash"), -1, filterFunc, tok, repo, []string{org.PublicId}, false)
			require.ErrorContains(t, err, "page size must be at least 1")
		})
		t.Run("nil filter func", func(t *testing.T) {
			t.Parallel()
			tok, err := listtoken.NewRefresh(ctx, fiveDaysAgo, resource.AuthMethod, []byte("some hash"), fiveDaysAgo, fiveDaysAgo, fiveDaysAgo, "some other id", fiveDaysAgo)
			require.NoError(t, err)
			_, err = auth.ListAuthMethodsRefreshPage(ctx, []byte("some hash"), 1, nil, tok, repo, []string{org.PublicId}, false)
			require.ErrorContains(t, err, "missing filter item callback")
		})
		t.Run("nil token", func(t *testing.T) {
			t.Parallel()
			filterFunc := func(_ context.Context, am auth.AuthMethod) (bool, error) {
				return true, nil
			}
			_, err := auth.ListAuthMethodsRefreshPage(ctx, []byte("some hash"), 1, filterFunc, nil, repo, []string{org.PublicId}, false)
			require.ErrorContains(t, err, "missing token")
		})
		t.Run("wrong token type", func(t *testing.T) {
			t.Parallel()
			filterFunc := func(_ context.Context, am auth.AuthMethod) (bool, error) {
				return true, nil
			}
			tok, err := listtoken.NewPagination(ctx, fiveDaysAgo, resource.AuthMethod, []byte("some hash"), "some-id", fiveDaysAgo)
			require.NoError(t, err)
			_, err = auth.ListAuthMethodsRefreshPage(ctx, []byte("some hash"), 1, filterFunc, tok, repo, []string{org.PublicId}, false)
			require.ErrorContains(t, err, "token did not have a refresh token component")
		})
		t.Run("missing repo", func(t *testing.T) {
			t.Parallel()
			filterFunc := func(_ context.Context, am auth.AuthMethod) (bool, error) {
				return true, nil
			}
			tok, err := listtoken.NewRefresh(ctx, fiveDaysAgo, resource.AuthMethod, []byte("some hash"), fiveDaysAgo, fiveDaysAgo, fiveDaysAgo, "some other id", fiveDaysAgo)
			require.NoError(t, err)
			_, err = auth.ListAuthMethodsRefreshPage(ctx, []byte("some hash"), 1, filterFunc, tok, nil, []string{org.PublicId}, false)
			require.ErrorContains(t, err, "missing repo")
		})
		t.Run("missing scope ids", func(t *testing.T) {
			t.Parallel()
			filterFunc := func(_ context.Context, am auth.AuthMethod) (bool, error) {
				return true, nil
			}
			tok, err := listtoken.NewRefresh(ctx, fiveDaysAgo, resource.AuthMethod, []byte("some hash"), fiveDaysAgo, fiveDaysAgo, fiveDaysAgo, "some other id", fiveDaysAgo)
			require.NoError(t, err)
			_, err = auth.ListAuthMethodsRefreshPage(ctx, []byte("some hash"), 1, filterFunc, tok, repo, nil, false)
			require.ErrorContains(t, err, "missing scope ids")
		})
		t.Run("wrong token resource type", func(t *testing.T) {
			t.Parallel()
			filterFunc := func(_ context.Context, am auth.AuthMethod) (bool, error) {
				return true, nil
			}
			tok, err := listtoken.NewRefresh(ctx, fiveDaysAgo, resource.Target, []byte("some hash"), fiveDaysAgo, fiveDaysAgo, fiveDaysAgo, "some other id", fiveDaysAgo)
			require.NoError(t, err)
			_, err = auth.ListAuthMethodsRefreshPage(ctx, []byte("some hash"), 1, filterFunc, tok, repo, []string{org.GetPublicId()}, false)
			require.ErrorContains(t, err, "token did not have an auth method resource type")
		})
	})

	t.Run("simple pagination", func(t *testing.T) {
		filterFunc := func(context.Context, auth.AuthMethod) (bool, error) {
			return true, nil
		}
		resp, err := auth.ListAuthMethods(ctx, []byte("some hash"), 1, filterFunc, repo, []string{org.PublicId}, false)
		require.NoError(t, err)
		require.NotNil(t, resp.ListToken)
		require.Equal(t, resp.ListToken.GrantsHash, []byte("some hash"))
		require.False(t, resp.CompleteListing)
		require.Len(t, resp.Items, 1)
		require.Equal(t, resp.EstimatedItemCount, 6)
		require.Empty(t, resp.DeletedIds)
		require.Empty(t, cmp.Diff(resp.Items[0], ams[0], cmpOpts...))

		resp2, err := auth.ListAuthMethodsPage(ctx, []byte("some hash"), 1, filterFunc, resp.ListToken, repo, []string{org.PublicId}, false)
		require.NoError(t, err)
		require.Equal(t, resp2.ListToken.GrantsHash, []byte("some hash"))
		require.False(t, resp2.CompleteListing)
		require.Equal(t, resp2.EstimatedItemCount, 6)
		require.Empty(t, resp2.DeletedIds)
		require.Len(t, resp2.Items, 1)
		require.Empty(t, cmp.Diff(resp2.Items[0], ams[1], cmpOpts...))

		resp3, err := auth.ListAuthMethodsPage(ctx, []byte("some hash"), 1, filterFunc, resp2.ListToken, repo, []string{org.PublicId}, false)
		require.NoError(t, err)
		require.Equal(t, resp3.ListToken.GrantsHash, []byte("some hash"))
		require.False(t, resp3.CompleteListing)
		require.Equal(t, resp3.EstimatedItemCount, 6)
		require.Empty(t, resp3.DeletedIds)
		require.Len(t, resp3.Items, 1)
		require.Empty(t, cmp.Diff(resp3.Items[0], ams[2], cmpOpts...))

		resp4, err := auth.ListAuthMethodsPage(ctx, []byte("some hash"), 1, filterFunc, resp3.ListToken, repo, []string{org.PublicId}, false)
		require.NoError(t, err)
		require.Equal(t, resp4.ListToken.GrantsHash, []byte("some hash"))
		require.False(t, resp4.CompleteListing)
		require.Equal(t, resp4.EstimatedItemCount, 6)
		require.Empty(t, resp4.DeletedIds)
		require.Len(t, resp4.Items, 1)
		require.Empty(t, cmp.Diff(resp4.Items[0], ams[3], cmpOpts...))

		// get the rest
		resp5, err := auth.ListAuthMethodsPage(ctx, []byte("some hash"), 2, filterFunc, resp4.ListToken, repo, []string{org.PublicId}, false)
		require.NoError(t, err)
		require.Equal(t, resp5.ListToken.GrantsHash, []byte("some hash"))
		require.True(t, resp5.CompleteListing)
		require.Equal(t, resp5.EstimatedItemCount, 6)
		require.Empty(t, resp5.DeletedIds)
		require.Len(t, resp5.Items, 2)
		require.Empty(t, cmp.Diff(resp5.Items, ams[4:], cmpOpts...))

		// Finished initial pagination phase, request refresh
		// Expect no results.
		resp6, err := auth.ListAuthMethodsRefresh(ctx, []byte("some hash"), 1, filterFunc, resp5.ListToken, repo, []string{org.PublicId}, false)
		require.NoError(t, err)
		require.Equal(t, resp6.ListToken.GrantsHash, []byte("some hash"))
		require.True(t, resp6.CompleteListing)
		require.Equal(t, resp6.EstimatedItemCount, 6)
		require.Empty(t, resp6.DeletedIds)
		require.Empty(t, resp6.Items)

		// Create some new auth methods
		am1 := ldap.TestAuthMethod(t, conn, databaseWrapper, org.PublicId, []string{"ldaps://ldap1.alice.com"}, ldap.WithOperationalState(ctx, ldap.InactiveState))
		am2 := oidc.TestAuthMethod(t, conn, databaseWrapper, org.PublicId, oidc.InactiveState, "charlene_rp", "charlenes-dogs-name",
			oidc.WithIssuer(oidc.TestConvertToUrls(t, "https://charlene-inactive.com")[0]), oidc.WithApiUrl(oidc.TestConvertToUrls(t, "https://api.com")[0]))
		am3 := password.TestAuthMethod(t, conn, org.GetPublicId())
		t.Cleanup(func() {
			_, err := ldapRepo.DeleteAuthMethod(ctx, am1.PublicId)
			require.NoError(t, err)
			_, err = oidcRepo.DeleteAuthMethod(ctx, am2.PublicId)
			require.NoError(t, err)
			_, err = passwordRepo.DeleteAuthMethod(ctx, org.PublicId, am3.PublicId)
			require.NoError(t, err)
			// Run analyze to update count estimate
			_, err = sqlDb.ExecContext(ctx, "analyze")
			require.NoError(t, err)
		})
		// Run analyze to update count estimate
		_, err = sqlDb.ExecContext(ctx, "analyze")
		require.NoError(t, err)

		// Refresh again, should get am3
		resp7, err := auth.ListAuthMethodsRefresh(ctx, []byte("some hash"), 1, filterFunc, resp6.ListToken, repo, []string{org.PublicId}, false)
		require.NoError(t, err)
		require.Equal(t, resp7.ListToken.GrantsHash, []byte("some hash"))
		require.False(t, resp7.CompleteListing)
		require.Equal(t, resp7.EstimatedItemCount, 9)
		require.Empty(t, resp7.DeletedIds)
		require.Len(t, resp7.Items, 1)
		require.Empty(t, cmp.Diff(resp7.Items[0], am3, cmpOpts...))

		// Refresh again, should get am2
		resp8, err := auth.ListAuthMethodsRefreshPage(ctx, []byte("some hash"), 1, filterFunc, resp7.ListToken, repo, []string{org.PublicId}, false)
		require.NoError(t, err)
		require.Equal(t, resp8.ListToken.GrantsHash, []byte("some hash"))
		require.False(t, resp8.CompleteListing)
		require.Equal(t, resp8.EstimatedItemCount, 9)
		require.Empty(t, resp8.DeletedIds)
		require.Len(t, resp8.Items, 1)
		require.Empty(t, cmp.Diff(resp8.Items[0], am2, cmpOpts...))

		// Refresh again, should get am1
		resp9, err := auth.ListAuthMethodsRefreshPage(ctx, []byte("some hash"), 1, filterFunc, resp8.ListToken, repo, []string{org.PublicId}, false)
		require.NoError(t, err)
		require.Equal(t, resp9.ListToken.GrantsHash, []byte("some hash"))
		require.True(t, resp9.CompleteListing)
		require.Equal(t, resp9.EstimatedItemCount, 9)
		require.Empty(t, resp9.DeletedIds)
		require.Len(t, resp9.Items, 1)
		require.Empty(t, cmp.Diff(resp9.Items[0], am1, cmpOpts...))

		// Refresh again, should get no results
		resp10, err := auth.ListAuthMethodsRefresh(ctx, []byte("some hash"), 1, filterFunc, resp9.ListToken, repo, []string{org.PublicId}, false)
		require.NoError(t, err)
		require.Equal(t, resp10.ListToken.GrantsHash, []byte("some hash"))
		require.True(t, resp10.CompleteListing)
		require.Equal(t, resp10.EstimatedItemCount, 9)
		require.Empty(t, resp10.DeletedIds)
		require.Empty(t, resp10.Items)
	})

	t.Run("simple pagination with aggressive filtering", func(t *testing.T) {
		filterFunc := func(ctx context.Context, am auth.AuthMethod) (bool, error) {
			return am.GetPublicId() == ams[1].GetPublicId() ||
				am.GetPublicId() == ams[len(ams)-1].GetPublicId(), nil
		}
		resp, err := auth.ListAuthMethods(ctx, []byte("some hash"), 1, filterFunc, repo, []string{org.PublicId}, false)
		require.NoError(t, err)
		require.NotNil(t, resp.ListToken)
		require.Equal(t, resp.ListToken.GrantsHash, []byte("some hash"))
		require.False(t, resp.CompleteListing)
		require.Equal(t, resp.EstimatedItemCount, 6)
		require.Empty(t, resp.DeletedIds)
		require.Len(t, resp.Items, 1)
		require.Empty(t, cmp.Diff(resp.Items[0], ams[1], cmpOpts...))

		resp2, err := auth.ListAuthMethodsPage(ctx, []byte("some hash"), 2, filterFunc, resp.ListToken, repo, []string{org.PublicId}, false)
		require.NoError(t, err)
		require.NotNil(t, resp2.ListToken)
		require.Equal(t, resp2.ListToken.GrantsHash, []byte("some hash"))
		require.True(t, resp2.CompleteListing)
		require.Equal(t, resp2.EstimatedItemCount, 6)
		require.Empty(t, resp2.DeletedIds)
		require.Len(t, resp2.Items, 1)
		require.Empty(t, cmp.Diff(resp2.Items[0], ams[len(ams)-1], cmpOpts...))

		// request a refresh, nothing should be returned
		resp3, err := auth.ListAuthMethodsRefresh(ctx, []byte("some hash"), 1, filterFunc, resp.ListToken, repo, []string{org.PublicId}, false)
		require.NoError(t, err)
		require.Equal(t, resp3.ListToken.GrantsHash, []byte("some hash"))
		require.True(t, resp3.CompleteListing)
		require.Equal(t, resp3.EstimatedItemCount, 6)
		require.Empty(t, resp3.DeletedIds)
		require.Empty(t, resp3.Items)

		// Create some new auth methods
		am1 := ldap.TestAuthMethod(t, conn, databaseWrapper, org.PublicId, []string{"ldaps://ldap1.alice.com"}, ldap.WithOperationalState(ctx, ldap.InactiveState))
		am2 := oidc.TestAuthMethod(t, conn, databaseWrapper, org.PublicId, oidc.InactiveState, "charlene_rp", "charlenes-dogs-name",
			oidc.WithIssuer(oidc.TestConvertToUrls(t, "https://charlene-inactive.com")[0]), oidc.WithApiUrl(oidc.TestConvertToUrls(t, "https://api.com")[0]))
		am3 := password.TestAuthMethod(t, conn, org.GetPublicId())
		t.Cleanup(func() {
			_, err := ldapRepo.DeleteAuthMethod(ctx, am1.PublicId)
			require.NoError(t, err)
			_, err = oidcRepo.DeleteAuthMethod(ctx, am2.PublicId)
			require.NoError(t, err)
			_, err = passwordRepo.DeleteAuthMethod(ctx, org.PublicId, am3.PublicId)
			require.NoError(t, err)
			// Run analyze to update count estimate
			_, err = sqlDb.ExecContext(ctx, "analyze")
			require.NoError(t, err)
		})
		// Run analyze to update count estimate
		_, err = sqlDb.ExecContext(ctx, "analyze")
		require.NoError(t, err)

		filterFunc = func(ctx context.Context, am auth.AuthMethod) (bool, error) {
			return am.GetPublicId() == am1.GetPublicId() ||
				am.GetPublicId() == am3.GetPublicId(), nil
		}
		// Refresh again, should get am3
		resp4, err := auth.ListAuthMethodsRefresh(ctx, []byte("some hash"), 1, filterFunc, resp3.ListToken, repo, []string{org.PublicId}, false)
		require.NoError(t, err)
		require.Equal(t, resp4.ListToken.GrantsHash, []byte("some hash"))
		require.False(t, resp4.CompleteListing)
		require.Equal(t, resp4.EstimatedItemCount, 9)
		require.Empty(t, resp4.DeletedIds)
		require.Len(t, resp4.Items, 1)
		require.Empty(t, cmp.Diff(resp4.Items[0], am3, cmpOpts...))

		// Refresh again, should get am1
		resp5, err := auth.ListAuthMethodsRefreshPage(ctx, []byte("some hash"), 1, filterFunc, resp4.ListToken, repo, []string{org.PublicId}, false)
		require.NoError(t, err)
		require.Equal(t, resp5.ListToken.GrantsHash, []byte("some hash"))
		require.True(t, resp5.CompleteListing)
		require.Equal(t, resp5.EstimatedItemCount, 9)
		require.Empty(t, resp5.DeletedIds)
		require.Len(t, resp5.Items, 1)
		require.Empty(t, cmp.Diff(resp5.Items[0], am1, cmpOpts...))
	})

	t.Run("simple pagination with deletion", func(t *testing.T) {
		filterFunc := func(ctx context.Context, am auth.AuthMethod) (bool, error) {
			return true, nil
		}
		// delete passwords
		deletedAmId1 := ams[0].GetPublicId()
		_, err := passwordRepo.DeleteAuthMethod(ctx, org.GetPublicId(), deletedAmId1)
		require.NoError(t, err)
		ams = ams[1:]
		deletedAmId2 := ams[0].GetPublicId()
		_, err = passwordRepo.DeleteAuthMethod(ctx, org.GetPublicId(), deletedAmId2)
		require.NoError(t, err)
		ams = ams[1:]

		// Run analyze to update count estimate
		_, err = sqlDb.ExecContext(ctx, "analyze")
		require.NoError(t, err)

		resp, err := auth.ListAuthMethods(ctx, []byte("some hash"), 1, filterFunc, repo, []string{org.PublicId}, false)
		require.NoError(t, err)
		require.NotNil(t, resp.ListToken)
		require.Equal(t, resp.ListToken.GrantsHash, []byte("some hash"))
		require.False(t, resp.CompleteListing)
		require.Equal(t, resp.EstimatedItemCount, 4)
		require.Empty(t, resp.DeletedIds)
		require.Len(t, resp.Items, 1)
		require.Empty(t, cmp.Diff(resp.Items[0], ams[0], cmpOpts...))

		// request remaining results
		resp2, err := auth.ListAuthMethodsPage(ctx, []byte("some hash"), 3, filterFunc, resp.ListToken, repo, []string{org.PublicId}, false)
		require.NoError(t, err)
		require.Equal(t, resp2.ListToken.GrantsHash, []byte("some hash"))
		require.True(t, resp2.CompleteListing)
		require.Equal(t, resp2.EstimatedItemCount, 4)
		require.Empty(t, resp2.DeletedIds)
		require.Len(t, resp2.Items, 3)
		require.Empty(t, cmp.Diff(resp2.Items, ams[1:], cmpOpts...))

		// delete oidcs
		deletedAmId3 := ams[0].GetPublicId()
		_, err = oidcRepo.DeleteAuthMethod(ctx, deletedAmId3)
		require.NoError(t, err)
		ams = ams[1:]
		deletedAmId4 := ams[0].GetPublicId()
		_, err = oidcRepo.DeleteAuthMethod(ctx, deletedAmId4)
		require.NoError(t, err)
		ams = ams[1:]

		// Run analyze to update count estimate
		_, err = sqlDb.ExecContext(ctx, "analyze")
		require.NoError(t, err)

		resp3, err := auth.ListAuthMethodsRefresh(ctx, []byte("some hash"), 1, filterFunc, resp2.ListToken, repo, []string{org.PublicId}, false)
		require.NoError(t, err)
		require.Equal(t, resp3.ListToken.GrantsHash, []byte("some hash"))
		require.True(t, resp3.CompleteListing)
		require.Equal(t, resp3.EstimatedItemCount, 2)
		assert.Empty(t, cmp.Diff(resp3.DeletedIds, []string{deletedAmId3, deletedAmId4}, cmpopts.SortSlices(func(a, b string) bool { return a < b })))
		require.Empty(t, resp3.Items)
	})
}
