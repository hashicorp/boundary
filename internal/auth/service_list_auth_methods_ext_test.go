// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: BUSL-1.1

package auth_test

import (
	"context"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	"github.com/hashicorp/boundary/internal/auth"
	"github.com/hashicorp/boundary/internal/auth/ldap"
	ldapstore "github.com/hashicorp/boundary/internal/auth/ldap/store"
	"github.com/hashicorp/boundary/internal/auth/oidc"
	oidcstore "github.com/hashicorp/boundary/internal/auth/oidc/store"
	"github.com/hashicorp/boundary/internal/auth/password"
	pwstore "github.com/hashicorp/boundary/internal/auth/password/store"
	"github.com/hashicorp/boundary/internal/db"
	"github.com/hashicorp/boundary/internal/db/timestamp"
	"github.com/hashicorp/boundary/internal/iam"
	"github.com/hashicorp/boundary/internal/kms"
	"github.com/hashicorp/boundary/internal/refreshtoken"
	"github.com/hashicorp/boundary/internal/types/resource"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/types/known/timestamppb"
)

func TestService_List(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	conn, _ := db.TestSetup(t, "postgres")
	sqlDb, err := conn.SqlDB(ctx)
	require.NoError(t, err)
	rw := db.New(conn)
	wrapper := db.TestWrapper(t)
	kmsCache := kms.TestKms(t, conn, wrapper)
	org, _ := iam.TestScopes(t, iam.TestRepo(t, conn, wrapper))
	kms := kms.TestKms(t, conn, wrapper)
	ldapRepo, err := ldap.NewRepository(ctx, rw, rw, kms)
	require.NoError(t, err)
	oidcRepo, err := oidc.NewRepository(ctx, rw, rw, kms)
	require.NoError(t, err)
	pwRepo, err := password.NewRepository(ctx, rw, rw, kms)
	require.NoError(t, err)
	databaseWrapper, err := kmsCache.GetWrapper(context.Background(), org.GetPublicId(), 1)
	require.NoError(t, err)

	ams := []auth.AuthMethod{
		ldap.TestAuthMethod(t, conn, databaseWrapper, org.GetPublicId(), []string{"ldaps://ldap1.com"}, ldap.WithOperationalState(ctx, "active-public")),
		ldap.TestAuthMethod(t, conn, databaseWrapper, org.GetPublicId(), []string{"ldaps://ldap2.com"}, ldap.WithOperationalState(ctx, "active-public")),
		ldap.TestAuthMethod(t, conn, databaseWrapper, org.GetPublicId(), []string{"ldaps://ldap3.com"}, ldap.WithOperationalState(ctx, "active-public")),
	}

	oidcam := oidc.TestAuthMethod(t, conn, databaseWrapper, org.GetPublicId(), oidc.ActivePublicState, "alice_rp", "secret",
		oidc.WithIssuer(oidc.TestConvertToUrls(t, "https://alice.com")[0]), oidc.WithApiUrl(oidc.TestConvertToUrls(t, "https://api.com")[0]), oidc.WithSigningAlgs(oidc.EdDSA))
	ams = append(ams, oidcam)

	ams = append(ams, password.TestAuthMethod(t, conn, org.GetPublicId()))

	authMethodService, err := auth.NewAuthMethodService(ctx, rw, ldapRepo, oidcRepo, pwRepo)
	require.NoError(t, err)

	// 	// Run analyze to update count estimate
	_, err = sqlDb.ExecContext(ctx, "analyze")
	require.NoError(t, err)

	cmpOpts := []cmp.Option{
		cmpopts.IgnoreUnexported(
			ldap.AuthMethod{},
			ldapstore.AuthMethod{},
			oidc.AuthMethod{},
			oidcstore.AuthMethod{},
			password.AuthMethod{},
			pwstore.AuthMethod{},
			timestamp.Timestamp{},
			timestamppb.Timestamp{},
		),
	}

	t.Run("List validation", func(t *testing.T) {
		t.Parallel()
		t.Run("missing grants hash", func(t *testing.T) {
			t.Parallel()
			filterFunc := func(_ context.Context, am auth.AuthMethod) (bool, error) {
				return true, nil
			}
			_, err := authMethodService.ListAuthMethods(ctx, nil, 1, filterFunc, []string{"scopeID"}, false)
			require.ErrorContains(t, err, "missing grants hash")
		})
		t.Run("zero page size", func(t *testing.T) {
			t.Parallel()
			filterFunc := func(_ context.Context, am auth.AuthMethod) (bool, error) {
				return true, nil
			}
			_, err := authMethodService.ListAuthMethods(ctx, []byte("some hash"), 0, filterFunc, []string{"scopeID"}, false)
			require.ErrorContains(t, err, "page size must be at least 1")
		})
		t.Run("negative page size", func(t *testing.T) {
			t.Parallel()
			filterFunc := func(_ context.Context, am auth.AuthMethod) (bool, error) {
				return true, nil
			}
			_, err := authMethodService.ListAuthMethods(ctx, []byte("some hash"), -1, filterFunc, []string{"scopeID"}, false)
			require.ErrorContains(t, err, "page size must be at least 1")
		})
		t.Run("nil filter func", func(t *testing.T) {
			t.Parallel()
			_, err := authMethodService.ListAuthMethods(ctx, []byte("some hash"), 1, nil, []string{"scopeID"}, false)
			require.ErrorContains(t, err, "missing filter item callback")
		})
		t.Run("nil scope ids", func(t *testing.T) {
			t.Parallel()
			filterFunc := func(_ context.Context, am auth.AuthMethod) (bool, error) {
				return true, nil
			}
			_, err := authMethodService.ListAuthMethods(ctx, []byte("some hash"), 1, filterFunc, nil, false)
			require.ErrorContains(t, err, "missing scope ids")
		})
	})

	t.Run("ListRefresh validation", func(t *testing.T) {
		t.Parallel()
		t.Run("missing grants hash", func(t *testing.T) {
			t.Parallel()
			filterFunc := func(_ context.Context, am auth.AuthMethod) (bool, error) {
				return true, nil
			}
			tok, err := refreshtoken.New(ctx, time.Now(), time.Now(), resource.Session, []byte("some hash"), "some-id", time.Now())
			require.NoError(t, err)
			_, err = authMethodService.ListAuthMethodsRefresh(ctx, nil, 1, filterFunc, tok, []string{"scopeID"}, false)
			require.ErrorContains(t, err, "missing grants hash")
		})
		t.Run("zero page size", func(t *testing.T) {
			t.Parallel()
			filterFunc := func(_ context.Context, am auth.AuthMethod) (bool, error) {
				return true, nil
			}
			tok, err := refreshtoken.New(ctx, time.Now(), time.Now(), resource.Session, []byte("some hash"), "some-id", time.Now())
			require.NoError(t, err)
			_, err = authMethodService.ListAuthMethodsRefresh(ctx, []byte("some hash"), 0, filterFunc, tok, []string{"scopeID"}, false)
			require.ErrorContains(t, err, "page size must be at least 1")
		})
		t.Run("negative page size", func(t *testing.T) {
			t.Parallel()
			filterFunc := func(_ context.Context, am auth.AuthMethod) (bool, error) {
				return true, nil
			}
			tok, err := refreshtoken.New(ctx, time.Now(), time.Now(), resource.Session, []byte("some hash"), "some-id", time.Now())
			require.NoError(t, err)
			_, err = authMethodService.ListAuthMethodsRefresh(ctx, []byte("some hash"), -1, filterFunc, tok, []string{"scopeID"}, false)
			require.ErrorContains(t, err, "page size must be at least 1")
		})
		t.Run("nil filter func", func(t *testing.T) {
			t.Parallel()
			tok, err := refreshtoken.New(ctx, time.Now(), time.Now(), resource.Session, []byte("some hash"), "some-id", time.Now())
			require.NoError(t, err)
			_, err = authMethodService.ListAuthMethodsRefresh(ctx, []byte("some hash"), 1, nil, tok, []string{"scopeID"}, false)
			require.ErrorContains(t, err, "missing filter item callback")
		})
		t.Run("nil token", func(t *testing.T) {
			t.Parallel()
			filterFunc := func(_ context.Context, am auth.AuthMethod) (bool, error) {
				return true, nil
			}
			_, err = authMethodService.ListAuthMethodsRefresh(ctx, []byte("some hash"), 1, filterFunc, nil, []string{"scopeID"}, false)
			require.ErrorContains(t, err, "missing token")
		})
		t.Run("nil scope id", func(t *testing.T) {
			t.Parallel()
			filterFunc := func(_ context.Context, am auth.AuthMethod) (bool, error) {
				return true, nil
			}
			tok, err := refreshtoken.New(ctx, time.Now(), time.Now(), resource.Session, []byte("some hash"), "some-id", time.Now())
			require.NoError(t, err)
			_, err = authMethodService.ListAuthMethodsRefresh(ctx, []byte("some hash"), 1, filterFunc, tok, nil, false)
			require.ErrorContains(t, err, "missing scope id")
		})
	})

	t.Run("simple pagination", func(t *testing.T) {
		filterFunc := func(context.Context, auth.AuthMethod) (bool, error) {
			return true, nil
		}
		resp, err := authMethodService.ListAuthMethods(ctx, []byte("some hash"), 1, filterFunc, []string{org.GetPublicId()}, false)
		require.NoError(t, err)
		require.NotNil(t, resp.RefreshToken)
		require.Equal(t, resp.RefreshToken.GrantsHash, []byte("some hash"))
		require.False(t, resp.CompleteListing)
		require.Equal(t, 5, resp.EstimatedItemCount)
		require.Empty(t, resp.DeletedIds)
		require.Len(t, resp.Items, 1)
		require.Empty(t, cmp.Diff(resp.Items[0], ams[0], cmpOpts...))

		resp2, err := authMethodService.ListAuthMethodsRefresh(ctx, []byte("some hash"), 1, filterFunc, resp.RefreshToken, []string{org.GetPublicId()}, false)
		require.NoError(t, err)
		require.Equal(t, resp2.RefreshToken.GrantsHash, []byte("some hash"))
		require.False(t, resp2.CompleteListing)
		require.Equal(t, resp2.EstimatedItemCount, 5)
		require.Empty(t, resp2.DeletedIds)
		require.Len(t, resp2.Items, 1)
		require.Empty(t, cmp.Diff(resp2.Items[0], ams[1], cmpOpts...))

		resp3, err := authMethodService.ListAuthMethodsRefresh(ctx, []byte("some hash"), 1, filterFunc, resp.RefreshToken, []string{org.GetPublicId()}, false)
		require.NoError(t, err)
		require.Equal(t, resp3.RefreshToken.GrantsHash, []byte("some hash"))
		require.False(t, resp3.CompleteListing)
		require.Equal(t, resp3.EstimatedItemCount, 5)
		require.Empty(t, resp3.DeletedIds)
		require.Len(t, resp3.Items, 1)
		require.Empty(t, cmp.Diff(resp3.Items[0], ams[2], cmpOpts...))

		resp4, err := authMethodService.ListAuthMethodsRefresh(ctx, []byte("some hash"), 1, filterFunc, resp.RefreshToken, []string{org.GetPublicId()}, false)
		require.NoError(t, err)
		require.Equal(t, resp4.RefreshToken.GrantsHash, []byte("some hash"))
		require.False(t, resp4.CompleteListing)
		require.Equal(t, resp4.EstimatedItemCount, 5)
		require.Empty(t, resp4.DeletedIds)
		require.Len(t, resp4.Items, 1)
		require.Empty(t, cmp.Diff(resp4.Items[0], ams[3], cmpOpts...))

		resp5, err := authMethodService.ListAuthMethodsRefresh(ctx, []byte("some hash"), 1, filterFunc, resp.RefreshToken, []string{org.GetPublicId()}, false)
		require.NoError(t, err)
		require.Equal(t, resp5.RefreshToken.GrantsHash, []byte("some hash"))
		require.True(t, resp5.CompleteListing)
		require.Equal(t, resp5.EstimatedItemCount, 5)
		require.Empty(t, resp5.DeletedIds)
		require.Len(t, resp5.Items, 1)
		require.Empty(t, cmp.Diff(resp5.Items[0], ams[4], cmpOpts...))

		resp6, err := authMethodService.ListAuthMethodsRefresh(ctx, []byte("some hash"), 1, filterFunc, resp.RefreshToken, []string{org.GetPublicId()}, false)
		require.NoError(t, err)
		require.Equal(t, resp6.RefreshToken.GrantsHash, []byte("some hash"))
		require.True(t, resp6.CompleteListing)
		require.Equal(t, resp6.EstimatedItemCount, 5)
		require.Empty(t, resp6.DeletedIds)
		require.Empty(t, resp6.Items)
	})

	t.Run("simple pagination with aggressive filtering", func(t *testing.T) {
		filterFunc := func(_ context.Context, am auth.AuthMethod) (bool, error) {
			return am.GetPublicId() == ams[len(ams)-1].GetPublicId(), nil
		}
		resp, err := authMethodService.ListAuthMethods(ctx, []byte("some hash"), 1, filterFunc, []string{org.GetPublicId()}, false)
		require.NoError(t, err)
		require.NotNil(t, resp.RefreshToken)
		require.Equal(t, resp.RefreshToken.GrantsHash, []byte("some hash"))
		require.True(t, resp.CompleteListing)
		require.Equal(t, resp.EstimatedItemCount, 1)
		require.Empty(t, resp.DeletedIds)
		require.Len(t, resp.Items, 1)
		require.Empty(t, cmp.Diff(resp.Items[0], ams[4], cmpOpts...))

		resp2, err := authMethodService.ListAuthMethodsRefresh(ctx, []byte("some hash"), 1, filterFunc, resp.RefreshToken, []string{org.GetPublicId()}, false)
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
		filterFunc := func(context.Context, auth.AuthMethod) (bool, error) {
			return true, nil
		}
		deletedAuthMethodId := ams[0].GetPublicId()
		_, err := ldapRepo.DeleteAuthMethod(ctx, deletedAuthMethodId)
		require.NoError(t, err)
		ams = ams[1:]

		// Run analyze to update count estimate
		_, err = sqlDb.ExecContext(ctx, "analyze")
		require.NoError(t, err)

		resp, err := authMethodService.ListAuthMethods(ctx, []byte("some hash"), 1, filterFunc, []string{org.GetPublicId()}, false)
		require.NoError(t, err)
		require.NotNil(t, resp.RefreshToken)
		require.Equal(t, resp.RefreshToken.GrantsHash, []byte("some hash"))
		require.False(t, resp.CompleteListing)
		require.Equal(t, resp.EstimatedItemCount, 4)
		require.Empty(t, resp.DeletedIds)
		require.Len(t, resp.Items, 1)
		require.Empty(t, cmp.Diff(resp.Items[0], ams[0], cmpOpts...))

		resp2, err := authMethodService.ListAuthMethodsRefresh(ctx, []byte("some hash"), 1, filterFunc, resp.RefreshToken, []string{org.GetPublicId()}, false)
		require.NoError(t, err)
		require.Equal(t, resp2.RefreshToken.GrantsHash, []byte("some hash"))
		require.False(t, resp2.CompleteListing)
		require.Equal(t, resp2.EstimatedItemCount, 4)
		require.Empty(t, resp2.DeletedIds)
		require.Len(t, resp2.Items, 1)
		require.Empty(t, cmp.Diff(resp2.Items[0], ams[1], cmpOpts...))

		deletedAuthMethodId = ams[0].GetPublicId()
		_, err = ldapRepo.DeleteAuthMethod(ctx, deletedAuthMethodId)
		require.NoError(t, err)
		ams = ams[1:]

		// Run analyze to update count estimate
		_, err = sqlDb.ExecContext(ctx, "analyze")
		require.NoError(t, err)

		resp3, err := authMethodService.ListAuthMethodsRefresh(ctx, []byte("some hash"), 1, filterFunc, resp.RefreshToken, []string{org.GetPublicId()}, false)
		require.NoError(t, err)
		require.Equal(t, resp3.RefreshToken.GrantsHash, []byte("some hash"))
		require.False(t, resp3.CompleteListing)
		require.Equal(t, resp3.EstimatedItemCount, 3)
		require.Contains(t, resp3.DeletedIds, deletedAuthMethodId)
		require.Len(t, resp3.Items, 1)
		require.Empty(t, cmp.Diff(resp3.Items[0], ams[1], cmpOpts...))

		resp4, err := authMethodService.ListAuthMethodsRefresh(ctx, []byte("some hash"), 1, filterFunc, resp.RefreshToken, []string{org.GetPublicId()}, false)
		require.NoError(t, err)
		require.Equal(t, resp4.RefreshToken.GrantsHash, []byte("some hash"))
		require.True(t, resp4.CompleteListing)
		require.Equal(t, resp4.EstimatedItemCount, 3)
		require.Len(t, resp4.Items, 1)
		require.Empty(t, cmp.Diff(resp4.Items[0], ams[2], cmpOpts...))

		resp5, err := authMethodService.ListAuthMethodsRefresh(ctx, []byte("some hash"), 1, filterFunc, resp.RefreshToken, []string{org.GetPublicId()}, false)
		require.NoError(t, err)
		require.Equal(t, resp5.RefreshToken.GrantsHash, []byte("some hash"))
		require.True(t, resp5.CompleteListing)
		require.Equal(t, resp5.EstimatedItemCount, 3)
		require.Empty(t, resp5.Items)
	})
}
