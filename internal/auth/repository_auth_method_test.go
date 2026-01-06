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
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/types/known/timestamppb"
)

func TestAuthMethodRepository_List(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	conn, _ := db.TestSetup(t, "postgres")
	rw := db.New(conn)
	wrapper := db.TestWrapper(t)
	testKms := kms.TestKms(t, conn, wrapper)
	org, _ := iam.TestScopes(t, iam.TestRepo(t, conn, wrapper))
	databaseWrapper, err := testKms.GetWrapper(context.Background(), org.PublicId, kms.KeyPurposeDatabase)
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

	t.Run("validation", func(t *testing.T) {
		t.Parallel()
		t.Run("missing scope ids", func(t *testing.T) {
			t.Parallel()
			_, _, err := repo.List(ctx, nil, nil, auth.WithLimit(ctx, 1))
			require.ErrorContains(t, err, "missing scope ids")
		})
		t.Run("invalid limit", func(t *testing.T) {
			t.Parallel()
			_, _, err := repo.List(ctx, []string{org.PublicId}, nil, auth.WithLimit(ctx, 0))
			require.ErrorContains(t, err, "missing limit")
		})
	})

	t.Run("success-without-after-item", func(t *testing.T) {
		t.Parallel()
		resp, ttime, err := repo.List(ctx, []string{org.PublicId}, nil, auth.WithLimit(ctx, 10))
		require.NoError(t, err)
		// Transaction timestamp should be within ~10 seconds of now
		assert.True(t, time.Now().Before(ttime.Add(10*time.Second)))
		assert.True(t, time.Now().After(ttime.Add(-10*time.Second)))
		require.Empty(t, cmp.Diff(resp, ams, cmpOpts...))
	})
	t.Run("success-with-after-item", func(t *testing.T) {
		t.Parallel()
		resp, ttime, err := repo.List(ctx, []string{org.PublicId}, ams[0], auth.WithLimit(ctx, 10))
		require.NoError(t, err)
		// Transaction timestamp should be within ~10 seconds of now
		assert.True(t, time.Now().Before(ttime.Add(10*time.Second)))
		assert.True(t, time.Now().After(ttime.Add(-10*time.Second)))
		require.Empty(t, cmp.Diff(resp, ams[1:], cmpOpts...))
	})
	t.Run("success-with-unauthenticated-user", func(t *testing.T) {
		t.Parallel()
		resp, ttime, err := repo.List(ctx, []string{org.PublicId}, nil, auth.WithLimit(ctx, 10), auth.WithUnauthenticatedUser(ctx, true))
		require.NoError(t, err)
		// Transaction timestamp should be within ~10 seconds of now
		assert.True(t, time.Now().Before(ttime.Add(10*time.Second)))
		assert.True(t, time.Now().After(ttime.Add(-10*time.Second)))
		require.Empty(t, cmp.Diff(resp, ams[0:2], cmpOpts...))
	})
}

func TestAuthMethodRepository_ListRefresh(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	conn, _ := db.TestSetup(t, "postgres")
	rw := db.New(conn)
	wrapper := db.TestWrapper(t)
	testKms := kms.TestKms(t, conn, wrapper)
	org, _ := iam.TestScopes(t, iam.TestRepo(t, conn, wrapper))
	databaseWrapper, err := testKms.GetWrapper(context.Background(), org.PublicId, kms.KeyPurposeDatabase)
	require.NoError(t, err)
	fiveDaysAgo := time.Now().AddDate(0, 0, -5)

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

	t.Run("validation", func(t *testing.T) {
		t.Parallel()
		t.Run("missing updated after", func(t *testing.T) {
			t.Parallel()
			_, _, err := repo.ListRefresh(ctx, []string{org.PublicId}, time.Time{}, nil, auth.WithLimit(ctx, 1))
			require.ErrorContains(t, err, "missing updated after time")
		})
		t.Run("missing scope ids", func(t *testing.T) {
			t.Parallel()
			_, _, err := repo.ListRefresh(ctx, nil, fiveDaysAgo, nil, auth.WithLimit(ctx, 1))
			require.ErrorContains(t, err, "missing scope ids")
		})
		t.Run("invalid limit", func(t *testing.T) {
			t.Parallel()
			_, _, err := repo.ListRefresh(ctx, []string{org.PublicId}, fiveDaysAgo, nil, auth.WithLimit(ctx, 0))
			require.ErrorContains(t, err, "missing limit")
		})
	})

	t.Run("success-without-after-item", func(t *testing.T) {
		t.Parallel()
		resp, ttime, err := repo.ListRefresh(ctx, []string{org.PublicId}, fiveDaysAgo, nil, auth.WithLimit(ctx, 10))
		require.NoError(t, err)
		// Transaction timestamp should be within ~10 seconds of now
		assert.True(t, time.Now().Before(ttime.Add(10*time.Second)))
		assert.True(t, time.Now().After(ttime.Add(-10*time.Second)))
		require.Empty(t, cmp.Diff(resp, ams, cmpOpts...))
	})
	t.Run("success-with-after-item", func(t *testing.T) {
		t.Parallel()
		resp, ttime, err := repo.ListRefresh(ctx, []string{org.PublicId}, fiveDaysAgo, ams[0], auth.WithLimit(ctx, 10))
		require.NoError(t, err)
		// Transaction timestamp should be within ~10 seconds of now
		assert.True(t, time.Now().Before(ttime.Add(10*time.Second)))
		assert.True(t, time.Now().After(ttime.Add(-10*time.Second)))
		require.Empty(t, cmp.Diff(resp, ams[1:], cmpOpts...))
	})
	t.Run("success-without-after-item-recent-updated-after", func(t *testing.T) {
		t.Parallel()
		resp, ttime, err := repo.ListRefresh(ctx, []string{org.PublicId}, ams[len(ams)-1].GetUpdateTime().AsTime(), nil, auth.WithLimit(ctx, 10))
		require.NoError(t, err)
		// Transaction timestamp should be within ~10 seconds of now
		assert.True(t, time.Now().Before(ttime.Add(10*time.Second)))
		assert.True(t, time.Now().After(ttime.Add(-10*time.Second)))
		require.Empty(t, cmp.Diff(resp, ams[:len(ams)-1], cmpOpts...))
	})
	t.Run("success-with-after-item-recent-updated-after", func(t *testing.T) {
		t.Parallel()
		resp, ttime, err := repo.ListRefresh(ctx, []string{org.PublicId}, ams[len(ams)-1].GetUpdateTime().AsTime(), ams[0], auth.WithLimit(ctx, 10))
		require.NoError(t, err)
		// Transaction timestamp should be within ~10 seconds of now
		assert.True(t, time.Now().Before(ttime.Add(10*time.Second)))
		assert.True(t, time.Now().After(ttime.Add(-10*time.Second)))
		require.Empty(t, cmp.Diff(resp, ams[1:len(ams)-1], cmpOpts...))
	})
}

func TestAuthMethodRepository_EstimatedCount(t *testing.T) {
	t.Parallel()
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

	ldapRepo, err := ldap.NewRepository(ctx, rw, rw, testKms)
	require.NoError(t, err)
	oidcRepo, err := oidc.NewRepository(ctx, rw, rw, testKms)
	require.NoError(t, err)
	passwordRepo, err := password.NewRepository(ctx, rw, rw, testKms)
	require.NoError(t, err)

	repo, err := auth.NewAuthMethodRepository(ctx, rw, rw, testKms)
	require.NoError(t, err)

	// Check total entries at start, expect 0
	numItems, err := repo.EstimatedCount(ctx)
	require.NoError(t, err)
	assert.Equal(t, 0, numItems)

	// Create auth methods
	am1 := ldap.TestAuthMethod(t, conn, databaseWrapper, org.PublicId, []string{"ldaps://ldap1.alice.com"}, ldap.WithOperationalState(ctx, ldap.InactiveState))
	am2 := oidc.TestAuthMethod(t, conn, databaseWrapper, org.PublicId, oidc.InactiveState, "alice_rp", "alices-dogs-name",
		oidc.WithIssuer(oidc.TestConvertToUrls(t, "https://alice-inactive.com")[0]), oidc.WithApiUrl(oidc.TestConvertToUrls(t, "https://api.com")[0]))
	am3 := password.TestAuthMethod(t, conn, org.GetPublicId())

	// Run analyze to update postgres meta tables
	_, err = sqlDb.ExecContext(ctx, "analyze")
	require.NoError(t, err)

	numItems, err = repo.EstimatedCount(ctx)
	require.NoError(t, err)
	assert.Equal(t, 3, numItems)

	// Delete ldap auth method
	_, err = ldapRepo.DeleteAuthMethod(ctx, am1.GetPublicId())
	require.NoError(t, err)
	_, err = sqlDb.ExecContext(ctx, "analyze")
	require.NoError(t, err)

	numItems, err = repo.EstimatedCount(ctx)
	require.NoError(t, err)
	assert.Equal(t, 2, numItems)

	// Delete oidc auth method
	_, err = oidcRepo.DeleteAuthMethod(ctx, am2.GetPublicId())
	require.NoError(t, err)
	_, err = sqlDb.ExecContext(ctx, "analyze")
	require.NoError(t, err)

	numItems, err = repo.EstimatedCount(ctx)
	require.NoError(t, err)
	assert.Equal(t, 1, numItems)

	// Delete pw auth method
	_, err = passwordRepo.DeleteAuthMethod(ctx, org.GetPublicId(), am3.GetPublicId())
	require.NoError(t, err)
	_, err = sqlDb.ExecContext(ctx, "analyze")
	require.NoError(t, err)

	numItems, err = repo.EstimatedCount(ctx)
	require.NoError(t, err)
	assert.Equal(t, 0, numItems)
}

func TestRepository_ListDeletedStoreIds(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	conn, _ := db.TestSetup(t, "postgres")
	rw := db.New(conn)
	wrapper := db.TestWrapper(t)
	testKms := kms.TestKms(t, conn, wrapper)
	org, _ := iam.TestScopes(t, iam.TestRepo(t, conn, wrapper))
	databaseWrapper, err := testKms.GetWrapper(context.Background(), org.PublicId, kms.KeyPurposeDatabase)
	require.NoError(t, err)

	ldapRepo, err := ldap.NewRepository(ctx, rw, rw, testKms)
	require.NoError(t, err)
	oidcRepo, err := oidc.NewRepository(ctx, rw, rw, testKms)
	require.NoError(t, err)
	passwordRepo, err := password.NewRepository(ctx, rw, rw, testKms)
	require.NoError(t, err)

	repo, err := auth.NewAuthMethodRepository(ctx, rw, rw, testKms)
	require.NoError(t, err)

	// Check total entries at start, expect 0
	numItems, err := repo.EstimatedCount(ctx)
	require.NoError(t, err)
	assert.Equal(t, 0, numItems)

	// Create auth methods
	am1 := ldap.TestAuthMethod(t, conn, databaseWrapper, org.PublicId, []string{"ldaps://ldap1.alice.com"}, ldap.WithOperationalState(ctx, ldap.InactiveState))
	am2 := oidc.TestAuthMethod(t, conn, databaseWrapper, org.PublicId, oidc.InactiveState, "alice_rp", "alices-dogs-name",
		oidc.WithIssuer(oidc.TestConvertToUrls(t, "https://alice-inactive.com")[0]), oidc.WithApiUrl(oidc.TestConvertToUrls(t, "https://api.com")[0]))
	am3 := password.TestAuthMethod(t, conn, org.GetPublicId())

	// Expect no entries at the start
	deletedIds, ttime, err := repo.ListDeletedIds(ctx, time.Now().AddDate(-1, 0, 0))
	require.NoError(t, err)
	require.Empty(t, deletedIds)
	// Transaction timestamp should be within ~10 seconds of now
	assert.True(t, time.Now().Before(ttime.Add(10*time.Second)))
	assert.True(t, time.Now().After(ttime.Add(-10*time.Second)))

	_, err = ldapRepo.DeleteAuthMethod(ctx, am1.GetPublicId())
	require.NoError(t, err)

	// Expect one entry
	deletedIds, ttime, err = repo.ListDeletedIds(ctx, time.Now().AddDate(-1, 0, 0))
	require.NoError(t, err)
	assert.Empty(
		t,
		cmp.Diff(
			[]string{am1.GetPublicId()},
			deletedIds,
			cmpopts.SortSlices(func(i, j string) bool { return i < j }),
		),
	)
	assert.True(t, time.Now().Before(ttime.Add(10*time.Second)))
	assert.True(t, time.Now().After(ttime.Add(-10*time.Second)))

	// Try again with the time set to now, expect no entries
	deletedIds, ttime, err = repo.ListDeletedIds(ctx, time.Now())
	require.NoError(t, err)
	require.Empty(t, deletedIds)
	assert.True(t, time.Now().Before(ttime.Add(10*time.Second)))
	assert.True(t, time.Now().After(ttime.Add(-10*time.Second)))

	_, err = oidcRepo.DeleteAuthMethod(ctx, am2.GetPublicId())
	require.NoError(t, err)
	_, err = passwordRepo.DeleteAuthMethod(ctx, org.GetPublicId(), am3.GetPublicId())
	require.NoError(t, err)

	// Expect three entries (with a buffer of -30 seconds, we'll pick up am1)
	deletedIds, ttime, err = repo.ListDeletedIds(ctx, time.Now().AddDate(-1, 0, 0))
	require.NoError(t, err)
	assert.Empty(
		t,
		cmp.Diff(
			[]string{am1.GetPublicId(), am2.GetPublicId(), am3.GetPublicId()},
			deletedIds,
			cmpopts.SortSlices(func(i, j string) bool { return i < j }),
		),
	)
	assert.True(t, time.Now().Before(ttime.Add(10*time.Second)))
	assert.True(t, time.Now().After(ttime.Add(-10*time.Second)))

	// Try again with the time set to now, expect no entries
	deletedIds, ttime, err = repo.ListDeletedIds(ctx, time.Now())
	require.NoError(t, err)
	require.Empty(t, deletedIds)
	assert.True(t, time.Now().Before(ttime.Add(10*time.Second)))
	assert.True(t, time.Now().After(ttime.Add(-10*time.Second)))
}
