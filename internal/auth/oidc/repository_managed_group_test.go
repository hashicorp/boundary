// Copyright IBM Corp. 2020, 2025
// SPDX-License-Identifier: BUSL-1.1

package oidc

import (
	"context"
	"fmt"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	"github.com/hashicorp/boundary/globals"
	"github.com/hashicorp/boundary/internal/auth/oidc/store"
	"github.com/hashicorp/boundary/internal/db"
	dbassert "github.com/hashicorp/boundary/internal/db/assert"
	"github.com/hashicorp/boundary/internal/db/timestamp"
	"github.com/hashicorp/boundary/internal/errors"
	"github.com/hashicorp/boundary/internal/iam"
	"github.com/hashicorp/boundary/internal/kms"
	"github.com/hashicorp/boundary/internal/oplog"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/types/known/timestamppb"
)

func TestRepository_CreateManagedGroup(t *testing.T) {
	conn, _ := db.TestSetup(t, "postgres")
	rw := db.New(conn)
	wrapper := db.TestWrapper(t)

	kmsCache := kms.TestKms(t, conn, wrapper)
	iamRepo := iam.TestRepo(t, conn, wrapper)
	org, _ := iam.TestScopes(t, iamRepo)

	ctx := context.Background()
	databaseWrapper, err := kmsCache.GetWrapper(ctx, org.PublicId, kms.KeyPurposeDatabase)
	require.NoError(t, err)

	authMethod := TestAuthMethod(
		t, conn, databaseWrapper, org.GetPublicId(), ActivePrivateState,
		"alice-rp", "fido",
		WithSigningAlgs(RS256),
		WithIssuer(TestConvertToUrls(t, "https://www.alice.com")[0]),
		WithApiUrl(TestConvertToUrls(t, "https://www.alice.com/callback")[0]),
	)

	tests := []struct {
		name            string
		scopeId         string
		in              *ManagedGroup
		opts            []Option
		want            *ManagedGroup
		wantIsErr       errors.Code
		wantErrMsg      string
		wantErrContains string
	}{
		{
			name:       "nil-ManagedGroup",
			scopeId:    org.GetPublicId(),
			wantIsErr:  errors.InvalidParameter,
			wantErrMsg: "oidc.(Repository).CreateManagedGroup: missing ManagedGroup: parameter violation: error #100",
		},
		{
			name:       "nil-embedded-ManagedGroup",
			scopeId:    org.GetPublicId(),
			in:         &ManagedGroup{},
			wantIsErr:  errors.InvalidParameter,
			wantErrMsg: "oidc.(Repository).CreateManagedGroup: missing embedded ManagedGroup: parameter violation: error #100",
		},
		{
			name:    "invalid-no-auth-method-id",
			scopeId: org.GetPublicId(),
			in: &ManagedGroup{
				ManagedGroup: &store.ManagedGroup{},
			},
			wantIsErr:  errors.InvalidParameter,
			wantErrMsg: "oidc.(Repository).CreateManagedGroup: missing auth method id: parameter violation: error #100",
		},
		{
			name:    "invalid-no-filter",
			scopeId: org.GetPublicId(),
			in: &ManagedGroup{
				ManagedGroup: &store.ManagedGroup{
					AuthMethodId: authMethod.PublicId,
				},
			},
			wantIsErr:  errors.InvalidParameter,
			wantErrMsg: "oidc.(Repository).CreateManagedGroup: missing filter: parameter violation: error #100",
		},
		{
			name:    "invalid-public-id-set",
			scopeId: org.GetPublicId(),
			in: &ManagedGroup{
				ManagedGroup: &store.ManagedGroup{
					AuthMethodId: authMethod.PublicId,
					Filter:       TestFakeManagedGroupFilter,
					PublicId:     "mgoidc_OOOOOOOOOO",
				},
			},
			wantIsErr:  errors.InvalidParameter,
			wantErrMsg: "oidc.(Repository).CreateManagedGroup: public id must be empty: parameter violation: error #100",
		},
		{
			name: "no-scope",
			in: &ManagedGroup{
				ManagedGroup: &store.ManagedGroup{
					AuthMethodId: authMethod.PublicId,
					Filter:       TestFakeManagedGroupFilter,
				},
			},
			wantIsErr:  errors.InvalidParameter,
			wantErrMsg: "oidc.(Repository).CreateManagedGroup: missing scope id: parameter violation: error #100",
		},
		{
			name:    "valid-no-options",
			scopeId: org.GetPublicId(),
			in: &ManagedGroup{
				ManagedGroup: &store.ManagedGroup{
					AuthMethodId: authMethod.PublicId,
					Filter:       TestFakeManagedGroupFilter,
				},
			},
			want: &ManagedGroup{
				ManagedGroup: &store.ManagedGroup{
					AuthMethodId: authMethod.PublicId,
					Filter:       TestFakeManagedGroupFilter,
				},
			},
		},
		{
			name:    "valid-with-name",
			scopeId: org.GetPublicId(),
			in: &ManagedGroup{
				ManagedGroup: &store.ManagedGroup{
					AuthMethodId: authMethod.PublicId,
					Filter:       TestFakeManagedGroupFilter,
					Name:         "test-name-repo",
				},
			},
			want: &ManagedGroup{
				ManagedGroup: &store.ManagedGroup{
					AuthMethodId: authMethod.PublicId,
					Filter:       TestFakeManagedGroupFilter,
					Name:         "test-name-repo",
				},
			},
		},
		{
			name:    "valid-with-description",
			scopeId: org.GetPublicId(),
			in: &ManagedGroup{
				ManagedGroup: &store.ManagedGroup{
					AuthMethodId: authMethod.PublicId,
					Filter:       TestFakeManagedGroupFilter,
					Description:  ("test-description-repo"),
					Name:         "myname",
				},
			},
			want: &ManagedGroup{
				ManagedGroup: &store.ManagedGroup{
					AuthMethodId: authMethod.PublicId,
					Filter:       TestFakeManagedGroupFilter,
					Description:  ("test-description-repo"),
					Name:         "myname",
				},
			},
		},
		{
			name:    "duplicate-name",
			scopeId: org.GetPublicId(),
			in: &ManagedGroup{
				ManagedGroup: &store.ManagedGroup{
					AuthMethodId: authMethod.PublicId,
					Filter:       TestFakeManagedGroupFilter,
					Description:  ("test-description-repo"),
					Name:         "myname",
				},
			},
			wantIsErr:       errors.NotUnique,
			wantErrContains: `name "myname" already exists`,
		},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			assert, require := assert.New(t), require.New(t)
			repo, err := NewRepository(ctx, rw, rw, kmsCache)
			assert.NoError(err)
			require.NotNil(repo)
			got, err := repo.CreateManagedGroup(context.Background(), tt.scopeId, tt.in, tt.opts...)
			if tt.wantIsErr != 0 {
				require.Error(err)
				assert.Truef(errors.Match(errors.T(tt.wantIsErr), err), "Unexpected error %s", err)
				if tt.wantErrContains != "" {
					assert.True(strings.Contains(err.Error(), tt.wantErrContains))
				} else {
					assert.Equal(tt.wantErrMsg, err.Error())
				}
				return
			}
			require.NoError(err)
			assert.Empty(tt.in.PublicId)
			require.NotNil(got)
			assertPublicId(t, globals.OidcManagedGroupPrefix, got.PublicId)
			assert.NotSame(tt.in, got)
			assert.Equal(tt.want.Name, got.Name)
			assert.Equal(tt.want.Description, got.Description)
			assert.Equal(got.CreateTime, got.UpdateTime)

			assert.NoError(db.TestVerifyOplog(t, rw, got.PublicId, db.WithOperation(oplog.OpType_OP_TYPE_CREATE), db.WithCreateNotBefore(10*time.Second)))
		})
	}
}

func TestRepository_LookupManagedGroup(t *testing.T) {
	conn, _ := db.TestSetup(t, "postgres")
	rw := db.New(conn)
	wrapper := db.TestWrapper(t)

	kmsCache := kms.TestKms(t, conn, wrapper)
	iamRepo := iam.TestRepo(t, conn, wrapper)
	org, _ := iam.TestScopes(t, iamRepo)

	ctx := context.Background()
	databaseWrapper, err := kmsCache.GetWrapper(ctx, org.PublicId, kms.KeyPurposeDatabase)
	require.NoError(t, err)

	authMethod := TestAuthMethod(
		t, conn, databaseWrapper, org.PublicId, ActivePrivateState,
		"alice-rp", "fido",
		WithSigningAlgs(RS256),
		WithIssuer(TestConvertToUrls(t, "https://www.alice.com")[0]),
		WithApiUrl(TestConvertToUrls(t, "https://www.alice.com/callback")[0]),
	)
	mg := TestManagedGroup(t, conn, authMethod, TestFakeManagedGroupFilter)

	newMgId, err := newManagedGroupId(ctx)
	require.NoError(t, err)
	tests := []struct {
		name       string
		in         string
		want       *ManagedGroup
		wantIsErr  errors.Code
		wantErrMsg string
	}{
		{
			name:       "With no public id",
			wantIsErr:  errors.InvalidPublicId,
			wantErrMsg: "oidc.(Repository).LookupManagedGroup: missing public id: parameter violation: error #102",
		},
		{
			name: "With non existing mg id",
			in:   newMgId,
		},
		{
			name: "With existing mg id",
			in:   mg.GetPublicId(),
			want: mg,
		},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			assert, require := assert.New(t), require.New(t)
			repo, err := NewRepository(ctx, rw, rw, kmsCache)
			assert.NoError(err)
			require.NotNil(repo)
			got, err := repo.LookupManagedGroup(context.Background(), tt.in)
			if tt.wantIsErr != 0 {
				assert.Truef(errors.Match(errors.T(tt.wantIsErr), err), "Unexpected error %s", err)
				assert.Equal(tt.wantErrMsg, err.Error())
				return
			}
			require.NoError(err)
			assert.EqualValues(tt.want, got)
		})
	}
}

func TestRepository_DeleteManagedGroup(t *testing.T) {
	conn, _ := db.TestSetup(t, "postgres")
	rw := db.New(conn)
	wrapper := db.TestWrapper(t)

	ctx := context.Background()
	kmsCache := kms.TestKms(t, conn, wrapper)
	iamRepo := iam.TestRepo(t, conn, wrapper)
	org, _ := iam.TestScopes(t, iamRepo)

	databaseWrapper, err := kmsCache.GetWrapper(ctx, org.PublicId, kms.KeyPurposeDatabase)
	require.NoError(t, err)
	authMethod := TestAuthMethod(
		t, conn, databaseWrapper, org.PublicId, ActivePrivateState,
		"alice-rp", "fido",
		WithSigningAlgs(RS256),
		WithIssuer(TestConvertToUrls(t, "https://www.alice.com")[0]),
		WithApiUrl(TestConvertToUrls(t, "https://www.alice.com/callback")[0]),
	)
	mg := TestManagedGroup(t, conn, authMethod, TestFakeManagedGroupFilter)
	newMgId, err := newManagedGroupId(ctx)
	require.NoError(t, err)
	tests := []struct {
		name       string
		scopeId    string
		in         string
		want       int
		wantIsErr  errors.Code
		wantErrMsg string
	}{
		{
			name:       "With no scope id",
			scopeId:    "",
			in:         mg.GetPublicId(),
			wantIsErr:  errors.InvalidParameter,
			wantErrMsg: "oidc.(Repository).DeleteManagedGroup: missing scope id: parameter violation: error #100",
		},
		{
			name:       "With no public id",
			scopeId:    org.GetPublicId(),
			wantIsErr:  errors.InvalidPublicId,
			wantErrMsg: "oidc.(Repository).DeleteManagedGroup: missing public id: parameter violation: error #102",
		},
		{
			name:    "With non existing managed group id",
			scopeId: org.GetPublicId(),
			in:      newMgId,
			want:    0,
		},
		{
			name:    "With existing managed group id",
			scopeId: org.GetPublicId(),
			in:      mg.GetPublicId(),
			want:    1,
		},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			assert, require := assert.New(t), require.New(t)
			repo, err := NewRepository(ctx, rw, rw, kmsCache)
			assert.NoError(err)
			require.NotNil(repo)
			got, err := repo.DeleteManagedGroup(context.Background(), tt.scopeId, tt.in)
			if tt.wantIsErr != 0 {
				assert.Truef(errors.Match(errors.T(tt.wantIsErr), err), "Unexpected error %s", err)
				assert.Equal(tt.wantErrMsg, err.Error())
				return
			}
			require.NoError(err)
			assert.EqualValues(tt.want, got)
		})
	}
}

func TestRepository_ListManagedGroups(t *testing.T) {
	oldReadTimeout := globals.RefreshReadLookbackDuration
	globals.RefreshReadLookbackDuration = 0
	t.Cleanup(func() {
		globals.RefreshReadLookbackDuration = oldReadTimeout
	})

	conn, _ := db.TestSetup(t, "postgres")
	rw := db.New(conn)
	wrapper := db.TestWrapper(t)

	ctx := context.Background()
	kmsCache := kms.TestKms(t, conn, wrapper)
	iamRepo := iam.TestRepo(t, conn, wrapper)
	org, _ := iam.TestScopes(t, iamRepo)

	databaseWrapper, err := kmsCache.GetWrapper(ctx, org.PublicId, kms.KeyPurposeDatabase)
	require.NoError(t, err)

	repo, err := NewRepository(ctx, rw, rw, kmsCache)
	assert.NoError(t, err)
	require.NotNil(t, repo)

	authMethod1 := TestAuthMethod(
		t, conn, databaseWrapper, org.PublicId, ActivePrivateState,
		"alice-rp", "fido",
		WithSigningAlgs(RS256),
		WithIssuer(TestConvertToUrls(t, "https://www.alice1.com")[0]),
		WithApiUrl(TestConvertToUrls(t, "https://www.alice.com/callback")[0]),
	)
	authMethod2 := TestAuthMethod(
		t, conn, databaseWrapper, org.PublicId, ActivePrivateState,
		"alice-rp", "fido",
		WithSigningAlgs(RS256),
		WithIssuer(TestConvertToUrls(t, "https://www.alice2.com")[0]),
		WithApiUrl(TestConvertToUrls(t, "https://www.alice.com/callback")[0]),
	)
	authMethod3 := TestAuthMethod(
		t, conn, databaseWrapper, org.PublicId, ActivePrivateState,
		"alice-rp", "fido",
		WithSigningAlgs(RS256),
		WithIssuer(TestConvertToUrls(t, "https://www.alice3.com")[0]),
		WithApiUrl(TestConvertToUrls(t, "https://www.alice.com/callback")[0]),
	)
	mgs1 := []*ManagedGroup{
		TestManagedGroup(t, conn, authMethod1, TestFakeManagedGroupFilter),
		TestManagedGroup(t, conn, authMethod1, TestFakeManagedGroupFilter),
		TestManagedGroup(t, conn, authMethod1, TestFakeManagedGroupFilter),
	}

	mgs2 := []*ManagedGroup{
		TestManagedGroup(t, conn, authMethod2, TestFakeManagedGroupFilter),
		TestManagedGroup(t, conn, authMethod2, TestFakeManagedGroupFilter),
		TestManagedGroup(t, conn, authMethod2, TestFakeManagedGroupFilter),
	}

	slices.Reverse(mgs1)
	slices.Reverse(mgs2)

	cmpOpts := []cmp.Option{
		cmpopts.IgnoreUnexported(
			ManagedGroup{},
			store.ManagedGroup{},
			timestamp.Timestamp{},
			timestamppb.Timestamp{},
		),
	}

	tests := []struct {
		name       string
		in         string
		opts       []Option
		want       []*ManagedGroup
		wantIsErr  errors.Code
		wantErrMsg string
	}{
		{
			name:       "With no auth method id",
			wantIsErr:  errors.InvalidParameter,
			wantErrMsg: "oidc.(Repository).ListManagedGroups: missing auth method id: parameter violation: error #100",
		},
		{
			name: "With no managed groups",
			in:   authMethod3.GetPublicId(),
			want: []*ManagedGroup{},
		},
		{
			name: "With first auth method id",
			in:   authMethod1.GetPublicId(),
			want: mgs1,
		},
		{
			name: "With first auth method id",
			in:   authMethod2.GetPublicId(),
			want: mgs2,
		},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			got, ttime, err := repo.ListManagedGroups(context.Background(), tt.in, tt.opts...)
			if tt.wantIsErr != 0 {
				assert.Truef(t, errors.Match(errors.T(tt.wantIsErr), err), "Unexpected error %s", err)
				assert.Equal(t, tt.wantErrMsg, err.Error())
				return
			}
			require.NoError(t, err)
			// Transaction timestamp should be within ~10 seconds of now
			assert.True(t, time.Now().Before(ttime.Add(10*time.Second)))
			assert.True(t, time.Now().After(ttime.Add(-10*time.Second)))

			assert.EqualValues(t, tt.want, got)
		})
	}

	t.Run("validation", func(t *testing.T) {
		t.Parallel()
		t.Run("missing auth method id", func(t *testing.T) {
			t.Parallel()
			_, _, err := repo.ListManagedGroups(ctx, "", WithLimit(1))
			require.ErrorContains(t, err, "missing auth method id")
		})
	})

	t.Run("success-without-after-item", func(t *testing.T) {
		t.Parallel()
		resp, ttime, err := repo.ListManagedGroups(ctx, authMethod1.PublicId, WithLimit(10))
		require.NoError(t, err)
		// Transaction timestamp should be within ~10 seconds of now
		assert.True(t, time.Now().Before(ttime.Add(10*time.Second)))
		assert.True(t, time.Now().After(ttime.Add(-10*time.Second)))
		require.Empty(t, cmp.Diff(resp, mgs1, cmpOpts...))
	})
	t.Run("success-with-after-item", func(t *testing.T) {
		t.Parallel()
		resp, ttime, err := repo.ListManagedGroups(ctx, authMethod1.PublicId, WithStartPageAfterItem(mgs1[0]), WithLimit(10))
		require.NoError(t, err)
		// Transaction timestamp should be within ~10 seconds of now
		assert.True(t, time.Now().Before(ttime.Add(10*time.Second)))
		assert.True(t, time.Now().After(ttime.Add(-10*time.Second)))
		require.Empty(t, cmp.Diff(resp, mgs1[1:], cmpOpts...))
	})
}

func TestRepository_ListManagedGroups_Limits(t *testing.T) {
	conn, _ := db.TestSetup(t, "postgres")
	rw := db.New(conn)
	wrapper := db.TestWrapper(t)

	ctx := context.Background()
	kmsCache := kms.TestKms(t, conn, wrapper)
	iamRepo := iam.TestRepo(t, conn, wrapper)
	org, _ := iam.TestScopes(t, iamRepo)

	databaseWrapper, err := kmsCache.GetWrapper(ctx, org.PublicId, kms.KeyPurposeDatabase)
	require.NoError(t, err)

	am := TestAuthMethod(
		t, conn, databaseWrapper, org.PublicId, ActivePrivateState,
		"alice-rp", "fido",
		WithSigningAlgs(RS256),
		WithIssuer(TestConvertToUrls(t, "https://www.alice1.com")[0]),
		WithApiUrl(TestConvertToUrls(t, "https://www.alice.com/callback")[0]),
	)

	mgCount := 10
	for i := 0; i < mgCount; i++ {
		TestManagedGroup(t, conn, am, fmt.Sprintf(`"/foo/%d" == "bar"`, i))
	}

	tests := []struct {
		name     string
		repoOpts []Option
		listOpts []Option
		wantLen  int
	}{
		{
			name:    "With no limits",
			wantLen: mgCount,
		},
		{
			name:     "With repo limit",
			repoOpts: []Option{WithLimit(3)},
			wantLen:  3,
		},
		{
			name:     "With negative repo limit",
			repoOpts: []Option{WithLimit(-1)},
			wantLen:  mgCount,
		},
		{
			name:     "With List limit",
			listOpts: []Option{WithLimit(3)},
			wantLen:  3,
		},
		{
			name:     "With negative List limit",
			listOpts: []Option{WithLimit(-1)},
			wantLen:  mgCount,
		},
		{
			name:     "With repo smaller than list limit",
			repoOpts: []Option{WithLimit(2)},
			listOpts: []Option{WithLimit(6)},
			wantLen:  6,
		},
		{
			name:     "With repo larger than list limit",
			repoOpts: []Option{WithLimit(6)},
			listOpts: []Option{WithLimit(2)},
			wantLen:  2,
		},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			assert, require := assert.New(t), require.New(t)
			repo, err := NewRepository(ctx, rw, rw, kmsCache, tt.repoOpts...)
			assert.NoError(err)
			require.NotNil(repo)
			got, ttime, err := repo.ListManagedGroups(context.Background(), am.GetPublicId(), tt.listOpts...)
			require.NoError(err)
			// Transaction timestamp should be within ~10 seconds of now
			assert.True(time.Now().Before(ttime.Add(10 * time.Second)))
			assert.True(time.Now().After(ttime.Add(-10 * time.Second)))
			assert.Len(got, tt.wantLen)
		})
	}
}

func TestRepository_ListManagedGroupsRefresh(t *testing.T) {
	oldReadTimeout := globals.RefreshReadLookbackDuration
	globals.RefreshReadLookbackDuration = 0
	t.Cleanup(func() {
		globals.RefreshReadLookbackDuration = oldReadTimeout
	})
	conn, _ := db.TestSetup(t, "postgres")
	rw := db.New(conn)
	wrapper := db.TestWrapper(t)

	ctx := context.Background()
	kmsCache := kms.TestKms(t, conn, wrapper)
	iamRepo := iam.TestRepo(t, conn, wrapper)
	org, _ := iam.TestScopes(t, iamRepo)

	databaseWrapper, err := kmsCache.GetWrapper(ctx, org.PublicId, kms.KeyPurposeDatabase)
	require.NoError(t, err)

	authMethod1 := TestAuthMethod(
		t, conn, databaseWrapper, org.PublicId, ActivePrivateState,
		"alice-rp", "fido",
		WithSigningAlgs(RS256),
		WithIssuer(TestConvertToUrls(t, "https://www.alice1.com")[0]),
		WithApiUrl(TestConvertToUrls(t, "https://www.alice.com/callback")[0]),
	)
	authMethod2 := TestAuthMethod(
		t, conn, databaseWrapper, org.PublicId, ActivePrivateState,
		"alice-rp", "fido",
		WithSigningAlgs(RS256),
		WithIssuer(TestConvertToUrls(t, "https://www.alice2.com")[0]),
		WithApiUrl(TestConvertToUrls(t, "https://www.alice.com/callback")[0]),
	)

	mgs1 := []*ManagedGroup{
		TestManagedGroup(t, conn, authMethod1, TestFakeManagedGroupFilter),
		TestManagedGroup(t, conn, authMethod1, TestFakeManagedGroupFilter),
		TestManagedGroup(t, conn, authMethod1, TestFakeManagedGroupFilter),
	}

	mgs2 := []*ManagedGroup{
		TestManagedGroup(t, conn, authMethod2, TestFakeManagedGroupFilter),
		TestManagedGroup(t, conn, authMethod2, TestFakeManagedGroupFilter),
		TestManagedGroup(t, conn, authMethod2, TestFakeManagedGroupFilter),
	}

	slices.Reverse(mgs1)
	slices.Reverse(mgs2)

	fiveDaysAgo := time.Now().AddDate(0, 0, -5)

	cmpOpts := []cmp.Option{
		cmpopts.IgnoreUnexported(
			ManagedGroup{},
			store.ManagedGroup{},
			timestamp.Timestamp{},
			timestamppb.Timestamp{},
		),
		cmpopts.SortSlices(func(i, j string) bool { return i < j }),
	}

	repo, err := NewRepository(ctx, rw, rw, kmsCache)
	require.NotNil(t, repo)
	assert.NoError(t, err)

	t.Run("validation", func(t *testing.T) {
		t.Parallel()
		t.Run("missing updated after", func(t *testing.T) {
			t.Parallel()
			_, _, err := repo.ListManagedGroupsRefresh(ctx, authMethod1.PublicId, time.Time{}, WithLimit(1))
			require.ErrorContains(t, err, "missing updated after time")
		})
		t.Run("missing auth method id", func(t *testing.T) {
			t.Parallel()
			_, _, err := repo.ListManagedGroupsRefresh(ctx, "", fiveDaysAgo, WithLimit(1))
			require.ErrorContains(t, err, "missing auth method id")
		})
	})

	t.Run("success-without-after-item", func(t *testing.T) {
		t.Parallel()
		resp, ttime, err := repo.ListManagedGroupsRefresh(ctx, authMethod1.PublicId, fiveDaysAgo, WithLimit(10))
		require.NoError(t, err)
		// Transaction timestamp should be within ~10 seconds of now
		assert.True(t, time.Now().Before(ttime.Add(10*time.Second)))
		assert.True(t, time.Now().After(ttime.Add(-10*time.Second)))
		require.Empty(t, cmp.Diff(resp, mgs1, cmpOpts...))
	})
	t.Run("success-with-after-item", func(t *testing.T) {
		t.Parallel()
		resp, ttime, err := repo.ListManagedGroupsRefresh(ctx, authMethod1.PublicId, fiveDaysAgo, WithStartPageAfterItem(mgs1[0]), WithLimit(10))
		require.NoError(t, err)
		// Transaction timestamp should be within ~10 seconds of now
		assert.True(t, time.Now().Before(ttime.Add(10*time.Second)))
		assert.True(t, time.Now().After(ttime.Add(-10*time.Second)))
		require.Empty(t, cmp.Diff(resp, mgs1[1:], cmpOpts...))
	})
	t.Run("success-without-after-item-recent-updated-after", func(t *testing.T) {
		t.Parallel()
		resp, ttime, err := repo.ListManagedGroupsRefresh(ctx, authMethod1.PublicId, mgs1[len(mgs1)-1].GetUpdateTime().AsTime(), WithLimit(10))
		require.NoError(t, err)
		// Transaction timestamp should be within ~10 seconds of now
		assert.True(t, time.Now().Before(ttime.Add(10*time.Second)))
		assert.True(t, time.Now().After(ttime.Add(-10*time.Second)))
		require.Empty(t, cmp.Diff(resp, mgs1[:len(mgs1)-1], cmpOpts...))
	})
	t.Run("success-with-after-item-recent-updated-after", func(t *testing.T) {
		t.Parallel()
		resp, ttime, err := repo.ListManagedGroupsRefresh(ctx, authMethod1.PublicId, mgs1[len(mgs1)-1].GetUpdateTime().AsTime(), WithStartPageAfterItem(mgs1[0]), WithLimit(10))
		require.NoError(t, err)
		// Transaction timestamp should be within ~10 seconds of now
		assert.True(t, time.Now().Before(ttime.Add(10*time.Second)))
		assert.True(t, time.Now().After(ttime.Add(-10*time.Second)))
		require.Empty(t, cmp.Diff(resp, mgs1[1:len(mgs1)-1], cmpOpts...))
	})
}

func TestRepository_UpdateManagedGroup(t *testing.T) {
	ctx := context.Background()
	conn, _ := db.TestSetup(t, "postgres")
	rw := db.New(conn)
	wrapper := db.TestWrapper(t)
	kmsCache := kms.TestKms(t, conn, wrapper)
	iamRepo := iam.TestRepo(t, conn, wrapper)
	org, _ := iam.TestScopes(t, iamRepo)

	databaseWrapper, err := kmsCache.GetWrapper(ctx, org.PublicId, kms.KeyPurposeDatabase)
	require.NoError(t, err)
	am := TestAuthMethod(
		t, conn, databaseWrapper, org.PublicId, ActivePrivateState,
		"alice-rp", "fido",
		WithSigningAlgs(RS256),
		WithIssuer(TestConvertToUrls(t, "https://www.alice.com")[0]),
		WithApiUrl(TestConvertToUrls(t, "https://www.alice.com/callback")[0]),
	)

	changeName := func(s string) func(*ManagedGroup) *ManagedGroup {
		return func(mg *ManagedGroup) *ManagedGroup {
			mg.Name = s
			return mg
		}
	}

	changeDescription := func(s string) func(*ManagedGroup) *ManagedGroup {
		return func(mg *ManagedGroup) *ManagedGroup {
			mg.Description = s
			return mg
		}
	}

	changeFilter := func(s string) func(*ManagedGroup) *ManagedGroup {
		return func(mg *ManagedGroup) *ManagedGroup {
			mg.Filter = s
			return mg
		}
	}

	makeNil := func() func(*ManagedGroup) *ManagedGroup {
		return func(mg *ManagedGroup) *ManagedGroup {
			return nil
		}
	}

	makeEmbeddedNil := func() func(*ManagedGroup) *ManagedGroup {
		return func(mg *ManagedGroup) *ManagedGroup {
			return &ManagedGroup{}
		}
	}

	deletePublicId := func() func(*ManagedGroup) *ManagedGroup {
		return func(mg *ManagedGroup) *ManagedGroup {
			mg.PublicId = ""
			return mg
		}
	}

	nonExistentPublicId := func() func(*ManagedGroup) *ManagedGroup {
		return func(mg *ManagedGroup) *ManagedGroup {
			mg.PublicId = "abcd_OOOOOOOOOO"
			return mg
		}
	}

	combine := func(fns ...func(mg *ManagedGroup) *ManagedGroup) func(*ManagedGroup) *ManagedGroup {
		return func(mg *ManagedGroup) *ManagedGroup {
			for _, fn := range fns {
				mg = fn(mg)
			}
			return mg
		}
	}

	tests := []struct {
		name            string
		scopeId         string
		version         uint32
		orig            *ManagedGroup
		chgFn           func(*ManagedGroup) *ManagedGroup
		masks           []string
		want            *ManagedGroup
		wantCount       int
		wantIsErr       errors.Code
		wantErrMsg      string
		wantErrContains string
	}{
		{
			name:    "nil-ManagedGroup",
			scopeId: org.GetPublicId(),
			version: 1,
			orig: &ManagedGroup{
				ManagedGroup: &store.ManagedGroup{},
			},
			chgFn:      makeNil(),
			masks:      []string{NameField, DescriptionField},
			wantIsErr:  errors.InvalidParameter,
			wantErrMsg: "oidc.(Repository).UpdateManagedGroup: missing ManagedGroup: parameter violation: error #100",
		},
		{
			name:    "nil-embedded-ManagedGroup",
			scopeId: org.GetPublicId(),
			version: 1,
			orig: &ManagedGroup{
				ManagedGroup: &store.ManagedGroup{},
			},
			chgFn:      makeEmbeddedNil(),
			masks:      []string{NameField, DescriptionField},
			wantIsErr:  errors.InvalidParameter,
			wantErrMsg: "oidc.(Repository).UpdateManagedGroup: missing embedded ManagedGroup: parameter violation: error #100",
		},
		{
			name:    "no-scope-id",
			version: 1,
			orig: &ManagedGroup{
				ManagedGroup: &store.ManagedGroup{
					Name: "no-scope-id-test-name-repo",
				},
			},
			chgFn:      changeName("no-scope-id-test-update-name-repo"),
			masks:      []string{NameField},
			wantIsErr:  errors.InvalidParameter,
			wantErrMsg: "oidc.(Repository).UpdateManagedGroup: missing scope id: parameter violation: error #100",
		},
		{
			name:    "missing-version",
			scopeId: org.GetPublicId(),
			orig: &ManagedGroup{
				ManagedGroup: &store.ManagedGroup{
					Name: "missing-version-test-name-repo",
				},
			},
			chgFn:      changeName("test-update-name-repo"),
			masks:      []string{NameField},
			wantIsErr:  errors.InvalidParameter,
			wantErrMsg: "oidc.(Repository).UpdateManagedGroup: missing version: parameter violation: error #100",
		},
		{
			name:    "no-public-id",
			scopeId: org.GetPublicId(),
			version: 1,
			orig: &ManagedGroup{
				ManagedGroup: &store.ManagedGroup{},
			},
			chgFn:      deletePublicId(),
			masks:      []string{NameField, DescriptionField},
			wantIsErr:  errors.InvalidPublicId,
			wantErrMsg: "oidc.(Repository).UpdateManagedGroup: missing public id: parameter violation: error #102",
		},
		{
			name:    "updating-non-existent-ManagedGroup",
			scopeId: org.GetPublicId(),
			version: 1,
			orig: &ManagedGroup{
				ManagedGroup: &store.ManagedGroup{
					Name: "updating-non-existent-ManagedGroup-test-name-repo",
				},
			},
			chgFn:      combine(nonExistentPublicId(), changeName("updating-non-existent-ManagedGroup-test-update-name-repo")),
			masks:      []string{NameField},
			wantIsErr:  errors.RecordNotFound,
			wantErrMsg: "oidc.(Repository).UpdateManagedGroup: abcd_OOOOOOOOOO: db.DoTx: oidc.(Repository).UpdateManagedGroup: db.Update: record not found, search issue: error #1100: dbw.Update: dbw.lookupAfterWrite: dbw.LookupById: record not found",
		},
		{
			name:    "empty-field-mask",
			scopeId: org.GetPublicId(),
			version: 1,
			orig: &ManagedGroup{
				ManagedGroup: &store.ManagedGroup{
					Name: "empty-field-mask-test-name-repo",
				},
			},
			chgFn:      changeName("empty-field-mask-test-update-name-repo"),
			wantIsErr:  errors.EmptyFieldMask,
			wantErrMsg: "oidc.(Repository).UpdateManagedGroup: missing field mask: parameter violation: error #104",
		},
		{
			name:    "read-only-fields-in-field-mask",
			scopeId: org.GetPublicId(),
			version: 1,
			orig: &ManagedGroup{
				ManagedGroup: &store.ManagedGroup{
					Name: "read-only-fields-in-field-mask-test-name-repo",
				},
			},
			chgFn:      changeName("read-only-fields-in-field-mask-test-update-name-repo"),
			masks:      []string{"PublicId", "CreateTime", "UpdateTime", "AuthMethodId"},
			wantIsErr:  errors.InvalidFieldMask,
			wantErrMsg: "oidc.(Repository).UpdateManagedGroup: PublicId: parameter violation: error #103",
		},
		{
			name:    "unknown-field-in-field-mask",
			scopeId: org.GetPublicId(),
			version: 1,
			orig: &ManagedGroup{
				ManagedGroup: &store.ManagedGroup{
					Name: "unknown-field-in-field-mask-test-name-repo",
				},
			},
			chgFn:      changeName("unknown-field-in-field-mask-test-update-name-repo"),
			masks:      []string{"Bilbo"},
			wantIsErr:  errors.InvalidFieldMask,
			wantErrMsg: "oidc.(Repository).UpdateManagedGroup: Bilbo: parameter violation: error #103",
		},
		{
			name:    "change-name",
			scopeId: org.GetPublicId(),
			version: 1,
			orig: &ManagedGroup{
				ManagedGroup: &store.ManagedGroup{
					Name: "change-name-test-name-repo",
				},
			},
			chgFn: changeName("change-name-test-update-name-repo"),
			masks: []string{NameField},
			want: &ManagedGroup{
				ManagedGroup: &store.ManagedGroup{
					Name: "change-name-test-update-name-repo",
				},
			},
			wantCount: 1,
		},
		{
			name:    "change-description",
			scopeId: org.GetPublicId(),
			version: 1,
			orig: &ManagedGroup{
				ManagedGroup: &store.ManagedGroup{
					Description: "test-description-repo",
				},
			},
			chgFn: changeDescription("test-update-description-repo"),
			masks: []string{DescriptionField},
			want: &ManagedGroup{
				ManagedGroup: &store.ManagedGroup{
					Description: "test-update-description-repo",
				},
			},
			wantCount: 1,
		},
		{
			name:    "change-filter",
			scopeId: org.GetPublicId(),
			version: 1,
			orig: &ManagedGroup{
				ManagedGroup: &store.ManagedGroup{
					Filter: TestFakeManagedGroupFilter,
				},
			},
			chgFn: changeFilter(`"/zip" == "zap"`),
			masks: []string{FilterField},
			want: &ManagedGroup{
				ManagedGroup: &store.ManagedGroup{
					Filter: `"/zip" == "zap"`,
				},
			},
			wantCount: 1,
		},
		{
			name:    "change-name-and-description",
			scopeId: org.GetPublicId(),
			version: 1,
			orig: &ManagedGroup{
				ManagedGroup: &store.ManagedGroup{
					Name:        "change-name-and-description-test-name-repo",
					Description: "test-description-repo",
				},
			},
			chgFn: combine(changeDescription("test-update-description-repo"), changeName("change-name-and-description-test-update-name-repo")),
			masks: []string{NameField, DescriptionField},
			want: &ManagedGroup{
				ManagedGroup: &store.ManagedGroup{
					Name:        "change-name-and-description-test-update-name-repo",
					Description: "test-update-description-repo",
				},
			},
			wantCount: 1,
		},
		{
			name:    "delete-name",
			scopeId: org.GetPublicId(),
			version: 1,
			orig: &ManagedGroup{
				ManagedGroup: &store.ManagedGroup{
					Name:        "delete-name-test-name-repo",
					Description: "test-description-repo",
				},
			},
			masks: []string{NameField},
			chgFn: combine(changeDescription("test-update-description-repo"), changeName("")),
			want: &ManagedGroup{
				ManagedGroup: &store.ManagedGroup{
					Description: "test-description-repo",
				},
			},
			wantCount: 1,
		},
		{
			name:    "delete-description",
			scopeId: org.GetPublicId(),
			version: 1,
			orig: &ManagedGroup{
				ManagedGroup: &store.ManagedGroup{
					Name:        "delete-description-test-name-repo",
					Description: "test-description-repo",
				},
			},
			masks: []string{DescriptionField},
			chgFn: combine(changeDescription(""), changeName("test-update-name-repo")),
			want: &ManagedGroup{
				ManagedGroup: &store.ManagedGroup{
					Name: "delete-description-test-name-repo",
				},
			},
			wantCount: 1,
		},
		{
			name:    "delete-filter",
			scopeId: org.GetPublicId(),
			version: 1,
			orig: &ManagedGroup{
				ManagedGroup: &store.ManagedGroup{
					Filter: TestFakeManagedGroupFilter,
				},
			},
			masks:           []string{FilterField},
			chgFn:           combine(changeFilter("")),
			wantIsErr:       errors.NotNull,
			wantErrContains: "oidc.(Repository).UpdateManagedGroup: db.Update: filter must not be empty: not null constraint violated: integrity violation: error #1001",
		},
		{
			name:    "do-not-delete-name",
			scopeId: org.GetPublicId(),
			version: 1,
			orig: &ManagedGroup{
				ManagedGroup: &store.ManagedGroup{
					Name:        "do-not-delete-name-test-name-repo",
					Description: "test-description-repo",
				},
			},
			masks: []string{DescriptionField},
			chgFn: combine(changeDescription("test-update-description-repo"), changeName("")),
			want: &ManagedGroup{
				ManagedGroup: &store.ManagedGroup{
					Name:        "do-not-delete-name-test-name-repo",
					Description: "test-update-description-repo",
				},
			},
			wantCount: 1,
		},
		{
			name:    "do-not-delete-description",
			scopeId: org.GetPublicId(),
			version: 1,
			orig: &ManagedGroup{
				ManagedGroup: &store.ManagedGroup{
					Name:        "do-not-delete-description-test-name-repo",
					Description: "test-description-repo",
				},
			},
			masks: []string{NameField},
			chgFn: combine(changeDescription(""), changeName("do-not-delete-description-test-update-name-repo")),
			want: &ManagedGroup{
				ManagedGroup: &store.ManagedGroup{
					Name:        "do-not-delete-description-test-update-name-repo",
					Description: "test-description-repo",
				},
			},
			wantCount: 1,
		},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			assert, require := assert.New(t), require.New(t)
			repo, err := NewRepository(ctx, rw, rw, kmsCache)
			assert.NoError(err)
			require.NotNil(repo)

			orig := TestManagedGroup(t, conn, am, TestFakeManagedGroupFilter, WithName(tt.orig.GetName()), WithDescription(tt.orig.GetDescription()))

			tt.orig.AuthMethodId = am.PublicId
			if tt.chgFn != nil {
				orig = tt.chgFn(orig)
			}
			got, gotCount, err := repo.UpdateManagedGroup(context.Background(), tt.scopeId, orig, tt.version, tt.masks)
			if tt.wantIsErr != 0 {
				assert.Truef(errors.Match(errors.T(tt.wantIsErr), err), "want err: %q got: %q", tt.wantIsErr, err)
				if tt.wantErrContains != "" {
					assert.True(strings.Contains(err.Error(), tt.wantErrContains))
				} else {
					assert.Equal(tt.wantErrMsg, err.Error())
				}
				assert.Equal(tt.wantCount, gotCount, "row count")
				assert.Nil(got)
				return
			}
			assert.NoError(err)
			assert.Empty(tt.orig.PublicId)
			if tt.wantCount == 0 {
				assert.Equal(tt.wantCount, gotCount, "row count")
				assert.Nil(got)
				return
			}
			require.NotNil(got)
			assertPublicId(t, globals.OidcManagedGroupPrefix, got.PublicId)
			assert.Equal(tt.wantCount, gotCount, "row count")
			assert.NotSame(tt.orig, got)
			assert.Equal(tt.orig.AuthMethodId, got.AuthMethodId)
			underlyingDB, err := conn.SqlDB(ctx)
			require.NoError(err)
			dbassert := dbassert.New(t, underlyingDB)
			if tt.want.Name == "" {
				dbassert.IsNull(got, "name")
				return
			}
			assert.Equal(tt.want.Name, got.Name)
			if tt.want.Description == "" {
				dbassert.IsNull(got, "description")
				return
			}
			assert.Equal(tt.want.Description, got.Description)
			if tt.wantCount > 0 {
				assert.NoError(db.TestVerifyOplog(t, rw, got.PublicId, db.WithOperation(oplog.OpType_OP_TYPE_UPDATE), db.WithCreateNotBefore(10*time.Second)))
			}
		})
	}
}

func TestRepository_estimatedCountManagedGroups(t *testing.T) {
	oldReadTimeout := globals.RefreshReadLookbackDuration
	globals.RefreshReadLookbackDuration = 0
	t.Cleanup(func() {
		globals.RefreshReadLookbackDuration = oldReadTimeout
	})
	conn, _ := db.TestSetup(t, "postgres")
	rw := db.New(conn)
	wrapper := db.TestWrapper(t)

	ctx := context.Background()
	kmsCache := kms.TestKms(t, conn, wrapper)
	iamRepo := iam.TestRepo(t, conn, wrapper)
	org, _ := iam.TestScopes(t, iamRepo)

	databaseWrapper, err := kmsCache.GetWrapper(ctx, org.PublicId, kms.KeyPurposeDatabase)
	require.NoError(t, err)

	repo, err := NewRepository(ctx, rw, rw, kmsCache)
	assert.NoError(t, err)

	sqlDb, err := conn.SqlDB(ctx)
	require.NoError(t, err)

	// Check total entries at start, expect 0
	numItems, err := repo.estimatedManagedGroupCount(ctx)
	require.NoError(t, err)
	assert.Equal(t, 0, numItems)

	// create managed group and check count, expect 1
	authMethod1 := TestAuthMethod(
		t, conn, databaseWrapper, org.PublicId, ActivePrivateState,
		"alice-rp", "fido",
		WithSigningAlgs(RS256),
		WithIssuer(TestConvertToUrls(t, "https://www.alice1.com")[0]),
		WithApiUrl(TestConvertToUrls(t, "https://www.alice.com/callback")[0]),
	)
	mg := TestManagedGroup(t, conn, authMethod1, TestFakeManagedGroupFilter)
	_, err = sqlDb.ExecContext(ctx, "analyze")
	require.NoError(t, err)

	numItems, err = repo.estimatedManagedGroupCount(ctx)
	require.NoError(t, err)
	assert.Equal(t, 1, numItems)

	// Delete managed group and check count, expect 0 again
	_, err = repo.DeleteManagedGroup(ctx, org.GetPublicId(), mg.GetPublicId())
	require.NoError(t, err)
	_, err = sqlDb.ExecContext(ctx, "analyze")
	require.NoError(t, err)

	numItems, err = repo.estimatedManagedGroupCount(ctx)
	require.NoError(t, err)
	assert.Equal(t, 0, numItems)
}

func TestRepository_listDeletedIdsManagedGroups(t *testing.T) {
	oldReadTimeout := globals.RefreshReadLookbackDuration
	globals.RefreshReadLookbackDuration = 0
	t.Cleanup(func() {
		globals.RefreshReadLookbackDuration = oldReadTimeout
	})
	conn, _ := db.TestSetup(t, "postgres")
	rw := db.New(conn)
	wrapper := db.TestWrapper(t)

	ctx := context.Background()
	kmsCache := kms.TestKms(t, conn, wrapper)
	iamRepo := iam.TestRepo(t, conn, wrapper)
	org, _ := iam.TestScopes(t, iamRepo)

	databaseWrapper, err := kmsCache.GetWrapper(ctx, org.PublicId, kms.KeyPurposeDatabase)
	require.NoError(t, err)

	repo, err := NewRepository(ctx, rw, rw, kmsCache)
	assert.NoError(t, err)

	sqlDb, err := conn.SqlDB(ctx)
	require.NoError(t, err)

	// Check total entries at start, expect 0
	numItems, err := repo.estimatedManagedGroupCount(ctx)
	require.NoError(t, err)
	assert.Equal(t, 0, numItems)

	// create managed group and check count, expect 1
	authMethod1 := TestAuthMethod(
		t, conn, databaseWrapper, org.PublicId, ActivePrivateState,
		"alice-rp", "fido",
		WithSigningAlgs(RS256),
		WithIssuer(TestConvertToUrls(t, "https://www.alice1.com")[0]),
		WithApiUrl(TestConvertToUrls(t, "https://www.alice.com/callback")[0]),
	)
	mg := TestManagedGroup(t, conn, authMethod1, TestFakeManagedGroupFilter)
	_, err = sqlDb.ExecContext(ctx, "analyze")
	require.NoError(t, err)

	deletedIds, ttime, err := repo.listDeletedManagedGroupIds(ctx, time.Now().AddDate(-1, 0, 0))
	require.NoError(t, err)
	require.Empty(t, deletedIds)
	// Transaction timestamp should be within ~10 seconds of now
	assert.True(t, time.Now().Before(ttime.Add(10*time.Second)))
	assert.True(t, time.Now().After(ttime.Add(-10*time.Second)))

	// Delete mg and check count, expect 1 entry
	_, err = repo.DeleteManagedGroup(ctx, org.GetPublicId(), mg.GetPublicId())
	require.NoError(t, err)
	_, err = sqlDb.ExecContext(ctx, "analyze")
	require.NoError(t, err)

	deletedIds, ttime, err = repo.listDeletedManagedGroupIds(ctx, time.Now().AddDate(-1, 0, 0))
	require.NoError(t, err)
	assert.Empty(
		t,
		cmp.Diff(
			[]string{mg.GetPublicId()},
			deletedIds,
			cmpopts.SortSlices(func(i, j string) bool { return i < j }),
		),
	)
	// Transaction timestamp should be within ~10 seconds of now
	assert.True(t, time.Now().Before(ttime.Add(10*time.Second)))
	assert.True(t, time.Now().After(ttime.Add(-10*time.Second)))

	// Try again with the time set to now, expect no entries
	deletedIds, ttime, err = repo.listDeletedManagedGroupIds(ctx, time.Now())
	require.NoError(t, err)
	require.Empty(t, deletedIds)
	assert.True(t, time.Now().Before(ttime.Add(10*time.Second)))
	assert.True(t, time.Now().After(ttime.Add(-10*time.Second)))
}
