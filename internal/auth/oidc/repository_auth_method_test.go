package oidc

import (
	"context"
	"sort"
	"testing"

	"github.com/hashicorp/boundary/internal/db"
	"github.com/hashicorp/boundary/internal/errors"
	"github.com/hashicorp/boundary/internal/iam"
	"github.com/hashicorp/boundary/internal/kms"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestRepository_LookupAuthMethod(t *testing.T) {
	conn, _ := db.TestSetup(t, "postgres")
	rw := db.New(conn)
	wrapper := db.TestWrapper(t)
	kmsCache := kms.TestKms(t, conn, wrapper)
	ctx := context.Background()
	org, _ := iam.TestScopes(t, iam.TestRepo(t, conn, wrapper))
	databaseWrapper, err := kmsCache.GetWrapper(context.Background(), org.PublicId, kms.KeyPurposeDatabase)
	require.NoError(t, err)
	am := TestAuthMethod(t, conn, databaseWrapper, org.PublicId, InactiveState, TestConvertToUrls(t, "https://alice.com")[0], "alice_rp", "alices-dogs-name")

	amId, err := newAuthMethodId()
	require.NoError(t, err)
	tests := []struct {
		name         string
		in           string
		want         *AuthMethod
		wantErrMatch *errors.Template
	}{
		{
			name:         "With no public id",
			wantErrMatch: errors.T(errors.InvalidParameter),
		},
		{
			name: "With non existing auth method id",
			in:   amId,
		},
		{
			name: "With existing auth method id",
			in:   am.GetPublicId(),
			want: am,
		},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			assert, require := assert.New(t), require.New(t)
			repo, err := NewRepository(rw, rw, kmsCache)
			assert.NoError(err)
			require.NotNil(repo)
			got, err := repo.LookupAuthMethod(ctx, tt.in)
			if tt.wantErrMatch != nil {
				require.Error(err)
				assert.Truef(errors.Match(tt.wantErrMatch, err), "want err code: %q got: %q", tt.wantErrMatch, err)
				assert.Nil(got)
				return
			}
			require.NoError(err)
			assert.EqualValues(tt.want, got)
		})
	}
}

// TestRepository_ListAuthMethods only covers error conditions, since all the
// search criteria testing is handled in the TestRepository_getAuthMethods unit
// tests.
func TestRepository_ListAuthMethods(t *testing.T) {
	conn, _ := db.TestSetup(t, "postgres")
	rw := db.New(conn)
	wrapper := db.TestWrapper(t)
	kmsCache := kms.TestKms(t, conn, wrapper)
	ctx := context.Background()

	tests := []struct {
		name         string
		setupFn      func() (scopeIds []string, want []*AuthMethod)
		opt          []Option
		wantErrMatch *errors.Template
	}{
		{
			name: "with-limits",
			setupFn: func() ([]string, []*AuthMethod) {
				org, _ := iam.TestScopes(t, iam.TestRepo(t, conn, wrapper))
				databaseWrapper, err := kmsCache.GetWrapper(context.Background(), org.PublicId, kms.KeyPurposeDatabase)
				require.NoError(t, err)
				am1a := TestAuthMethod(t, conn, databaseWrapper, org.PublicId, InactiveState, TestConvertToUrls(t, "https://alice.com")[0], "alice_rp", "alices-dogs-name")
				_ = TestAuthMethod(t, conn, databaseWrapper, org.PublicId, InactiveState, TestConvertToUrls(t, "https://alice.com")[0], "alice_rp-2", "alices-cat-name")

				return []string{am1a.ScopeId}, []*AuthMethod{am1a}
			},
			opt: []Option{WithLimit(1), WithOrder("create_time asc")},
		},
		{
			name: "no-search-criteria",
			setupFn: func() ([]string, []*AuthMethod) {
				return nil, nil
			},
			wantErrMatch: errors.T(errors.InvalidParameter),
		},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			assert, require := assert.New(t), require.New(t)
			repo, err := NewRepository(rw, rw, kmsCache)
			assert.NoError(err)
			scopeIds, want := tt.setupFn()

			got, err := repo.ListAuthMethods(ctx, scopeIds, tt.opt...)
			if tt.wantErrMatch != nil {
				require.Error(err)
				assert.Truef(errors.Match(tt.wantErrMatch, err), "want err code: %q got: %q", tt.wantErrMatch, err)
				assert.Nil(got)
				return
			}
			require.NoError(err)
			sort.Slice(want, func(a, b int) bool {
				return want[a].PublicId < want[b].PublicId
			})
			sort.Slice(got, func(a, b int) bool {
				return got[a].PublicId < got[b].PublicId
			})
			assert.Equal(want, got)
		})
	}
}
