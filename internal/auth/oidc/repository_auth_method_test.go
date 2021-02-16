package oidc

import (
	"context"
	"sort"
	"testing"
	"time"

	"github.com/hashicorp/boundary/internal/db"
	"github.com/hashicorp/boundary/internal/errors"
	"github.com/hashicorp/boundary/internal/iam"
	"github.com/hashicorp/boundary/internal/kms"
	"github.com/hashicorp/boundary/internal/oplog"
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

func TestRepository_DeleteAuthMethod(t *testing.T) {
	conn, _ := db.TestSetup(t, "postgres")
	rw := db.New(conn)
	wrapper := db.TestWrapper(t)
	kmsCache := kms.TestKms(t, conn, wrapper)
	ctx := context.Background()

	tests := []struct {
		name            string
		authMethod      *AuthMethod
		wantRowsDeleted int
		wantErrMatch    *errors.Template
	}{
		{
			name: "valid",
			authMethod: func() *AuthMethod {
				org, _ := iam.TestScopes(t, iam.TestRepo(t, conn, wrapper))
				databaseWrapper, err := kmsCache.GetWrapper(context.Background(), org.PublicId, kms.KeyPurposeDatabase)
				require.NoError(t, err)
				return TestAuthMethod(t, conn, databaseWrapper, org.PublicId, InactiveState, TestConvertToUrls(t, "https://alice.com")[0], "alice_rp", "alices-dogs-name")
			}(),
			wantRowsDeleted: 1,
		},
		{
			name:         "no-public-id",
			authMethod:   func() *AuthMethod { am := AllocAuthMethod(); return &am }(),
			wantErrMatch: errors.T(errors.InvalidPublicId),
		},
		{
			name: "not-found",
			authMethod: func() *AuthMethod {
				am := AllocAuthMethod()
				var err error
				am.PublicId, err = newAuthMethodId()
				require.NoError(t, err)
				return &am
			}(),
			wantErrMatch: errors.T(errors.RecordNotFound),
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert, require := assert.New(t), require.New(t)
			repo, err := NewRepository(rw, rw, kmsCache)
			require.NoError(err)
			deletedRows, err := repo.DeleteAuthMethod(ctx, tt.authMethod.PublicId)
			if tt.wantErrMatch != nil {
				require.Error(err)

				assert.Truef(errors.Match(tt.wantErrMatch, err), "want err: %q got: %q", tt.wantErrMatch.Msg, err)

				assert.Equalf(0, deletedRows, "expected 0 deleted rows and got %d", deletedRows)

				err := db.TestVerifyOplog(t, rw, tt.authMethod.PublicId, db.WithOperation(oplog.OpType_OP_TYPE_DELETE), db.WithCreateNotBefore(10*time.Second))
				require.Errorf(err, "should not have found oplog entry for %s", tt.authMethod.PublicId)
				assert.Truef(errors.Match(errors.T(errors.RecordNotFound), err), "expected error code %s and got %s", errors.RecordNotFound, err)

				return
			}
			require.NoError(err)
			assert.Equalf(tt.wantRowsDeleted, deletedRows, "expected rows deleted == %d and got %d", tt.wantRowsDeleted, deletedRows)

			err = db.TestVerifyOplog(t, rw, tt.authMethod.PublicId, db.WithOperation(oplog.OpType_OP_TYPE_DELETE), db.WithCreateNotBefore(10*time.Second))
			require.NoErrorf(err, "unexpected error verifying oplog entry: %s", err)

			found, err := repo.LookupAuthMethod(ctx, tt.authMethod.PublicId)
			require.NoError(err)
			assert.Nil(found)
		})
	}
}
