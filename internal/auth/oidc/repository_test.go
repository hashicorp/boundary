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

func TestNewRepository(t *testing.T) {
	conn, _ := db.TestSetup(t, "postgres")
	rw := db.New(conn)
	wrapper := db.TestWrapper(t)
	kmsCache := kms.TestKms(t, conn, wrapper)

	type args struct {
		r    db.Reader
		w    db.Writer
		kms  *kms.Kms
		opts []Option
	}
	tests := []struct {
		name         string
		args         args
		want         *Repository
		wantErrMatch *errors.Template
	}{
		{
			name: "valid",
			args: args{
				r:   rw,
				w:   rw,
				kms: kmsCache,
			},
			want: &Repository{
				reader:       rw,
				writer:       rw,
				kms:          kmsCache,
				defaultLimit: db.DefaultLimit,
			},
		},
		{
			name: "valid with limit",
			args: args{
				r:    rw,
				w:    rw,
				kms:  kmsCache,
				opts: []Option{WithLimit(5)},
			},
			want: &Repository{
				reader:       rw,
				writer:       rw,
				kms:          kmsCache,
				defaultLimit: 5,
			},
		},
		{
			name: "nil-reader",
			args: args{
				r:   nil,
				w:   rw,
				kms: kmsCache,
			},
			want:         nil,
			wantErrMatch: errors.T(errors.InvalidParameter),
		},
		{
			name: "nil-writer",
			args: args{
				r:   rw,
				w:   nil,
				kms: kmsCache,
			},
			want:         nil,
			wantErrMatch: errors.T(errors.InvalidParameter),
		},
		{
			name: "nil-wrapper",
			args: args{
				r:   rw,
				w:   rw,
				kms: nil,
			},
			want:         nil,
			wantErrMatch: errors.T(errors.InvalidParameter),
		},
		{
			name: "all-nils",
			args: args{
				r:   nil,
				w:   nil,
				kms: nil,
			},
			want:         nil,
			wantErrMatch: errors.T(errors.InvalidParameter),
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert, require := assert.New(t), require.New(t)
			got, err := NewRepository(tt.args.r, tt.args.w, tt.args.kms, tt.args.opts...)
			if tt.wantErrMatch != nil {
				require.Error(err)
				assert.Truef(errors.Match(tt.wantErrMatch, err), "want err code: %q got: %q", tt.wantErrMatch, err)
				assert.Nil(got)
				return
			}
			require.NoError(err)
			require.NotNil(got)
			assert.Equal(tt.want, got)
		})
	}
}

func TestRepository_getAuthMethods(t *testing.T) {
	conn, _ := db.TestSetup(t, "postgres")
	rw := db.New(conn)
	wrapper := db.TestWrapper(t)
	kmsCache := kms.TestKms(t, conn, wrapper)
	ctx := context.Background()

	tests := []struct {
		name         string
		setupFn      func() (authMethodId string, scopeIds []string, want []*AuthMethod)
		opt          []Option
		wantErrMatch *errors.Template
	}{
		{
			name: "valid-multi-scopes",
			setupFn: func() (string, []string, []*AuthMethod) {
				org, _ := iam.TestScopes(t, iam.TestRepo(t, conn, wrapper))
				databaseWrapper, err := kmsCache.GetWrapper(context.Background(), org.PublicId, kms.KeyPurposeDatabase)
				require.NoError(t, err)
				org2, _ := iam.TestScopes(t, iam.TestRepo(t, conn, wrapper))
				databaseWrapper2, err := kmsCache.GetWrapper(context.Background(), org2.PublicId, kms.KeyPurposeDatabase)
				require.NoError(t, err)
				am1a := TestAuthMethod(t, conn, databaseWrapper, org.PublicId, InactiveState, TestConvertToUrls(t, "https://alice.com")[0], "alice_rp", "alices-dogs-name")
				am1b := TestAuthMethod(t, conn, databaseWrapper, org.PublicId, InactiveState, TestConvertToUrls(t, "https://alice.com")[0], "alice_rp-2", "alices-cat-name")

				am2 := TestAuthMethod(t, conn, databaseWrapper2, org2.PublicId, InactiveState, TestConvertToUrls(t, "https://bob.com")[0], "bob_rp", "bobs-dogs-name")
				return "", []string{am1a.ScopeId, am1b.ScopeId, am2.ScopeId}, []*AuthMethod{am1a, am1b, am2}
			},
		},
		{
			name: "valid-single-scopes",
			setupFn: func() (string, []string, []*AuthMethod) {
				org, _ := iam.TestScopes(t, iam.TestRepo(t, conn, wrapper))
				databaseWrapper, err := kmsCache.GetWrapper(context.Background(), org.PublicId, kms.KeyPurposeDatabase)
				require.NoError(t, err)
				am1a := TestAuthMethod(t, conn, databaseWrapper, org.PublicId, InactiveState, TestConvertToUrls(t, "https://alice.com")[0], "alice_rp", "alices-dogs-name")
				am1b := TestAuthMethod(t, conn, databaseWrapper, org.PublicId, InactiveState, TestConvertToUrls(t, "https://alice.com")[0], "alice_rp-2", "alices-cat-name")

				return "", []string{am1a.ScopeId}, []*AuthMethod{am1a, am1b}
			},
		},
		{
			name: "valid-auth-method-id",
			setupFn: func() (string, []string, []*AuthMethod) {
				org, _ := iam.TestScopes(t, iam.TestRepo(t, conn, wrapper))
				databaseWrapper, err := kmsCache.GetWrapper(context.Background(), org.PublicId, kms.KeyPurposeDatabase)
				require.NoError(t, err)
				am := TestAuthMethod(t, conn, databaseWrapper, org.PublicId, InactiveState, TestConvertToUrls(t, "https://alice.com")[0], "alice_rp", "alices-dogs-name")

				return am.PublicId, nil, []*AuthMethod{am}
			},
		},
		{
			name: "not-found-auth-method-id",
			setupFn: func() (string, []string, []*AuthMethod) {
				return "not-a-valid-id", nil, nil
			},
		},
		{
			name: "not-found-scope-ids",
			setupFn: func() (string, []string, []*AuthMethod) {
				return "", []string{"not-valid-scope-1", "not-valid-scope-2"}, nil
			},
		},
		{
			name: "no-search-criteria",
			setupFn: func() (string, []string, []*AuthMethod) {
				return "", nil, nil
			},
			wantErrMatch: errors.T(errors.InvalidParameter),
		},
		{
			name: "search-too-many",
			setupFn: func() (string, []string, []*AuthMethod) {
				return "auth-method-id", []string{"scope-id"}, nil
			},
			wantErrMatch: errors.T(errors.InvalidParameter),
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert, require := assert.New(t), require.New(t)
			r, err := NewRepository(rw, rw, kmsCache)
			require.NoError(err)

			authMethodId, scopeIds, want := tt.setupFn()

			got, err := r.getAuthMethods(ctx, authMethodId, scopeIds, tt.opt...)

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
