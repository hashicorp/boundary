// Copyright IBM Corp. 2020, 2025
// SPDX-License-Identifier: BUSL-1.1

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
	amInactive := TestAuthMethod(t, conn, databaseWrapper, org.PublicId, InactiveState, "alice_rp", "alices-dogs-name",
		WithIssuer(TestConvertToUrls(t, "https://alice-inactive.com")[0]), WithApiUrl(TestConvertToUrls(t, "https://api.com")[0]))
	amActivePriv := TestAuthMethod(
		t,
		conn, databaseWrapper, org.PublicId, ActivePrivateState,
		"alice_rp", "alices-dogs-name",
		WithAccountClaimMap(map[string]AccountToClaim{"oid": ToSubClaim, "display_name": ToNameClaim}),
		WithApiUrl(TestConvertToUrls(t, "https://alice-active-priv.com/callback")[0]),
		WithSigningAlgs(RS256),
		WithPrompts(Consent, SelectAccount))
	amActivePub := TestAuthMethod(
		t,
		conn, databaseWrapper, org.PublicId, ActivePublicState,
		"alice_rp", "alices-dogs-name",
		WithAccountClaimMap(map[string]AccountToClaim{"oid": ToSubClaim, "display_name": ToNameClaim}),
		WithApiUrl(TestConvertToUrls(t, "https://alice-active-pub.com/callback")[0]),
		WithSigningAlgs(RS256),
		WithClaimsScopes("email", "profile"),
	)
	amActivePub.IsPrimaryAuthMethod = true
	iam.TestSetPrimaryAuthMethod(t, iam.TestRepo(t, conn, wrapper), org, amActivePub.PublicId)

	amId, err := newAuthMethodId(ctx)
	require.NoError(t, err)
	tests := []struct {
		name          string
		in            string
		opt           []Option
		want          *AuthMethod
		wantIsPrimary bool
		wantErrMatch  *errors.Template
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
			in:   amActivePriv.GetPublicId(),
			want: amActivePriv,
		},
		{
			name: "unauthenticated user - not found using active priv",
			in:   amActivePriv.GetPublicId(),
			opt:  []Option{WithUnauthenticatedUser(true)},
			want: nil,
		},
		{
			name:          "unauthenticated user - found active pub",
			in:            amActivePub.GetPublicId(),
			opt:           []Option{WithUnauthenticatedUser(true)},
			want:          amActivePub,
			wantIsPrimary: true,
		},
		{
			name: "unauthenticated user - found inactive",
			in:   amInactive.GetPublicId(),
			opt:  []Option{WithUnauthenticatedUser(true)},
			want: nil,
		},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			assert, require := assert.New(t), require.New(t)
			repo, err := NewRepository(ctx, rw, rw, kmsCache)
			assert.NoError(err)
			require.NotNil(repo)
			got, err := repo.LookupAuthMethod(ctx, tt.in, tt.opt...)
			if tt.wantErrMatch != nil {
				require.Error(err)
				assert.Truef(errors.Match(tt.wantErrMatch, err), "want err code: %q got: %q", tt.wantErrMatch, err)
				assert.Nil(got)
				return
			}
			require.NoError(err)
			if tt.want != nil && tt.want.AccountClaimMaps != nil {
				sort.Strings(tt.want.AccountClaimMaps)
			}
			if got != nil && got.AccountClaimMaps != nil {
				sort.Strings(got.AccountClaimMaps)
			}
			assert.EqualValues(tt.want, got)
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
				cert1, _ := testGenerateCA(t, "localhost")
				cert2, _ := testGenerateCA(t, "127.0.0.1")

				// make a test auth method with all options
				am1a := TestAuthMethod(
					t,
					conn,
					databaseWrapper,
					org.PublicId,
					InactiveState,
					"alice_rp",
					"alices-dogs-name",
					WithAudClaims("alice_rp", "alice_rp-2"),
					WithApiUrl(TestConvertToUrls(t, "https://alice.com/callback")[0]),
					WithSigningAlgs(RS256, ES256),
					WithCertificates(cert1, cert2),
					WithClaimsScopes("email", "profile"),
					WithAccountClaimMap(map[string]AccountToClaim{"oid": ToSubClaim, "display_name": ToNameClaim}),
				)
				am1b := TestAuthMethod(t, conn, databaseWrapper, org.PublicId, InactiveState, "alice_rp-2", "alices-cat-name",
					WithIssuer(TestConvertToUrls(t, "https://alice.com")[0]), WithApiUrl(TestConvertToUrls(t, "https://api.com")[0]))

				am2 := TestAuthMethod(t, conn, databaseWrapper2, org2.PublicId, InactiveState, "bob_rp", "bobs-dogs-name",
					WithIssuer(TestConvertToUrls(t, "https://bob.com")[0]), WithApiUrl(TestConvertToUrls(t, "https://api.com")[0]))
				return "", []string{am1a.ScopeId, am1b.ScopeId, am2.ScopeId}, []*AuthMethod{am1a, am1b, am2}
			},
		},
		{
			name: "valid-single-scopes",
			setupFn: func() (string, []string, []*AuthMethod) {
				org, _ := iam.TestScopes(t, iam.TestRepo(t, conn, wrapper))
				databaseWrapper, err := kmsCache.GetWrapper(context.Background(), org.PublicId, kms.KeyPurposeDatabase)
				require.NoError(t, err)
				am1a := TestAuthMethod(t, conn, databaseWrapper, org.PublicId, InactiveState, "alice_rp", "alices-dogs-name",
					WithIssuer(TestConvertToUrls(t, "https://alice.com")[0]), WithApiUrl(TestConvertToUrls(t, "https://api.com")[0]))
				am1b := TestAuthMethod(t, conn, databaseWrapper, org.PublicId, InactiveState, "alice_rp-2", "alices-cat-name",
					WithIssuer(TestConvertToUrls(t, "https://alice.com")[0]), WithApiUrl(TestConvertToUrls(t, "https://api.com")[0]))

				return "", []string{am1a.ScopeId}, []*AuthMethod{am1a, am1b}
			},
		},
		{
			name: "valid-auth-method-id",
			setupFn: func() (string, []string, []*AuthMethod) {
				org, _ := iam.TestScopes(t, iam.TestRepo(t, conn, wrapper))
				databaseWrapper, err := kmsCache.GetWrapper(context.Background(), org.PublicId, kms.KeyPurposeDatabase)
				require.NoError(t, err)
				am := TestAuthMethod(t, conn, databaseWrapper, org.PublicId, InactiveState, "alice_rp", "alices-dogs-name",
					WithIssuer(TestConvertToUrls(t, "https://alice.com")[0]), WithApiUrl(TestConvertToUrls(t, "https://api.com")[0]))

				return am.PublicId, nil, []*AuthMethod{am}
			},
		},
		{
			name: "with-limits",
			setupFn: func() (string, []string, []*AuthMethod) {
				org, _ := iam.TestScopes(t, iam.TestRepo(t, conn, wrapper))
				databaseWrapper, err := kmsCache.GetWrapper(context.Background(), org.PublicId, kms.KeyPurposeDatabase)
				require.NoError(t, err)
				am1a := TestAuthMethod(t, conn, databaseWrapper, org.PublicId, InactiveState, "alice_rp", "alices-dogs-name",
					WithIssuer(TestConvertToUrls(t, "https://alice.com")[0]), WithApiUrl(TestConvertToUrls(t, "https://api.com")[0]))
				_ = TestAuthMethod(t, conn, databaseWrapper, org.PublicId, InactiveState, "alice_rp-2", "alices-cat-name",
					WithIssuer(TestConvertToUrls(t, "https://alice.com")[0]), WithApiUrl(TestConvertToUrls(t, "https://api.com")[0]))

				return "", []string{am1a.ScopeId}, []*AuthMethod{am1a}
			},
			opt: []Option{WithLimit(1), WithOrderByCreateTime(true)},
		},
		{
			name: "unauthenticated-user",
			setupFn: func() (string, []string, []*AuthMethod) {
				org, _ := iam.TestScopes(t, iam.TestRepo(t, conn, wrapper))
				databaseWrapper, err := kmsCache.GetWrapper(context.Background(), org.PublicId, kms.KeyPurposeDatabase)
				require.NoError(t, err)
				_ = TestAuthMethod(t, conn, databaseWrapper, org.PublicId, InactiveState, "alice_rp", "alices-dogs-name",
					WithIssuer(TestConvertToUrls(t, "https://alice.com")[0]), WithApiUrl(TestConvertToUrls(t, "https://api.com")[0]))
				_ = TestAuthMethod(
					t, conn, databaseWrapper, org.PublicId, ActivePrivateState,
					"alice_rp", "alices-dogs-name",
					WithApiUrl(TestConvertToUrls(t, "https://alice-active-priv.com/callback")[0]),
					WithSigningAlgs(RS256))
				amActivePub := TestAuthMethod(
					t, conn, databaseWrapper, org.PublicId, ActivePublicState,
					"alice_rp", "alices-dogs-name",
					WithApiUrl(TestConvertToUrls(t, "https://alice-active-pub.com")[0]),
					WithSigningAlgs(RS256))
				return "", []string{amActivePub.ScopeId}, []*AuthMethod{amActivePub}
			},
			opt: []Option{WithUnauthenticatedUser(true)},
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
			r, err := NewRepository(ctx, rw, rw, kmsCache)
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
			TestSortAuthMethods(t, want)
			TestSortAuthMethods(t, got)
			assert.Equal(want, got)
		})
	}
}
