// Copyright IBM Corp. 2020, 2025
// SPDX-License-Identifier: BUSL-1.1

package ldap

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"testing"

	"github.com/hashicorp/boundary/internal/db"
	"github.com/hashicorp/boundary/internal/errors"
	"github.com/hashicorp/boundary/internal/iam"
	"github.com/hashicorp/boundary/internal/kms"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestRepository_LookupAuthMethod(t *testing.T) {
	testConn, _ := db.TestSetup(t, "postgres")
	testRw := db.New(testConn)
	testWrapper := db.TestWrapper(t)
	testKms := kms.TestKms(t, testConn, testWrapper)
	testCtx := context.Background()
	org, _ := iam.TestScopes(t, iam.TestRepo(t, testConn, testWrapper))
	orgDbWrapper, err := testKms.GetWrapper(context.Background(), org.PublicId, kms.KeyPurposeDatabase)
	require.NoError(t, err)
	amInactive := TestAuthMethod(t, testConn, orgDbWrapper, org.PublicId, []string{"ldaps://ldap1.alice.com"}, WithOperationalState(testCtx, InactiveState))
	amActivePriv := TestAuthMethod(t, testConn, orgDbWrapper, org.PublicId, []string{"ldaps://ldap2.alice.com"}, WithOperationalState(testCtx, ActivePrivateState))
	amActivePub := TestAuthMethod(t, testConn, orgDbWrapper, org.PublicId, []string{"ldaps://ldap3.alice.com"}, WithOperationalState(testCtx, ActivePublicState))
	amActivePub.IsPrimaryAuthMethod = true
	iam.TestSetPrimaryAuthMethod(t, iam.TestRepo(t, testConn, testWrapper), org, amActivePub.PublicId)

	amId, err := newAuthMethodId(testCtx)
	require.NoError(t, err)
	tests := []struct {
		name            string
		in              string
		opt             []Option
		want            *AuthMethod
		wantIsPrimary   bool
		wantErrMatch    *errors.Template
		wantErrContains string
	}{
		{
			name:            "missing-public-id",
			wantErrMatch:    errors.T(errors.InvalidParameter),
			wantErrContains: "missing public id",
		},
		{
			name:            "invalid-opts",
			in:              amActivePub.GetPublicId(),
			opt:             []Option{WithBindCredential(testCtx, "", "")},
			wantErrMatch:    errors.T(errors.InvalidParameter),
			wantErrContains: "missing both dn and password",
		},
		{
			name: "non-existing-auth-method-id",
			in:   amId,
		},
		{
			name: "existing-auth-method-id",
			in:   amActivePriv.GetPublicId(),
			want: amActivePriv,
		},
		{
			name: "unauthenticated-user-not-found-using-active-priv",
			in:   amActivePriv.GetPublicId(),
			opt:  []Option{WithUnauthenticatedUser(testCtx, true)},
			want: nil,
		},
		{
			name:          "unauthenticated-user-found-active-pub",
			in:            amActivePub.GetPublicId(),
			opt:           []Option{WithUnauthenticatedUser(testCtx, true)},
			want:          amActivePub,
			wantIsPrimary: true,
		},
		{
			name: "unauthenticated-user-found-inactive",
			in:   amInactive.GetPublicId(),
			opt:  []Option{WithUnauthenticatedUser(testCtx, true)},
			want: nil,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			assert, require := assert.New(t), require.New(t)
			repo, err := NewRepository(testCtx, testRw, testRw, testKms)
			assert.NoError(err)
			require.NotNil(repo)
			got, err := repo.LookupAuthMethod(testCtx, tc.in, tc.opt...)
			if tc.wantErrMatch != nil {
				require.Error(err)
				assert.Truef(errors.Match(tc.wantErrMatch, err), "want err code: %q got: %q", tc.wantErrMatch, err)
				assert.Nil(got)
				if tc.wantErrContains != "" {
					assert.Contains(err.Error(), tc.wantErrContains)
				}
				return
			}
			require.NoError(err)
			assert.EqualValues(tc.want, got)
		})
	}
}

func TestRepository_getAuthMethods(t *testing.T) {
	testConn, _ := db.TestSetup(t, "postgres")
	testRw := db.New(testConn)
	testWrapper := db.TestWrapper(t)
	testKms := kms.TestKms(t, testConn, testWrapper)
	testCtx := context.Background()

	tests := []struct {
		name            string
		setupFn         func() (authMethodId string, scopeIds []string, want []*AuthMethod)
		opt             []Option
		wantErrMatch    *errors.Template
		wantErrContains string
	}{
		{
			name: "valid-multi-scopes",
			setupFn: func() (string, []string, []*AuthMethod) {
				org, _ := iam.TestScopes(t, iam.TestRepo(t, testConn, testWrapper))
				orgDBWrapper, err := testKms.GetWrapper(context.Background(), org.PublicId, kms.KeyPurposeDatabase)
				require.NoError(t, err)
				org2, _ := iam.TestScopes(t, iam.TestRepo(t, testConn, testWrapper))
				orgDBWrapper2, err := testKms.GetWrapper(context.Background(), org2.PublicId, kms.KeyPurposeDatabase)
				require.NoError(t, err)

				// make a test auth method with all options
				am1a := TestAuthMethod(t, testConn, orgDBWrapper, org.PublicId, []string{"ldaps://ldap1.alice.com"}, WithOperationalState(testCtx, InactiveState))
				am1b := TestAuthMethod(t, testConn, orgDBWrapper, org.PublicId, []string{"ldaps://ldap2.alice.com"}, WithOperationalState(testCtx, InactiveState))
				am2 := TestAuthMethod(t, testConn, orgDBWrapper2, org2.PublicId, []string{"ldaps://ldap3.alice.com"}, WithOperationalState(testCtx, InactiveState))
				return "", []string{am1a.ScopeId, am1b.ScopeId, am2.ScopeId}, []*AuthMethod{am1a, am1b, am2}
			},
		},
		{
			name: "valid-single-scopes",
			setupFn: func() (string, []string, []*AuthMethod) {
				org, _ := iam.TestScopes(t, iam.TestRepo(t, testConn, testWrapper))
				orgDBWrapper, err := testKms.GetWrapper(context.Background(), org.PublicId, kms.KeyPurposeDatabase)
				require.NoError(t, err)
				am1a := TestAuthMethod(t, testConn, orgDBWrapper, org.PublicId, []string{"ldaps://ldap1.alice.com"}, WithOperationalState(testCtx, InactiveState))
				am1b := TestAuthMethod(t, testConn, orgDBWrapper, org.PublicId, []string{"ldaps://ldap2.alice.com"}, WithOperationalState(testCtx, InactiveState))

				return "", []string{am1a.ScopeId}, []*AuthMethod{am1a, am1b}
			},
		},
		{
			name: "valid-auth-method-id-all-opts",
			setupFn: func() (string, []string, []*AuthMethod) {
				org, _ := iam.TestScopes(t, iam.TestRepo(t, testConn, testWrapper))
				orgDbWrapper, err := testKms.GetWrapper(context.Background(), org.PublicId, kms.KeyPurposeDatabase)
				require.NoError(t, err)
				testCert, _ := TestGenerateCA(t, "localhost")
				_, testPrivKey, err := ed25519.GenerateKey(rand.Reader)
				require.NoError(t, err)
				derPrivKey, err := x509.MarshalPKCS8PrivateKey(testPrivKey)
				require.NoError(t, err)

				am := TestAuthMethod(t, testConn, orgDbWrapper, org.PublicId, []string{"ldaps://alice.com"},
					WithName(testCtx, "test-name"),
					WithDescription(testCtx, "test-description"),
					WithStartTLS(testCtx),
					WithInsecureTLS(testCtx),
					WithDiscoverDn(testCtx),
					WithAnonGroupSearch(testCtx),
					WithUpnDomain(testCtx, "alice.com"),
					WithUserDn(testCtx, "user-dn"),
					WithUserAttr(testCtx, "user-attr"),
					WithUserFilter(testCtx, "user-filter"),
					WithEnableGroups(testCtx),
					WithUseTokenGroups(testCtx),
					WithGroupDn(testCtx, "group-dn"),
					WithGroupAttr(testCtx, "group-attr"),
					WithGroupFilter(testCtx, "group-filter"),
					WithBindCredential(testCtx, "bind-dn", "bind-password"),
					WithCertificates(testCtx, testCert),
					WithClientCertificate(testCtx, derPrivKey, testCert), // not a client cert but good enough for this test.)
					WithAccountAttributeMap(testCtx, map[string]AccountToAttribute{"mail": ToEmailAttribute, "displayName": ToFullNameAttribute}),
					WithMaximumPageSize(testCtx, 10),
					WithDerefAliases(testCtx, DerefAlways),
				)
				return am.PublicId, nil, []*AuthMethod{am}
			},
		},
		{
			name: "with-limits",
			setupFn: func() (string, []string, []*AuthMethod) {
				org, _ := iam.TestScopes(t, iam.TestRepo(t, testConn, testWrapper))
				orgDBWrapper, err := testKms.GetWrapper(context.Background(), org.PublicId, kms.KeyPurposeDatabase)
				require.NoError(t, err)
				am1a := TestAuthMethod(t, testConn, orgDBWrapper, org.PublicId, []string{"ldaps://alice.com"})
				_ = TestAuthMethod(t, testConn, orgDBWrapper, org.PublicId, []string{"ldaps://alice2.com"})

				return "", []string{am1a.ScopeId}, []*AuthMethod{am1a}
			},
			opt: []Option{WithLimit(testCtx, 1), WithOrderByCreateTime(testCtx, true)},
		},
		{
			name: "unauthenticated-user",
			setupFn: func() (string, []string, []*AuthMethod) {
				org, _ := iam.TestScopes(t, iam.TestRepo(t, testConn, testWrapper))
				databaseWrapper, err := testKms.GetWrapper(context.Background(), org.PublicId, kms.KeyPurposeDatabase)
				require.NoError(t, err)
				_ = TestAuthMethod(t, testConn, databaseWrapper, org.PublicId, []string{"ldaps://ldap1.alice.com"}, WithOperationalState(testCtx, InactiveState))
				_ = TestAuthMethod(t, testConn, databaseWrapper, org.PublicId, []string{"ldaps://ldap2.alice.com"}, WithOperationalState(testCtx, ActivePrivateState))
				amActivePub := TestAuthMethod(t, testConn, databaseWrapper, org.PublicId, []string{"ldaps://ldap3.alice.com"}, WithOperationalState(testCtx, ActivePublicState))

				return "", []string{amActivePub.ScopeId}, []*AuthMethod{amActivePub}
			},
			opt: []Option{WithUnauthenticatedUser(testCtx, true)},
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
			wantErrMatch:    errors.T(errors.InvalidParameter),
			wantErrContains: "missing search criteria: both auth method id and scope ids are empty",
		},
		{
			name: "search-too-many",
			setupFn: func() (string, []string, []*AuthMethod) {
				return "auth-method-id", []string{"scope-id"}, nil
			},
			wantErrMatch:    errors.T(errors.InvalidParameter),
			wantErrContains: "searching for both an auth method id and scope ids is not supported",
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			assert, require := assert.New(t), require.New(t)
			r, err := NewRepository(testCtx, testRw, testRw, testKms)
			require.NoError(err)

			authMethodId, scopeIds, want := tc.setupFn()

			got, err := r.getAuthMethods(testCtx, authMethodId, scopeIds, tc.opt...)

			if tc.wantErrMatch != nil {
				require.Error(err)
				assert.Truef(errors.Match(tc.wantErrMatch, err), "want err code: %q got: %q", tc.wantErrMatch, err)
				assert.Nil(got)
				if tc.wantErrContains != "" {
					assert.Contains(err.Error(), tc.wantErrContains)
				}
				return
			}
			require.NoError(err)
			TestSortAuthMethods(t, want)
			TestSortAuthMethods(t, got)
			assert.Equal(want, got)
		})
	}
}
