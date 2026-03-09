// Copyright IBM Corp. 2020, 2025
// SPDX-License-Identifier: BUSL-1.1

package oidc

import (
	"context"
	"fmt"
	"net/http"
	"net/url"
	"sort"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"
	"github.com/hashicorp/boundary/internal/auth/oidc/store"
	"github.com/hashicorp/boundary/internal/db"
	"github.com/hashicorp/boundary/internal/errors"
	"github.com/hashicorp/boundary/internal/iam"
	"github.com/hashicorp/boundary/internal/kms"
	"github.com/hashicorp/boundary/internal/oplog"
	"github.com/hashicorp/boundary/sdk/testutil"
	"github.com/hashicorp/cap/oidc"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/testing/protocmp"
)

func Test_UpdateAuthMethod(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	conn, _ := db.TestSetup(t, "postgres")
	wrapper := db.TestWrapper(t)
	kmsCache := kms.TestKms(t, conn, wrapper)

	tp := oidc.StartTestProvider(t)
	tpClientId := "alice-rp"
	tpClientSecret := "her-dog's-name"
	tp.SetClientCreds(tpClientId, tpClientSecret)
	_, _, tpAlg, _ := tp.SigningKeys()
	tpCert, err := ParseCertificates(ctx, tp.CACert())
	require.NoError(t, err)
	require.Equal(t, 1, len(tpCert))

	rw := db.New(conn)
	repo, err := NewRepository(ctx, rw, rw, kmsCache)
	require.NoError(t, err)

	tests := []struct {
		name             string
		setup            func() *AuthMethod
		updateWith       func(orig *AuthMethod) *AuthMethod
		fieldMasks       []string
		version          uint32
		opt              []Option
		want             func(orig, updateWith *AuthMethod) *AuthMethod
		wantErrMatch     *errors.Template
		wantNoRowsUpdate bool
	}{
		{
			name: "very-simple",
			setup: func() *AuthMethod {
				org, _ := iam.TestScopes(t, iam.TestRepo(t, conn, wrapper))
				databaseWrapper, err := kmsCache.GetWrapper(context.Background(), org.PublicId, kms.KeyPurposeDatabase)
				require.NoError(t, err)
				return TestAuthMethod(t,
					conn, databaseWrapper,
					org.PublicId,
					InactiveState,
					"alice-rp", "alice-secret",
					WithCertificates(tpCert[0]),
					WithSigningAlgs(Alg(tpAlg)),
					WithClaimsScopes("email", "profile"),
					WithAccountClaimMap(map[string]AccountToClaim{"display_name": "name"}),
					WithApiUrl(TestConvertToUrls(t, "https://www.alice.com/callback")[0]),
				)
			},
			updateWith: func(orig *AuthMethod) *AuthMethod {
				am := AllocAuthMethod()
				am.PublicId = orig.PublicId
				am.Name = "alice's restaurant"
				am.Description = "the best place to eat"
				am.AudClaims = []string{"www.alice.com", "www.alice.com/admin"}
				am.ClientSecret = "This is a new secret"
				am.AccountClaimMaps = []string{"preferred_name=name"}
				return &am
			},
			fieldMasks: []string{NameField, DescriptionField, AudClaimsField, ClientSecretField, AccountClaimMapsField},
			version:    1,
			want: func(orig, updateWith *AuthMethod) *AuthMethod {
				am := orig.Clone()
				am.Name = updateWith.Name
				am.Description = updateWith.Description
				am.AudClaims = updateWith.AudClaims
				am.ClientSecret = updateWith.ClientSecret
				am.CtClientSecret = updateWith.CtClientSecret
				am.ClientSecretHmac = updateWith.ClientSecretHmac
				am.AccountClaimMaps = updateWith.AccountClaimMaps
				return am
			},
		},
		{
			name: "with-force-all-value-objects",
			setup: func() *AuthMethod {
				org, _ := iam.TestScopes(t, iam.TestRepo(t, conn, wrapper))
				databaseWrapper, err := kmsCache.GetWrapper(context.Background(), org.PublicId, kms.KeyPurposeDatabase)
				require.NoError(t, err)
				return TestAuthMethod(t,
					conn, databaseWrapper,
					org.PublicId,
					InactiveState,
					"alice-rp", "alice-secret",
					WithAudClaims("www.alice.com"),
					WithCertificates(tpCert[0]),
					WithSigningAlgs(Alg(tpAlg)),
					WithClaimsScopes("email", "profile"),
					WithApiUrl(TestConvertToUrls(t, "https://www.alice.com/callback")[0]),
				)
			},
			updateWith: func(orig *AuthMethod) *AuthMethod {
				_, pem := testGenerateCA(t, "127.0.0.1")
				am := AllocAuthMethod()
				am.PublicId = orig.PublicId
				am.Name = "alice's restaurant"
				am.Description = "the best place to eat"
				am.ApiUrl = "https://www.bob.com/callback"
				am.AudClaims = []string{"www.alice.com/admin"}
				am.SigningAlgs = []string{string(ES384), string(ES512)}
				am.Certificates = []string{pem}
				am.ClaimsScopes = []string{"custom-scope1", "email"}
				return &am
			},
			fieldMasks: []string{NameField, DescriptionField, AudClaimsField, ApiUrlField, SigningAlgsField, CertificatesField, ClaimsScopesField},
			version:    1,
			opt:        []Option{WithForce()},
			want: func(orig, updateWith *AuthMethod) *AuthMethod {
				am := orig.Clone()
				am.Name = updateWith.Name
				am.Description = updateWith.Description
				am.ApiUrl = updateWith.ApiUrl
				am.AudClaims = updateWith.AudClaims
				am.SigningAlgs = updateWith.SigningAlgs
				am.Certificates = updateWith.Certificates
				am.ClaimsScopes = updateWith.ClaimsScopes
				am.DisableDiscoveredConfigValidation = true
				return am
			},
		},
		{
			name: "null-name-description",
			setup: func() *AuthMethod {
				org, _ := iam.TestScopes(t, iam.TestRepo(t, conn, wrapper))
				databaseWrapper, err := kmsCache.GetWrapper(context.Background(), org.PublicId, kms.KeyPurposeDatabase)
				require.NoError(t, err)
				return TestAuthMethod(t, conn, databaseWrapper, org.PublicId, InactiveState, "alice-rp", "alice-secret", WithName("alice's restaurant"), WithDescription("the best place to eat"), WithCertificates(tpCert[0]), WithSigningAlgs(Alg(tpAlg)), WithApiUrl(TestConvertToUrls(t, "https://www.alice.com/callback")[0]))
			},
			updateWith: func(orig *AuthMethod) *AuthMethod {
				am := AllocAuthMethod()
				am.PublicId = orig.PublicId
				am.Name = ""
				am.Description = ""
				return &am
			},
			fieldMasks: []string{NameField, DescriptionField},
			version:    1,
			want: func(orig, updateWith *AuthMethod) *AuthMethod {
				am := orig.Clone()
				am.Name = ""
				am.Description = ""
				return am
			},
		},
		{
			name: "null-signing-algs",
			setup: func() *AuthMethod {
				org, _ := iam.TestScopes(t, iam.TestRepo(t, conn, wrapper))
				databaseWrapper, err := kmsCache.GetWrapper(context.Background(), org.PublicId, kms.KeyPurposeDatabase)
				require.NoError(t, err)
				return TestAuthMethod(t, conn, databaseWrapper, org.PublicId, InactiveState, "alice-rp", "alice-secret", WithCertificates(tpCert[0]), WithSigningAlgs(Alg(tpAlg)), WithApiUrl(TestConvertToUrls(t, "https://www.alice.com/callback")[0]))
			},
			updateWith: func(orig *AuthMethod) *AuthMethod {
				am := AllocAuthMethod()
				am.PublicId = orig.PublicId
				return &am
			},
			fieldMasks: []string{SigningAlgsField},
			version:    1,
			want: func(orig, updateWith *AuthMethod) *AuthMethod {
				am := orig.Clone()
				am.SigningAlgs = nil
				return am
			},
		},
		{
			name: "null-claims-scope",
			setup: func() *AuthMethod {
				org, _ := iam.TestScopes(t, iam.TestRepo(t, conn, wrapper))
				databaseWrapper, err := kmsCache.GetWrapper(context.Background(), org.PublicId, kms.KeyPurposeDatabase)
				require.NoError(t, err)
				return TestAuthMethod(t, conn, databaseWrapper, org.PublicId, InactiveState, "alice-rp", "alice-secret",
					WithCertificates(tpCert[0]),
					WithSigningAlgs(Alg(tpAlg)),
					WithClaimsScopes("email", "profile"),
					WithApiUrl(TestConvertToUrls(t, "https://www.alice.com/callback")[0]))
			},
			updateWith: func(orig *AuthMethod) *AuthMethod {
				am := AllocAuthMethod()
				am.PublicId = orig.PublicId
				return &am
			},
			fieldMasks: []string{ClaimsScopesField},
			version:    1,
			want: func(orig, updateWith *AuthMethod) *AuthMethod {
				am := orig.Clone()
				am.ClaimsScopes = nil
				return am
			},
		},
		{
			name: "change-callback-url",
			setup: func() *AuthMethod {
				org, _ := iam.TestScopes(t, iam.TestRepo(t, conn, wrapper))
				databaseWrapper, err := kmsCache.GetWrapper(context.Background(), org.PublicId, kms.KeyPurposeDatabase)
				require.NoError(t, err)
				return TestAuthMethod(t, conn, databaseWrapper, org.PublicId, InactiveState, "alice-rp", "alice-secret", WithCertificates(tpCert[0]), WithSigningAlgs(Alg(tpAlg)), WithApiUrl(TestConvertToUrls(t, "https://www.alice.com/callback")[0]))
			},
			updateWith: func(orig *AuthMethod) *AuthMethod {
				am := AllocAuthMethod()
				am.PublicId = orig.PublicId
				am.ApiUrl = "https://www.updated.com/callback"
				return &am
			},
			fieldMasks: []string{ApiUrlField},
			version:    1,
			want: func(orig, updateWith *AuthMethod) *AuthMethod {
				am := orig.Clone()
				am.ApiUrl = updateWith.ApiUrl
				return am
			},
		},
		{
			name: "no-changes",
			setup: func() *AuthMethod {
				org, _ := iam.TestScopes(t, iam.TestRepo(t, conn, wrapper))
				databaseWrapper, err := kmsCache.GetWrapper(context.Background(), org.PublicId, kms.KeyPurposeDatabase)
				require.NoError(t, err)
				return TestAuthMethod(t, conn, databaseWrapper, org.PublicId, InactiveState, "alice-rp", "alice-secret",
					WithCertificates(tpCert[0]),
					WithSigningAlgs(Alg(tpAlg)),
					WithApiUrl(TestConvertToUrls(t, "https://www.alice.com/callback")[0]))
			},
			updateWith: func(orig *AuthMethod) *AuthMethod {
				am := AllocAuthMethod()
				am.PublicId = orig.PublicId
				am.SigningAlgs = []string{string(tpAlg)}
				return &am
			},
			fieldMasks: []string{SigningAlgsField},
			version:    1,
			want: func(orig, updateWith *AuthMethod) *AuthMethod {
				am := orig.Clone()
				return am
			},
			wantNoRowsUpdate: true,
		},
		{
			name: "inactive-not-complete-no-with-force",
			setup: func() *AuthMethod {
				org, _ := iam.TestScopes(t, iam.TestRepo(t, conn, wrapper))
				databaseWrapper, err := kmsCache.GetWrapper(context.Background(), org.PublicId, kms.KeyPurposeDatabase)
				require.NoError(t, err)
				return TestAuthMethod(t, conn, databaseWrapper, org.PublicId, InactiveState, "alice-rp", "alice-secret", WithCertificates(tpCert[0]), WithApiUrl(TestConvertToUrls(t, "https://www.alice.com/callback")[0]))
			},
			updateWith: func(orig *AuthMethod) *AuthMethod {
				am := AllocAuthMethod()
				am.PublicId = orig.PublicId
				am.Name = "alice's restaurant"
				am.Description = "the best place to eat"
				am.AudClaims = []string{"www.alice.com", "www.alice.com/admin"}
				return &am
			},
			fieldMasks: []string{NameField, DescriptionField, AudClaimsField},
			version:    1,
			want: func(orig, updateWith *AuthMethod) *AuthMethod {
				am := orig.Clone()
				am.Name = updateWith.Name
				am.Description = updateWith.Description
				am.AudClaims = updateWith.AudClaims
				return am
			},
		},
		{
			name: "with-dry-run",
			setup: func() *AuthMethod {
				org, _ := iam.TestScopes(t, iam.TestRepo(t, conn, wrapper))
				databaseWrapper, err := kmsCache.GetWrapper(context.Background(), org.PublicId, kms.KeyPurposeDatabase)
				require.NoError(t, err)
				return TestAuthMethod(t,
					conn, databaseWrapper,
					org.PublicId,
					InactiveState,
					"alice-rp", "alice-secret",
					WithAudClaims("www.alice.com"),
					WithCertificates(tpCert[0]),
					WithSigningAlgs(Alg(tpAlg)),
					WithClaimsScopes("email", "profile"),
					WithIssuer(TestConvertToUrls(t, tp.Addr())[0]),
					WithApiUrl(TestConvertToUrls(t, "https://www.alice.com/callback")[0]),
				)
			},
			updateWith: func(orig *AuthMethod) *AuthMethod {
				am := AllocAuthMethod()
				am.PublicId = orig.PublicId
				am.Name = "alice's restaurant"
				am.Description = "the best place to eat"
				am.AudClaims = []string{"www.alice.com/admin"}
				am.ApiUrl = "https://www.bob.com/callback"
				am.ClaimsScopes = []string{"custom-scope1"}
				am.SigningAlgs = []string{string(ES384), string(ES512)}
				return &am
			},
			fieldMasks: []string{NameField, DescriptionField, AudClaimsField, ApiUrlField, SigningAlgsField, ClaimsScopesField},
			version:    1,
			opt:        []Option{WithDryRun()},
			want: func(orig, updateWith *AuthMethod) *AuthMethod {
				am := orig.Clone()
				am.Name = updateWith.Name
				am.Description = updateWith.Description
				am.AudClaims = updateWith.AudClaims
				am.ApiUrl = updateWith.ApiUrl
				am.SigningAlgs = updateWith.SigningAlgs
				am.ClaimsScopes = updateWith.ClaimsScopes
				return am
			},
			wantErrMatch: errors.T(errors.InvalidParameter),
		},
		{
			name: "with-dry-run-on-validated-authmethod",
			setup: func() *AuthMethod {
				org, _ := iam.TestScopes(t, iam.TestRepo(t, conn, wrapper))
				databaseWrapper, err := kmsCache.GetWrapper(context.Background(), org.PublicId, kms.KeyPurposeDatabase)
				require.NoError(t, err)
				return TestAuthMethod(t,
					conn, databaseWrapper,
					org.PublicId,
					InactiveState,
					"alice-rp", "alice-secret",
					WithAudClaims("www.alice.com"),
					WithCertificates(tpCert[0]),
					WithSigningAlgs(Alg(tpAlg)),
					WithClaimsScopes("email", "profile"),
					WithIssuer(TestConvertToUrls(t, tp.Addr())[0]),
					WithApiUrl(TestConvertToUrls(t, "https://www.alice.com/callback")[0]),
				)
			},
			updateWith: func(orig *AuthMethod) *AuthMethod {
				am := AllocAuthMethod()
				am.PublicId = orig.PublicId
				am.Name = "alice's restaurant"
				am.Description = "the best place to eat"
				am.AudClaims = []string{"www.alice.com/admin"}
				am.ApiUrl = "https://www.bob.com/callback"
				return &am
			},
			fieldMasks: []string{NameField, DescriptionField, AudClaimsField, ApiUrlField},
			version:    1,
			opt:        []Option{WithDryRun()},
			want: func(orig, updateWith *AuthMethod) *AuthMethod {
				am := orig.Clone()
				am.Name = updateWith.Name
				am.Description = updateWith.Description
				am.AudClaims = updateWith.AudClaims
				am.ApiUrl = updateWith.ApiUrl
				return am
			},
		},
		{
			name: "attempt-to-update-sub-account-claim-map",
			setup: func() *AuthMethod {
				org, _ := iam.TestScopes(t, iam.TestRepo(t, conn, wrapper))
				databaseWrapper, err := kmsCache.GetWrapper(context.Background(), org.PublicId, kms.KeyPurposeDatabase)
				require.NoError(t, err)
				return TestAuthMethod(t,
					conn, databaseWrapper,
					org.PublicId,
					InactiveState,
					"alice-rp", "alice-secret",
					WithCertificates(tpCert[0]),
					WithSigningAlgs(Alg(tpAlg)),
					WithClaimsScopes("email", "profile"),
					WithAccountClaimMap(map[string]AccountToClaim{"oid": "sub"}),
					WithApiUrl(TestConvertToUrls(t, "https://www.alice.com/callback")[0]),
				)
			},
			updateWith: func(orig *AuthMethod) *AuthMethod {
				am := AllocAuthMethod()
				am.PublicId = orig.PublicId
				am.AccountClaimMaps = []string{"uid=sub"}
				return &am
			},
			fieldMasks:   []string{AccountClaimMapsField},
			version:      1,
			wantErrMatch: errors.T(errors.InvalidParameter),
		},
		{
			name:         "nil-authMethod",
			setup:        func() *AuthMethod { return nil },
			updateWith:   func(orig *AuthMethod) *AuthMethod { return nil },
			fieldMasks:   []string{NameField},
			version:      1,
			wantErrMatch: errors.T(errors.InvalidParameter),
		},
		{
			name:         "nil-authMethod-store",
			setup:        func() *AuthMethod { return nil },
			updateWith:   func(orig *AuthMethod) *AuthMethod { return &AuthMethod{} },
			fieldMasks:   []string{NameField},
			version:      1,
			wantErrMatch: errors.T(errors.InvalidParameter),
		},
		{
			name:         "missing-public-id",
			setup:        func() *AuthMethod { return nil },
			updateWith:   func(orig *AuthMethod) *AuthMethod { a := AllocAuthMethod(); return &a },
			fieldMasks:   []string{NameField},
			version:      1,
			wantErrMatch: errors.T(errors.InvalidParameter),
		},
		{
			name:  "bad-field-mask",
			setup: func() *AuthMethod { return nil },
			updateWith: func(orig *AuthMethod) *AuthMethod {
				a := AllocAuthMethod()
				id, _ := newAuthMethodId(ctx)
				a.PublicId = id
				return &a
			},
			fieldMasks:   []string{"CreateTime"},
			version:      1,
			wantErrMatch: errors.T(errors.InvalidParameter),
		},
		{
			name:  "no-mask-or-null-fields",
			setup: func() *AuthMethod { return nil },
			updateWith: func(orig *AuthMethod) *AuthMethod {
				a := AllocAuthMethod()
				id, _ := newAuthMethodId(ctx)
				a.PublicId = id
				return &a
			},
			version:      1,
			wantErrMatch: errors.T(errors.EmptyFieldMask),
		},
		{
			name:  "not-found",
			setup: func() *AuthMethod { return nil },
			updateWith: func(orig *AuthMethod) *AuthMethod {
				a := AllocAuthMethod()
				id, _ := newAuthMethodId(ctx)
				a.PublicId = id
				return &a
			},
			fieldMasks:   []string{NameField},
			version:      1,
			wantErrMatch: errors.T(errors.RecordNotFound),
		},
		{
			name: "bad-version",
			setup: func() *AuthMethod {
				org, _ := iam.TestScopes(t, iam.TestRepo(t, conn, wrapper))
				databaseWrapper, err := kmsCache.GetWrapper(context.Background(), org.PublicId, kms.KeyPurposeDatabase)
				require.NoError(t, err)
				return TestAuthMethod(t, conn, databaseWrapper, org.PublicId, InactiveState, "alice-rp", "alice-secret", WithAudClaims("www.alice.com"), WithCertificates(tpCert[0]), WithSigningAlgs(Alg(tpAlg)), WithApiUrl(TestConvertToUrls(t, "https://www.alice.com/callback")[0]))
			},
			updateWith: func(orig *AuthMethod) *AuthMethod {
				am := AllocAuthMethod()
				am.PublicId = orig.PublicId
				am.Name = "alice's restaurant"
				return &am
			},
			fieldMasks:   []string{NameField},
			version:      100,
			wantErrMatch: errors.T(errors.VersionMismatch),
		},
		{
			name: "not-valid-auth-method",
			setup: func() *AuthMethod {
				org, _ := iam.TestScopes(t, iam.TestRepo(t, conn, wrapper))
				databaseWrapper, err := kmsCache.GetWrapper(context.Background(), org.PublicId, kms.KeyPurposeDatabase)
				require.NoError(t, err)
				return TestAuthMethod(t,
					conn, databaseWrapper,
					org.PublicId,
					InactiveState,
					"alice-rp", "alice-secret",
					WithAudClaims("www.alice.com"),
					WithCertificates(tpCert[0]),
					WithSigningAlgs(Alg(tpAlg)),
					WithIssuer(TestConvertToUrls(t, tp.Addr())[0]),
					WithApiUrl(TestConvertToUrls(t, "https://www.alice.com/callback")[0]),
				)
			},
			updateWith: func(orig *AuthMethod) *AuthMethod {
				am := AllocAuthMethod()
				am.PublicId = orig.PublicId
				am.Name = "alice's restaurant"
				am.Description = "the best place to eat"
				am.SigningAlgs = []string{string(ES384), string(ES512)}
				return &am
			},
			fieldMasks:   []string{NameField, DescriptionField, SigningAlgsField},
			version:      1,
			wantErrMatch: errors.T(errors.InvalidParameter),
		},
		{
			name: "active-with-update-to-incomplete",
			setup: func() *AuthMethod {
				org, _ := iam.TestScopes(t, iam.TestRepo(t, conn, wrapper))
				databaseWrapper, err := kmsCache.GetWrapper(context.Background(), org.PublicId, kms.KeyPurposeDatabase)
				require.NoError(t, err)
				return TestAuthMethod(t, conn, databaseWrapper, org.PublicId, ActivePublicState, "alice-rp", "alice-secret", WithCertificates(tpCert[0]), WithSigningAlgs(Alg(tpAlg)), WithApiUrl(TestConvertToUrls(t, "https://www.alice.com/callback")[0]))
			},
			updateWith: func(orig *AuthMethod) *AuthMethod {
				am := AllocAuthMethod()
				am.PublicId = orig.PublicId
				return &am
			},
			fieldMasks:   []string{SigningAlgsField},
			version:      2, // since TestAuthMethod(...) did an update to get it to ActivePublicState
			wantErrMatch: errors.T(errors.InvalidParameter),
		},
		{
			name: "update-with-prompt",
			setup: func() *AuthMethod {
				org, _ := iam.TestScopes(t, iam.TestRepo(t, conn, wrapper))
				databaseWrapper, err := kmsCache.GetWrapper(context.Background(), org.PublicId, kms.KeyPurposeDatabase)
				require.NoError(t, err)
				return TestAuthMethod(
					t,
					conn,
					databaseWrapper,
					org.PublicId,
					InactiveState,
					"alice-rp",
					"alice-secret",
					WithCertificates(tpCert[0]),
					WithSigningAlgs(Alg(tpAlg)),
				)
			},
			updateWith: func(orig *AuthMethod) *AuthMethod {
				am := AllocAuthMethod()
				am.PublicId = orig.PublicId
				am.Prompts = []string{string(SelectAccount)}
				return &am
			},
			fieldMasks: []string{PromptsField},
			version:    1,
			want: func(orig, updateWith *AuthMethod) *AuthMethod {
				am := orig.Clone()
				am.Prompts = updateWith.Prompts
				return am
			},
		},
		{
			name: "update-with-existing-prompt",
			setup: func() *AuthMethod {
				org, _ := iam.TestScopes(t, iam.TestRepo(t, conn, wrapper))
				databaseWrapper, err := kmsCache.GetWrapper(context.Background(), org.PublicId, kms.KeyPurposeDatabase)
				require.NoError(t, err)
				return TestAuthMethod(
					t,
					conn,
					databaseWrapper,
					org.PublicId,
					InactiveState,
					"alice-rp",
					"alice-secret",
					WithCertificates(tpCert[0]),
					WithSigningAlgs(Alg(tpAlg)),
					WithPrompts(Consent),
				)
			},
			updateWith: func(orig *AuthMethod) *AuthMethod {
				am := AllocAuthMethod()
				am.PublicId = orig.PublicId
				am.Prompts = []string{string(SelectAccount)}
				return &am
			},
			fieldMasks: []string{PromptsField},
			version:    1,
			want: func(orig, updateWith *AuthMethod) *AuthMethod {
				am := orig.Clone()
				am.Prompts = updateWith.Prompts
				return am
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert, require := assert.New(t), require.New(t)
			orig := tt.setup()
			updateWith := tt.updateWith(orig)
			updated, rowsUpdated, err := repo.UpdateAuthMethod(ctx, updateWith, tt.version, tt.fieldMasks, tt.opt...)
			opts := getOpts(tt.opt...)
			if tt.wantErrMatch != nil && !opts.withDryRun {
				require.Error(err)
				assert.Equal(0, rowsUpdated)
				assert.Nil(updated)
				assert.Truef(errors.Match(tt.wantErrMatch, err), "want err code: %q got: %q", tt.wantErrMatch.Code, err)

				if updateWith != nil && updateWith.AuthMethod != nil && updateWith.PublicId != "" {
					err := db.TestVerifyOplog(t, rw, updateWith.PublicId, db.WithOperation(oplog.OpType_OP_TYPE_UPDATE), db.WithCreateNotBefore(10*time.Second))
					require.Errorf(err, "should not have found oplog entry for %s", updateWith.PublicId)
				}
				return
			}
			switch opts.withDryRun {
			case true:
				assert.Equal(0, rowsUpdated)
				switch tt.wantErrMatch != nil {
				case true:
					require.Error(err)
				default:
					require.NoError(err)
				}
				require.NotNil(updated)
				want := tt.want(orig, updateWith)
				want.CreateTime = orig.CreateTime
				want.UpdateTime = orig.UpdateTime
				want.Version = orig.Version
				TestSortAuthMethods(t, []*AuthMethod{want, updated})
				assert.Equal(want, updated)

				err := db.TestVerifyOplog(t, rw, updateWith.PublicId, db.WithOperation(oplog.OpType_OP_TYPE_UPDATE), db.WithCreateNotBefore(10*time.Second))
				require.Errorf(err, "should not have found oplog entry for %s", updateWith.PublicId)
			default:
				require.NoError(err)
				require.NotNil(updated)
				want := tt.want(orig, updateWith)
				want.CreateTime = updated.CreateTime
				want.UpdateTime = updated.UpdateTime
				want.Version = updated.Version
				TestSortAuthMethods(t, []*AuthMethod{want, updated})
				assert.Empty(cmp.Diff(updated.AuthMethod, want.AuthMethod, protocmp.Transform()))
				if !tt.wantNoRowsUpdate {
					assert.Equal(1, rowsUpdated)
					err = db.TestVerifyOplog(t, rw, updateWith.PublicId, db.WithOperation(oplog.OpType_OP_TYPE_UPDATE), db.WithCreateNotBefore(10*time.Second))
					require.NoErrorf(err, "unexpected error verifying oplog entry: %s", err)
				}
				found, err := repo.LookupAuthMethod(ctx, want.PublicId)
				require.NoError(err)
				TestSortAuthMethods(t, []*AuthMethod{found})
				assert.Empty(cmp.Diff(found.AuthMethod, want.AuthMethod, protocmp.Transform()))
			}
		})
	}
}

func Test_DisableDiscoveredConfigValidation(t *testing.T) {
	t.Parallel()
	assert, require := assert.New(t), require.New(t)
	ctx := context.Background()
	conn, _ := db.TestSetup(t, "postgres")
	wrapper := db.TestWrapper(t)
	kmsCache := kms.TestKms(t, conn, wrapper)

	tp := oidc.StartTestProvider(t)
	tpClientId := "alice-rp"
	tpClientSecret := "her-dog's-name"
	tp.SetClientCreds(tpClientId, tpClientSecret)
	_, _, tpAlg, _ := tp.SigningKeys()
	tpCert, err := ParseCertificates(ctx, tp.CACert())
	require.NoError(err)
	require.Equal(1, len(tpCert))

	rw := db.New(conn)
	repo, err := NewRepository(ctx, rw, rw, kmsCache)
	require.NoError(err)
	org, _ := iam.TestScopes(t, iam.TestRepo(t, conn, wrapper))
	databaseWrapper, err := kmsCache.GetWrapper(context.Background(), org.PublicId, kms.KeyPurposeDatabase)
	require.NoError(err)
	am := TestAuthMethod(t,
		conn, databaseWrapper,
		org.PublicId,
		InactiveState,
		"alice-rp", "alice-secret",
		WithAudClaims("www.alice.com"),
		WithCertificates(tpCert[0]),
		WithSigningAlgs(Alg(tpAlg)),
		WithIssuer(TestConvertToUrls(t, tp.Addr())[0]),
		WithApiUrl(TestConvertToUrls(t, "https://www.alice.com/callback")[0]),
	)

	updateWith := am.Clone()
	updateWith.Name = "alice's restaurant"
	updatedWithForce, rowsUpdated, err := repo.UpdateAuthMethod(ctx, updateWith, updateWith.Version, []string{NameField}, WithForce())
	require.NoError(err)
	assert.Equal(1, rowsUpdated)
	assert.Equal(true, updatedWithForce.DisableDiscoveredConfigValidation)

	updateWith.Name = "alice and eve's restaurant"
	updatedWithoutForce, rowsUpdated, err := repo.UpdateAuthMethod(ctx, updatedWithForce, updatedWithForce.Version, []string{NameField})
	require.NoError(err)
	assert.Equal(1, rowsUpdated)
	assert.Equal(false, updatedWithoutForce.DisableDiscoveredConfigValidation)

	privWithForce, err := repo.MakePrivate(ctx, updatedWithForce.PublicId, updatedWithoutForce.Version, WithForce())
	require.NoError(err)
	assert.Equal(true, privWithForce.DisableDiscoveredConfigValidation)

	privWithoutForce, err := repo.MakePrivate(ctx, privWithForce.PublicId, privWithForce.Version)
	require.NoError(err)
	assert.Equal(false, privWithoutForce.DisableDiscoveredConfigValidation)

	pubWithForce, err := repo.MakePublic(ctx, privWithoutForce.PublicId, privWithoutForce.Version, WithForce())
	require.NoError(err)
	assert.Equal(true, pubWithForce.DisableDiscoveredConfigValidation)
	pubWithoutForce, err := repo.MakePrivate(ctx, pubWithForce.PublicId, pubWithForce.Version)
	require.NoError(err)
	assert.Equal(false, pubWithoutForce.DisableDiscoveredConfigValidation)
}

func Test_ValidateDiscoveryInfo(t *testing.T) {
	// do not run these tests with t.Parallel()
	ctx := context.Background()

	tp := oidc.StartTestProvider(t, oidc.WithTestHost("::1"))
	tpClientId := "alice-rp"
	tpClientSecret := "her-dog's-name"
	tp.SetClientCreds(tpClientId, tpClientSecret)
	_, _, tpAlg, _ := tp.SigningKeys()
	tpCert, err := ParseCertificates(ctx, tp.CACert())
	require.NoError(t, err)
	require.Equal(t, 1, len(tpCert))

	conn, _ := db.TestSetup(t, "postgres")
	wrapper := db.TestWrapper(t)
	kmsCache := kms.TestKms(t, conn, wrapper)
	org, _ := iam.TestScopes(t, iam.TestRepo(t, conn, wrapper))
	rw := db.New(conn)
	repo, err := NewRepository(ctx, rw, rw, kmsCache)
	require.NoError(t, err)

	databaseWrapper, err := kmsCache.GetWrapper(context.Background(), org.PublicId, kms.KeyPurposeDatabase)
	require.NoError(t, err)
	port := testutil.TestFreePort(t)
	testAuthMethodCallback, err := url.Parse(fmt.Sprintf("http://[::1]:%d/callback", port))
	require.NoError(t, err)
	testAuthMethod := TestAuthMethod(t,
		conn, databaseWrapper,
		org.PublicId,
		ActivePrivateState,
		tpClientId, ClientSecret(tpClientSecret),
		WithCertificates(tpCert[0]),
		WithSigningAlgs(Alg(tpAlg)),
		WithIssuer(TestConvertToUrls(t, tp.Addr())[0]),
		WithApiUrl(testAuthMethodCallback),
	)
	tests := []struct {
		name            string
		setup           func()
		cleanup         func()
		authMethod      *AuthMethod
		withAuthMethod  bool
		withPublicId    bool
		wantErrMatch    *errors.Template
		wantErrContains string
	}{
		{
			name:           "simple-and-valid",
			authMethod:     testAuthMethod,
			withAuthMethod: true,
		},
		{
			name:         "simple-and-valid",
			authMethod:   testAuthMethod,
			withPublicId: true,
		},
		{
			name:         "missing-withPublicId-or-withAuthMethod",
			authMethod:   testAuthMethod,
			wantErrMatch: errors.T(errors.InvalidParameter),
		},
		{
			name:            "not-complete",
			authMethod:      func() *AuthMethod { cp := testAuthMethod.Clone(); cp.SigningAlgs = nil; return cp }(),
			withAuthMethod:  true,
			wantErrMatch:    errors.T(errors.InvalidParameter),
			wantErrContains: " missing signing algorithms",
		},
		{
			name: "no-discovery",
			authMethod: func() *AuthMethod {
				cp := testAuthMethod.Clone()
				port := testutil.TestFreePort(t)
				cp.Issuer = fmt.Sprintf("http://[::1]:%d", port)
				return cp
			}(),
			withAuthMethod:  true,
			wantErrMatch:    errors.T(errors.InvalidParameter),
			wantErrContains: "AuthMethod cannot be converted to a valid OIDC Provider",
		},
		{
			name:            "fail-jwks",
			setup:           func() { tp.SetDisableJWKs(true) },
			cleanup:         func() { tp.SetDisableJWKs(false) },
			authMethod:      testAuthMethod,
			withAuthMethod:  true,
			wantErrMatch:    errors.T(errors.Unknown),
			wantErrContains: "non-200",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert, require := assert.New(t), require.New(t)
			var opts []Option
			switch {
			case tt.withAuthMethod:
				opts = append(opts, WithAuthMethod(tt.authMethod))
			case tt.withPublicId:
				opts = append(opts, WithPublicId(tt.authMethod.PublicId))
			}
			if tt.setup != nil {
				tt.setup()
				defer tt.cleanup()
			}
			err := repo.ValidateDiscoveryInfo(ctx, opts...)
			if tt.wantErrMatch != nil {
				require.Error(err)
				assert.Truef(errors.Match(tt.wantErrMatch, err), "want err code: %q got: %q", tt.wantErrMatch.Code, err)
				if tt.wantErrContains != "" {
					assert.Containsf(err.Error(), tt.wantErrContains, "want err to contain %s got: %s", tt.wantErrContains, err.Error())
				}
				return
			}
			require.NoError(err)
		})
	}
}

func Test_valueObjectChanges(t *testing.T) {
	t.Parallel()
	ctx := context.TODO()
	_, pem1 := testGenerateCA(t, "localhost")
	_, pem2 := testGenerateCA(t, "127.0.0.1")
	_, pem3 := testGenerateCA(t, "www.example.com")
	tests := []struct {
		name         string
		id           string
		voName       voName
		new          []string
		old          []string
		dbMask       []string
		nullFields   []string
		wantAdd      []any
		wantDel      []any
		wantErrMatch *errors.Template
	}{
		{
			name:   string(SigningAlgVO),
			id:     "am-public-id",
			voName: SigningAlgVO,
			new:    []string{"ES256", "ES384"},
			old:    []string{"RS256", "RS384", "RS512"},
			dbMask: []string{string(SigningAlgVO)},
			wantAdd: func() []any {
				a, err := NewSigningAlg(ctx, "am-public-id", ES256)
				require.NoError(t, err)
				a2, err := NewSigningAlg(ctx, "am-public-id", ES384)
				require.NoError(t, err)
				return []any{a, a2}
			}(),
			wantDel: func() []any {
				a, err := NewSigningAlg(ctx, "am-public-id", RS256)
				require.NoError(t, err)
				a2, err := NewSigningAlg(ctx, "am-public-id", RS384)
				require.NoError(t, err)
				a3, err := NewSigningAlg(ctx, "am-public-id", RS512)
				require.NoError(t, err)
				return []any{a, a2, a3}
			}(),
		},
		{
			name:   string(CertificateVO),
			id:     "am-public-id",
			voName: CertificateVO,
			new:    []string{pem1, pem2},
			old:    []string{pem3},
			dbMask: []string{string(CertificateVO)},
			wantAdd: func() []any {
				c, err := NewCertificate(ctx, "am-public-id", pem1)
				require.NoError(t, err)
				c2, err := NewCertificate(ctx, "am-public-id", pem2)
				require.NoError(t, err)
				return []any{c, c2}
			}(),
			wantDel: func() []any {
				c, err := NewCertificate(ctx, "am-public-id", pem3)
				require.NoError(t, err)
				return []any{c}
			}(),
		},
		{
			name:   string(AudClaimVO),
			id:     "am-public-id",
			voName: AudClaimVO,
			new:    []string{"new-aud1", "new-aud2"},
			old:    []string{"old-aud1", "old-aud2", "old-aud3"},
			dbMask: []string{string(AudClaimVO)},
			wantAdd: func() []any {
				a, err := NewAudClaim(ctx, "am-public-id", "new-aud1")
				require.NoError(t, err)
				a2, err := NewAudClaim(ctx, "am-public-id", "new-aud2")
				require.NoError(t, err)
				return []any{a, a2}
			}(),
			wantDel: func() []any {
				a, err := NewAudClaim(ctx, "am-public-id", "old-aud1")
				require.NoError(t, err)
				a2, err := NewAudClaim(ctx, "am-public-id", "old-aud2")
				require.NoError(t, err)
				a3, err := NewAudClaim(ctx, "am-public-id", "old-aud3")
				require.NoError(t, err)
				return []any{a, a2, a3}
			}(),
		},

		{
			name:       string(AudClaimVO) + "-null-fields",
			id:         "am-public-id",
			voName:     AudClaimVO,
			new:        nil,
			old:        []string{"old-aud1", "old-aud2", "old-aud3"},
			nullFields: []string{string(AudClaimVO)},
			wantDel: func() []any {
				a, err := NewAudClaim(ctx, "am-public-id", "old-aud1")
				require.NoError(t, err)
				a2, err := NewAudClaim(ctx, "am-public-id", "old-aud2")
				require.NoError(t, err)
				a3, err := NewAudClaim(ctx, "am-public-id", "old-aud3")
				require.NoError(t, err)
				return []any{a, a2, a3}
			}(),
		},
		{
			name:   string(ClaimsScopesVO),
			id:     "am-public-id",
			voName: ClaimsScopesVO,
			new:    []string{"new-scope1", "new-scope2"},
			old:    []string{"old-scope1", "old-scope2", "old-scope3"},
			dbMask: []string{string(ClaimsScopesVO)},
			wantAdd: func() []any {
				cs, err := NewClaimsScope(ctx, "am-public-id", "new-scope1")
				require.NoError(t, err)
				cs2, err := NewClaimsScope(ctx, "am-public-id", "new-scope2")
				require.NoError(t, err)
				return []any{cs, cs2}
			}(),
			wantDel: func() []any {
				cs, err := NewClaimsScope(ctx, "am-public-id", "old-scope1")
				require.NoError(t, err)
				cs2, err := NewClaimsScope(ctx, "am-public-id", "old-scope2")
				require.NoError(t, err)
				cs3, err := NewClaimsScope(ctx, "am-public-id", "old-scope3")
				require.NoError(t, err)
				return []any{cs, cs2, cs3}
			}(),
		},
		{
			name:       string(ClaimsScopesVO) + "-null-fields",
			id:         "am-public-id",
			voName:     ClaimsScopesVO,
			new:        nil,
			old:        []string{"old-scope1", "old-scope2", "old-scope3"},
			nullFields: []string{string(ClaimsScopesVO)},
			wantDel: func() []any {
				cs, err := NewClaimsScope(ctx, "am-public-id", "old-scope1")
				require.NoError(t, err)
				cs2, err := NewClaimsScope(ctx, "am-public-id", "old-scope2")
				require.NoError(t, err)
				cs3, err := NewClaimsScope(ctx, "am-public-id", "old-scope3")
				require.NoError(t, err)
				return []any{cs, cs2, cs3}
			}(),
		},
		{
			name:       "missing-public-id",
			voName:     AudClaimVO,
			new:        nil,
			old:        []string{"old-aud1", "old-aud2", "old-aud3"},
			nullFields: []string{string(AudClaimVO)},
			wantDel: func() []any {
				a, err := NewAudClaim(ctx, "am-public-id", "old-aud1")
				require.NoError(t, err)
				a2, err := NewAudClaim(ctx, "am-public-id", "old-aud2")
				require.NoError(t, err)
				a3, err := NewAudClaim(ctx, "am-public-id", "old-aud3")
				require.NoError(t, err)
				return []any{a, a2, a3}
			}(),
			wantErrMatch: errors.T(errors.InvalidParameter),
		},
		{
			name:       "invalid-vo-name",
			voName:     voName("invalid-name"),
			id:         "am-public-id",
			new:        nil,
			old:        []string{"old-aud1", "old-aud2", "old-aud3"},
			nullFields: []string{string(AudClaimVO)},
			wantDel: func() []any {
				a, err := NewAudClaim(ctx, "am-public-id", "old-aud1")
				require.NoError(t, err)
				a2, err := NewAudClaim(ctx, "am-public-id", "old-aud2")
				require.NoError(t, err)
				a3, err := NewAudClaim(ctx, "am-public-id", "old-aud3")
				require.NoError(t, err)
				return []any{a, a2, a3}
			}(),
			wantErrMatch: errors.T(errors.InvalidParameter),
		},
		{
			name:   "dup-new",
			id:     "am-public-id",
			voName: SigningAlgVO,
			new:    []string{"ES256", "ES256"},
			old:    []string{"RS256", "RS384", "RS512"},
			dbMask: []string{string(SigningAlgVO)},
			wantAdd: func() []any {
				a, err := NewSigningAlg(ctx, "am-public-id", ES256)
				require.NoError(t, err)
				a2, err := NewSigningAlg(ctx, "am-public-id", ES384)
				require.NoError(t, err)
				return []any{a, a2}
			}(),
			wantDel: func() []any {
				a, err := NewSigningAlg(ctx, "am-public-id", RS256)
				require.NoError(t, err)
				a2, err := NewSigningAlg(ctx, "am-public-id", RS384)
				require.NoError(t, err)
				a3, err := NewSigningAlg(ctx, "am-public-id", RS512)
				require.NoError(t, err)
				return []any{a, a2, a3}
			}(),
			wantErrMatch: errors.T(errors.InvalidParameter),
		},
		{
			name:   "dup-old",
			id:     "am-public-id",
			voName: SigningAlgVO,
			new:    []string{"ES256", "ES384"},
			old:    []string{"RS256", "RS256", "RS512"},
			dbMask: []string{string(SigningAlgVO)},
			wantAdd: func() []any {
				a, err := NewSigningAlg(ctx, "am-public-id", ES256)
				require.NoError(t, err)
				a2, err := NewSigningAlg(ctx, "am-public-id", ES384)
				require.NoError(t, err)
				return []any{a, a2}
			}(),
			wantDel: func() []any {
				a, err := NewSigningAlg(ctx, "am-public-id", RS256)
				require.NoError(t, err)
				a2, err := NewSigningAlg(ctx, "am-public-id", RS384)
				require.NoError(t, err)
				a3, err := NewSigningAlg(ctx, "am-public-id", RS512)
				require.NoError(t, err)
				return []any{a, a2, a3}
			}(),
			wantErrMatch: errors.T(errors.InvalidParameter),
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert, require := assert.New(t), require.New(t)
			gotAdd, gotDel, err := valueObjectChanges(context.TODO(), tt.id, tt.voName, tt.new, tt.old, tt.dbMask, tt.nullFields)
			if tt.wantErrMatch != nil {
				require.Error(err)
				assert.Truef(errors.Match(tt.wantErrMatch, err), "want err code: %q got: %q", tt.wantErrMatch.Code, err)
				return
			}
			require.NoError(err)
			assert.Equal(tt.wantAdd, gotAdd)

			switch tt.voName {
			case CertificateVO:
				sort.Slice(gotDel, func(a, b int) bool {
					aa := gotDel[a]
					bb := gotDel[b]
					return aa.(*Certificate).Cert < bb.(*Certificate).Cert
				})
			case SigningAlgVO:
				sort.Slice(gotDel, func(a, b int) bool {
					aa := gotDel[a]
					bb := gotDel[b]
					return aa.(*SigningAlg).Alg < bb.(*SigningAlg).Alg
				})
			case AudClaimVO:
				sort.Slice(gotDel, func(a, b int) bool {
					aa := gotDel[a]
					bb := gotDel[b]
					return aa.(*AudClaim).Aud < bb.(*AudClaim).Aud
				})
			case ClaimsScopesVO:
				sort.Slice(gotDel, func(a, b int) bool {
					aa := gotDel[a]
					bb := gotDel[b]
					return aa.(*ClaimsScope).Scope < bb.(*ClaimsScope).Scope
				})
			}
			assert.Equalf(tt.wantDel, gotDel, "wantDel: %s\ngotDel:  %s\n", tt.wantDel, gotDel)
		})
	}
}

func Test_validateFieldMask(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name      string
		fieldMask []string
		wantErr   bool
	}{
		{
			name: "all-valid-fields",
			fieldMask: []string{
				NameField,
				DescriptionField,
				IssuerField,
				ClientIdField,
				ClientSecretField,
				MaxAgeField,
				SigningAlgsField,
				ApiUrlField,
				AudClaimsField,
				CertificatesField,
				ClaimsScopesField,
				PromptsField,
			},
		},
		{
			name:      "invalid",
			fieldMask: []string{"Invalid", NameField},
			wantErr:   true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			require := require.New(t)
			err := validateFieldMask(context.TODO(), tt.fieldMask)
			if tt.wantErr {
				require.Error(err)
				return
			}
			require.NoError(err)
		})
	}
}

func Test_applyUpdate(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name      string
		new       *AuthMethod
		orig      *AuthMethod
		fieldMask []string
		want      *AuthMethod
	}{
		{
			name: "valid-all-fields",
			new: &AuthMethod{
				AuthMethod: &store.AuthMethod{
					Name:             "new-name",
					Description:      "new-description",
					OperationalState: string(ActivePublicState),
					Issuer:           "new-issuer",
					ClientId:         "new-client-id",
					ClientSecret:     "new-client-secret",
					MaxAge:           100,
					SigningAlgs:      []string{"new-alg1", "new-alg2"},
					ApiUrl:           "new-callback-1",
					AudClaims:        []string{"new-aud-1", "new-aud-2"},
					Certificates:     []string{"new-pem1", "new-pem-2"},
					ClaimsScopes:     []string{"new-scope1", "new-scope2"},
					Prompts:          []string{string(SelectAccount)},
				},
			},
			orig: &AuthMethod{
				AuthMethod: &store.AuthMethod{
					Name:             "orig-name",
					Description:      "orig-description",
					OperationalState: string(InactiveState),
					Issuer:           "orig-issuer",
					ClientId:         "orig-client-id",
					ClientSecret:     "orig-client-secret",
					MaxAge:           100,
					SigningAlgs:      []string{"orig-alg1", "orig-alg2"},
					ApiUrl:           "orig-callback-1",
					AudClaims:        []string{"orig-aud-1", "orig-aud-2"},
					Certificates:     []string{"orig-pem1", "orig-pem-2"},
					ClaimsScopes:     []string{"orig-scope1", "orig-scope2"},
					Prompts:          []string{string(None)},
				},
			},
			want: &AuthMethod{
				AuthMethod: &store.AuthMethod{
					Name:             "new-name",
					Description:      "new-description",
					OperationalState: string(InactiveState),
					Issuer:           "new-issuer",
					ClientId:         "new-client-id",
					ClientSecret:     "new-client-secret",
					MaxAge:           100,
					SigningAlgs:      []string{"new-alg1", "new-alg2"},
					ApiUrl:           "new-callback-1",
					AudClaims:        []string{"new-aud-1", "new-aud-2"},
					Certificates:     []string{"new-pem1", "new-pem-2"},
					ClaimsScopes:     []string{"new-scope1", "new-scope2"},
					Prompts:          []string{string(SelectAccount)},
				},
			},
			fieldMask: []string{
				NameField,
				DescriptionField,
				IssuerField,
				ClientIdField,
				ClientSecretField,
				MaxAgeField,
				SigningAlgsField,
				ApiUrlField,
				AudClaimsField,
				CertificatesField,
				ClaimsScopesField,
				PromptsField,
			},
		},
		{
			name: "nil-value-objects",
			new: &AuthMethod{
				AuthMethod: &store.AuthMethod{
					Name:             "new-name",
					Description:      "new-description",
					OperationalState: string(ActivePublicState),
					Issuer:           "new-issuer",
					ClientId:         "new-client-id",
					ClientSecret:     "new-client-secret",
					MaxAge:           100,
				},
			},
			orig: &AuthMethod{
				AuthMethod: &store.AuthMethod{
					Name:             "orig-name",
					Description:      "orig-description",
					OperationalState: string(InactiveState),
					Issuer:           "orig-issuer",
					ClientId:         "orig-client-id",
					ClientSecret:     "orig-client-secret",
					MaxAge:           100,
					SigningAlgs:      []string{"orig-alg1", "orig-alg2"},
					ApiUrl:           "orig-callback-1",
					AudClaims:        []string{"orig-aud-1", "orig-aud-2"},
					Certificates:     []string{"orig-pem1", "orig-pem-2"},
					ClaimsScopes:     []string{"orig-scope1", "orig-scope2"},
					Prompts:          []string{string(SelectAccount)},
				},
			},
			want: &AuthMethod{
				AuthMethod: &store.AuthMethod{
					Name:             "new-name",
					Description:      "new-description",
					OperationalState: string(InactiveState),
					Issuer:           "new-issuer",
					ClientId:         "new-client-id",
					ClientSecret:     "new-client-secret",
					MaxAge:           100,
				},
			},
			fieldMask: []string{
				NameField,
				DescriptionField,
				IssuerField,
				ClientIdField,
				ClientSecretField,
				MaxAgeField,
				SigningAlgsField,
				ApiUrlField,
				AudClaimsField,
				CertificatesField,
				ClaimsScopesField,
				PromptsField,
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert := assert.New(t)
			got := applyUpdate(tt.new, tt.orig, tt.fieldMask)
			assert.Empty(cmp.Diff(got, tt.want, protocmp.Transform()))
		})
	}
}

type mockClient struct {
	mockDo func(req *http.Request) (*http.Response, error)
}

// Overriding what the Do function should "do" in our MockClient
func (m *mockClient) Do(req *http.Request) (*http.Response, error) {
	return m.mockDo(req)
}

func Test_pingEndpoint(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	tests := []struct {
		name       string
		setup      func() (HTTPClient, string, string)
		wantStatus int
		wantErr    bool
	}{
		{
			name: "valid-endpoint",
			setup: func() (HTTPClient, string, string) {
				client := &mockClient{
					mockDo: func(*http.Request) (*http.Response, error) {
						return &http.Response{
							StatusCode: 200,
						}, nil
					},
				}
				return client, http.MethodGet, "http://[::1]/get"
			},
			wantStatus: 200,
		},
		{
			name: "valid-500",
			setup: func() (HTTPClient, string, string) {
				client := &mockClient{
					mockDo: func(*http.Request) (*http.Response, error) {
						return &http.Response{
							StatusCode: 500,
						}, nil
					},
				}
				return client, http.MethodGet, "http://[::1]/get"
			},
			wantStatus: 500,
		},
		{
			name: "failed",
			setup: func() (HTTPClient, string, string) {
				client := &mockClient{
					mockDo: func(*http.Request) (*http.Response, error) {
						return nil, fmt.Errorf("invalid request")
					},
				}
				return client, http.MethodGet, "http://[::1]/get"
			},
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert, require := assert.New(t), require.New(t)
			client, method, url := tt.setup()
			gotStatus, err := pingEndpoint(ctx, client, tt.name, method, url)
			assert.Equal(gotStatus, tt.wantStatus)
			if tt.wantErr {
				require.Error(err)
				return
			}
			require.NoError(err)
		})
	}
}
