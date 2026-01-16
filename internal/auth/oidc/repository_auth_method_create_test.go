// Copyright IBM Corp. 2020, 2025
// SPDX-License-Identifier: BUSL-1.1

package oidc

import (
	"context"
	"crypto/x509"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"
	"github.com/hashicorp/boundary/internal/db"
	"github.com/hashicorp/boundary/internal/errors"
	"github.com/hashicorp/boundary/internal/iam"
	"github.com/hashicorp/boundary/internal/kms"
	"github.com/hashicorp/boundary/internal/oplog"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/testing/protocmp"
)

func TestRepository_CreateAuthMethod(t *testing.T) {
	conn, _ := db.TestSetup(t, "postgres")
	rw := db.New(conn)
	wrapper := db.TestWrapper(t)
	kmsCache := kms.TestKms(t, conn, wrapper)
	ctx := context.Background()
	org, _ := iam.TestScopes(t, iam.TestRepo(t, conn, wrapper))

	convertAlg := func(alg ...Alg) []string {
		s := make([]string, 0, len(alg))
		for _, a := range alg {
			s = append(s, string(a))
		}
		return s
	}

	convertPrompts := func(prompts ...PromptParam) []string {
		s := make([]string, 0, len(prompts))
		for _, a := range prompts {
			s = append(s, string(a))
		}
		return s
	}
	tests := []struct {
		name         string
		am           func(*testing.T) *AuthMethod
		opt          []Option
		wantErrMatch *errors.Template
	}{
		{
			name: "valid",
			am: func(t *testing.T) *AuthMethod {
				algs := []Alg{RS256, ES256}
				cbs := TestConvertToUrls(t, "https://www.alice.com/callback")[0]
				auds := []string{"alice-rp", "bob-rp"}
				prompts := []PromptParam{"consent", "select_account"}
				cert1, pem1 := testGenerateCA(t, "localhost")
				cert2, pem2 := testGenerateCA(t, "localhost")
				certs := []*x509.Certificate{cert1, cert2}
				pems := []string{pem1, pem2}
				am, err := NewAuthMethod(
					ctx,
					org.PublicId,
					"alice-rp",
					"alice-secret", WithAudClaims("alice-rp"),
					WithAudClaims(auds...),
					WithIssuer(TestConvertToUrls(t, "https://www.alice.com")[0]),
					WithApiUrl(cbs),
					WithSigningAlgs(algs...),
					WithCertificates(certs...),
					WithName("alice's restaurant"),
					WithDescription("it's a good place to eat"),
					WithClaimsScopes("email", "profile"),
					WithPrompts(prompts...),
					WithAccountClaimMap(map[string]AccountToClaim{"display_name": ToNameClaim, "oid": ToSubClaim}),
				)
				require.NoError(t, err)
				require.Equal(t, am.SigningAlgs, convertAlg(algs...))
				require.Equal(t, am.ApiUrl, cbs.String())
				require.Equal(t, "https://www.alice.com", am.Issuer)
				require.Equal(t, am.AudClaims, auds)
				require.Equal(t, am.Certificates, pems)
				require.Equal(t, am.OperationalState, string(InactiveState))
				require.Equal(t, am.Prompts, convertPrompts(prompts...))
				return am
			},
		},
		{
			name: "valid with custom ID",
			am: func(t *testing.T) *AuthMethod {
				algs := []Alg{RS256, ES256}
				cbs := TestConvertToUrls(t, "https://www.alice.com/callback")[0]
				auds := []string{"alice-rp-custom", "bob-rp-custom"}
				prompts := []PromptParam{"consent", "select_account"}
				cert1, pem1 := testGenerateCA(t, "localhost")
				cert2, pem2 := testGenerateCA(t, "localhost")
				certs := []*x509.Certificate{cert1, cert2}
				pems := []string{pem1, pem2}
				am, err := NewAuthMethod(
					ctx,
					org.PublicId,
					"alice-rp-custom",
					"alice-secret-custom", WithAudClaims("alice-rp-custom"),
					WithAudClaims(auds...),
					WithIssuer(TestConvertToUrls(t, "https://www.alice.com")[0]),
					WithApiUrl(cbs),
					WithSigningAlgs(algs...),
					WithCertificates(certs...),
					WithPrompts(prompts...),
					WithName("alice's restaurant with a twist"),
					WithDescription("it's an okay but kinda weird place to eat"),
					WithClaimsScopes("email", "profile"),
					WithAccountClaimMap(map[string]AccountToClaim{"display_name": ToNameClaim, "oid": ToSubClaim}),
				)
				require.NoError(t, err)
				require.Equal(t, am.SigningAlgs, convertAlg(algs...))
				require.Equal(t, am.ApiUrl, cbs.String())
				require.Equal(t, "https://www.alice.com", am.Issuer)
				require.Equal(t, am.AudClaims, auds)
				require.Equal(t, am.Certificates, pems)
				require.Equal(t, am.OperationalState, string(InactiveState))
				require.Equal(t, am.Prompts, convertPrompts(prompts...))
				return am
			},
			opt: []Option{WithPublicId("amoidc_1234567890")},
		},
		{
			name: "bad custom ID",
			am: func(t *testing.T) *AuthMethod {
				algs := []Alg{RS256, ES256}
				cbs := TestConvertToUrls(t, "https://www.alice.com/callback")[0]
				auds := []string{"alice-rp-bad", "bob-rp-bad"}
				cert1, pem1 := testGenerateCA(t, "localhost")
				cert2, pem2 := testGenerateCA(t, "localhost")
				certs := []*x509.Certificate{cert1, cert2}
				pems := []string{pem1, pem2}
				am, err := NewAuthMethod(
					ctx,
					org.PublicId,
					"alice-rp-bad",
					"alice-secret-bad", WithAudClaims("alice-rp-bad"),
					WithAudClaims(auds...),
					WithIssuer(TestConvertToUrls(t, "https://www.alice.com")[0]),
					WithApiUrl(cbs),
					WithSigningAlgs(algs...),
					WithCertificates(certs...),
					WithName("alice's restaurant is bad"),
					WithDescription("their food is awful"),
					WithClaimsScopes("email", "profile"),
					WithAccountClaimMap(map[string]AccountToClaim{"display_name": ToNameClaim, "oid": ToSubClaim}),
				)
				require.NoError(t, err)
				require.Equal(t, am.SigningAlgs, convertAlg(algs...))
				require.Equal(t, am.ApiUrl, cbs.String())
				require.Equal(t, "https://www.alice.com", am.Issuer)
				require.Equal(t, am.AudClaims, auds)
				require.Equal(t, am.Certificates, pems)
				require.Equal(t, am.OperationalState, string(InactiveState))
				return am
			},
			opt:          []Option{WithPublicId("amoic_1234567890")},
			wantErrMatch: errors.T(errors.InvalidParameter),
		},
		{
			name: "bad-state",
			am: func(t *testing.T) *AuthMethod {
				am, err := NewAuthMethod(ctx, org.PublicId, "bad-state-rp", "alice-secret",
					WithAudClaims("alice-rp"), WithApiUrl(TestConvertToUrls(t, "https://api.com")[0]))
				require.NoError(t, err)
				am.OperationalState = "not-a-valid-state"
				return am
			},
			wantErrMatch: errors.T(errors.InvalidParameter),
		},
		{
			name: "missing-auth-method",
			am: func(t *testing.T) *AuthMethod {
				return nil
			},
			wantErrMatch: errors.T(errors.InvalidParameter),
		},
		{
			name: "bad-public-id",
			am: func(t *testing.T) *AuthMethod {
				id, err := newAuthMethodId(ctx)
				require.NoError(t, err)
				am := AllocAuthMethod()
				am.PublicId = id
				return &am
			},
			wantErrMatch: errors.T(errors.InvalidParameter),
		},
		{
			name: "bad-version",
			am: func(t *testing.T) *AuthMethod {
				am := AllocAuthMethod()
				am.Version = 22
				return &am
			},
			wantErrMatch: errors.T(errors.InvalidParameter),
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert, require := assert.New(t), require.New(t)
			repo, err := NewRepository(ctx, rw, rw, kmsCache)
			assert.NoError(err)
			require.NotNil(repo)
			am := tt.am(t)
			got, err := repo.CreateAuthMethod(ctx, am, tt.opt...)
			if tt.wantErrMatch != nil {
				require.Error(err)
				assert.Truef(errors.Match(tt.wantErrMatch, err), "want err code: %q got: %q", tt.wantErrMatch, err)
				assert.Nil(got)

				if am != nil {
					err := db.TestVerifyOplog(t, rw, am.PublicId, db.WithOperation(oplog.OpType_OP_TYPE_CREATE), db.WithCreateNotBefore(10*time.Second))
					require.Errorf(err, "should not have found oplog entry for %s", am.PublicId)
				}
				return
			}
			require.NoError(err)
			if tt.opt != nil {
				if opts := getOpts(tt.opt...); opts.withPublicId != "" {
					require.Equal(opts.withPublicId, got.PublicId)
				}
			}
			am.PublicId = got.PublicId
			am.CreateTime = got.CreateTime
			am.UpdateTime = got.UpdateTime
			am.Version = got.Version
			assert.Truef(proto.Equal(am.AuthMethod, got.AuthMethod), "got %+v expected %+v", got, tt.am)

			err = db.TestVerifyOplog(t, rw, am.PublicId, db.WithOperation(oplog.OpType_OP_TYPE_CREATE), db.WithCreateNotBefore(10*time.Second))
			require.NoErrorf(err, "unexpected error verifying oplog entry: %s", err)

			found, err := repo.LookupAuthMethod(ctx, am.PublicId)
			require.NoError(err)
			found.CreateTime = got.CreateTime
			found.UpdateTime = got.UpdateTime
			found.Version = got.Version
			TestSortAuthMethods(t, []*AuthMethod{found, am})
			assert.Empty(cmp.Diff(found.AuthMethod, am.AuthMethod, protocmp.Transform()))
		})
	}
}
