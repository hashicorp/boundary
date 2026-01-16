// Copyright IBM Corp. 2020, 2025
// SPDX-License-Identifier: BUSL-1.1

package oidc

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/hashicorp/boundary/internal/auth/oidc/request"
	"github.com/hashicorp/boundary/internal/db"
	"github.com/hashicorp/boundary/internal/errors"
	"github.com/hashicorp/boundary/internal/iam"
	"github.com/hashicorp/boundary/internal/kms"
	"github.com/hashicorp/cap/oidc"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/proto"
)

func Test_StartAuth(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	tp := oidc.StartTestProvider(t)
	_, _, tpAlg, _ := tp.SigningKeys()
	tpCert, err := ParseCertificates(ctx, tp.CACert())
	require.NoError(t, err)
	tpPrompt := []PromptParam{SelectAccount}
	tpNoneWithMultiplePrompts := []PromptParam{None, SelectAccount}
	tpWithMultiplePrompts := []PromptParam{Consent, SelectAccount}
	conn, _ := db.TestSetup(t, "postgres")
	rw := db.New(conn)
	rootWrapper := db.TestWrapper(t)
	kmsCache := kms.TestKms(t, conn, rootWrapper)
	testController := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		w.WriteHeader(200)
	}))
	defer testController.Close()

	repoFn := func() (*Repository, error) {
		return NewRepository(ctx, rw, rw, kmsCache)
	}
	org, _ := iam.TestScopes(t, iam.TestRepo(t, conn, rootWrapper))
	databaseWrapper, err := kmsCache.GetWrapper(ctx, org.PublicId, kms.KeyPurposeDatabase)
	require.NoError(t, err)
	testAuthMethod := TestAuthMethod(
		t, conn, databaseWrapper, org.PublicId, ActivePublicState,
		"test-rp", "fido",
		WithIssuer(TestConvertToUrls(t, tp.Addr())[0]),
		WithApiUrl(TestConvertToUrls(t, testController.URL)[0]),
		WithSigningAlgs(Alg(tpAlg)),
		WithCertificates(tpCert...),
		WithClaimsScopes("email", "profile"),
	)

	testAuthMethodInactive := TestAuthMethod(
		t, conn, databaseWrapper, org.PublicId, InactiveState,
		"test-rp2", "fido",
		WithIssuer(TestConvertToUrls(t, tp.Addr())[0]),
		WithApiUrl(TestConvertToUrls(t, testController.URL)[0]),
		WithSigningAlgs(Alg(tpAlg)),
		WithCertificates(tpCert...),
	)

	testAuthMethodWithMaxAge := TestAuthMethod(
		t, conn, databaseWrapper, org.PublicId, ActivePublicState,
		"test-rp3", "fido",
		WithIssuer(TestConvertToUrls(t, tp.Addr())[0]),
		WithApiUrl(TestConvertToUrls(t, testController.URL)[0]),
		WithSigningAlgs(Alg(tpAlg)),
		WithCertificates(tpCert...),
		WithMaxAge(-1),
	)

	testAuthMethodWithPrompt := TestAuthMethod(
		t, conn, databaseWrapper, org.PublicId, ActivePublicState,
		"test-rp4", "fido",
		WithIssuer(TestConvertToUrls(t, tp.Addr())[0]),
		WithApiUrl(TestConvertToUrls(t, testController.URL)[0]),
		WithSigningAlgs(Alg(tpAlg)),
		WithCertificates(tpCert...),
		WithPrompts(tpPrompt...),
	)

	testAuthMethodWithMultiplePrompts := TestAuthMethod(
		t, conn, databaseWrapper, org.PublicId, ActivePublicState,
		"test-rp5", "fido",
		WithIssuer(TestConvertToUrls(t, tp.Addr())[0]),
		WithApiUrl(TestConvertToUrls(t, testController.URL)[0]),
		WithSigningAlgs(Alg(tpAlg)),
		WithCertificates(tpCert...),
		WithPrompts(tpWithMultiplePrompts...),
	)

	testAuthMethodNoneWithMultiplePrompts := TestAuthMethod(
		t, conn, databaseWrapper, org.PublicId, ActivePublicState,
		"test-rp6", "fido",
		WithIssuer(TestConvertToUrls(t, tp.Addr())[0]),
		WithApiUrl(TestConvertToUrls(t, testController.URL)[0]),
		WithSigningAlgs(Alg(tpAlg)),
		WithCertificates(tpCert...),
		WithPrompts(tpNoneWithMultiplePrompts...),
	)

	stdSetup := func(am *AuthMethod, repoFn OidcRepoFactory, apiSrv *httptest.Server) (a *AuthMethod, allowedRedirect string) {
		// update the allowed redirects for the TestProvider
		tpAllowedRedirect := fmt.Sprintf(CallbackEndpoint, apiSrv.URL)
		tp.SetAllowedRedirectURIs([]string{tpAllowedRedirect})
		r, err := repoFn()
		require.NoError(t, err)
		// update the test's auth method, now that we've added a new callback
		am, err = r.lookupAuthMethod(ctx, am.PublicId)
		require.NoError(t, err)
		require.NotNil(t, am)
		return am, tpAllowedRedirect
	}
	tests := []struct {
		name            string
		repoFn          OidcRepoFactory
		apiSrv          *httptest.Server
		authMethod      *AuthMethod
		roundTripper    string
		setup           func(am *AuthMethod, repoFn OidcRepoFactory, apiSrv *httptest.Server) (*AuthMethod, string)
		wantErrMatch    *errors.Template
		wantErrContains string
	}{
		{
			name:       "simple",
			repoFn:     repoFn,
			apiSrv:     testController,
			authMethod: testAuthMethod,
			setup:      stdSetup,
		},
		{
			name:         "simple-with-roundtripper",
			repoFn:       repoFn,
			apiSrv:       testController,
			authMethod:   testAuthMethod,
			setup:        stdSetup,
			roundTripper: `{"alice": "hi bob", "eve": "chuckles says hi alice"}`,
		},
		{
			name:       "simple-with-max-age",
			repoFn:     repoFn,
			apiSrv:     testController,
			authMethod: testAuthMethodWithMaxAge,
			setup:      stdSetup,
		},
		{
			name:            "inactive",
			repoFn:          repoFn,
			apiSrv:          testController,
			authMethod:      testAuthMethodInactive,
			wantErrMatch:    errors.T(errors.AuthMethodInactive),
			wantErrContains: "not allowed to start authentication attempt",
			setup:           stdSetup,
		},
		{
			name:            "missing-repo-func",
			repoFn:          nil,
			apiSrv:          testController,
			authMethod:      testAuthMethodInactive,
			wantErrMatch:    errors.T(errors.InvalidParameter),
			wantErrContains: "missing oidc repo function",
		},
		{
			name:            "missing-authmethod-id",
			repoFn:          repoFn,
			apiSrv:          testController,
			authMethod:      func() *AuthMethod { am := AllocAuthMethod(); return &am }(),
			wantErrMatch:    errors.T(errors.InvalidParameter),
			wantErrContains: "missing auth method id",
		},
		{
			name:            "bad-authmethod-id",
			repoFn:          repoFn,
			apiSrv:          testController,
			authMethod:      func() *AuthMethod { am := AllocAuthMethod(); am.PublicId = "not-valid"; return &am }(),
			wantErrMatch:    errors.T(errors.RecordNotFound),
			wantErrContains: "auth method not-valid not found:",
		},
		{
			name:       "simple-with-prompt",
			repoFn:     repoFn,
			apiSrv:     testController,
			authMethod: testAuthMethodWithPrompt,
			setup:      stdSetup,
		},
		{
			name:       "simple-with-multiple-prompts",
			repoFn:     repoFn,
			apiSrv:     testController,
			authMethod: testAuthMethodWithMultiplePrompts,
			setup:      stdSetup,
		},
		{
			name:            "simple-with-none-and-multiple-prompts",
			repoFn:          repoFn,
			apiSrv:          testController,
			authMethod:      testAuthMethodNoneWithMultiplePrompts,
			setup:           stdSetup,
			wantErrMatch:    errors.T(errors.InvalidParameter),
			wantErrContains: "prompts ([none select_account]) includes \"none\" with other values",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert, require := assert.New(t), require.New(t)
			var allowedRedirect string
			if tt.setup != nil {
				tt.authMethod, allowedRedirect = tt.setup(tt.authMethod, tt.repoFn, tt.apiSrv)
			}

			now := time.Now()
			authUrl, tokenId, err := StartAuth(ctx, tt.repoFn, tt.authMethod.PublicId, WithRoundtripPayload(tt.roundTripper))
			if tt.wantErrMatch != nil {
				require.Error(err)
				assert.Nil(authUrl)
				assert.Truef(errors.Match(tt.wantErrMatch, err), "want err code: %q got: %q", tt.wantErrMatch, err)
				assert.Contains(err.Error(), tt.wantErrContains)
				return
			}
			require.NoError(err)
			require.NotNil(authUrl)

			authParams, err := url.ParseQuery(authUrl.RawQuery)
			require.NoError(err)
			assert.Equal(authParams["response_type"], []string{"code"})
			assert.Equal(authParams["response_type"], []string{"code"})
			assert.Equal(authParams["redirect_uri"], []string{allowedRedirect})
			assert.Equal(authParams["client_id"], []string{tt.authMethod.ClientId})
			require.Equal(1, len(authParams["nonce"]))
			require.Equal(1, len(authParams["state"]))

			require.Len(authParams["scope"], 1)
			wantClaimsScopes := append(tt.authMethod.ClaimsScopes, DefaultClaimsScope)
			gotScopes := strings.Split(authParams["scope"][0], " ")
			sort.Strings(gotScopes)
			sort.Strings(wantClaimsScopes)
			assert.Equal(wantClaimsScopes, gotScopes)

			if tt.authMethod.MaxAge != 0 {
				var expected int
				switch {
				case tt.authMethod.MaxAge == -1:
					expected = 0
				default:
					expected = int(tt.authMethod.MaxAge)
				}
				gotSlice, ok := authParams["max_age"]
				require.True(ok)
				require.Equal(1, len(gotSlice))
				got, err := strconv.Atoi(gotSlice[0])
				require.NoError(err)
				assert.Equal(expected, got)
			}

			// verify the state in the authUrl can be decrypted and it's correct
			state := authParams["state"][0]
			wrappedStReq, err := UnwrapMessage(ctx, state)
			require.NoError(err)
			repo, err := tt.repoFn()
			require.NoError(err)
			wrappingWrapper, err := requestWrappingWrapper(ctx, repo.kms, wrappedStReq.ScopeId, wrappedStReq.AuthMethodId)
			require.NoError(err)
			decryptedBytes, err := decryptMessage(ctx, wrappingWrapper, wrappedStReq)
			require.NoError(err)
			var reqState request.State
			err = proto.Unmarshal(decryptedBytes, &reqState)
			require.NoError(err)
			assert.NotNil(reqState.CreateTime)
			assert.NotEmpty(reqState.FinalRedirectUrl)
			switch tt.roundTripper != "" {
			case true:
				u := make(url.Values)
				u.Add("roundtrip_payload", tt.roundTripper)
				assert.Equal(fmt.Sprintf(FinalRedirectEndpoint, tt.apiSrv.URL)+"?"+u.Encode(), reqState.FinalRedirectUrl)
				assert.Contains(reqState.FinalRedirectUrl, u.Encode())
			default:
				assert.Equal(fmt.Sprintf(FinalRedirectEndpoint, tt.apiSrv.URL), reqState.FinalRedirectUrl)
			}
			assert.Equal(authParams["nonce"][0], reqState.Nonce)

			assert.WithinDuration(reqState.CreateTime.Timestamp.AsTime(), now, 1*time.Second)
			assert.WithinDuration(reqState.ExpirationTime.Timestamp.AsTime(), now.Add(AttemptExpiration), 1*time.Second)

			p, err := convertToProvider(ctx, tt.authMethod)
			require.NoError(err)
			configHash, err := p.ConfigHash()
			require.NoError(err)
			assert.Equal(configHash, reqState.ProviderConfigHash)

			// verify the token_id in the tokenUrl can be decrypted and it's correct
			wrappedTkReq, err := UnwrapMessage(ctx, tokenId)
			require.NoError(err)
			wrappingWrapper, err = requestWrappingWrapper(ctx, repo.kms, wrappedTkReq.ScopeId, wrappedTkReq.AuthMethodId)
			require.NoError(err)
			decryptedBytes, err = decryptMessage(ctx, wrappingWrapper, wrappedTkReq)
			require.NoError(err)
			var reqToken request.Token
			err = proto.Unmarshal(decryptedBytes, &reqToken)
			require.NoError(err)

			assert.Equal(reqState.TokenRequestId, reqToken.RequestId)
			assert.Equal(reqState.ExpirationTime, reqToken.ExpirationTime)
		})
	}
}
