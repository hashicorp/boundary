package oidc

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
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
	tpCert, err := ParseCertificates(tp.CACert())
	require.NoError(t, err)
	conn, _ := db.TestSetup(t, "postgres")
	rw := db.New(conn)
	rootWrapper := db.TestWrapper(t)
	kmsCache := kms.TestKms(t, conn, rootWrapper)
	testController := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		w.WriteHeader(200)
	}))
	defer testController.Close()

	repoFn := func() (*Repository, error) {
		return NewRepository(rw, rw, kmsCache)
	}
	org, _ := iam.TestScopes(t, iam.TestRepo(t, conn, rootWrapper))
	databaseWrapper, err := kmsCache.GetWrapper(ctx, org.PublicId, kms.KeyPurposeDatabase)
	require.NoError(t, err)
	testAuthMethod := TestAuthMethod(
		t, conn, databaseWrapper, org.PublicId, ActivePublicState,
		TestConvertToUrls(t, tp.Addr())[0],
		"test-rp", "fido",
		WithCallbackUrls(TestConvertToUrls(t, testController.URL)...),
		WithSigningAlgs(Alg(tpAlg)),
		WithCertificates(tpCert...),
	)

	testAuthMethodInactive := TestAuthMethod(
		t, conn, databaseWrapper, org.PublicId, InactiveState,
		TestConvertToUrls(t, tp.Addr())[0],
		"test-rp2", "fido",
		WithCallbackUrls(TestConvertToUrls(t, testController.URL)...),
		WithSigningAlgs(Alg(tpAlg)),
		WithCertificates(tpCert...),
	)

	stdSetup := func(am *AuthMethod, repoFn OidcRepoFactory, apiSrv *httptest.Server) (a *AuthMethod, allowedRedirect string) {
		// update the allowed redirects for the TestProvider
		tpAllowedRedirect := fmt.Sprintf(CallbackEndpoint, apiSrv.URL, am.PublicId)
		tp.SetAllowedRedirectURIs([]string{tpAllowedRedirect})
		allowedCallback, err := NewCallbackUrl(am.PublicId, TestConvertToUrls(t, tpAllowedRedirect)[0])
		require.NoError(t, err)
		err = rw.Create(ctx, allowedCallback)
		if err != nil && !errors.Match(errors.T(errors.NotUnique), err) {
			// ignore dup errors, but raise all others as an invalid test setup
			require.NoError(t, err)
		}
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
			roundTripper: "alice-says-hi-bob&eve-chuckles-&bob-says-hi-alice",
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
			name:            "bad-api-addr",
			repoFn:          repoFn,
			apiSrv:          nil,
			authMethod:      testAuthMethod,
			wantErrMatch:    errors.T(errors.InvalidParameter),
			wantErrContains: "missing api address",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert, require := assert.New(t), require.New(t)
			var allowedRedirect string
			if tt.setup != nil {
				tt.authMethod, allowedRedirect = tt.setup(tt.authMethod, tt.repoFn, tt.apiSrv)
			}
			var apiAddr string
			if tt.apiSrv != nil {
				apiAddr = tt.apiSrv.URL
			}

			now := time.Now()
			authUrl, tokenUrl, err := StartAuth(ctx, tt.repoFn, apiAddr, tt.authMethod.PublicId, WithRoundtripPayload(tt.roundTripper))
			if tt.wantErrMatch != nil {
				require.Error(err)
				assert.Nil(authUrl)
				assert.Nil(tokenUrl)
				assert.Truef(errors.Match(tt.wantErrMatch, err), "want err code: %q got: %q", tt.wantErrMatch, err)
				assert.Contains(err.Error(), tt.wantErrContains)
				return
			}
			require.NoError(err)
			require.NotNil(authUrl)
			require.NotNil(tokenUrl)

			authParams, err := url.ParseQuery(authUrl.RawQuery)
			require.NoError(err)
			assert.Equal(authParams["response_type"], []string{"code"})
			assert.Equal(authParams["scope"], []string{"openid"})
			assert.Equal(authParams["response_type"], []string{"code"})
			assert.Equal(authParams["redirect_uri"], []string{allowedRedirect})
			assert.Equal(authParams["client_id"], []string{tt.authMethod.ClientId})
			require.Equal(1, len(authParams["nonce"]))
			require.Equal(1, len(authParams["state"]))

			tokenParams, err := url.ParseQuery(tokenUrl.RawQuery)
			require.NoError(err)
			require.Equal(1, len(tokenParams["token_id"]))

			// verify the state in the authUrl can be decrypted and it's correct
			state := authParams["state"][0]
			wrappedStReq, err := unwrapMessage(ctx, state)
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
				assert.Equal(fmt.Sprintf(FinalRedirectEndpoint, tt.apiSrv.URL)+"?"+tt.roundTripper, reqState.FinalRedirectUrl)
				assert.Contains(reqState.FinalRedirectUrl, tt.roundTripper)
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
			tokenId := tokenParams["token_id"][0]
			wrappedTkReq, err := unwrapMessage(ctx, tokenId)
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
