package oidc

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"

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

	tests := []struct {
		name         string
		repoFn       OidcRepoFactory
		apiSrv       *httptest.Server
		authMethod   *AuthMethod
		wantErrMatch *errors.Template
	}{
		{
			name:       "simple",
			repoFn:     repoFn,
			apiSrv:     testController,
			authMethod: testAuthMethod,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert, require := assert.New(t), require.New(t)
			require.NotNilf(tt.apiSrv, "invalid test parameter: tt.apiSrv is nil")
			require.NotNilf(tt.authMethod, "invalid test parameter: tt.authMethod is nil")

			// update the allowed redirects for the TestProvider
			tpAllowedRedirect := fmt.Sprintf(CallbackEndpoint, tt.apiSrv.URL, tt.authMethod.PublicId)
			tp.SetAllowedRedirectURIs([]string{tpAllowedRedirect})
			allowedCallback, err := NewCallbackUrl(tt.authMethod.PublicId, TestConvertToUrls(t, tpAllowedRedirect)[0])
			require.NoError(err)
			err = rw.Create(ctx, allowedCallback)
			require.NoError(err)
			r, err := tt.repoFn()
			require.NoError(err)
			// update the test's auth method, now that we've added a new callback
			tt.authMethod, err = r.lookupAuthMethod(ctx, tt.authMethod.PublicId)
			require.NoError(err)
			require.NotNil(tt.authMethod)

			authUrl, tokenUrl, err := StartAuth(ctx, tt.repoFn, tt.apiSrv.URL, tt.authMethod.PublicId)
			if tt.wantErrMatch != nil {
				require.Error(err)
				assert.Nil(authUrl)
				assert.Nil(tokenUrl)
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
			assert.Equal(authParams["redirect_uri"], []string{tpAllowedRedirect})
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
			assert.Equal(fmt.Sprintf(FinalRedirectEndpoint, tt.apiSrv.URL), reqState.FinalRedirectUrl)
			assert.Equal(authParams["nonce"][0], reqState.Nonce)

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
