package auth

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/hashicorp/boundary/internal/authtoken"
	"github.com/hashicorp/boundary/internal/db"
	"github.com/hashicorp/boundary/internal/iam"
	"github.com/hashicorp/boundary/internal/kms"
	"github.com/hashicorp/boundary/internal/servers"
	"github.com/hashicorp/boundary/internal/servers/controller/handlers"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestAuthTokenAuthenticator(t *testing.T) {
	conn, _ := db.TestSetup(t, "postgres")
	rw := db.New(conn)
	wrapper := db.TestWrapper(t)
	kms := kms.TestKms(t, conn, wrapper)
	tokenRepo, err := authtoken.NewRepository(rw, rw, kms)
	require.NoError(t, err)
	iamRepo := iam.TestRepo(t, conn, wrapper)
	tokenRepoFn := func() (*authtoken.Repository, error) {
		return tokenRepo, nil
	}
	iamRepoFn := func() (*iam.Repository, error) {
		return iamRepo, nil
	}
	serversRepoFn := func() (*servers.Repository, error) {
		return servers.NewRepository(rw, rw, kms)
	}

	o, _ := iam.TestScopes(t, iamRepo)
	at := authtoken.TestAuthToken(t, conn, kms, o.GetPublicId())
	encToken, err := authtoken.EncryptToken(context.Background(), kms, o.GetPublicId(), at.GetPublicId(), at.GetToken())
	require.NoError(t, err)

	tokValue := at.GetPublicId() + "_" + encToken
	jsCookieVal, httpCookieVal := tokValue[:len(tokValue)/2], tokValue[len(tokValue)/2:]

	cases := []struct {
		name        string
		headers     map[string]string
		cookies     []http.Cookie
		userId      string
		tokenFormat TokenFormat
	}{
		{
			name:        "Empty headers",
			headers:     map[string]string{},
			tokenFormat: AuthTokenTypeUnknown,
		},
		{
			name:        "Bearer token",
			headers:     map[string]string{"Authorization": fmt.Sprintf("Bearer %s", tokValue)},
			userId:      at.GetIamUserId(),
			tokenFormat: AuthTokenTypeBearer,
		},
		{
			name: "Split cookie token",
			cookies: []http.Cookie{
				{Name: handlers.HttpOnlyCookieName, Value: httpCookieVal},
				{Name: handlers.JsVisibleCookieName, Value: jsCookieVal},
			},
			userId:      at.GetIamUserId(),
			tokenFormat: AuthTokenTypeSplitCookie,
		},
		{
			name: "Split cookie token only http cookie",
			cookies: []http.Cookie{
				{Name: handlers.HttpOnlyCookieName, Value: httpCookieVal},
			},
			tokenFormat: AuthTokenTypeUnknown,
		},
		{
			name: "Split cookie token only js cookie",
			cookies: []http.Cookie{
				{Name: handlers.JsVisibleCookieName, Value: jsCookieVal},
			},
			tokenFormat: AuthTokenTypeUnknown,
		},
		{
			name:    "Cookie and auth header",
			headers: map[string]string{"Authorization": fmt.Sprintf("Bearer %s", tokValue)},
			cookies: []http.Cookie{
				{Name: handlers.HttpOnlyCookieName, Value: httpCookieVal},
				{Name: handlers.JsVisibleCookieName, Value: jsCookieVal},
			},
			userId:      at.GetIamUserId(),
			tokenFormat: AuthTokenTypeBearer,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			req := httptest.NewRequest("GET", "http://127.0.0.1/v1/scopes/o_1", nil)
			for k, v := range tc.headers {
				req.Header.Set(k, v)
			}
			for _, c := range tc.cookies {
				req.AddCookie(&c)
			}

			// Add values for authn/authz checking
			requestInfo := RequestInfo{
				Path:   req.URL.Path,
				Method: req.Method,
			}
			requestInfo.PublicId, requestInfo.EncryptedToken, requestInfo.TokenFormat = GetTokenFromRequest(context.TODO(), kms, req)
			assert.Equal(t, tc.tokenFormat, requestInfo.TokenFormat)

			if tc.userId == "" {
				return
			}
			ctx := NewVerifierContext(context.Background(), iamRepoFn, tokenRepoFn, serversRepoFn, kms, requestInfo)

			v, ok := ctx.Value(verifierKey).(*verifier)
			require.True(t, ok)
			require.NotNil(t, v)

			v.decryptToken(context.TODO())

			at, err := tokenRepo.ValidateToken(ctx, v.requestInfo.PublicId, v.requestInfo.Token)
			require.NoError(t, err)
			assert.Equal(t, tc.userId, at.GetIamUserId())
		})
	}
}
