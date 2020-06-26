package handlers

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/grpc-ecosystem/grpc-gateway/runtime"
	"github.com/hashicorp/go-hclog"
	"github.com/hashicorp/watchtower/internal/gen/controller/api/services"
	pbs "github.com/hashicorp/watchtower/internal/gen/controller/api/services"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Any generated service would do, but using organization since the path is the shortest for testing.
type fakeHandler struct {
	pbs.UnimplementedOrganizationServiceServer
	validateFn func(context.Context)
}

func (s *fakeHandler) GetOrganization(ctx context.Context, _ *pbs.GetOrganizationRequest) (*pbs.GetOrganizationResponse, error) {
	s.validateFn(ctx)
	return nil, errors.New("Doesn't matter this is just for testing input.")
}

func TestAuthTokenAuthenticator(t *testing.T) {
	cases := []struct {
		name          string
		headers       map[string]string
		cookies       []http.Cookie
		wantAuthTokMd TokenMetadata
	}{
		{
			name:          "Empty headers",
			headers:       map[string]string{},
			wantAuthTokMd: TokenMetadata{recievedTokenType: authTokenTypeUnknown},
		},
		{
			name:          "Bear token",
			headers:       map[string]string{"Authorization": "Bearer sometokenfortests"},
			wantAuthTokMd: TokenMetadata{recievedTokenType: authTokenTypeBearer, bearerPayload: "sometokenfortests"},
		},
		{
			name: "Split cookie token",
			cookies: []http.Cookie{
				{Name: httpOnlyCookieName, Value: "httpcookie"},
				{Name: jsVisibleCookieName, Value: "jscookie"},
			},
			wantAuthTokMd: TokenMetadata{
				recievedTokenType: authTokenTypeSplitCookie,
				httpCookiePayload: "httpcookie",
				jsCookiePayload:   "jscookie",
			},
		},
		{
			name: "Split cookie token only http cookie",
			cookies: []http.Cookie{
				{Name: httpOnlyCookieName, Value: "httpcookie"},
			},
			wantAuthTokMd: TokenMetadata{
				recievedTokenType: authTokenTypeUnknown,
				httpCookiePayload: "httpcookie",
			},
		},
		{
			name: "Split cookie token only js cookie",
			cookies: []http.Cookie{
				{Name: jsVisibleCookieName, Value: "jscookie"},
			},
			wantAuthTokMd: TokenMetadata{
				recievedTokenType: authTokenTypeUnknown,
				jsCookiePayload:   "jscookie",
			},
		},
		{
			name:    "Cookie and auth header",
			headers: map[string]string{"Authorization": "Bearer sometokenfortests"},
			cookies: []http.Cookie{
				{Name: httpOnlyCookieName, Value: "httpcookie"},
				{Name: jsVisibleCookieName, Value: "jscookie"},
			},
			wantAuthTokMd: TokenMetadata{
				recievedTokenType: authTokenTypeBearer,
				httpCookiePayload: "httpcookie",
				jsCookiePayload:   "jscookie",
				bearerPayload:     "sometokenfortests",
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			hook := &fakeHandler{validateFn: func(ctx context.Context) {
				tMD, err := ToTokenMetadata(ctx)
				assert.NoError(t, err)
				assert.Equal(t, tc.wantAuthTokMd, tMD)
			}}
			mux := runtime.NewServeMux(runtime.WithMetadata(TokenAuthenticator(hclog.L())))
			err := services.RegisterOrganizationServiceHandlerServer(context.Background(), mux, hook)
			require.NoError(t, err)

			req := httptest.NewRequest("GET", "http://127.0.0.1/v1/orgs/1", nil)
			for k, v := range tc.headers {
				req.Header.Set(k, v)
			}
			for _, c := range tc.cookies {
				req.AddCookie(&c)
			}

			resp := httptest.NewRecorder()
			mux.ServeHTTP(resp, req)
		})
	}
}
