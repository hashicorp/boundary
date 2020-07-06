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

func TestAuthTokenPublicIdTokenValue(t *testing.T) {
	cases := []struct {
		name      string
		in        TokenMetadata
		wantId    string
		wantToken string
	}{
		{
			name: "no delimeter",
			in: TokenMetadata{
				recievedTokenType: authTokenTypeBearer,
				bearerPayload:     "prefix_publicid_token",
				jsCookiePayload:   "this_is_just_junk",
				httpCookiePayload: "this_can_be_ignored",
			},
			wantId:    "prefix_publicid",
			wantToken: "token",
		},
		{
			name: "no delimeter",
			in: TokenMetadata{
				recievedTokenType: authTokenTypeSplitCookie,
				bearerPayload:     "this_is_just_junk_that_should_be_ignored",
				jsCookiePayload:   "prefix_publicid_token",
				httpCookiePayload: "cookiepayload",
			},
			wantId:    "prefix_publicid",
			wantToken: "tokencookiepayload",
		},
		{
			name: "no delimeter",
			in: TokenMetadata{
				recievedTokenType: authTokenTypeBearer,
				bearerPayload:     "this-doesnt-have-the-expected-delimiter",
			},
			wantId:    "",
			wantToken: "",
		},
		{
			name: "to many delimeters",
			in: TokenMetadata{
				recievedTokenType: authTokenTypeBearer,
				bearerPayload:     "this_has_to_many_delimiters",
			},
			wantId:    "",
			wantToken: "",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.wantId, tc.in.publicId(), "got wrong public id")
			assert.Equal(t, tc.wantToken, tc.in.token(), "got wrong token value")
		})
	}
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
			// We prioritize the auth header over the cookie and if the header is set we ignore the cookies completely.
			wantAuthTokMd: TokenMetadata{
				recievedTokenType: authTokenTypeBearer,
				bearerPayload:     "sometokenfortests",
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			hook := &fakeHandler{validateFn: func(ctx context.Context) {
				tMD := ToTokenMetadata(ctx)
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
