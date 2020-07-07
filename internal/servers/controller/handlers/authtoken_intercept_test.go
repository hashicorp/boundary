package handlers

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/grpc-ecosystem/grpc-gateway/runtime"
	"github.com/hashicorp/go-hclog"
	"github.com/hashicorp/watchtower/internal/authtoken"
	"github.com/hashicorp/watchtower/internal/db"
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
	conn, _ := db.TestSetup(t, "postgres")
	rw := db.New(conn)
	wrapper := db.TestWrapper(t)
	repo, err := authtoken.NewRepository(rw, rw, wrapper)
	require.NoError(t, err)
	repoFn := func() (*authtoken.Repository, error) {
		return repo, nil
	}

	at := authtoken.TestAuthToken(t, conn, wrapper)

	tokValue := at.GetPublicId() + "_" + at.GetToken()
	jsCookieVal, httpCookieVal := tokValue[:len(tokValue)/2], tokValue[len(tokValue)/2:]

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
			name:    "Bear token",
			headers: map[string]string{"Authorization": fmt.Sprintf("Bearer %s", tokValue)},
			wantAuthTokMd: TokenMetadata{
				recievedTokenType: authTokenTypeBearer,
				bearerPayload:     tokValue,
				UserId:            at.GetIamUserId(),
			},
		},
		{
			name: "Split cookie token",
			cookies: []http.Cookie{
				{Name: httpOnlyCookieName, Value: httpCookieVal},
				{Name: jsVisibleCookieName, Value: jsCookieVal},
			},
			wantAuthTokMd: TokenMetadata{
				recievedTokenType: authTokenTypeSplitCookie,
				httpCookiePayload: httpCookieVal,
				jsCookiePayload:   jsCookieVal,
				UserId:            at.GetIamUserId(),
			},
		},
		{
			name: "Split cookie token only http cookie",
			cookies: []http.Cookie{
				{Name: httpOnlyCookieName, Value: httpCookieVal},
			},
			wantAuthTokMd: TokenMetadata{
				recievedTokenType: authTokenTypeUnknown,
				httpCookiePayload: httpCookieVal,
			},
		},
		{
			name: "Split cookie token only js cookie",
			cookies: []http.Cookie{
				{Name: jsVisibleCookieName, Value: jsCookieVal},
			},
			wantAuthTokMd: TokenMetadata{
				recievedTokenType: authTokenTypeUnknown,
				jsCookiePayload:   jsCookieVal,
			},
		},
		{
			name:    "Cookie and auth header",
			headers: map[string]string{"Authorization": fmt.Sprintf("Bearer %s", tokValue)},
			cookies: []http.Cookie{
				{Name: httpOnlyCookieName, Value: httpCookieVal},
				{Name: jsVisibleCookieName, Value: jsCookieVal},
			},
			// We prioritize the auth header over the cookie and if the header is set we ignore the cookies completely.
			wantAuthTokMd: TokenMetadata{
				recievedTokenType: authTokenTypeBearer,
				bearerPayload:     tokValue,
				UserId:            at.GetIamUserId(),
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			hook := &fakeHandler{validateFn: func(ctx context.Context) {
				tMD := ToTokenMetadata(ctx)
				assert.Equal(t, tc.wantAuthTokMd, tMD)
			}}
			mux := runtime.NewServeMux(runtime.WithMetadata(TokenAuthenticator(hclog.L(), repoFn)))
			require.NoError(t, services.RegisterOrganizationServiceHandlerServer(context.Background(), mux, hook))

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
