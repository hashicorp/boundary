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
	"github.com/hashicorp/boundary/internal/types/action"
	"github.com/hashicorp/boundary/internal/types/resource"
	"github.com/kr/pretty"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestHandler_AuthDecoration(t *testing.T) {
	conn, _ := db.TestSetup(t, "postgres")
	rw := db.New(conn)
	wrapper := db.TestWrapper(t)
	iamRepo, err := iam.NewRepository(rw, rw, wrapper)
	require.NoError(t, err)
	iamRepoFn := func() (*iam.Repository, error) {
		return iamRepo, nil
	}
	org, proj := iam.TestScopes(t, conn)
	cases := []struct {
		name            string
		path            string
		method          string
		action          action.Type
		scope           string
		resource        resource.Type
		id              string
		pin             string
		wantErrContains string
	}{
		{
			name:     "global scope, read, with id",
			path:     "/v1/scopes/global/users/u_anon",
			method:   "GET",
			action:   action.Read,
			scope:    "global",
			resource: resource.User,
			id:       "u_anon",
		},
		{
			name:     "global scope, update, with id",
			path:     "/v1/scopes/global/auth-methods/am_1234",
			method:   "PATCH",
			action:   action.Update,
			scope:    "global",
			resource: resource.AuthMethod,
			id:       "am_1234",
		},
		{
			name:     "global scope, delete org",
			path:     "/v1/scopes/o_1234",
			method:   "DELETE",
			action:   action.Delete,
			scope:    "global",
			resource: resource.Scope,
			id:       "o_1234",
		},
		{
			name:     "org scope, delete project",
			path:     fmt.Sprintf("/v1/scopes/%s", proj.GetPublicId()),
			method:   "DELETE",
			action:   action.Delete,
			scope:    org.GetPublicId(),
			resource: resource.Scope,
			id:       proj.GetPublicId(),
		},
		{
			name:            "empty segments",
			path:            "/v1/scopes/o_abc1234/auth-methods//am_1234",
			wantErrContains: "empty segment found",
		},
		{
			name:     "global scope, create",
			path:     "/v1/scopes/global/roles",
			method:   "POST",
			action:   action.Create,
			scope:    "global",
			resource: resource.Role,
		},
		{
			name:            "global, invalid collection syntax",
			path:            "/v1/scope",
			wantErrContains: `parse auth params: invalid first segment "scope"`,
		},
		{
			name:            "invalid scopes segment with id",
			path:            "/v1/scope/o_abc",
			wantErrContains: `parse auth params: invalid first segment "scope"`,
		},
		{
			name:     "org, custom action",
			path:     "/v1/scopes/o_123/auth-methods/am_1234:authenticate",
			method:   "POST",
			action:   action.Authenticate,
			scope:    "o_123",
			resource: resource.AuthMethod,
			id:       "am_1234",
		},
		{
			name:            "unknown action in first segment",
			path:            "/v1/:authentifake",
			wantErrContains: `parse auth params: invalid first segment ":authentifake"`,
		},
		{
			name:            "root, unknown action",
			path:            "/v1/scopes/o_abc/:authentifake",
			wantErrContains: `parse auth params: unknown action "authentifake"`,
		},
		{
			name:            "root, unknown empty action",
			path:            "/v1/:",
			wantErrContains: `parse auth params: invalid first segment ":"`,
		},
		{
			name:            "root, invalid method",
			path:            "/v1/scopes/o_abc/:authenticate",
			method:          "FOOBAR",
			wantErrContains: `unknown method "FOOBAR"`,
		},
		{
			name:            "root, wrong number of colons",
			path:            "/v1/scopes/o_abc/:auth:enticate",
			wantErrContains: "unexpected number of colons",
		},
		{
			name:     "root, action on global",
			path:     "/v1/scopes/global",
			method:   "GET",
			action:   action.Read,
			scope:    "global",
			resource: resource.Scope,
			id:       "global",
		},
		{
			name:     "org scope, valid",
			path:     "/v1/scopes/o_abc123/auth-methods",
			method:   "POST",
			action:   action.Create,
			scope:    "o_abc123",
			resource: resource.AuthMethod,
		},
		{
			name:     "project scope, valid",
			path:     "/v1/scopes/p_1234/host-catalogs",
			method:   "POST",
			action:   action.Create,
			scope:    "p_1234",
			resource: resource.HostCatalog,
		},
		{
			name:     "project scope, action on project",
			path:     "/v1/scopes/p_1234/:deauthenticate",
			method:   "POST",
			action:   action.Deauthenticate,
			scope:    "p_1234",
			resource: resource.Scope,
			id:       "p_1234",
		},
		{
			name:     "global scope, action on org, token scope",
			path:     "/v1/scopes/o_1234:set-principals",
			method:   "POST",
			action:   action.SetPrincipals,
			scope:    "global",
			resource: resource.Scope,
			id:       "o_1234",
		},
		{
			name:     "org scope, get on collection is list",
			path:     "/v1/scopes/o_abc123/projects",
			action:   action.List,
			scope:    "o_abc123",
			resource: resource.Project,
		},
		{
			name:     "global action, valid",
			path:     "/v1/scopes/global/:read",
			action:   action.Read,
			scope:    "global",
			resource: resource.Scope,
			id:       "global",
		},
		{
			name:            "top level, invalid",
			path:            "/v1/",
			wantErrContains: `invalid first segment "v1"`,
		},
		{
			name:            "non-api path",
			path:            "/",
			wantErrContains: `parse auth params: invalid first segment ""`,
		},
		{
			name:     "project scope, pinning collection",
			path:     "/v1/scopes/p_1234/host-catalogs/hc_1234/host-sets",
			action:   action.List,
			scope:    "p_1234",
			pin:      "hc_1234",
			resource: resource.HostSet,
		},
		{
			name:     "project scope, pinning collection, custom action",
			path:     "/v1/scopes/p_1234/host-catalogs/hc_1234/host-sets:create",
			action:   action.Create,
			scope:    "p_1234",
			pin:      "hc_1234",
			resource: resource.HostSet,
		},
		{
			name:     "project scope, pinning id",
			path:     "/v1/scopes/p_1234/host-catalogs/hc_1234/host-sets/hs_abc",
			action:   action.Read,
			id:       "hs_abc",
			scope:    "p_1234",
			pin:      "hc_1234",
			resource: resource.HostSet,
		},
		{
			name:     "project scope, pinning id, custom action",
			path:     "/v1/scopes/p_1234/host-catalogs/hc_1234/host-sets/hs_abc:update",
			action:   action.Update,
			id:       "hs_abc",
			scope:    "p_1234",
			pin:      "hc_1234",
			resource: resource.HostSet,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			require, assert := require.New(t), assert.New(t)
			if tc.method == "" {
				tc.method = "GET"
			}
			req, err := http.NewRequest(tc.method, fmt.Sprintf("http://127.0.0.1:9200:%s", tc.path), nil)
			require.NoError(err)

			v := &verifier{
				requestInfo: RequestInfo{
					Path:   req.URL.Path,
					Method: tc.method,
				},
				iamRepoFn: iamRepoFn,
			}

			err = v.parseAuthParams()
			if tc.wantErrContains != "" {
				require.Error(err)
				assert.Contains(err.Error(), tc.wantErrContains, err.Error())
				return
			}
			require.NoError(err, pretty.Sprint(v))

			if tc.path == "/" {
				return
			}

			require.NotNil(v.res)
			require.NotEqual(action.Unknown, v.act)
			assert.Equal(tc.scope, v.res.ScopeId, "scope "+pretty.Sprint(v))
			assert.Equal(tc.action, v.act, "action "+pretty.Sprint(v))
			assert.Equal(tc.resource, v.res.Type, "type "+pretty.Sprint(v))
			assert.Equal(tc.id, v.res.Id, "id "+pretty.Sprint(v))
			assert.Equal(tc.pin, v.res.Pin, "pin "+pretty.Sprint(v))
		})
	}
}

func TestAuthTokenAuthenticator(t *testing.T) {
	conn, _ := db.TestSetup(t, "postgres")
	rw := db.New(conn)
	wrapper := db.TestWrapper(t)
	tokenRepo, err := authtoken.NewRepository(rw, rw, wrapper)
	require.NoError(t, err)
	iamRepo, err := iam.NewRepository(rw, rw, wrapper)
	require.NoError(t, err)
	tokenRepoFn := func() (*authtoken.Repository, error) {
		return tokenRepo, nil
	}
	iamRepoFn := func() (*iam.Repository, error) {
		return iamRepo, nil
	}

	o, _ := iam.TestScopes(t, conn)
	at := authtoken.TestAuthToken(t, conn, wrapper, o.GetPublicId())

	tokValue := at.GetPublicId() + "_" + at.GetToken()
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
				{Name: HttpOnlyCookieName, Value: httpCookieVal},
				{Name: JsVisibleCookieName, Value: jsCookieVal},
			},
			userId:      at.GetIamUserId(),
			tokenFormat: AuthTokenTypeSplitCookie,
		},
		{
			name: "Split cookie token only http cookie",
			cookies: []http.Cookie{
				{Name: HttpOnlyCookieName, Value: httpCookieVal},
			},
			tokenFormat: AuthTokenTypeUnknown,
		},
		{
			name: "Split cookie token only js cookie",
			cookies: []http.Cookie{
				{Name: JsVisibleCookieName, Value: jsCookieVal},
			},
			tokenFormat: AuthTokenTypeUnknown,
		},
		{
			name:    "Cookie and auth header",
			headers: map[string]string{"Authorization": fmt.Sprintf("Bearer %s", tokValue)},
			cookies: []http.Cookie{
				{Name: HttpOnlyCookieName, Value: httpCookieVal},
				{Name: JsVisibleCookieName, Value: jsCookieVal},
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
			requestInfo.PublicId, requestInfo.Token, requestInfo.TokenFormat = GetTokenFromRequest(nil, req)
			assert.Equal(t, tc.tokenFormat, requestInfo.TokenFormat)

			if tc.userId == "" {
				return
			}
			ctx := NewVerifierContext(context.Background(), nil, iamRepoFn, tokenRepoFn, requestInfo)

			v, ok := ctx.Value(verifierKey).(*verifier)
			require.True(t, ok)
			require.NotNil(t, v)

			at, err := tokenRepo.ValidateToken(ctx, v.requestInfo.PublicId, v.requestInfo.Token)
			require.NoError(t, err)
			assert.Equal(t, tc.userId, at.GetIamUserId())
		})
	}
}
