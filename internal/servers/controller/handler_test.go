package controller

import (
	"context"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/grpc-ecosystem/grpc-gateway/runtime"
	"github.com/hashicorp/watchtower/globals"
	"github.com/hashicorp/watchtower/internal/gen/controller/api/services"
	"github.com/hashicorp/watchtower/internal/types/action"
	"github.com/hashicorp/watchtower/internal/types/resource"
	"github.com/hashicorp/watchtower/internal/types/scope"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestGrpcGatewayRouting(t *testing.T) {
	ctx := context.Background()
	// The unimplemented result indicates the grpc routing is happening successfully otherwise it would return NotFound.
	routed := http.StatusNotImplemented
	unrouted := http.StatusNotFound

	cases := []struct {
		name           string
		setup          func(mux *runtime.ServeMux)
		url            string
		expectedResult int
	}{
		{
			name: "project",
			setup: func(mux *runtime.ServeMux) {
				require.NoError(t, services.RegisterProjectServiceHandlerServer(ctx, mux, &services.UnimplementedProjectServiceServer{}))
			},
			url:            "v1/orgs/someid/projects",
			expectedResult: routed,
		},
		{
			name: "users",
			setup: func(mux *runtime.ServeMux) {
				require.NoError(t, services.RegisterUserServiceHandlerServer(ctx, mux, &services.UnimplementedUserServiceServer{}))
			},
			url:            "v1/orgs/someid/users",
			expectedResult: routed,
		},
		{
			name: "roles",
			setup: func(mux *runtime.ServeMux) {
				require.NoError(t, services.RegisterRoleServiceHandlerServer(ctx, mux, &services.UnimplementedRoleServiceServer{}))
			},
			url:            "v1/orgs/someid/roles",
			expectedResult: routed,
		},
		{
			name: "project_scoped_roles",
			setup: func(mux *runtime.ServeMux) {
				require.NoError(t, services.RegisterRoleServiceHandlerServer(ctx, mux, &services.UnimplementedRoleServiceServer{}))
			},
			url:            "v1/orgs/someid/projects/_someprojectid/roles",
			expectedResult: routed,
		},
		{
			name: "groups",
			setup: func(mux *runtime.ServeMux) {
				require.NoError(t, services.RegisterGroupServiceHandlerServer(ctx, mux, &services.UnimplementedGroupServiceServer{}))
			},
			url:            "v1/orgs/someid/groups",
			expectedResult: routed,
		},
		{
			name: "project_scoped_groups",
			setup: func(mux *runtime.ServeMux) {
				require.NoError(t, services.RegisterGroupServiceHandlerServer(ctx, mux, &services.UnimplementedGroupServiceServer{}))
			},
			url:            "v1/orgs/someid/projects/_someprojectid/groups",
			expectedResult: routed,
		},
		{
			name:           "not routed",
			setup:          func(mux *runtime.ServeMux) {},
			url:            "v1/nothing",
			expectedResult: unrouted,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			mux := runtime.NewServeMux()
			tc.setup(mux)

			// List request
			req := httptest.NewRequest("GET", fmt.Sprintf("http://localhost/%s", tc.url), nil)
			resp := httptest.NewRecorder()
			mux.ServeHTTP(resp, req)
			assert.Equal(t, tc.expectedResult, resp.Result().StatusCode, "Got response %v", resp)

			// Create request
			req = httptest.NewRequest("POST", fmt.Sprintf("http://localhost/%s", tc.url), nil)
			resp = httptest.NewRecorder()
			mux.ServeHTTP(resp, req)
			assert.Equal(t, tc.expectedResult, resp.Result().StatusCode, "Got response %v", resp)

			// Get request
			req = httptest.NewRequest("GET", fmt.Sprintf("http://localhost/%s/somemadeupid", tc.url), nil)
			resp = httptest.NewRecorder()
			mux.ServeHTTP(resp, req)
			assert.Equal(t, tc.expectedResult, resp.Result().StatusCode, "Got response %v", resp)

			// Update request
			req = httptest.NewRequest("PATCH", fmt.Sprintf("http://localhost/%s/somemadeupid", tc.url), nil)
			resp = httptest.NewRecorder()
			mux.ServeHTTP(resp, req)
			assert.Equal(t, tc.expectedResult, resp.Result().StatusCode, "Got response %v", resp)

			// Delete request
			req = httptest.NewRequest("DELETE", fmt.Sprintf("http://localhost/%s/somemadeupid", tc.url), nil)
			resp = httptest.NewRecorder()
			mux.ServeHTTP(resp, req)
			assert.Equal(t, tc.expectedResult, resp.Result().StatusCode, "Got response %v", resp)
		})
	}
}

func TestAuthenticationHandler(t *testing.T) {
	c := NewTestController(t, &TestControllerOpts{DefaultOrgId: "o_1234567890"})
	defer c.Shutdown()

	resp, err := http.Post(fmt.Sprintf("%s/v1/orgs/o_1234567890:authenticate", c.ApiAddrs()[0]), "application/json",
		strings.NewReader("{\"auth_method_id\": \"whatever\", \"token_type\": null, \"credentials\": {\"name\":\"test\", \"password\": \"test\"}}"))
	require.NoError(t, err)
	assert.Equal(t, http.StatusOK, resp.StatusCode, "Got response: %v", resp)

	b, err := ioutil.ReadAll(resp.Body)
	require.NoError(t, err)
	body := make(map[string]interface{})
	require.NoError(t, json.Unmarshal(b, &body))

	require.Contains(t, body, "id")
	require.Contains(t, body, "token")
	pubId, tok := body["id"].(string), body["token"].(string)
	assert.NotEmpty(t, pubId)
	assert.NotEmpty(t, tok)
	assert.Truef(t, strings.HasPrefix(tok, pubId), "Token: %q, Id: %q", tok, pubId)
}

func TestGrpcGatewayRouting_CustomActions(t *testing.T) {
	ctx := context.Background()
	// The unimplemented result indicates the grpc routing is happening successfully otherwise it would return NotFound.
	routed := http.StatusNotImplemented

	cases := []struct {
		name      string
		setup     func(mux *runtime.ServeMux)
		post_urls []string
	}{
		{
			name: "roles",
			setup: func(mux *runtime.ServeMux) {
				require.NoError(t, services.RegisterRoleServiceHandlerServer(ctx, mux, &services.UnimplementedRoleServiceServer{}))
			},
			post_urls: []string{
				"v1/orgs/someid/roles/r_anotherid:add-principals",
				"v1/orgs/someid/roles/r_anotherid:set-principals",
				"v1/orgs/someid/roles/r_anotherid:remove-principals",
				"v1/orgs/someid/projects/p_something/roles/r_anotherid:add-principals",
				"v1/orgs/someid/projects/p_something/roles/r_anotherid:set-principals",
				"v1/orgs/someid/projects/p_something/roles/r_anotherid:remove-principals",
				"v1/orgs/someid/roles/r_anotherid:add-grants",
				"v1/orgs/someid/roles/r_anotherid:set-grants",
				"v1/orgs/someid/roles/r_anotherid:remove-grants",
				"v1/orgs/someid/projects/p_something/roles/r_anotherid:add-grants",
				"v1/orgs/someid/projects/p_something/roles/r_anotherid:set-grants",
				"v1/orgs/someid/projects/p_something/roles/r_anotherid:remove-grants",
			},
		},
	}

	for _, tc := range cases {
		for _, url := range tc.post_urls {
			t.Run(tc.name+"_"+url, func(t *testing.T) {
				mux := runtime.NewServeMux()
				tc.setup(mux)

				req := httptest.NewRequest("POST", fmt.Sprintf("http://localhost/%s", url), nil)
				resp := httptest.NewRecorder()
				mux.ServeHTTP(resp, req)
				assert.Equal(t, routed, resp.Result().StatusCode, "Got response %v", resp)
			})
		}
	}
}

func TestHandleGrpcGateway(t *testing.T) {
	c := NewTestController(t, nil)
	defer c.Shutdown()

	cases := []struct {
		name string
		path string
		code int
	}{
		{
			"Non existent path",
			"v1/this-is-made-ups",
			http.StatusNotFound,
		},
		{
			"Unimplemented path",
			"v1/orgs/1/projects/2/host-catalogs/3/host-sets/hs_4",
			http.StatusMethodNotAllowed,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			url := fmt.Sprintf("%s/%s", c.ApiAddrs()[0], tc.path)
			resp, err := http.Get(url)
			if err != nil {
				t.Errorf("Got error: %v when non was expected.", err)
			}
			if got, want := resp.StatusCode, tc.code; got != want {
				t.Errorf("GET on %q got code %d, wanted %d", tc.path, got, want)
			}

		})
	}
}

func TestHandler_AuthDecoration(t *testing.T) {
	cases := []struct {
		name            string
		path            string
		method          string
		action          action.Type
		scope           scope.Type
		resource        resource.Type
		id              string
		wantErrContains string
	}{
		{
			name:     "global scope, read, with id",
			path:     "/v1/users/u_anon",
			method:   "GET",
			action:   action.Read,
			scope:    scope.Global,
			resource: resource.User,
			id:       "u_anon",
		},
		{
			name:     "global scope, update, with id",
			path:     "/v1/auth-methods/am_1234",
			method:   "PATCH",
			action:   action.Update,
			scope:    scope.Global,
			resource: resource.AuthMethod,
			id:       "am_1234",
		},
		{
			name:     "global scope, delete",
			path:     "/v1/orgs/o_1234",
			method:   "DELETE",
			action:   action.Delete,
			scope:    scope.Global,
			resource: resource.Org,
			id:       "o_1234",
		},
		{
			name:     "global scope, create",
			path:     "/v1/roles",
			method:   "POST",
			action:   action.Create,
			scope:    scope.Global,
			resource: resource.Role,
		},
		{
			name:            "global, invalid collection syntax",
			path:            "/v1/org",
			wantErrContains: "invalid collection syntax",
		},
		{
			name:     "global, custom action",
			path:     "/v1/orgs/o_123/auth-methods/am_1234:authenticate",
			method:   "POST",
			action:   action.Authenticate,
			scope:    scope.Org,
			resource: resource.AuthMethod,
			id:       "am_1234",
		},
		{
			name:            "root, unknown action",
			path:            "/v1/:authentifake",
			wantErrContains: "unknown action",
		},
		{
			name:            "root, unknown empty action",
			path:            "/v1/:",
			wantErrContains: "unknown action",
		},
		{
			name:            "root, invalid method",
			path:            "/v1/:authenticate",
			method:          "FOOBAR",
			wantErrContains: "unknown method",
		},
		{
			name:            "root, wrong number of colons",
			path:            "/v1/:auth:enticate",
			wantErrContains: "unexpected number of colons",
		},
		{
			name:     "org scope, valid",
			path:     "/v1/orgs/o_abc123/auth-methods",
			method:   "POST",
			action:   action.Create,
			scope:    scope.Org,
			resource: resource.AuthMethod,
		},
		{
			name:     "project scope, valid",
			path:     "/v1/orgs/o_abc123/projects/p_1234/host-catalogs",
			method:   "POST",
			action:   action.Create,
			scope:    scope.Project,
			resource: resource.HostCatalog,
		},
		{
			name:     "project scope, action on project",
			path:     "/v1/orgs/o_abc123/projects/p_1234/:set-principals",
			method:   "POST",
			action:   action.SetPrincipals,
			scope:    scope.Project,
			resource: resource.Project,
			id:       "p_1234",
		},
		{
			name:     "org scope, action on project",
			path:     "/v1/orgs/o_abc123/projects/p_1234:set-principals",
			method:   "POST",
			action:   action.SetPrincipals,
			scope:    scope.Org,
			resource: resource.Project,
			id:       "p_1234",
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

			ctx, err := decorateAuthParams(nil)
			require.Error(err)
			assert.Contains(err.Error(), "incoming request is nil")

			ctx, err = decorateAuthParams(req)
			if tc.wantErrContains != "" {
				require.Error(err)
				assert.Contains(err.Error(), tc.wantErrContains)
				return
			}
			require.NoError(err)
			require.NotNil(ctx)

			scopeVal := ctx.Value(globals.ContextScopeValue)
			require.NotNil(scopeVal)
			assert.Equal(tc.scope, scopeVal.(scope.Type), "scope")

			actionVal := ctx.Value(globals.ContextActionValue)
			require.NotNil(actionVal)
			assert.Equal(tc.action, actionVal.(action.Type), "action")

			typVal := ctx.Value(globals.ContextTypeValue)
			require.NotNil(typVal)
			assert.Equal(tc.resource, typVal.(resource.Type), "type")

			idVal := ctx.Value(globals.ContextResourceValue)
			require.NotNil(idVal)
			assert.Equal(tc.id, idVal.(string), "id")
		})
	}
}
