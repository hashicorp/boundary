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
	"github.com/hashicorp/watchtower/internal/gen/controller/api/services"
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
			"v1/this-is-made-up",
			http.StatusNotFound,
		},
		{
			"Unimplemented path",
			"v1/orgs/1/projects/2/host-catalogs/3/host-sets/4",
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
