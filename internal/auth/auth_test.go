package auth

import (
	"fmt"
	"net/http"
	"testing"

	"github.com/hashicorp/watchtower/internal/types/action"
	"github.com/hashicorp/watchtower/internal/types/resource"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestHandler_AuthDecoration(t *testing.T) {
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
			path:     "/v1/users/u_anon",
			method:   "GET",
			action:   action.Read,
			scope:    "global",
			resource: resource.User,
			id:       "u_anon",
		},
		{
			name:     "global scope, update, with id",
			path:     "/v1/auth-methods/am_1234",
			method:   "PATCH",
			action:   action.Update,
			scope:    "global",
			resource: resource.AuthMethod,
			id:       "am_1234",
		},
		{
			name:     "global scope, delete",
			path:     "/v1/orgs/o_1234",
			method:   "DELETE",
			action:   action.Delete,
			scope:    "global",
			resource: resource.Org,
			id:       "o_1234",
		},
		{
			name:     "global scope, create",
			path:     "/v1/roles",
			method:   "POST",
			action:   action.Create,
			scope:    "global",
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
			scope:    "o_123",
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
			scope:    "o_abc123",
			resource: resource.AuthMethod,
		},
		{
			name:     "project scope, valid",
			path:     "/v1/orgs/o_abc123/projects/p_1234/host-catalogs",
			method:   "POST",
			action:   action.Create,
			scope:    "p_1234",
			resource: resource.HostCatalog,
		},
		{
			name:     "project scope, action on project",
			path:     "/v1/orgs/o_abc123/projects/p_1234/:set-principals",
			method:   "POST",
			action:   action.SetPrincipals,
			scope:    "p_1234",
			resource: resource.Project,
			id:       "p_1234",
		},
		{
			name:     "org scope, action on project",
			path:     "/v1/orgs/o_abc123/projects/p_1234:set-principals",
			method:   "POST",
			action:   action.SetPrincipals,
			scope:    "o_abc123",
			resource: resource.Project,
			id:       "p_1234",
		},
		{
			name:     "org scope, get on collection is list",
			path:     "/v1/orgs/o_abc123/projects",
			action:   action.List,
			scope:    "o_abc123",
			resource: resource.Project,
		},
		{
			name:     "org scope, action on org",
			path:     "/v1/orgs/o_abc123/:deauthenticate",
			action:   action.Deauthenticate,
			scope:    "o_abc123",
			resource: resource.Org,
			id:       "o_abc123",
		},
		{
			name:            "top level action, invalid",
			path:            "/v1/:read",
			wantErrContains: "id and type both not found",
		},
		{
			name:            "top level, invalid",
			path:            "/v1/",
			wantErrContains: "id and type both not found",
		},
		{
			name:            "non-api path",
			path:            "/",
			wantErrContains: "id and type both not found",
		},
		{
			name:     "project scope, pinning collection",
			path:     "/v1/orgs/o_abc123/projects/p_1234/host-catalogs/hc_1234/host-sets",
			action:   action.List,
			scope:    "p_1234",
			pin:      "hc_1234",
			resource: resource.HostSet,
		},
		{
			name:     "project scope, pinning collection, custom action",
			path:     "/v1/orgs/o_abc123/projects/p_1234/host-catalogs/hc_1234/host-sets:create",
			action:   action.Create,
			scope:    "p_1234",
			pin:      "hc_1234",
			resource: resource.HostSet,
		},
		{
			name:     "project scope, pinning id",
			path:     "/v1/orgs/o_abc123/projects/p_1234/host-catalogs/hc_1234/host-sets/hs_abc",
			action:   action.Read,
			id:       "hs_abc",
			scope:    "p_1234",
			pin:      "hc_1234",
			resource: resource.HostSet,
		},
		{
			name:     "project scope, pinning id, custom action",
			path:     "/v1/orgs/o_abc123/projects/p_1234/host-catalogs/hc_1234/host-sets/hs_abc:update",
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
			}

			err = v.parseAuthParams()
			if tc.wantErrContains != "" {
				require.Error(err)
				assert.Contains(err.Error(), tc.wantErrContains, err.Error())
				return
			}
			require.NoError(err)

			if tc.path == "/" {
				return
			}

			require.NotNil(v.res)
			require.NotEqual(action.Unknown, v.act)
			assert.Equal(tc.scope, v.res.ScopeId, "scope")
			assert.Equal(tc.action, v.act, "action")
			assert.Equal(tc.resource, v.res.Type, "type")
			assert.Equal(tc.id, v.res.Id, "id")
			assert.Equal(tc.pin, v.res.Pin, "pin")
		})
	}
}
