package controller

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestAuthenticationHandler(t *testing.T) {
	c := NewTestController(t, &TestControllerOpts{DefaultOrgId: "o_1234567890"})
	defer c.Shutdown()

	resp, err := http.Post(fmt.Sprintf("%s/v1/orgs/o_1234567890/auth-methods/am_1234567890:authenticate", c.ApiAddrs()[0]), "application/json",
		strings.NewReader(`{"token_type": null, "credentials": {"name":"test", "password": "test"}}`))
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

func TestHandleImplementedPaths(t *testing.T) {
	c := NewTestController(t, &TestControllerOpts{
		DisableAuthorizationFailures: true,
	})
	defer c.Shutdown()

	for verb, paths := range map[string][]string{
		"GET": {
			"v1/orgs/someid",
			"v1/orgs/someid/projects",
			"v1/orgs/someid/projects/someid",
			"v1/orgs/someid/users",
			"v1/orgs/someid/users/someid",
			"v1/orgs/someid/roles",
			"v1/orgs/someid/roles/someid",
			"v1/orgs/someid/projects/someid/roles",
			"v1/orgs/someid/projects/someid/roles/someid",
			"v1/orgs/someid/groups",
			"v1/orgs/someid/groups/someid",
			"v1/orgs/someid/projects/someid/groups",
			"v1/orgs/someid/projects/someid/groups/someid",
			"v1/orgs/someid/projects/someid/host-catalogs",
			"v1/orgs/someid/projects/someid/host-catalogs/someid",
		},
		"POST": {
			// Creation end points
			"v1/orgs/someid/projects",
			"v1/orgs/someid/users",
			"v1/orgs/someid/roles",
			"v1/orgs/someid/projects/someid/roles",
			"v1/orgs/someid/groups",
			"v1/orgs/someid/projects/someid/groups",

			// custom methods
			"v1/orgs/someid/roles/someid:add-principals",
			"v1/orgs/someid/roles/someid:set-principals",
			"v1/orgs/someid/roles/someid:remove-principals",
			"v1/orgs/someid/projects/someid/roles/someid:add-principals",
			"v1/orgs/someid/projects/someid/roles/someid:set-principals",
			"v1/orgs/someid/projects/someid/roles/someid:remove-principals",
			"v1/orgs/someid/roles/someid:add-grants",
			"v1/orgs/someid/roles/someid:set-grants",
			"v1/orgs/someid/roles/someid:remove-grants",
			"v1/orgs/someid/projects/someid/roles/someid:add-grants",
			"v1/orgs/someid/projects/someid/roles/someid:set-grants",
			"v1/orgs/someid/projects/someid/roles/someid:remove-grants",
		},
		"DELETE": {
			"v1/orgs/someid/projects/someid",
			"v1/orgs/someid/users/someid",
			"v1/orgs/someid/roles/someid",
			"v1/orgs/someid/projects/someid/roles/someid",
			"v1/orgs/someid/groups/someid",
			"v1/orgs/someid/projects/someid/groups/someid",
		},
		"PATCH": {
			"v1/orgs/someid/projects/someid",
			"v1/orgs/someid/users/someid",
			"v1/orgs/someid/roles/someid",
			"v1/orgs/someid/projects/someid/roles/someid",
			"v1/orgs/someid/groups/someid",
			"v1/orgs/someid/projects/someid/groups/someid",
		},
	} {
		for _, p := range paths {
			t.Run(fmt.Sprintf("%s/%s", verb, p), func(t *testing.T) {
				url := fmt.Sprintf("%s/%s", c.ApiAddrs()[0], p)
				req, err := http.NewRequest(verb, url, nil)
				require.NoError(t, err)
				resp, err := http.DefaultClient.Do(req)
				require.NoError(t, err)
				assert.NotEqualf(t, resp.StatusCode, http.StatusNotFound, "Got response %v, wanted not 404", resp.StatusCode)
			})
		}
	}
}
