package controller

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"strings"
	"testing"

	"github.com/hashicorp/boundary/internal/servers/controller/handlers"
	"github.com/hashicorp/boundary/internal/types/scope"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestAuthenticationHandler(t *testing.T) {
	c := NewTestController(t, &TestControllerOpts{
		DisableAuthorizationFailures: true,
		DefaultLoginName:             "admin",
		DefaultPassword:              "password123",
	})
	defer c.Shutdown()

	request := map[string]interface{}{
		"credentials": map[string]interface{}{
			"login_name": "admin",
			"password":   "password123",
		},
	}
	// No token_type defined means "token" type
	b, err := json.Marshal(request)
	require.NoError(t, err)

	resp, err := http.Post(fmt.Sprintf("%s/v1/scopes/%s/auth-methods/ampw_1234567890:authenticate", c.ApiAddrs()[0],
		scope.Global.String()), "application/json", bytes.NewReader(b))

	require.NoError(t, err)
	assert.Equal(t, http.StatusOK, resp.StatusCode, "Got response: %v", resp)

	b, err = ioutil.ReadAll(resp.Body)
	require.NoError(t, err)
	body := make(map[string]interface{})
	require.NoError(t, json.Unmarshal(b, &body))

	require.Contains(t, body, "id")
	require.Contains(t, body, "token")
	pubId, tok := body["id"].(string), body["token"].(string)
	assert.NotEmpty(t, pubId)
	assert.NotEmpty(t, tok)
	assert.Truef(t, strings.HasPrefix(tok, pubId), "Token: %q, Id: %q", tok, pubId)

	// Set the token type to cookie and make sure the body does not contain the token anymore.
	request["token_type"] = "cookie"
	b, err = json.Marshal(request)
	resp, err = http.Post(fmt.Sprintf("%s/v1/scopes/%s/auth-methods/ampw_1234567890:authenticate", c.ApiAddrs()[0],
		scope.Global.String()), "application/json", bytes.NewReader(b))

	require.NoError(t, err)
	assert.Equal(t, http.StatusOK, resp.StatusCode, "Got response: %v", resp)

	b, err = ioutil.ReadAll(resp.Body)
	require.NoError(t, err)
	body = make(map[string]interface{})
	require.NoError(t, json.Unmarshal(b, &body))

	require.Contains(t, body, "id")
	require.Contains(t, body, "auth_method_id")
	require.Contains(t, body, "user_id")
	require.NotContains(t, body, "token")

	cookies := make(map[string]*http.Cookie)
	for _, c := range resp.Cookies() {
		cookies[c.Name] = c
	}
	require.Contains(t, cookies, handlers.HttpOnlyCookieName)
	require.Contains(t, cookies, handlers.JsVisibleCookieName)
	assert.NotEmpty(t, cookies[handlers.HttpOnlyCookieName].Value)
	assert.NotEmpty(t, cookies[handlers.JsVisibleCookieName].Value)
	assert.True(t, cookies[handlers.HttpOnlyCookieName].HttpOnly)
	assert.False(t, cookies[handlers.JsVisibleCookieName].HttpOnly)
	tok = cookies[handlers.JsVisibleCookieName].Value

	pubId = body["id"].(string)
	assert.NotEmpty(t, pubId)
	assert.Truef(t, strings.HasPrefix(tok, pubId), "Token: %q, Id: %q", tok, pubId)
}

func TestHandleImplementedPaths(t *testing.T) {
	c := NewTestController(t, &TestControllerOpts{
		DisableAuthorizationFailures: true,
	})
	defer c.Shutdown()

	for verb, paths := range map[string][]string{
		"GET": {
			"v1/scopes",
			"v1/scopes/someid",
			"v1/scopes/someid/auth-tokens",
			"v1/scopes/someid/auth-tokens/someid",
			"v1/scopes/someid/auth-methods",
			"v1/scopes/someid/auth-methods/someid",
			"v1/scopes/someid/auth-methods/someid/accounts",
			"v1/scopes/someid/auth-methods/someid/accounts/someid",
			"v1/scopes/someid/groups",
			"v1/scopes/someid/groups/someid",
			"v1/scopes/someid/host-catalogs",
			"v1/scopes/someid/host-catalogs/someid",
			"v1/scopes/someid/host-catalogs/someid/host-sets",
			"v1/scopes/someid/host-catalogs/someid/host-sets/someid",
			"v1/scopes/someid/host-catalogs/someid/hosts",
			"v1/scopes/someid/host-catalogs/someid/hosts/someid",
			"v1/scopes/someid/roles",
			"v1/scopes/someid/roles/someid",
			"v1/scopes/someid/users",
			"v1/scopes/someid/users/someid",
		},
		"POST": {
			// Creation end points
			"v1/scopes",
			"v1/scopes/someid/groups",
			"v1/scopes/someid/roles",
			"v1/scopes/someid/users",
			"v1/scopes/someid/auth-methods",
			"v1/scopes/someid/auth-methods/someid/accounts",
			"v1/scopes/someid/host-catalogs",
			"v1/scopes/someid/host-catalogs/someid/host-sets",
			"v1/scopes/someid/host-catalogs/someid/hosts",

			// custom methods
			"v1/scopes/someid/auth-methods/someid:authenticate",
			"v1/scopes/someid/auth-methods/someid/accounts/someid:set-password",
			"v1/scopes/someid/auth-methods/someid/accounts/someid:change-password",
			"v1/scopes/someid/roles/someid:add-principals",
			"v1/scopes/someid/roles/someid:set-principals",
			"v1/scopes/someid/roles/someid:remove-principals",
			"v1/scopes/someid/roles/someid:add-grants",
			"v1/scopes/someid/roles/someid:set-grants",
			"v1/scopes/someid/roles/someid:remove-grants",
			"v1/scopes/someid/groups/someid:add-members",
			"v1/scopes/someid/groups/someid:set-members",
			"v1/scopes/someid/groups/someid:remove-members",
		},
		"DELETE": {
			"v1/scopes/someid",
			"v1/scopes/someid/users/someid",
			"v1/scopes/someid/roles/someid",
			"v1/scopes/someid/groups/someid",
			"v1/scopes/someid/auth-tokens/someid",
			"v1/scopes/someid/auth-methods/someid",
			"v1/scopes/someid/auth-methods/someid/accounts/someid",
			"v1/scopes/someid/host-catalogs/someid",
			"v1/scopes/someid/host-catalogs/someid/host-sets/someid",
			"v1/scopes/someid/host-catalogs/someid/hosts/someid",
		},
		"PATCH": {
			"v1/scopes/someid",
			"v1/scopes/someid/users/someid",
			"v1/scopes/someid/roles/someid",
			"v1/scopes/someid/groups/someid",
			"v1/scopes/someid/auth-methods/someid",
			"v1/scopes/someid/host-catalogs/someid",
			"v1/scopes/someid/host-catalogs/someid/host-sets/someid",
			"v1/scopes/someid/host-catalogs/someid/hosts/someid",
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
