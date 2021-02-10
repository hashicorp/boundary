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
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestAuthenticationHandler(t *testing.T) {
	c := NewTestController(t, &TestControllerOpts{
		DisableAuthorizationFailures: true,
		DefaultAuthMethodId:          "ampw_1234567890",
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

	resp, err := http.Post(fmt.Sprintf("%s/v1/auth-methods/ampw_1234567890:authenticate", c.ApiAddrs()[0]), "application/json", bytes.NewReader(b))

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
	require.NoError(t, err)
	resp, err = http.Post(fmt.Sprintf("%s/v1/auth-methods/ampw_1234567890:authenticate", c.ApiAddrs()[0]), "application/json", bytes.NewReader(b))

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
			"v1/accounts",
			"v1/accounts/someid",
			"v1/auth-methods",
			"v1/auth-methods/someid",
			"v1/auth-tokens",
			"v1/auth-tokens/someid",
			"v1/groups",
			"v1/groups/someid",
			"v1/host-catalogs",
			"v1/host-catalogs/someid",
			"v1/host-sets",
			"v1/host-sets/someid",
			"v1/hosts",
			"v1/hosts/someid",
			"v1/roles",
			"v1/roles/someid",
			"400_v1/sc\u200Bopes",
			"200_v1/scopes",
			"v1/scopes/someid",
			"v1/sessions",
			"v1/sessions/someid",
			"v1/targets",
			"v1/targets/someid",
			"v1/users",
			"v1/users/someid",
		},
		"POST": {
			// Creation end points
			"v1/accounts",
			"v1/auth-methods",
			"v1/groups",
			"v1/host-catalogs",
			"v1/host-sets",
			"v1/hosts",
			"v1/roles",
			"v1/scopes",
			"v1/targets",
			"v1/users",

			// custom methods
			"v1/accounts/someid:set-password",
			"v1/accounts/someid:change-password",
			"v1/auth-methods/someid:authenticate",
			"v1/groups/someid:add-members",
			"v1/groups/someid:set-members",
			"v1/groups/someid:remove-members",
			"v1/host-sets/someid:add-hosts",
			"v1/host-sets/someid:remove-hosts",
			"v1/host-sets/someid:set-hosts",
			"v1/roles/someid:add-grants",
			"v1/roles/someid:set-grants",
			"v1/roles/someid:remove-grants",
			"v1/roles/someid:add-principals",
			"v1/roles/someid:set-principals",
			"v1/roles/someid:remove-principals",
			"v1/sessions/someid:cancel",
			"v1/targets/someid:authorize-session",
			"v1/targets/someid:add-host-sets",
			"v1/targets/someid:set-host-sets",
			"v1/targets/someid:remove-host-sets",
			"v1/users/someid:add-accounts",
			"v1/users/someid:set-accounts",
			"v1/users/someid:remove-accounts",
		},
		"DELETE": {
			"v1/accounts/someid",
			"v1/auth-methods/someid",
			"v1/auth-tokens/someid",
			"v1/groups/someid",
			"v1/host-catalogs/someid",
			"v1/host-sets/someid",
			"v1/hosts/someid",
			"v1/roles/someid",
			"v1/scopes/someid",
			"v1/targets/someid",
			"v1/users/someid",
		},
		"PATCH": {
			"v1/accounts/someid",
			"v1/auth-methods/someid",
			"v1/groups/someid",
			"v1/host-catalogs/someid",
			"v1/host-sets/someid",
			"v1/hosts/someid",
			"v1/roles/someid",
			"v1/scopes/someid",
			"v1/targets/someid",
			"v1/users/someid",
		},
	} {
		for _, p := range paths {
			t.Run(fmt.Sprintf("%s/%s", verb, p), func(t *testing.T) {
				var expCode int
				if !strings.HasPrefix(p, "v1/") {
					sp := strings.Split(p, "_")
					require.Len(t, sp, 2)
					switch sp[0] {
					case "400":
						expCode = http.StatusBadRequest
					case "200":
						expCode = http.StatusOK
					}
					p = sp[1]
				}

				url := fmt.Sprintf("%s/%s", c.ApiAddrs()[0], p)
				req, err := http.NewRequest(verb, url, nil)
				require.NoError(t, err)
				resp, err := http.DefaultClient.Do(req)
				require.NoError(t, err)
				if expCode != 0 {
					assert.Equal(t, expCode, resp.StatusCode)
				}
				assert.NotEqualf(t, resp.StatusCode, http.StatusNotFound, "Got response %v, wanted not 404", resp.StatusCode)
			})
		}
	}
}
