package controller_testing

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

func TestAuthenticationMulti(t *testing.T) {
	c1 := NewTestController(t, &TestControllerOpts{DefaultOrgId: "o_1234567890"})
	defer c1.Shutdown()

	c2 := NewTestController(t, &TestControllerOpts{DatabaseUrl: c1.Config().DatabaseUrl})
	defer c2.Shutdown()

	resp, err := http.Post(fmt.Sprintf("%s/v1/scopes/o_1234567890/auth-methods/am_1234567890:authenticate", c.ApiAddrs()[0]), "application/json",
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
